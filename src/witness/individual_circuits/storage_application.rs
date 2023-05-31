use super::*;
use crate::biguint_from_u256;
use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::tree::*;
use blake2::Blake2s256;
use derivative::Derivative;
use num_bigint::BigUint;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::glue::keccak256_round_function_circuit::*;
use sync_vm::glue::storage_application::input::StorageApplicationCircuitInstanceWitness;
use sync_vm::glue::storage_application::input::StorageApplicationFSM;
use tracing;
use zk_evm::precompiles::keccak256::BUFFER_SIZE;

pub fn decompose_into_storage_application_witnesses<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>,
>(
    artifacts: &mut FullBlockArtifacts<E>,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    round_function: &R,
    num_rounds_per_circuit: usize,
) -> Vec<StorageApplicationCircuitInstanceWitness<E>> {
    use crate::witness::tree::EnumeratedBinaryLeaf;
    use crate::witness::tree::ZkSyncStorageLeaf;
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;
    use sync_vm::glue::storage_application::input::*;
    use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;

    if artifacts.deduplicated_rollup_storage_queries.is_empty() {
        // return singe dummy witness

        let initial_fsm_state = StorageApplicationFSM::<E>::placeholder_witness();

        let mut passthrough_input = StorageApplicationInputData::placeholder_witness();
        passthrough_input.initial_next_enumeration_counter = tree.next_enumeration_index();
        let root_as_u128 = bytes_to_u128_le(&tree.root());
        passthrough_input.initial_root = root_as_u128;
        passthrough_input.storage_application_log_state =
            take_queue_state_from_simulator(&artifacts.deduplicated_rollup_storage_queue_simulator);

        let mut final_fsm_state = StorageApplicationFSM::<E>::placeholder_witness();
        let first_writes_simulator = InitialStorageWritesSimulator::<E>::empty();
        let repeated_writes_simulator = RepeatedStorageWritesSimulator::<E>::empty();

        let root_as_u128 = bytes_to_u128_le(&tree.root());
        final_fsm_state.root_hash = root_as_u128;
        final_fsm_state.next_enumeration_counter = tree.next_enumeration_index();
        final_fsm_state.current_storage_application_log_state = take_queue_state_from_simulator(
            &&artifacts.deduplicated_rollup_storage_queue_simulator,
        );
        final_fsm_state.repeated_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&repeated_writes_simulator);
        final_fsm_state.initial_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&first_writes_simulator);

        let mut passthrough_output = StorageApplicationOutputData::placeholder_witness();
        passthrough_output.final_next_enumeration_counter = tree.next_enumeration_index();
        let root_as_u128 = bytes_to_u128_le(&tree.root());
        passthrough_output.final_root = root_as_u128;
        passthrough_output.repeated_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&repeated_writes_simulator);
        passthrough_output.initial_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&first_writes_simulator);

        let wit = StorageApplicationCircuitInstanceWitness {
            closed_form_input: StorageApplicationCycleInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            storage_queue_witness: FixedWidthEncodingGenericQueueWitness::default(),
            leaf_indexes_for_reads: vec![],
            merkle_paths: vec![],
        };

        return vec![wit];
    }

    let mut result = vec![];

    // first split into chunks of work for every circuit

    let mut total_tree_queries = 0;

    let mut chunks = vec![];

    let mut current_chunk = vec![];

    for el in artifacts.deduplicated_rollup_storage_queries.iter() {
        if el.rw_flag {
            total_tree_queries += 2;
        } else {
            total_tree_queries += 1;
        }

        current_chunk.push(*el);

        // we leave 1 to make a final application of "write"
        if total_tree_queries >= num_rounds_per_circuit - 1 {
            let current = std::mem::replace(&mut current_chunk, vec![]);
            assert!(current.len() <= num_rounds_per_circuit);
            chunks.push(current);
            total_tree_queries = 0;
        }
    }

    if total_tree_queries != 0 {
        let current = std::mem::replace(&mut current_chunk, vec![]);
        assert!(current.len() <= num_rounds_per_circuit);
        chunks.push(current);
    }

    // now proceed as FSM over individual circuits

    use crate::bytes_to_u32_le;
    use crate::witness::tree::BinarySparseStorageTree;
    use sync_vm::traits::CSWitnessable;

    let mut initial_fsm_state = StorageApplicationFSM::<E>::placeholder_witness();
    // queue states are trivial for a start

    use crate::encodings::initial_storage_write::*;
    use crate::encodings::repeated_storage_write::*;

    let mut first_writes_simulator = InitialStorageWritesSimulator::<E>::empty();
    let mut repeated_writes_simulator = RepeatedStorageWritesSimulator::<E>::empty();
    let mut storage_queue_state_idx = 0;

    let num_chunks = chunks.len();

    let mut storage_application_simulator = artifacts
        .deduplicated_rollup_storage_queue_simulator
        .clone();

    tracing::debug!(
        "Initial enumeration index = {}",
        tree.next_enumeration_index()
    );
    let mut current_root = tree.root();
    tracing::debug!("Initial root = {}", hex::encode(&tree.root()));

    for (idx, chunk) in chunks.into_iter().enumerate() {
        let is_last = idx == num_chunks - 1;

        let mut merkle_paths = vec![];
        let mut leaf_enumeration_index_for_read = vec![];

        let mut passthrough_input = StorageApplicationInputData::placeholder_witness();
        if idx == 0 {
            passthrough_input.initial_next_enumeration_counter = tree.next_enumeration_index();
            let root_as_u128 = bytes_to_u128_le(&tree.root());
            passthrough_input.initial_root = root_as_u128;
            passthrough_input.storage_application_log_state = take_queue_state_from_simulator(
                &artifacts.deduplicated_rollup_storage_queue_simulator,
            );
        }

        let chunk_len = chunk.len();

        // apply one by one in chunk
        for el in chunk.into_iter() {
            let _ = storage_application_simulator.pop_and_output_intermediate_data(round_function);

            let key = el.derive_final_address();
            if el.rw_flag {
                // by convension we have read and write both
                let read_query = tree.get_leaf(&key);
                // assert!(tree.verify_inclusion_proxy(&tree.root(), &read_query));

                // assert_eq!(current_root, tree.root());
                // we can use independent implementation here to check
                assert!(
                    ZKSyncTestingTree::verify_inclusion(&current_root, &read_query),
                    "failed to verify inclusion of read query during write operation over log query {:?}",
                    &el
                );

                let mut buffer = [0u8; 32];
                el.read_value.to_big_endian(&mut buffer);
                assert_eq!(&buffer, read_query.leaf.value(), "While writing: divergent leaf read value for index {}: expecting to read {}, got {}", hex::encode(&key), hex::encode(&buffer), hex::encode(&read_query.leaf.value()));

                let leaf_index = read_query.leaf.current_index();
                leaf_enumeration_index_for_read.push(leaf_index);

                let mut leaf = ZkSyncStorageLeaf::empty();
                el.written_value.to_big_endian(leaf.value_ref_mut());
                // we expect that tree properly updates enumeration index on insert
                let write_query = tree.insert_leaf(&key, leaf);
                current_root = tree.root();
                assert!(tree.verify_inclusion_proxy(&tree.root(), &write_query));
                assert!(
                    ZKSyncTestingTree::verify_inclusion(&current_root, &write_query),
                    "failed to verify inclusion of write query during write operation over log query {:?}",
                    &el
                );

                assert_eq!(&*read_query.merkle_path, &*write_query.merkle_path);

                let LeafQuery {
                    leaf,
                    first_write,
                    index: _,
                    merkle_path,
                } = write_query;

                let path = (*merkle_path)
                    .into_iter()
                    .map(|el| bytes_to_u32_le(&el))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                merkle_paths.push(path);

                if first_write {
                    assert_eq!(leaf_index, 0);
                    let first_write = InitialStorageWrite {
                        key,
                        value: leaf.value,
                    };
                    first_writes_simulator.push(first_write, round_function);
                } else {
                    assert_ne!(leaf_index, 0);
                    let repeated_write = RepeatedStorageWrite {
                        index: leaf.index,
                        value: leaf.value,
                    };
                    repeated_writes_simulator.push(repeated_write, round_function);
                }
            } else {
                // read
                assert_eq!(current_root, tree.root());

                let read_query = tree.get_leaf(&key);
                assert!(tree.verify_inclusion_proxy(&tree.root(), &read_query));

                // we can use independent implementation here to check
                assert!(
                    ZKSyncTestingTree::verify_inclusion(&current_root, &read_query),
                    "failed to verify inclusion of query during read operation over log query {:?}",
                    &el
                );

                let LeafQuery {
                    leaf,
                    first_write: _,
                    index: _,
                    merkle_path,
                } = read_query;
                let leaf_index = leaf.current_index();
                leaf_enumeration_index_for_read.push(leaf_index);

                let mut buffer = [0u8; 32];
                el.read_value.to_big_endian(&mut buffer);
                assert_eq!(&buffer, leaf.value(), "While reading: divergent leaf value for index {}: expecting to read {}, got {}", hex::encode(&key), hex::encode(&buffer), hex::encode(&leaf.value()));

                let path = (*merkle_path)
                    .into_iter()
                    .map(|el| bytes_to_u32_le(&el))
                    .collect::<Vec<_>>();
                assert_eq!(path.len(), 256);

                merkle_paths.push(path);
            }
        }
        assert_eq!(leaf_enumeration_index_for_read.len(), merkle_paths.len());

        let mut final_fsm_state = StorageApplicationFSM::<E>::placeholder_witness();
        // set current values
        let root_as_u128 = bytes_to_u128_le(&tree.root());
        final_fsm_state.root_hash = root_as_u128;
        final_fsm_state.next_enumeration_counter = tree.next_enumeration_index();
        final_fsm_state.current_storage_application_log_state =
            take_queue_state_from_simulator(&storage_application_simulator);
        final_fsm_state.repeated_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&repeated_writes_simulator);
        final_fsm_state.initial_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&first_writes_simulator);

        let wit = transform_queue_witness(
            artifacts
                .deduplicated_rollup_storage_queue_simulator
                .witness
                .iter()
                .skip(storage_queue_state_idx)
                .take(chunk_len),
        );

        storage_queue_state_idx += chunk_len;

        let mut passthrough_output = StorageApplicationOutputData::placeholder_witness();
        if is_last {
            passthrough_output.final_next_enumeration_counter = tree.next_enumeration_index();
            let root_as_u128 = bytes_to_u128_le(&tree.root());
            passthrough_output.final_root = root_as_u128;
            passthrough_output.repeated_writes_pubdata_queue_state =
                take_queue_state_from_simulator(&repeated_writes_simulator);
            passthrough_output.initial_writes_pubdata_queue_state =
                take_queue_state_from_simulator(&first_writes_simulator);
        }

        let input = StorageApplicationCircuitInstanceWitness {
            closed_form_input: StorageApplicationCycleInputOutputWitness {
                start_flag: idx == 0,
                completion_flag: is_last,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            storage_queue_witness: wit,
            leaf_indexes_for_reads: leaf_enumeration_index_for_read,
            merkle_paths,
        };

        initial_fsm_state = final_fsm_state.clone();

        result.push(input);
    }

    tracing::debug!(
        "Final enumeration index = {}",
        tree.next_enumeration_index()
    );
    assert_eq!(current_root, tree.root());
    tracing::debug!("Final root = {}", hex::encode(&tree.root()));

    result
}
