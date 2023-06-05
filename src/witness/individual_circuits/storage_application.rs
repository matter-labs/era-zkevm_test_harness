use super::*;
use crate::boojum::gadgets::keccak256::{self};
use crate::boojum::sha3::digest::{FixedOutput, Update};
use crate::boojum::sha3::Keccak256;
use crate::witness::individual_circuits::keccak256_round_function::encode_kecca256_inner_state;
use crate::witness::tree::*;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::{transmute_state, BUFFER_SIZE};
use crate::zkevm_circuits::base_structures::state_diff_record::NUM_KECCAK256_ROUNDS_PER_RECORD_ACCUMULATION;
use crate::zkevm_circuits::storage_application::input::*;
use blake2::Blake2s256;
use circuit_definitions::encodings::state_diff_record::StateDiffRecord;
use tracing;

use crate::sha3::Digest;

pub fn decompose_into_storage_application_witnesses<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    round_function: &R,
    num_rounds_per_circuit: usize,
) -> Vec<StorageApplicationCircuitInstanceWitness<F>> {
    use crate::witness::tree::EnumeratedBinaryLeaf;
    use crate::witness::tree::ZkSyncStorageLeaf;

    const SHARD_ID_TO_PROCEED: u8 = 0; // rollup shard ID

    if artifacts.deduplicated_rollup_storage_queries.is_empty() {
        // return singe dummy witness

        let initial_fsm_state = StorageApplicationFSMInputOutput::<F>::placeholder_witness();

        let mut passthrough_input = StorageApplicationInputData::placeholder_witness();
        passthrough_input.initial_next_enumeration_counter =
            u64_as_u32_le(tree.next_enumeration_index());
        passthrough_input.initial_root_hash = tree.root();
        passthrough_input.shard = SHARD_ID_TO_PROCEED;
        passthrough_input.storage_application_log_state =
            take_queue_state_from_simulator(&artifacts.deduplicated_rollup_storage_queue_simulator);

        let hasher = <Keccak256 as Digest>::new();
        let mut accumulator = [0u8; 32];
        accumulator.copy_from_slice(hasher.clone().finalize().as_slice());

        let state = transmute_state(hasher);

        let mut final_fsm_state = StorageApplicationFSMInputOutput::<F>::placeholder_witness();
        final_fsm_state.next_enumeration_counter = u64_as_u32_le(tree.next_enumeration_index());
        final_fsm_state.current_root_hash = tree.root();
        final_fsm_state.current_storage_application_log_state = take_queue_state_from_simulator(
            &&artifacts.deduplicated_rollup_storage_queue_simulator,
        );
        final_fsm_state.current_diffs_keccak_accumulator_state = encode_kecca256_inner_state(state);

        let mut passthrough_output = StorageApplicationOutputData::placeholder_witness();
        passthrough_output.new_next_enumeration_counter =
            u64_as_u32_le(tree.next_enumeration_index());
        passthrough_output.new_root_hash = tree.root();
        passthrough_output.state_diffs_keccak256_hash = accumulator;

        let wit = StorageApplicationCircuitInstanceWitness {
            closed_form_input: StorageApplicationInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
            },
            storage_queue_witness: CircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
            merkle_paths: VecDeque::new(),
            leaf_indexes_for_reads: VecDeque::new(),
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

    let mut initial_fsm_state = StorageApplicationFSMInputOutput::<F>::placeholder_witness();
    // queue states are trivial for a start

    let mut hasher = <Keccak256 as Digest>::new();

    let mut storage_queue_state_idx = 0;

    let num_chunks = chunks.len();

    let mut storage_application_simulator = artifacts
        .deduplicated_rollup_storage_queue_simulator
        .clone();

    tracing::debug!(
        "Initial enumeration index = {}",
        tree.next_enumeration_index()
    );
    tracing::debug!("Initial root = {}", hex::encode(&tree.root()));

    for (idx, chunk) in chunks.into_iter().enumerate() {
        let is_last = idx == num_chunks - 1;

        let mut merkle_paths = VecDeque::new();
        let mut leaf_enumeration_index_for_read = VecDeque::new();

        let mut passthrough_input = StorageApplicationInputData::placeholder_witness();
        if idx == 0 {
            passthrough_input.initial_next_enumeration_counter =
                u64_as_u32_le(tree.next_enumeration_index());
            passthrough_input.initial_root_hash = tree.root();
            passthrough_input.shard = SHARD_ID_TO_PROCEED;
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
                let mut buffer = [0u8; 32];
                el.read_value.to_big_endian(&mut buffer);
                assert_eq!(&buffer, read_query.leaf.value(), "While writing: divergent leaf read value for index {}: expecting to read {}, got {}", hex::encode(&key), hex::encode(&buffer), hex::encode(&read_query.leaf.value()));

                let leaf_index = read_query.leaf.current_index();
                leaf_enumeration_index_for_read.push_back(leaf_index);

                let mut leaf = ZkSyncStorageLeaf::empty();
                el.written_value.to_big_endian(leaf.value_ref_mut());
                // we expect that tree properly updates enumeration index on insert
                let write_query = tree.insert_leaf(&key, leaf);
                assert!(tree.verify_inclusion_proxy(&tree.root(), &write_query));

                assert_eq!(&*read_query.merkle_path, &*write_query.merkle_path);

                let LeafQuery {
                    leaf: _,
                    first_write: _,
                    index: _,
                    merkle_path,
                } = write_query;

                merkle_paths.push_back((*merkle_path).into_iter().collect());

                // NOTE: we need enumeration index BEFORE writing
                let state_diff = StateDiffRecord {
                    address: el.address,
                    key: el.key,
                    derived_key: key,
                    enumeration_index: read_query.leaf.current_index(),
                    initial_value: el.read_value,
                    final_value: el.written_value,
                };

                let mut extended_state_diff_encoding = [0u8; keccak256::KECCAK_RATE_BYTES
                    * NUM_KECCAK256_ROUNDS_PER_RECORD_ACCUMULATION];
                let packed_encoding = state_diff.encode();
                extended_state_diff_encoding[0..packed_encoding.len()]
                    .copy_from_slice(&packed_encoding);
                // dbg!(hex::encode(&extended_state_diff_encoding));

                Digest::update(&mut hasher, &extended_state_diff_encoding);

                // dbg!(transmute_state(hasher.clone()));
            } else {
                // read
                let read_query = tree.get_leaf(&key);
                assert!(tree.verify_inclusion_proxy(&tree.root(), &read_query));
                let LeafQuery {
                    leaf,
                    first_write: _,
                    index: _,
                    merkle_path,
                } = read_query;
                let leaf_index = leaf.current_index();
                leaf_enumeration_index_for_read.push_back(leaf_index);

                let mut buffer = [0u8; 32];
                el.read_value.to_big_endian(&mut buffer);
                assert_eq!(&buffer, leaf.value(), "While reading: divergent leaf value for index {}: expecting to read {}, got {}", hex::encode(&key), hex::encode(&buffer), hex::encode(&leaf.value()));

                merkle_paths.push_back((*merkle_path).into_iter().collect());
            }
        }

        assert_eq!(leaf_enumeration_index_for_read.len(), merkle_paths.len());

        let state = transmute_state(hasher.clone());

        let mut final_fsm_state = StorageApplicationFSMInputOutput::<F>::placeholder_witness();
        final_fsm_state.next_enumeration_counter = u64_as_u32_le(tree.next_enumeration_index());
        final_fsm_state.current_root_hash = tree.root();
        final_fsm_state.current_storage_application_log_state =
            take_queue_state_from_simulator(&storage_application_simulator);
        final_fsm_state.current_diffs_keccak_accumulator_state = encode_kecca256_inner_state(state);

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
            let mut accumulator = [0u8; 32];
            accumulator.copy_from_slice(hasher.clone().finalize().as_slice());

            passthrough_output.new_next_enumeration_counter =
                u64_as_u32_le(tree.next_enumeration_index());
            passthrough_output.new_root_hash = tree.root();
            passthrough_output.state_diffs_keccak256_hash = accumulator;
        }

        let input = StorageApplicationCircuitInstanceWitness {
            closed_form_input: StorageApplicationInputOutputWitness {
                start_flag: idx == 0,
                completion_flag: is_last,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
            },
            storage_queue_witness: CircuitQueueRawWitness {
                elements: wit.elements.into_inner().unwrap(),
            },
            merkle_paths: merkle_paths,
            leaf_indexes_for_reads: leaf_enumeration_index_for_read,
        };

        initial_fsm_state = final_fsm_state.clone();

        result.push(input);
    }

    tracing::debug!(
        "Final enumeration index = {}",
        tree.next_enumeration_index()
    );
    tracing::debug!("Final root = {}", hex::encode(&tree.root()));

    result
}
