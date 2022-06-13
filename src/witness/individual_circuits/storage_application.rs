use super::*;
use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use derivative::Derivative;
use num_bigint::BigUint;
use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::glue::keccak256_round_function_circuit::*;
use zk_evm::precompiles::keccak256::BUFFER_SIZE;
use crate::biguint_from_u256;
use crate::witness_structures::*;
use crate::witness::tree::{ZKSyncTestingTree, LeafQuery};
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::storage_application::input::{StorageApplicationCircuitInstanceWitness};
use crate::witness::full_block_artifact::FullBlockArtifacts;
use sync_vm::glue::storage_application::input::StorageApplicationFSM;

pub fn decompose_into_storage_application_witnesses<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>,
>(
    artifacts: &mut FullBlockArtifacts<E>,
    tree: &mut ZKSyncTestingTree,
    round_function: &R,
    num_rounds_per_circuit: usize,
) -> Vec<StorageApplicationCircuitInstanceWitness<E>> {
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
            chunks.push(current);
            total_tree_queries = 0;
        }
    }

    // now proceed as FSM over individual circuits

    use crate::witness::tree::BinarySparseStorageTree;
    use crate::bytes_to_u32_le;
    use sync_vm::traits::CSWitnessable;

    let mut fsm_witness = StorageApplicationFSM::<E>::placeholder_witness();
    // queue states are trivial for a start

    use crate::encodings::initial_storage_write::*;
    use crate::encodings::repeated_storage_write::*;

    let mut first_writes_simulator = InitialStorageWritesSimulator::<E>::empty();
    let mut repeated_writes_simulator = RepeatedStorageWritesSimulator::<E>::empty();
    let mut storage_queue_state_idx = 0;

    let num_chunks = chunks.len();

    let mut storage_application_simulator = artifacts.deduplicated_rollup_storage_queue_simulator.clone();

    for (idx, chunk) in chunks.into_iter().enumerate() {
        let is_last = idx == num_chunks - 1;
        let initial_fsm_state = fsm_witness.clone();

        let mut merkle_paths = vec![];

        use sync_vm::glue::storage_application::input::*;
        use sync_vm::circuit_structures::bytes32::Bytes32Witness;
        use crate::witness::tree::ZkSyncStorageLeaf;
        use crate::witness::tree::EnumeratedBinaryLeaf;

        let mut passthrough_input = StorageApplicationInputData::placeholder_witness();
        if idx == 0 {
            passthrough_input.initial_next_enumeration_counter = tree.next_enumeration_index();
            passthrough_input.initial_root = Bytes32Witness::from_bytes_array(&tree.root());
            passthrough_input.storage_application_log_state = take_queue_state_from_simulator(&artifacts.deduplicated_rollup_storage_queue_simulator);
        }

        let chunk_len = chunk.len();

        // apply one by one in chunk
        for el in chunk.into_iter() {
            let _ = storage_application_simulator.pop_and_output_intermediate_data(round_function);

            let key = el.derive_final_address();
            if el.rw_flag {
                // write
                let mut leaf = ZkSyncStorageLeaf::empty();
                el.written_value.to_big_endian(leaf.value_ref_mut());

                let tree_query = tree.insert_leaf(&key, leaf);

                let LeafQuery {
                    leaf,
                    first_write,
                    index: _,
                    merkle_path,
                } = tree_query;

                let path = (*merkle_path).into_iter().map(|el| bytes_to_u32_le(&el)).collect::<Vec<_>>().try_into().unwrap();
                
                merkle_paths.push(path);

                if first_write {
                    let first_write = InitialStorageWrite {
                        key,
                        value: leaf.value
                    };
                    first_writes_simulator.push(first_write, round_function);
                } else {
                    let repeated_write = RepeatedStorageWrite {
                        index: leaf.index,
                        value: leaf.value
                    };
                    repeated_writes_simulator.push(repeated_write, round_function);
                }
            } else {
                // read
                let tree_query = tree.get_leaf(&key);

                let LeafQuery {
                    leaf,
                    first_write: _,
                    index: _,
                    merkle_path,
                } = tree_query;

                let mut buffer = [0u8; 32];
                el.read_value.to_big_endian(&mut buffer);
                assert_eq!(buffer, leaf.value);

                let path = (*merkle_path).into_iter().map(|el| bytes_to_u32_le(&el)).collect::<Vec<_>>().try_into().unwrap();
                
                merkle_paths.push(path);
            }
        }

        let mut final_fsm_state = StorageApplicationFSM::<E>::placeholder_witness();
        // set current values
        final_fsm_state.root_hash_as_u32_words = bytes_to_u32_le(&tree.root());
        final_fsm_state.next_enumeration_counter = tree.next_enumeration_index();
        final_fsm_state.current_storage_application_log_state = take_queue_state_from_simulator(&storage_application_simulator);
        final_fsm_state.repeated_writes_pubdata_queue_state = take_queue_state_from_simulator(&first_writes_simulator);
        final_fsm_state.initial_writes_pubdata_queue_state = take_queue_state_from_simulator(&repeated_writes_simulator);

        let wit = transform_queue_witness(
            artifacts.deduplicated_rollup_storage_queue_simulator.witness.iter().skip(storage_queue_state_idx).take(chunk_len)
        );

        storage_queue_state_idx += chunk_len;

        let mut passthrough_output = StorageApplicationOutputData::placeholder_witness();
        if is_last {
            passthrough_output.final_next_enumeration_counter = tree.next_enumeration_index();
            passthrough_output.final_root = Bytes32Witness::from_bytes_array(&tree.root());
            passthrough_output.repeated_writes_pubdata_queue_state = take_queue_state_from_simulator(&first_writes_simulator);
            passthrough_output.initial_writes_pubdata_queue_state = take_queue_state_from_simulator(&repeated_writes_simulator);
        }

        let input = StorageApplicationCircuitInstanceWitness {
            closed_form_input: StorageApplicationCycleInputOutputWitness {
                start_flag: idx == 0,
                completion_flag: is_last,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state,
                hidden_fsm_output: final_fsm_state,
                _marker_e: (),
                _marker: std::marker::PhantomData
            },
            sorted_storage_queue_witness: wit,
            merkle_paths,
        };

        result.push(input);
    }

    result
}
