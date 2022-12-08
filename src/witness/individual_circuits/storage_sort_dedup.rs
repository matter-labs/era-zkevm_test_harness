use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::*;
use super::*;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::utils::biguint_from_u256;
use std::cmp::Ordering;
use crate::bellman::Engine;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use crate::ff::Field;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use sync_vm::glue::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use crate::encodings::log_query::log_query_into_storage_record_witness;
use crate::encodings::log_query::*;

pub fn compute_storage_dedup_and_sort<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(
    artifacts: &mut FullBlockArtifacts<E>,
    round_function: &R,
) -> StorageDeduplicatorInstanceWitness<E> {
    // parallelizable 
    
    // have to manually unroll, otherwise borrow checker will complain

    // first we sort the storage log (only storage now) by composite key

    use crate::witness::sort_storage_access::sort_storage_access_queries;

    let (sorted_storage_queries_with_extra_timestamp, deduplicated_rollup_storage_queries) = sort_storage_access_queries(
        &artifacts.demuxed_rollup_storage_queries
    );

    // dbg!(&sorted_storage_queries_with_extra_timestamp);
    // dbg!(&deduplicated_rollup_storage_queries);

    artifacts.deduplicated_rollup_storage_queries = deduplicated_rollup_storage_queries;

    let mut sorted_log_simulator = LogWithExtendedEnumerationQueueSimulator::empty();
    for el in sorted_storage_queries_with_extra_timestamp.iter() {
        let _ = sorted_log_simulator.push(el.clone(), round_function);
    }
    
    use sync_vm::glue::storage_validity_by_grand_product::TimestampedStorageLogRecordWitness;

    let sorted_log_simulator_final_state = take_queue_state_from_simulator(&sorted_log_simulator);
    let sorted_queue_witness: VecDeque<_> = sorted_log_simulator.witness.into_iter().map(|(encoding, old_tail, el)| {
        let transformed_query = log_query_into_storage_record_witness(&el.raw_query);
        let wit = TimestampedStorageLogRecordWitness {
            record: transformed_query,
            timestamp: el.extended_timestamp,
        };

        (encoding, wit, old_tail)
    }).collect();

    // now just implement the logic to sort and deduplicate

    let mut result_queue_simulator = LogQueueSimulator::empty();

    for el in artifacts.deduplicated_rollup_storage_queries.iter() {
        let _ = result_queue_simulator.push(*el, round_function);
    }

    // in general we have everything ready, just form the witness
    use sync_vm::glue::storage_validity_by_grand_product::input::*;
    use sync_vm::traits::CSWitnessable;

    let mut input_passthrough_data = StorageDeduplicatorInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.initial_log_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);

    let mut output_passthrough_data = StorageDeduplicatorOutputData::placeholder_witness();
    output_passthrough_data.final_queue_state = take_queue_state_from_simulator(&result_queue_simulator);

    let initial_queue_witness: VecDeque<_> = artifacts.demuxed_rollup_storage_queue_simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let as_storage_log = log_query_into_storage_record_witness(element);

        (*encoding, as_storage_log, *old_tail)
    }).collect();
    
    let witness = StorageDeduplicatorInstanceWitness {
        closed_form_input: ClosedFormInputWitness { 
            start_flag: true, 
            completion_flag: true, 
            observable_input: input_passthrough_data, 
            observable_output: output_passthrough_data, 
            hidden_fsm_input: (), 
            hidden_fsm_output: (), 
            _marker_e: (), 
            _marker: std::marker::PhantomData 
        },

        initial_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: initial_queue_witness},
        intermediate_sorted_queue_state: sorted_log_simulator_final_state,
        sorted_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: sorted_queue_witness},
    };

    artifacts.deduplicated_rollup_storage_queue_simulator = result_queue_simulator;

    witness
}