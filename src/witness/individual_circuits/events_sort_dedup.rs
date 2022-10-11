use smallvec::SmallVec;
use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::testing::Bn256;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::*;
use crate::ethereum_types::U256;
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
use sync_vm::glue::log_sorter::input::EventsDeduplicatorInstanceWitness;
use crate::encodings::log_query::log_query_into_storage_record_witness;
use crate::encodings::log_query::*;
use sync_vm::glue::log_sorter::input::*;
use super::*;

pub fn compute_events_dedup_and_sort<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(
    unsorted_queries: &Vec<LogQuery>,
    target_deduplicated_queries: &mut Vec<LogQuery>,
    unsorted_simulator: &LogQueueSimulator<E>,
    result_queue_simulator: &mut LogQueueSimulator<E>,
    round_function: &R,
) -> EventsDeduplicatorInstanceWitness<E> {
    // parallelizable 
    
    // have to manually unroll, otherwise borrow checker will complain

    // first we sort the storage log (only storage now) by composite key

    let mut sorted_queries: Vec<_> = unsorted_queries.clone();

    sorted_queries.par_sort_by(|a, b| {
        match a.timestamp.0.cmp(&b.timestamp.0) {
            Ordering::Equal => {
                if b.rollback {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            r @ _ => r
        }
    });

    let mut sorted_simulator = LogQueueSimulator::empty();
    for el in sorted_queries.iter() {
        let _ = sorted_simulator.push(*el, round_function);
    }

    let sorted_simulator_final_state = take_queue_state_from_simulator(&sorted_simulator);
    let sorted_queue_witness: Vec<_> = sorted_simulator.witness.into_iter().map(|(encoding, old_tail, el)| {
        let transformed_query = log_query_into_storage_record_witness(&el);

        (encoding, transformed_query, old_tail)
    }).collect();

    let sorted_queries = sort_and_dedup_events_log(sorted_queries);

    for sorted_log_query in sorted_queries.iter().copied() {
        result_queue_simulator.push(sorted_log_query, round_function);
    }

    *target_deduplicated_queries = sorted_queries;

    // in general we have everything ready, just form the witness
    use sync_vm::traits::CSWitnessable;

    let mut input_passthrough_data = EventsDeduplicatorInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.initial_log_queue_state = take_queue_state_from_simulator(&unsorted_simulator);

    let mut output_passthrough_data = EventsDeduplicatorOutputData::placeholder_witness();
    output_passthrough_data.final_queue_state = take_queue_state_from_simulator(&result_queue_simulator);

    // dbg!(take_queue_state_from_simulator(&result_queue_simulator));
    // dbg!(&result_queue_simulator.witness);

    let initial_queue_witness: Vec<_> = unsorted_simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let as_storage_log = log_query_into_storage_record_witness(element);

        (*encoding, as_storage_log, *old_tail)
    }).collect();
    
    let witness = EventsDeduplicatorInstanceWitness {
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
        intermediate_sorted_queue_state: sorted_simulator_final_state,
        sorted_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: sorted_queue_witness},
    };

    witness
}

pub fn sort_and_dedup_events_log(sorted_history: Vec<LogQuery>) -> Vec<LogQuery> {
    let mut stack = SmallVec::<[LogQuery; 2]>::new();

    let mut net_history = vec![];

    for el in sorted_history.iter().copied() {
        assert_eq!(el.shard_id, 0, "only rollup shard is supported");
        if stack.is_empty() {
            assert!(el.rollback == false);
            stack.push(el);
        } else {
            // we can always pop as it's either one to add to queue, or discard
            let previous = stack.pop().unwrap();
            if previous.timestamp == el.timestamp {
                assert!(previous.rollback == false);
                assert!(el.rollback == true);
                assert!(previous.rw_flag == true);
                assert!(el.rw_flag == true);
                assert_eq!(previous.tx_number_in_block, el.tx_number_in_block);
                assert_eq!(previous.shard_id, el.shard_id);
                assert_eq!(previous.address, el.address);
                assert_eq!(previous.key, el.key);
                assert_eq!(previous.written_value, el.written_value);
                assert_eq!(previous.is_service, el.is_service);
                // do nothing, it's rolled back
                
                continue
            } else {
                assert!(el.rollback == false);
                stack.push(el);

                // cleanup some fields
                // flags are conventions
                let sorted_log_query = LogQuery {
                    timestamp: Timestamp(0),
                    tx_number_in_block: previous.tx_number_in_block,
                    aux_byte: 0,
                    shard_id: previous.shard_id,
                    address: previous.address,
                    key: previous.key,
                    read_value: U256::zero(),
                    written_value: previous.written_value,
                    rw_flag: false,
                    rollback: false,
                    is_service: previous.is_service,
                };

                net_history.push(sorted_log_query);
            }
        }
    }

    if let Some(previous) = stack.pop() {
        // cleanup some fields
        // flags are conventions
        let sorted_log_query = LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: previous.tx_number_in_block,
            aux_byte: 0,
            shard_id: previous.shard_id,
            address: previous.address,
            key: previous.key,
            read_value: U256::zero(),
            written_value: previous.written_value,
            rw_flag: false,
            rollback: false,
            is_service: previous.is_service,
        };

        net_history.push(sorted_log_query);
    }

    net_history
}

// For server side use convenience
pub fn simulate_events_log_for_commitment(history: Vec<LogQuery>) -> (Vec<LogQuery>, (u32, sync_vm::testing::Fr)) {
    use sync_vm::recursion::get_prefered_committer;

    let round_function = get_prefered_committer();

    let mut sorted_history = history;
    sorted_history.sort_by(|a, b| {
        match a.timestamp.0.cmp(&b.timestamp.0) {
            Ordering::Equal => {
                if b.rollback {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            r @ _ => r
        }
    });

    let net_history = sort_and_dedup_events_log(sorted_history);

    let mut simulator = LogQueueSimulator::<Bn256>::empty();
    for el in net_history.iter().copied() {
        simulator.push(el, &round_function);
    }

    let queue_len = simulator.num_items;
    let tail = simulator.tail;

    (net_history, (queue_len, tail))
}