use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::circuit::input::rollup_shard_id;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::*;
use crate::ethereum_types::U256;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::utils::biguint_from_u256;
use crate::witness_structures::transform_sponge_like_queue_state;
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

    // dbg!(&sorted_storage_queries_with_extra_timestamp);


    let mut sorted_simulator = LogQueueSimulator::empty();
    for el in sorted_queries.iter() {
        let _ = sorted_simulator.push(*el, round_function);
    }

    let sorted_simulator_final_state = take_queue_state_from_simulator(&sorted_simulator);
    let sorted_queue_witness: Vec<_> = sorted_simulator.witness.into_iter().map(|(encoding, old_tail, el)| {
        let transformed_query = log_query_into_storage_record_witness(&el);

        (encoding, transformed_query, old_tail)
    }).collect();

    // now just implement the logic to sort and deduplicate
    let mut it = sorted_queries.iter().peekable();

    loop {
        if it.peek().is_none() {
            break;
        }

        let mut stack: Vec<LogQuery> = vec![];

        let candidate = it.peek().unwrap().clone();

        let subit = it.clone().take_while(|el| {
            el.timestamp == candidate.timestamp
        });

        // let tmp: Vec<_> = it.clone().take_while(|el| {
        //     el.raw_query.shard_id == candidate.raw_query.shard_id &&
        //     el.raw_query.address == candidate.raw_query.address &&
        //     el.raw_query.key == candidate.raw_query.key
        // }).collect();

        // dbg!(&tmp);

        for (idx, el) in subit.enumerate() {
            let _ = it.next().unwrap();
            assert!(el.rw_flag);
            if idx == 0 {
                assert!(el.rollback == false);
            } 

            if el.rollback {
                assert!(stack.len() == 1);
                let _ = stack.pop().unwrap();
            } else {
                assert!(stack.len() == 0);
                stack.push(*el);
            }
        }

        if stack.len() == 0 {
            continue;
        }

        assert!(stack.len() == 1);
        let final_value = stack.pop().unwrap();
        assert_eq!(final_value.written_value, candidate.written_value);

        // flags are conventions
        let sorted_log_query = LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: candidate.tx_number_in_block,
            aux_byte: 0,
            shard_id: candidate.shard_id,
            address: candidate.address,
            key: candidate.key,
            read_value: U256::zero(),
            written_value: candidate.written_value,
            rw_flag: false,
            rollback: false,
            is_service: false,
        };

        result_queue_simulator.push(sorted_log_query, round_function);
        target_deduplicated_queries.push(sorted_log_query);
    }

    // dbg!(&target_deduplicated_queries);

    // in general we have everything ready, just form the witness
    use sync_vm::traits::CSWitnessable;
    use crate::witness_structures::take_queue_state_from_simulator;

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