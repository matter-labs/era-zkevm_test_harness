use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::circuit::input::rollup_shard_id;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::*;

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

    let mut sorted_storage_queries_with_extra_timestamp: Vec<_> = artifacts.demuxed_rollup_storage_queries.iter()
        .enumerate().map(|(i, el)| {
            LogQueryWithExtendedEnumeration {
                raw_query: *el,
                extended_timestamp: i as u32
            }
    }).collect();

    sorted_storage_queries_with_extra_timestamp.par_sort_by(|a, b| {
        match a.raw_query.shard_id.cmp(&a.raw_query.shard_id) {
            Ordering::Equal => {
                match a.raw_query.address.cmp(&b.raw_query.address) {
                    Ordering::Equal => {
                        match a.raw_query.key.cmp(&b.raw_query.key) {
                            Ordering::Equal => {
                                a.extended_timestamp.cmp(&b.extended_timestamp)
                            },
                            r @ _ => r
                        }
                    },
                    r @ _ => r
                }
            }
            r @ _ => r
        }
    });

    // dbg!(&sorted_storage_queries_with_extra_timestamp);


    let mut sorted_log_simulator = LogWithExtendedEnumerationQueueSimulator::empty();
    for el in sorted_storage_queries_with_extra_timestamp.iter() {
        let _ = sorted_log_simulator.push(*el, round_function);
    }
    
    use sync_vm::glue::storage_validity_by_grand_product::TimestampedStorageLogRecordWitness;

    let sorted_log_simulator_final_state = take_queue_state_from_simulator(&sorted_log_simulator);
    let sorted_queue_witness: Vec<_> = sorted_log_simulator.witness.into_iter().map(|(encoding, old_tail, el)| {
        let transformed_query = log_query_into_storage_record_witness(&el.raw_query);
        let wit = TimestampedStorageLogRecordWitness {
            record: transformed_query,
            timestamp: el.extended_timestamp,
        };

        (encoding, wit, old_tail)
    }).collect();

    // now just implement the logic to sort and deduplicate

    let mut result_queue_simulator = LogQueueSimulator::empty();

    let mut it = sorted_storage_queries_with_extra_timestamp.iter().peekable();

    loop {
        if it.peek().is_none() {
            break;
        }

        let mut stack: Vec<LogQueryWithExtendedEnumeration> = vec![];

        let candidate = it.peek().unwrap().clone();

        let subit = it.clone().take_while(|el| {
            el.raw_query.shard_id == candidate.raw_query.shard_id &&
            el.raw_query.address == candidate.raw_query.address &&
            el.raw_query.key == candidate.raw_query.key
        });

        // let tmp: Vec<_> = it.clone().take_while(|el| {
        //     el.raw_query.shard_id == candidate.raw_query.shard_id &&
        //     el.raw_query.address == candidate.raw_query.address &&
        //     el.raw_query.key == candidate.raw_query.key
        // }).collect();

        // dbg!(&tmp);

        let mut did_read_at_no_rollback = false;

        for (idx, el) in subit.enumerate() {
            let _ = it.next().unwrap();

            if idx == 0 {
                if el.raw_query.rw_flag == false {
                    did_read_at_no_rollback = true;
                }
            } else {
                if stack.len() == 0 && el.raw_query.rw_flag == false {
                    did_read_at_no_rollback = true;
                }
            }

            if el.raw_query.rollback {
                loop {
                    // if we see rollback then we start unwinding the stack until we see a write
                    // that we should effectively cancel
                    if let Some(previous) = stack.pop() {
                        if previous.raw_query.rw_flag {
                            assert_eq!(el.raw_query.written_value, previous.raw_query.written_value);
                            break;
                        } else {
                            // we have reads, do nothing until we find write
                        }
                    } else {
                        // nothing in there, we rolled back literally everything
                        // and no reads ever were issued
                        break;
                    }

                }
            } else {
                stack.push(*el);
            }
        }

        if stack.len() == 0 {
            continue;
        }

        let initial_value = stack.first().unwrap().raw_query.read_value;
        let mut final_value = initial_value;
        let mut was_written = false;
        for el in stack.into_iter().rev() {
            if el.raw_query.rw_flag {
                // rollback just indicates, and doesn't swap values out of circuit
                if el.raw_query.rollback {
                    final_value = el.raw_query.read_value;
                } else {
                    final_value = el.raw_query.written_value;
                }

                was_written = true;
                break;
            }
        }

        let write_different = initial_value != final_value && was_written;
        let protective_read_only = !write_different && did_read_at_no_rollback;

        let sorted_rw_flag = if write_different {
            true
        } else if protective_read_only {
            false
        } else {
            unreachable!()
        };

        let sorted_log_query = LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: 0,
            aux_byte: 0,
            shard_id: candidate.raw_query.shard_id,
            address: candidate.raw_query.address,
            key: candidate.raw_query.key,
            read_value: initial_value,
            written_value: final_value,
            rw_flag: sorted_rw_flag,
            rollback: false,
            is_service: false,
        };

        result_queue_simulator.push(sorted_log_query, round_function);
        artifacts.deduplicated_rollup_storage_queries.push(sorted_log_query);
    }

    // dbg!(&artifacts.deduplicated_rollup_storage_queries);

    // in general we have everything ready, just form the witness
    use sync_vm::glue::storage_validity_by_grand_product::input::StorageDeduplicatorPassthroughData;
    use sync_vm::traits::CSWitnessable;
    use crate::witness_structures::take_queue_state_from_simulator;

    let mut input_passthrough_data = StorageDeduplicatorPassthroughData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.initial_log_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);

    let mut output_passthrough_data = StorageDeduplicatorPassthroughData::placeholder_witness();
    output_passthrough_data.final_queue_state = take_queue_state_from_simulator(&result_queue_simulator);

    // dbg!(take_queue_state_from_simulator(&result_queue_simulator));
    // dbg!(&result_queue_simulator.witness);

    let initial_queue_witness: Vec<_> = artifacts.demuxed_rollup_storage_queue_simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let as_storage_log = log_query_into_storage_record_witness(element);

        (*encoding, as_storage_log, *old_tail)
    }).collect();
    
    let witness = StorageDeduplicatorInstanceWitness {
        closed_form_input: ClosedFormInputWitness { 
            start_flag: true, 
            completion_flag: true, 
            passthrough_input_data: input_passthrough_data, 
            passthrough_output_data: output_passthrough_data, 
            fsm_input: (), 
            fsm_output: (), 
            _marker_e: (), 
            _marker: std::marker::PhantomData 
        },

        initial_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: initial_queue_witness},
        intermediate_sorted_queue_state: sorted_log_simulator_final_state,
        sorted_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: sorted_queue_witness},
    };

    witness
}