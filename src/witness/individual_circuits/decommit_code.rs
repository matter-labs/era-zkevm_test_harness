use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;

use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::utils::biguint_from_u256;
use crate::witness_structures::transform_sponge_like_queue_state;
use std::cmp::Ordering;
use std::sync::Arc;
use crate::bellman::Engine;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use crate::ff::Field;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;

pub fn compute_decommitter_circuit_snapshots<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(
    artifacts: &mut FullBlockArtifacts<E>,
    memory_queue_simulator: &mut MemoryQueueSimulator<E>,
    round_function: &R,
    per_circuit_capacity: usize
) -> (Vec<CodeDecommitterCircuitInstanceWitness<E>>, CodeDecommittmentsDeduplicatorInstanceWitness<E>) {
    let start_idx_for_memory_accumulator = artifacts.all_memory_queue_states.len();

    let mut results: Vec<CodeDecommitterCircuitInstanceWitness<E>> = vec![];

    use crate::witness_structures::take_sponge_like_queue_state_from_simulator;
    let initial_memory_queue_state = take_sponge_like_queue_state_from_simulator(memory_queue_simulator);

    // we produce witness for two circuits at once

    let mut unsorted_decommittment_queue_simulator = DecommittmentQueueSimulator::<E>::empty();
    let mut sorted_decommittment_queue_simulator = DecommittmentQueueSimulator::<E>::empty();
    let mut deduplicated_decommittment_queue_simulator = DecommittmentQueueSimulator::<E>::empty();

    // sort decommittment requests

    let mut sorted_decommittment_queue_states = vec![];
    let mut deduplicated_decommittment_queue_states = vec![];

    let mut unsorted_decommittment_requests_with_data = vec![];
    for (_cycle, decommittment_request, writes) in artifacts.all_decommittment_queries.iter_mut() {
        let data = std::mem::replace(writes, vec![]);
        unsorted_decommittment_requests_with_data.push((*decommittment_request, data));
    }

    // internally parallelizable by the factor of 3
    for (cycle, decommittment_request, _) in artifacts.all_decommittment_queries.iter() {
        // sponge
        let (_old_tail, intermediate_info) = unsorted_decommittment_queue_simulator
            .push_and_output_intermediate_data(*decommittment_request, round_function);

        artifacts.all_decommittment_queue_states
            .push((*cycle, intermediate_info));
    }

    // sort queries
    let mut sorted_decommittment_requests_with_data = unsorted_decommittment_requests_with_data;
    sorted_decommittment_requests_with_data.par_sort_by(|a, b| 
        // sort by hash first, and then by timestamp
        match a.0.hash.cmp(&b.0.hash) {
            Ordering::Equal => a.0.timestamp.cmp(&b.0.timestamp),
            a @ _ => a,
        }
    );

    let mut deduplicated_decommit_requests_with_data = vec![];

    for (query, writes) in sorted_decommittment_requests_with_data.into_iter() {
        if query.is_fresh {
            // now feed the queries into it
            let as_queries_it: Vec<_> = writes.iter().cloned().enumerate().map(|(idx, el)| MemoryQuery {
                timestamp: query.timestamp,
                location: zk_evm::aux_structures::MemoryLocation {
                    memory_type: zk_evm::abstractions::MemoryType::Code,
                    page: query.memory_page,
                    index: MemoryIndex(idx as u32),
                },
                rw_flag: true,
                value: el,
                is_pended: false,
            }).collect();

            // fill up the memory queue
            for query in as_queries_it.iter() {
                let (_old_tail, intermediate_info) =
                    memory_queue_simulator.push_and_output_intermediate_data(*query, round_function);

                artifacts.all_memory_queue_states.push(intermediate_info);
            }

            // and plain test memory queues
            artifacts.all_memory_queries_accumulated.extend(as_queries_it);

            // and sorted request
            artifacts.deduplicated_decommittment_queries.push(query);

            let (_old_tail, intermediate_info) = deduplicated_decommittment_queue_simulator
                .push_and_output_intermediate_data(query, round_function);
            
            deduplicated_decommittment_queue_states.push(intermediate_info);

            deduplicated_decommit_requests_with_data.push((query, writes));
        }

        let (_old_tail, intermediate_info) = sorted_decommittment_queue_simulator
            .push_and_output_intermediate_data(query, round_function);
        
        sorted_decommittment_queue_states.push(intermediate_info);

        artifacts.sorted_decommittment_queries.push(query);
    }

    // first we assume that procedure of sorting the decommittment requests will only take 1 circuit,
    // so we can trivially form a single instance for it

    use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInputOutputWitness;
    use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorPassthroughData;

    let mut input_passthrough_data = CodeDecommittmentsDeduplicatorPassthroughData::<E>::placeholder_witness();
    input_passthrough_data.initial_log_queue_state = take_sponge_like_queue_state_from_simulator(&unsorted_decommittment_queue_simulator);

    let input_witness: Vec<_> = unsorted_decommittment_queue_simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let wit = DecommitQueryWitness {
            root_hash: biguint_from_u256(element.hash),
            page: element.memory_page.0,
            is_first: element.is_fresh,
            timestamp: element.timestamp.0,
            _marker: std::marker::PhantomData
        };

        (*encoding, wit, *old_tail)
    }).collect();

    let sorted_witness: Vec<_> = unsorted_decommittment_queue_simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let wit = DecommitQueryWitness {
            root_hash: biguint_from_u256(element.hash),
            page: element.memory_page.0,
            is_first: element.is_fresh,
            timestamp: element.timestamp.0,
            _marker: std::marker::PhantomData
        };

        (*encoding, wit, *old_tail)
    }).collect();

    let mut output_passthrough_data = CodeDecommittmentsDeduplicatorPassthroughData::<E>::placeholder_witness();
    output_passthrough_data.final_queue_state = take_sponge_like_queue_state_from_simulator(&deduplicated_decommittment_queue_simulator);

    let decommittments_deduplicator_witness = CodeDecommittmentsDeduplicatorInstanceWitness {
        closed_form_input: CodeDecommittmentsDeduplicatorInputOutputWitness {
            start_flag: true, 
            completion_flag: true, 
            passthrough_input_data: input_passthrough_data, 
            passthrough_output_data: output_passthrough_data, 
            fsm_input: (), 
            fsm_output: (), 
            _marker_e: (), 
            _marker: std::marker::PhantomData 
        },
        initial_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness { wit: input_witness},
        intermediate_sorted_queue_state: take_sponge_like_queue_state_from_simulator(&sorted_decommittment_queue_simulator),
        sorted_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness { wit: sorted_witness},
    };

    // now we should start chunking the requests into separate decommittment circuits by running a micro-simulator

    // our simulator is simple: it will try to take an element from the queue, run some number of rounds, and compare the results

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DecommitterState {
        BeginNew,
        DecommmitMore(usize),
        Done
    }

    let final_deduplicated_queue_state = transform_sponge_like_queue_state(deduplicated_decommittment_queue_states.last().unwrap().clone());
    assert_eq!(deduplicated_decommit_requests_with_data.len(), deduplicated_decommittment_queue_states.len());

    let mut current_decommittment_requests_queue_simulator = deduplicated_decommittment_queue_simulator.clone();

    let mut it = deduplicated_decommit_requests_with_data.into_iter()
        .zip(deduplicated_decommittment_queue_states.iter())
        .zip(deduplicated_decommittment_queue_simulator.witness.iter())
        .peekable();

    let mut fsm_state = DecommitterState::BeginNew;
    let mut current_memory_data = vec![];
    let mut start = true;
    let mut memory_queue_state_offset = 0;

    use zk_evm::precompiles::sha256::{transmute_state, Sha256InnerState};
    use zk_evm::precompiles::sha256::Sha256;
    use zk_evm::precompiles::keccak256::Digest;

    let mut internal_state = Sha256::default();

    use sync_vm::traits::CSWitnessable;
    use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;
    use sync_vm::scheduler::queues::FullSpongeLikeQueueState;

    let mut fsm_internals = CodeDecommittmentFSM::<E>::placeholder_witness();

    'outer: loop {
        let mut current_circuit_witness = CodeDecommitterCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: start,
                completion_flag: false,
                passthrough_input_data: CodeDecommitterPassthroughData::placeholder_witness(),
                passthrough_output_data: CodeDecommitterPassthroughData::placeholder_witness(),
                fsm_input: CodeDecommitterFSMInputOutput::placeholder_witness(),
                fsm_output: CodeDecommitterFSMInputOutput::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            sorted_requests_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness {wit: vec![]},
            code_words: vec![],
        };

        current_circuit_witness.closed_form_input.fsm_input.memory_queue_state = transform_sponge_like_queue_state(artifacts.all_memory_queue_states.iter().skip(
                start_idx_for_memory_accumulator + memory_queue_state_offset - 1
            ).next().unwrap().clone()
        );

        let initial_decommittment_queue_state = results.last().map(|el| {
            el.closed_form_input.fsm_output.decommittment_requests_queue_state.clone()
        }).unwrap_or(
            FullSpongeLikeQueueState::placeholder_witness()
        );

        let initial_internal_fsm_state = results.last().map(|el| {
            el.closed_form_input.fsm_output.internal_fsm.clone()
        }).unwrap_or(
            CodeDecommittmentFSM::placeholder_witness()
        );

        current_circuit_witness.closed_form_input.fsm_input.internal_fsm = initial_internal_fsm_state;
        current_circuit_witness.closed_form_input.fsm_input.decommittment_requests_queue_state = initial_decommittment_queue_state;

        if start {
            // set passthrough input
            start = false;
            current_circuit_witness.closed_form_input.passthrough_input_data.memory_queue_initial_state = initial_memory_queue_state.clone();
            current_circuit_witness.closed_form_input.passthrough_input_data.sorted_requests_queue_initial_state = final_deduplicated_queue_state.clone();
        } else {
            if DecommitterState::BeginNew != fsm_state {
                current_circuit_witness.code_words.push(vec![]);
            }
        }

        for _cycle_idx in 0..per_circuit_capacity {
            // we will kind of fall through, so "if" instead of "match"
            if &DecommitterState::BeginNew == &fsm_state {
                internal_state = Sha256::default();

                let (((_query, memory_data), _state) , wit) = it.next().unwrap();
                let _ = current_decommittment_requests_queue_simulator.pop_and_output_intermediate_data(round_function);
                current_memory_data = memory_data;

                // fill the witness
                use zk_evm::aux_structures::DecommittmentQuery;

                let DecommittmentQuery {
                    hash,
                    timestamp,
                    memory_page,
                    decommitted_length: _,
                    is_fresh,
                } = wit.2;

                let num_words = hash.0[3] >> 48;
                assert!(num_words & 1 == 1); // should be odd
                let num_rounds = (num_words + 1) / 2;

                let mut hash_as_be = [0u8; 32];
                hash.to_big_endian(&mut hash_as_be);
                
                let as_circuit_data = DecommitQueryWitness {
                    root_hash: biguint_from_u256(hash),
                    page: memory_page.0,
                    is_first: is_fresh,
                    timestamp: timestamp.0,
                    _marker: std::marker::PhantomData
                };

                let wit = (
                    wit.0,
                    as_circuit_data,
                    wit.1,
                );

                current_circuit_witness.sorted_requests_queue_witness.wit.push(wit);

                fsm_internals.state_get_from_queue = false;
                fsm_internals.state_decommit = true;
                fsm_internals.num_rounds_left = num_rounds as u16;
                fsm_internals.sha256_inner_state = crate::franklin_crypto::plonk::circuit::hashes_with_tables::sha256::gadgets::Sha256Gadget::<E>::iv();
                fsm_internals.current_index = 0;
                fsm_internals.current_page = memory_page.0;
                fsm_internals.timestamp = timestamp.0;
                fsm_internals.length_in_bits = (num_words * 32 * 8) as u32;
                
                for (idx, chunk) in hash_as_be.chunks_exact(16).enumerate() {
                    let mut as_array: [_; 16] = chunk.try_into().unwrap();
                    if idx == 0 {
                        as_array[0] = 0;
                        as_array[1] = 0;
                    }
                    let word = u128::from_be_bytes(as_array);
                    fsm_internals.hash_to_compare_against[idx] = u128_to_fe(word);
                }

                fsm_state = DecommitterState::DecommmitMore(num_rounds as usize);
                current_circuit_witness.code_words.push(vec![]);
            }

            // do the actual round
            match &mut fsm_state {
                DecommitterState::DecommmitMore(num_rounds_left) => {
                    let mut block = [0u8; 64];

                    fsm_internals.num_rounds_left -= 1;
                    *num_rounds_left -= 1;
                    let word0 = current_memory_data.drain(0..1).next().unwrap();
                    word0.to_big_endian(&mut block[0..32]);

                    current_circuit_witness.code_words.last_mut().unwrap().push(biguint_from_u256(word0));
                    memory_queue_state_offset += 1;
                    fsm_internals.current_index += 1;

                    if *num_rounds_left != 0 {
                        let word1 = current_memory_data.drain(0..1).next().unwrap();
                        current_circuit_witness.code_words.last_mut().unwrap().push(biguint_from_u256(word1));
                        word1.to_big_endian(&mut block[32..64]);

                        memory_queue_state_offset += 1;
                    } else {
                        // pad
                        block[32] = 0x80;
                        let length_in_bits_be = fsm_internals.length_in_bits.to_be_bytes();
                        block[60..64].copy_from_slice(&length_in_bits_be);
                    }
                    fsm_internals.current_index += 1;

                    // absorb
                    internal_state.update(&block);

                    if *num_rounds_left == 0 {
                        let raw_state = transmute_state(internal_state.clone());
                        let word0 = raw_state[0] & ((1u32<<16) - 1);
                        let mut word0 = word0 as u128;
                        word0 <<= 32;
                        word0 += raw_state[1] as u128;
                        word0 <<= 32;
                        word0 += raw_state[2] as u128;
                        word0 <<= 32;
                        word0 += raw_state[3] as u128;
                        let word0 = u128_to_fe(word0);

                        let mut word1 = raw_state[4] as u128;
                        word1 <<= 32;
                        word1 += raw_state[5] as u128;
                        word1 <<= 32;
                        word1 += raw_state[6] as u128;
                        word1 <<= 32;
                        word1 += raw_state[7] as u128;
                        let word1 = u128_to_fe(word1);

                        assert_eq!(fsm_internals.hash_to_compare_against[0], word0);
                        assert_eq!(fsm_internals.hash_to_compare_against[1], word1);

                        if it.peek().is_none() {
                            fsm_state = DecommitterState::Done;
                            fsm_internals.state_get_from_queue = false;
                            fsm_internals.state_decommit = false;
                            fsm_internals.finished = true;
                        } else {
                            fsm_state = DecommitterState::BeginNew;
                            fsm_internals.state_get_from_queue = true;
                            fsm_internals.state_decommit = false;
                        }
                    }

                },
                a @ _ => unreachable!("we should never hit the state {:?}", a)
            }

            if fsm_state == DecommitterState::Done {
                break;
            }

            // if we are done than push some data into witness
        }

        // copy the final state

        let raw_state = transmute_state(internal_state.clone());

        for (dst, src) in fsm_internals.sha256_inner_state.iter_mut().zip(raw_state.into_iter()) {
            *dst = u64_to_fe(src as u64)
        }

        // proceed with final bits
        current_circuit_witness.closed_form_input.fsm_output.decommittment_requests_queue_state = take_sponge_like_queue_state_from_simulator(&current_decommittment_requests_queue_simulator);
        current_circuit_witness.closed_form_input.fsm_output.decommittment_requests_queue_state = take_sponge_like_queue_state_from_simulator(&current_decommittment_requests_queue_simulator);
        current_circuit_witness.closed_form_input.fsm_output.memory_queue_state = transform_sponge_like_queue_state(artifacts.all_memory_queue_states.iter().skip(
                start_idx_for_memory_accumulator + memory_queue_state_offset - 1
            ).next().unwrap().clone()
        );
        current_circuit_witness.closed_form_input.fsm_output.internal_fsm = fsm_internals.clone();

        results.push(current_circuit_witness);
            
        if fsm_state == DecommitterState::Done {
            // mark as done and set passthrough output
            results.last_mut().unwrap().closed_form_input.completion_flag = true;
            let final_memory_state = results.last().unwrap().closed_form_input.fsm_output.memory_queue_state.clone();
            results.last_mut().unwrap().closed_form_input.passthrough_output_data.memory_queue_final_state = final_memory_state;
            break 'outer;
        }
    }

    (results, decommittments_deduplicator_witness)
}