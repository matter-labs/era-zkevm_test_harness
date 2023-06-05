use super::*;
use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::boojum::gadgets::u256::recompose_u256_as_u32x8;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::zk_evm::aux_structures::MemoryIndex;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::ethereum_types::U256;
use crate::zkevm_circuits::base_structures::decommit_query::DecommitQueryWitness;
use crate::zkevm_circuits::base_structures::decommit_query::DECOMMIT_QUERY_PACKED_WIDTH;
use crate::zkevm_circuits::code_unpacker_sha256::input::*;
use crate::zkevm_circuits::code_unpacker_sha256::*;
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::Arc;

pub fn compute_decommitter_circuit_snapshots<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    round_function: &R,
    decommiter_circuit_capacity: usize,
) -> Vec<CodeDecommitterCircuitInstanceWitness<F>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    let start_idx_for_memory_accumulator = artifacts.all_memory_queue_states.len();

    let initial_memory_queue_state =
        take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);

    // now we should start chunking the requests into separate decommittment circuits by running a micro-simulator

    for (query, writes) in artifacts.deduplicated_decommit_requests_with_data.iter() {
        assert!(query.is_fresh);

        // now feed the queries into it
        let as_queries: Vec<_> = writes
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, el)| MemoryQuery {
                timestamp: query.timestamp,
                location: zk_evm::aux_structures::MemoryLocation {
                    memory_type: zk_evm::abstractions::MemoryType::Code,
                    page: query.memory_page,
                    index: MemoryIndex(idx as u32),
                },
                rw_flag: true,
                value: el,
                value_is_pointer: false,
            })
            .collect();

        // fill up the memory queue
        for query in as_queries.iter() {
            let (_old_tail, intermediate_info) = artifacts
                .memory_queue_simulator
                .push_and_output_intermediate_data(*query, round_function);

            artifacts.all_memory_queue_states.push(intermediate_info);
        }

        // and plain test memory queues
        artifacts.all_memory_queries_accumulated.extend(as_queries);
    }

    assert_eq!(
        artifacts.all_memory_queue_states.len(),
        artifacts.all_memory_queries_accumulated.len()
    );

    // our simulator is simple: it will try to take an element from the queue, run some number of rounds, and compare the results

    let mut results: Vec<CodeDecommitterCircuitInstanceWitness<F>> = vec![];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DecommitterState {
        BeginNew,
        DecommmitMore(usize),
        Done,
    }

    let final_deduplicated_queue_state = transform_sponge_like_queue_state(
        artifacts
            .deduplicated_decommittment_queue_states
            .last()
            .unwrap()
            .clone(),
    );
    assert_eq!(
        artifacts.deduplicated_decommit_requests_with_data.len(),
        artifacts.deduplicated_decommittment_queue_states.len()
    );

    let mut current_decommittment_requests_queue_simulator =
        artifacts.deduplicated_decommittment_queue_simulator.clone();

    assert_eq!(
        artifacts.deduplicated_decommit_requests_with_data.len(),
        artifacts.deduplicated_decommittment_queue_states.len(),
    );

    assert_eq!(
        artifacts.deduplicated_decommit_requests_with_data.len(),
        artifacts
            .deduplicated_decommittment_queue_simulator
            .witness
            .len(),
    );

    let mut it = artifacts
        .deduplicated_decommit_requests_with_data
        .drain(..)
        .zip(artifacts.deduplicated_decommittment_queue_states.iter())
        .zip(
            artifacts
                .deduplicated_decommittment_queue_simulator
                .witness
                .iter(),
        )
        .peekable();

    let mut fsm_state = DecommitterState::BeginNew;
    let mut current_memory_data = vec![];
    let mut start = true;
    let mut memory_queue_state_offset = 0;

    use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Digest;
    use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::transmute_state;
    use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256;

    let mut internal_state = Sha256::default();
    let mut fsm_internals = CodeDecommittmentFSM::<F>::placeholder_witness();

    use crate::boojum::gadgets::queue::QueueState;
    let placeholder_witness = QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder_witness();

    'outer: loop {
        let mut current_circuit_witness = CodeDecommitterCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: start,
                completion_flag: false,
                observable_input: CodeDecommitterInputData::placeholder_witness(),
                observable_output: CodeDecommitterOutputData::placeholder_witness(),
                hidden_fsm_input: CodeDecommitterFSMInputOutput::placeholder_witness(),
                hidden_fsm_output: CodeDecommitterFSMInputOutput::placeholder_witness(),
            },
            sorted_requests_queue_witness: FullStateCircuitQueueRawWitness::<
                F,
                zkevm_circuits::base_structures::decommit_query::DecommitQuery<F>,
                FULL_SPONGE_QUEUE_STATE_WIDTH,
                DECOMMIT_QUERY_PACKED_WIDTH,
            > {
                elements: VecDeque::new(),
            },
            code_words: vec![],
        };

        current_circuit_witness
            .closed_form_input
            .hidden_fsm_input
            .memory_queue_state = transform_sponge_like_queue_state(
            artifacts
                .all_memory_queue_states
                .iter()
                .skip(start_idx_for_memory_accumulator + memory_queue_state_offset - 1)
                .next()
                .unwrap()
                .clone(),
        );

        let initial_decommittment_queue_state = results
            .last()
            .map(|el| {
                el.closed_form_input
                    .hidden_fsm_output
                    .decommittment_requests_queue_state
                    .clone()
            })
            .unwrap_or(placeholder_witness.clone());

        let initial_internal_fsm_state = results
            .last()
            .map(|el| el.closed_form_input.hidden_fsm_output.internal_fsm.clone())
            .unwrap_or(CodeDecommittmentFSM::placeholder_witness());

        current_circuit_witness
            .closed_form_input
            .hidden_fsm_input
            .internal_fsm = initial_internal_fsm_state;
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_input
            .decommittment_requests_queue_state = initial_decommittment_queue_state;

        if start {
            // set passthrough input
            start = false;
            current_circuit_witness
                .closed_form_input
                .observable_input
                .memory_queue_initial_state = initial_memory_queue_state.clone();
            current_circuit_witness
                .closed_form_input
                .observable_input
                .sorted_requests_queue_initial_state = final_deduplicated_queue_state.clone();
        } else {
            if DecommitterState::BeginNew != fsm_state {
                current_circuit_witness.code_words.push(vec![]);
            }
        }

        for _cycle_idx in 0..decommiter_circuit_capacity {
            // we will kind of fall through, so "if" instead of "match"
            if &DecommitterState::BeginNew == &fsm_state {
                internal_state = Sha256::default();

                let (((_query, memory_data), _state), wit) = it.next().unwrap();
                let (_el, _intermediate_info) = current_decommittment_requests_queue_simulator
                    .pop_and_output_intermediate_data(round_function);
                debug_assert_eq!(_query, _el);

                assert!(memory_data.len() > 0);
                current_memory_data = memory_data;

                // fill the witness
                use crate::zk_evm::aux_structures::DecommittmentQuery;

                let DecommittmentQuery {
                    hash,
                    timestamp,
                    memory_page,
                    decommitted_length: _,
                    is_fresh,
                } = wit.2;

                let num_words = (hash.0[3] >> 32) as u16;
                assert!(num_words & 1 == 1); // should be odd
                let num_words = num_words as u64;
                let num_rounds = (num_words + 1) / 2;

                let mut hash_as_be = [0u8; 32];
                hash.to_big_endian(&mut hash_as_be);

                let as_circuit_data = DecommitQueryWitness {
                    code_hash: hash,
                    page: memory_page.0,
                    is_first: is_fresh,
                    timestamp: timestamp.0,
                };

                let wit = (as_circuit_data, wit.1);

                current_circuit_witness
                    .sorted_requests_queue_witness
                    .elements
                    .push_back(wit);

                fsm_internals.state_get_from_queue = false;
                fsm_internals.state_decommit = true;
                fsm_internals.num_rounds_left = num_rounds as u16;
                fsm_internals.sha256_inner_state = boojum::gadgets::sha256::INITIAL_STATE;
                fsm_internals.current_index = 0;
                fsm_internals.current_page = memory_page.0;
                fsm_internals.timestamp = timestamp.0;
                fsm_internals.length_in_bits = (num_words * 32 * 8) as u32;

                let mut tmp_hash = hash_as_be;
                tmp_hash[0] = 0;
                tmp_hash[1] = 0;
                tmp_hash[2] = 0;
                tmp_hash[3] = 0;
                fsm_internals.hash_to_compare_against = U256::from_big_endian(&tmp_hash);

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

                    current_circuit_witness
                        .code_words
                        .last_mut()
                        .unwrap()
                        .push(word0);
                    memory_queue_state_offset += 1;
                    fsm_internals.current_index += 1;

                    if *num_rounds_left != 0 {
                        let word1 = current_memory_data.drain(0..1).next().unwrap();
                        current_circuit_witness
                            .code_words
                            .last_mut()
                            .unwrap()
                            .push(word1);
                        word1.to_big_endian(&mut block[32..64]);

                        memory_queue_state_offset += 1;
                        fsm_internals.current_index += 1;
                    } else {
                        // pad and do not increment index
                        block[32] = 0x80;
                        let length_in_bits_be = fsm_internals.length_in_bits.to_be_bytes();
                        block[60..64].copy_from_slice(&length_in_bits_be);
                    }

                    // absorb
                    internal_state.update(&block);

                    if *num_rounds_left == 0 {
                        let mut raw_state = transmute_state(internal_state.clone());
                        raw_state[0] = 0;
                        let mut buffer = [0u8; 32];
                        for (dst, src) in buffer.array_chunks_mut::<4>().zip(raw_state.iter()) {
                            *dst = src.to_be_bytes();
                        }

                        let word = U256::from_big_endian(&buffer);

                        assert!(
                            fsm_internals.hash_to_compare_against == word,
                            "Hash in FSM is 0x{:064x}, while hash in simulator is 0x{:064x}",
                            fsm_internals.hash_to_compare_against,
                            word,
                        );

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
                }
                a @ _ => unreachable!("we should never hit the state {:?}", a),
            }

            if fsm_state == DecommitterState::Done {
                break;
            }

            // if we are done than push some data into witness
        }

        // copy the final state

        let raw_state = transmute_state(internal_state.clone());

        for (dst, src) in fsm_internals
            .sha256_inner_state
            .iter_mut()
            .zip(raw_state.into_iter())
        {
            *dst = src;
        }

        // proceed with final bits
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .decommittment_requests_queue_state = take_sponge_like_queue_state_from_simulator(
            &current_decommittment_requests_queue_simulator,
        );
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .decommittment_requests_queue_state = take_sponge_like_queue_state_from_simulator(
            &current_decommittment_requests_queue_simulator,
        );
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .memory_queue_state = transform_sponge_like_queue_state(
            artifacts
                .all_memory_queue_states
                .iter()
                .skip(start_idx_for_memory_accumulator + memory_queue_state_offset - 1)
                .next()
                .unwrap()
                .clone(),
        );
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .internal_fsm = fsm_internals.clone();

        results.push(current_circuit_witness);

        if fsm_state == DecommitterState::Done {
            // mark as done and set passthrough output
            results
                .last_mut()
                .unwrap()
                .closed_form_input
                .completion_flag = true;
            let final_memory_state = results
                .last()
                .unwrap()
                .closed_form_input
                .hidden_fsm_output
                .memory_queue_state
                .clone();
            results
                .last_mut()
                .unwrap()
                .closed_form_input
                .observable_output
                .memory_queue_final_state = final_memory_state;
            break 'outer;
        }
    }

    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    results
}
