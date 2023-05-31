use super::*;
use crate::bellman::Engine;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::ff::Field;
use crate::utils::biguint_from_u256;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use sync_vm::utils::IdentifyFirstLast;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::Arc;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;

pub fn compute_decommitter_circuit_snapshots<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>,
>(
    artifacts: &mut FullBlockArtifacts<E>,
    round_function: &R,
    decommiter_circuit_capacity: usize,
    dedublicator_circuit_capacity: usize,
) -> (
    Vec<CodeDecommitterCircuitInstanceWitness<E>>,
    Vec<CodeDecommittmentsDeduplicatorInstanceWitness<E>>,
) {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    let start_idx_for_memory_accumulator = artifacts.all_memory_queue_states.len();

    let mut results: Vec<CodeDecommitterCircuitInstanceWitness<E>> = vec![];

    let initial_memory_queue_state =
        take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);

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

    let num_circuits = (artifacts.all_decommittment_queries.len() + dedublicator_circuit_capacity - 1) / dedublicator_circuit_capacity;

    // internally parallelizable by the factor of 3
    for (cycle, decommittment_request, _) in artifacts.all_decommittment_queries.iter() {
        // sponge
        let (_old_tail, intermediate_info) = unsorted_decommittment_queue_simulator
            .push_and_output_intermediate_data(*decommittment_request, round_function);

        artifacts
            .all_decommittment_queue_states
            .push((*cycle, intermediate_info));
    }

    // sort queries
    let mut sorted_decommittment_requests_with_data = unsorted_decommittment_requests_with_data;
    sorted_decommittment_requests_with_data.par_sort_by(|a, b|
        // sort by hash first, and then by timestamp
        match a.0.hash.cmp(&b.0.hash) {
            Ordering::Equal => a.0.timestamp.cmp(&b.0.timestamp),
            a @ _ => a,
        });

    let mut deduplicated_decommit_requests_with_data = vec![];

    let mut counter = 0;
    let mut dedublicated_intermediate_states = vec![];
    let mut previous_packed_keys = vec![];
    let mut previous_items_are_trivial = vec![];
    let mut first_encountered_timestamps = vec![];
    let mut previous_record_encodings = vec![];
    let mut first_encountered_timestamp = 0;
    let mut previous_deduplicated_decommittment_queue_simulator = deduplicated_decommittment_queue_simulator.clone();

    let num_items = sorted_decommittment_requests_with_data.len();

    for (idx, (query, writes)) in sorted_decommittment_requests_with_data.into_iter().enumerate() {
        let last = idx == num_items - 1;
        if query.is_fresh {
            first_encountered_timestamp = query.timestamp.0;

            // now feed the queries into it
            let as_queries_it: Vec<_> = writes
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
                    is_pended: false,
                    value_is_pointer: false,
                })
                .collect();

            // fill up the memory queue
            for query in as_queries_it.iter() {
                let (_old_tail, intermediate_info) = artifacts
                    .memory_queue_simulator
                    .push_and_output_intermediate_data(*query, round_function);

                artifacts.all_memory_queue_states.push(intermediate_info);
            }

            // and plain test memory queues
            artifacts
                .all_memory_queries_accumulated
                .extend(as_queries_it);

            // and sorted request
            artifacts.deduplicated_decommittment_queries.push(query);

            previous_deduplicated_decommittment_queue_simulator = deduplicated_decommittment_queue_simulator.clone();
            let (_old_tail, intermediate_info) = deduplicated_decommittment_queue_simulator
                .push_and_output_intermediate_data(query, round_function);

            deduplicated_decommittment_queue_states.push(intermediate_info);

            deduplicated_decommit_requests_with_data.push((query, writes));
        }

        let (_old_tail, intermediate_info) = sorted_decommittment_queue_simulator
            .push_and_output_intermediate_data(query, round_function);

        sorted_decommittment_queue_states.push(intermediate_info);

        artifacts.sorted_decommittment_queries.push(query);

        counter += 1;

        if counter == dedublicator_circuit_capacity {
            counter = 0;

            if last {
                dedublicated_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&deduplicated_decommittment_queue_simulator));
            } else {
                dedublicated_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&previous_deduplicated_decommittment_queue_simulator));
            }

            let record = sorted_decommittment_queue_simulator.witness.pop_back().unwrap();
            previous_packed_keys.push(
                pack_key(record.2.hash.0, record.2.timestamp.0)
            );
            previous_items_are_trivial.push(false);
            previous_record_encodings.push(record.0);
            first_encountered_timestamps.push(first_encountered_timestamp);

            sorted_decommittment_queue_simulator.witness.push_back(record);
        }
    }
    if counter > 0 {
        dedublicated_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&deduplicated_decommittment_queue_simulator));

        previous_packed_keys.push([E::Fr::zero(); 2]);
        previous_items_are_trivial.push(true);
        previous_record_encodings.push([E::Fr::zero(); 2]);
        first_encountered_timestamps.push(0);
    }

    assert_eq!(
        artifacts.all_memory_queue_states.len(),
        artifacts.all_memory_queries_accumulated.len()
    );

    let mut decommittments_deduplicator_witness: Vec<CodeDecommittmentsDeduplicatorInstanceWitness<E>> = vec![];

    use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInputOutputWitness;
    use sync_vm::glue::sort_decommittment_requests::input::*;
    use sync_vm::scheduler::queues::DecommitQuery;

    let mut input_passthrough_data =
        CodeDecommittmentsDeduplicatorInputData::<E>::placeholder_witness();
    input_passthrough_data.initial_log_queue_state =
        take_sponge_like_queue_state_from_simulator(&unsorted_decommittment_queue_simulator);
    input_passthrough_data.sorted_queue_initial_state = 
        take_sponge_like_queue_state_from_simulator(&sorted_decommittment_queue_simulator);

    let mut output_passthrough_data =
        CodeDecommittmentsDeduplicatorOutputData::<E>::placeholder_witness();
    output_passthrough_data.final_queue_state =
        take_sponge_like_queue_state_from_simulator(&deduplicated_decommittment_queue_simulator);


    // now we should chunk it by circuits but briefly simulating their logic

    let mut challenges = vec![];

    let mut fs_input = vec![];
    fs_input.extend_from_slice(&unsorted_decommittment_queue_simulator.tail);
    fs_input.push(u64_to_fe(unsorted_decommittment_queue_simulator.num_items as u64));
    fs_input.extend_from_slice(&sorted_decommittment_queue_simulator.tail);
    fs_input.push(u64_to_fe(sorted_decommittment_queue_simulator.num_items as u64));

    let sequence_of_states =
        round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&fs_input);
    let final_state = sequence_of_states.last().unwrap().1;

    // manually unroll to get irreducible over every challenge
    challenges.push(final_state[0]);
    challenges.push(final_state[1]);
    let final_state = round_function.simulate_round_function(final_state);
    challenges.push(final_state[0]);

    let lhs_contributions: Vec<_> = unsorted_decommittment_queue_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();
    let rhs_contributions: Vec<_> = sorted_decommittment_queue_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    use crate::witness::individual_circuits::ram_permutation::compute_grand_product_chains;

    let (lhs_grand_product_chain, rhs_grand_product_chain) =
        compute_grand_product_chains::<E, 2, 3>(&lhs_contributions, &rhs_contributions, challenges.clone());

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    assert_eq!(
        lhs_grand_product_chain.len(),
        unsorted_decommittment_queue_simulator.witness.len()
    );
    assert_eq!(
        lhs_grand_product_chain.len(),
        sorted_decommittment_queue_simulator.witness.len()
    );

    let num_items = unsorted_decommittment_queue_simulator.num_items;
    let mut input_product = E::Fr::one();
    let mut input_products = vec![];
    let mut input_witness = vec![];
    let mut input_witness_chunk = VecDeque::new();
    let mut unsorted_intermediate_states = vec![];
    let mut i = 0;
    for _ in 0..num_items {
        let (encoding, old_tail, element) = unsorted_decommittment_queue_simulator.witness.front().unwrap();

        let wit = DecommitQueryWitness {
            root_hash: biguint_from_u256(element.hash),
            page: element.memory_page.0,
            is_first: element.is_fresh,
            timestamp: element.timestamp.0,
            _marker: std::marker::PhantomData,
        };

        let mut contribution = challenges[2];
        for (el, coeff) in encoding.iter().zip(challenges.iter()) {
            let mut contr_part = *el;
            contr_part.mul_assign(coeff);
          
            contribution.add_assign(&contr_part);
        }
        input_product.mul_assign(&contribution);

        assert_eq!(input_product, lhs_grand_product_chain[i]);
        i += 1;

        input_witness_chunk.push_back((*encoding, wit, *old_tail));

        unsorted_decommittment_queue_simulator.pop_and_output_intermediate_data(round_function);
        if input_witness_chunk.len() == dedublicator_circuit_capacity {
            let completed_chunk = std::mem::replace(&mut input_witness_chunk, VecDeque::new());
            input_witness.push(completed_chunk);
            input_products.push(input_product);
            unsorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&unsorted_decommittment_queue_simulator));
        }

    }
    if input_witness_chunk.len() > 0 {
        input_witness.push(input_witness_chunk);
        input_products.push(input_product);
        unsorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&unsorted_decommittment_queue_simulator));
    }

    assert_eq!(num_items, sorted_decommittment_queue_simulator.num_items);
    let mut sorted_product = E::Fr::one();
    let mut sorted_products = vec![];
    let mut sorted_witness = vec![];
    let mut sorted_witness_chunk = VecDeque::new();
    let mut sorted_intermediate_states = vec![];
    let mut i = 0;
    for _ in 0..num_items {
        let (encoding, old_tail, element) = sorted_decommittment_queue_simulator.witness.front().unwrap();
        let wit = DecommitQueryWitness {
            root_hash: biguint_from_u256(element.hash),
            page: element.memory_page.0,
            is_first: element.is_fresh,
            timestamp: element.timestamp.0,
            _marker: std::marker::PhantomData,
        };

        let mut contribution = challenges[2];
        for (el, coeff) in encoding.iter().zip(challenges.iter()) {
            let mut contr_part = *el;
            contr_part.mul_assign(coeff);
          
            contribution.add_assign(&contr_part);
        }
        sorted_product.mul_assign(&contribution);

        assert_eq!(sorted_product, rhs_grand_product_chain[i]);
        i += 1;

        sorted_witness_chunk.push_back((*encoding, wit, *old_tail));

        sorted_decommittment_queue_simulator.pop_and_output_intermediate_data(round_function);
        if sorted_witness_chunk.len() == dedublicator_circuit_capacity {
            let completed_chunk = std::mem::replace(&mut sorted_witness_chunk, VecDeque::new());
            sorted_witness.push(completed_chunk);
            sorted_products.push(sorted_product);
            sorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&sorted_decommittment_queue_simulator));
        }
    }
    if sorted_witness_chunk.len() > 0 {
        sorted_witness.push(sorted_witness_chunk);
        sorted_products.push(sorted_product);
        sorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(&sorted_decommittment_queue_simulator));
    }

    for i in 0..num_circuits {
        let mut current_witness = CodeDecommittmentsDeduplicatorInstanceWitness {
            closed_form_input: CodeDecommittmentsDeduplicatorInputOutputWitness {
                start_flag: i == 0,
                completion_flag: i == num_circuits - 1,
                observable_input: input_passthrough_data.clone(),
                observable_output: CodeDecommittmentsDeduplicatorOutputData::placeholder_witness(),
                hidden_fsm_input: CodeDecommittmentsDeduplicatorFSMInputOutput::placeholder_witness(),
                hidden_fsm_output: CodeDecommittmentsDeduplicatorFSMInputOutput::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            initial_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness{wit: VecDeque::new()},
            sorted_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness{wit: VecDeque::new()},
            previous_record_witness: DecommitQuery::placeholder_witness(),
        };

        if i == num_circuits - 1 {
            // set passthrough output
            current_witness.closed_form_input.observable_output = output_passthrough_data.clone();
        }
        current_witness.initial_queue_witness = FixedWidthEncodingSpongeLikeQueueWitness { wit: input_witness[i].clone() };
        current_witness.sorted_queue_witness = FixedWidthEncodingSpongeLikeQueueWitness { wit: sorted_witness[i].clone() };

        if let Some(previous_witness) = decommittments_deduplicator_witness.last() {
            current_witness.closed_form_input.hidden_fsm_input = previous_witness.closed_form_input.hidden_fsm_output.clone();
            current_witness.previous_record_witness = previous_witness.sorted_queue_witness.wit.iter().last().unwrap().1.clone();
        }

        current_witness.closed_form_input.hidden_fsm_output = CodeDecommittmentsDeduplicatorFSMInputOutputWitness {
            initial_log_queue_state: unsorted_intermediate_states[i].clone(),
            sorted_queue_state: sorted_intermediate_states[i].clone(),
            final_queue_state: dedublicated_intermediate_states[i].clone(),

            grand_products: [input_products[i], sorted_products[i]],

            previous_packed_key: previous_packed_keys[i],
            previous_item_is_trivial: previous_items_are_trivial[i],
            first_encountered_timestamp: first_encountered_timestamps[i],
            previous_record_encoding: previous_record_encodings[i],

            _marker: std::marker::PhantomData,
        };

        decommittments_deduplicator_witness.push(current_witness);
    }

    // now we should start chunking the requests into separate decommittment circuits by running a micro-simulator

    // our simulator is simple: it will try to take an element from the queue, run some number of rounds, and compare the results

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DecommitterState {
        BeginNew,
        DecommmitMore(usize),
        Done,
    }

    let final_deduplicated_queue_state = transform_sponge_like_queue_state(
        deduplicated_decommittment_queue_states
            .last()
            .unwrap()
            .clone(),
    );
    assert_eq!(
        deduplicated_decommit_requests_with_data.len(),
        deduplicated_decommittment_queue_states.len()
    );

    let mut current_decommittment_requests_queue_simulator =
        deduplicated_decommittment_queue_simulator.clone();

    let mut it = deduplicated_decommit_requests_with_data
        .into_iter()
        .zip(deduplicated_decommittment_queue_states.iter())
        .zip(deduplicated_decommittment_queue_simulator.witness.iter())
        .peekable();

    let mut fsm_state = DecommitterState::BeginNew;
    let mut current_memory_data = vec![];
    let mut start = true;
    let mut memory_queue_state_offset = 0;

    use zk_evm::precompiles::keccak256::Digest;
    use zk_evm::precompiles::sha256::transmute_state;
    use zk_evm::precompiles::sha256::Sha256;

    let mut internal_state = Sha256::default();

    use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;
    use sync_vm::scheduler::queues::FullSpongeLikeQueueState;
    use sync_vm::traits::CSWitnessable;

    let mut fsm_internals = CodeDecommittmentFSM::<E>::placeholder_witness();

    'outer: loop {
        let mut current_circuit_witness = CodeDecommitterCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: start,
                completion_flag: false,
                observable_input: CodeDecommitterInputData::placeholder_witness(),
                observable_output: CodeDecommitterOutputData::placeholder_witness(),
                hidden_fsm_input: CodeDecommitterFSMInputOutput::placeholder_witness(),
                hidden_fsm_output: CodeDecommitterFSMInputOutput::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            sorted_requests_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness {
                wit: VecDeque::new(),
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
            .unwrap_or(FullSpongeLikeQueueState::placeholder_witness());

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
                let _ = current_decommittment_requests_queue_simulator
                    .pop_and_output_intermediate_data(round_function);
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

                let num_words = (hash.0[3] >> 32) as u16;
                assert!(num_words & 1 == 1); // should be odd
                let num_words = num_words as u64;
                let num_rounds = (num_words + 1) / 2;

                let mut hash_as_be = [0u8; 32];
                hash.to_big_endian(&mut hash_as_be);

                let as_circuit_data = DecommitQueryWitness {
                    root_hash: biguint_from_u256(hash),
                    page: memory_page.0,
                    is_first: is_fresh,
                    timestamp: timestamp.0,
                    _marker: std::marker::PhantomData,
                };

                let wit = (wit.0, as_circuit_data, wit.1);

                current_circuit_witness
                    .sorted_requests_queue_witness
                    .wit
                    .push_back(wit);

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
                        as_array[2] = 0;
                        as_array[3] = 0;
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

                    current_circuit_witness
                        .code_words
                        .last_mut()
                        .unwrap()
                        .push(biguint_from_u256(word0));
                    memory_queue_state_offset += 1;
                    fsm_internals.current_index += 1;

                    if *num_rounds_left != 0 {
                        let word1 = current_memory_data.drain(0..1).next().unwrap();
                        current_circuit_witness
                            .code_words
                            .last_mut()
                            .unwrap()
                            .push(biguint_from_u256(word1));
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
                        let raw_state = transmute_state(internal_state.clone());
                        let word0 = 0u32; // 4 bytes are reserved
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
            *dst = u64_to_fe(src as u64)
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

    (results, decommittments_deduplicator_witness)
}

fn pack_key<F: crate::ff::PrimeField>(
    hash: [u64; 4],
    timestamp: u32,
) -> [F; 2] {
    // LE packing
    let fe_32 = F::from_repr(F::Repr::from(1u64 << 32)).unwrap();

    let mut value_0 = F::from_repr(F::Repr::from(u64::from(timestamp))).unwrap();

    let mut part = F::from_repr(F::Repr::from(hash[0])).unwrap();
    part.mul_assign(&fe_32);
    value_0.add_assign(&part);


    let mut value_1 = F::from_repr(F::Repr::from(hash[1])).unwrap();
    let mut shift = fe_32;
    shift.mul_assign(&fe_32);

    let mut part = F::from_repr(F::Repr::from(hash[2])).unwrap();
    part.mul_assign(&shift);
    value_1.add_assign(&part);

    shift.mul_assign(&fe_32);
    shift.mul_assign(&fe_32);

    let mut part = F::from_repr(F::Repr::from(hash[3])).unwrap();
    part.mul_assign(&shift);
    value_1.add_assign(&part);

    [value_0, value_1]
}
