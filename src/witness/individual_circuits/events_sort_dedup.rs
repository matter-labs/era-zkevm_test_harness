use super::*;
use crate::bellman::Engine;
use crate::encodings::log_query::log_query_into_storage_record_witness;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::log_query::*;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::encodings::QueueIntermediateStates;
use crate::ethereum_types::U256;
use crate::ff::Field;
use crate::utils::biguint_from_u256;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::cmp::Ordering;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::log_sorter::input::EventsDeduplicatorInstanceWitness;
use sync_vm::glue::log_sorter::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::testing::Bn256;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use zk_evm::aux_structures::*;

pub fn compute_events_dedup_and_sort<E: Engine, R: CircuitArithmeticRoundFunction<E, 2, 3>>(
    unsorted_queries: &Vec<LogQuery>,
    target_deduplicated_queries: &mut Vec<LogQuery>,
    unsorted_simulator: &LogQueueSimulator<E>,
    unsorted_simulator_states: &Vec<QueueIntermediateStates<E, 3, 3>>,
    result_queue_simulator: &mut LogQueueSimulator<E>,
    per_circuit_capacity: usize,
    round_function: &R,
) -> Vec<EventsDeduplicatorInstanceWitness<E>> {
    // parallelizable

    // have to manually unroll, otherwise borrow checker will complain

    // first we sort the storage log (only storage now) by composite key

    let mut sorted_queries: Vec<_> = unsorted_queries.clone();

    sorted_queries.par_sort_by(|a, b| match a.timestamp.0.cmp(&b.timestamp.0) {
        Ordering::Equal => {
            if b.rollback {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        r @ _ => r,
    });

    let mut intermediate_sorted_simulator = LogQueueSimulator::empty();
    let mut intermediate_sorted_log_simulator_states = Vec::with_capacity(sorted_queries.len());
    for el in sorted_queries.iter() {
        let (_, states) =
            intermediate_sorted_simulator.push_and_output_intermediate_data(*el, round_function);
        intermediate_sorted_log_simulator_states.push(states);
    }

    let intermediate_sorted_simulator_final_state =
        take_queue_state_from_simulator(&intermediate_sorted_simulator);
    // let sorted_queue_witness: VecDeque<_> = intermediate_sorted_simulator.witness.into_iter().map(|(encoding, old_tail, el)| {
    //     let transformed_query = log_query_into_storage_record_witness(&el);

    //     (encoding, transformed_query, old_tail)
    // }).collect();

    let sorted_queries = sort_and_dedup_events_log(sorted_queries);

    let unsorted_simulator_final_state = take_queue_state_from_simulator(unsorted_simulator);

    let mut challenges = vec![];

    let mut fs_input = vec![];
    fs_input.push(unsorted_simulator_final_state.tail_state);
    fs_input.push(u64_to_fe(unsorted_simulator_final_state.num_items as u64));
    fs_input.push(intermediate_sorted_simulator_final_state.tail_state);
    fs_input.push(u64_to_fe(
        intermediate_sorted_simulator_final_state.num_items as u64,
    ));

    let sequence_of_states =
        round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&fs_input);
    let final_state = sequence_of_states.last().unwrap().1;

    // manually unroll to get irreducible over every challenge
    challenges.push(final_state[0]);
    challenges.push(final_state[1]);
    let final_state = round_function.simulate_round_function(final_state);
    challenges.push(final_state[0]);
    challenges.push(final_state[1]);
    let final_state = round_function.simulate_round_function(final_state);
    challenges.push(final_state[0]);
    challenges.push(final_state[1]);

    assert_eq!(
        unsorted_simulator_final_state.num_items,
        intermediate_sorted_simulator_final_state.num_items
    );

    let lhs_contributions: Vec<_> = unsorted_simulator.witness.iter().map(|el| el.0).collect();
    let rhs_contributions: Vec<_> = intermediate_sorted_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    // --------------------

    // compute chains themselves

    use crate::witness::individual_circuits::ram_permutation::compute_grand_product_chains;

    let (lhs_grand_product_chain, rhs_grand_product_chain) =
        compute_grand_product_chains::<E, 5, 6>(&lhs_contributions, &rhs_contributions, challenges);

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    assert_eq!(
        lhs_grand_product_chain.len(),
        unsorted_simulator.witness.len()
    );
    assert_eq!(
        lhs_grand_product_chain.len(),
        intermediate_sorted_simulator.witness.len()
    );

    assert!(unsorted_simulator.witness.as_slices().1.is_empty());
    assert!(intermediate_sorted_simulator
        .witness
        .as_slices()
        .1
        .is_empty());

    let it = unsorted_simulator_states
        .chunks(per_circuit_capacity)
        .zip(intermediate_sorted_log_simulator_states.chunks(per_circuit_capacity))
        .zip(lhs_grand_product_chain.chunks(per_circuit_capacity))
        .zip(rhs_grand_product_chain.chunks(per_circuit_capacity))
        .zip(
            unsorted_simulator
                .witness
                .as_slices()
                .0
                .chunks(per_circuit_capacity),
        )
        .zip(
            intermediate_sorted_simulator
                .witness
                .as_slices()
                .0
                .chunks(per_circuit_capacity),
        );

    let num_circuits = it.len();
    let mut results = vec![];

    use crate::ethereum_types::Address;
    use crate::ethereum_types::U256;

    let mut current_lhs_product = E::Fr::zero();
    let mut current_rhs_product = E::Fr::zero();
    let mut previous_packed_key = E::Fr::zero();
    let empty_log_item = LogQuery {
        timestamp: Timestamp(0),
        tx_number_in_block: 0,
        aux_byte: 0,
        shard_id: 0,
        address: Address::zero(),
        key: U256::zero(),
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let mut previous_item = empty_log_item;

    let mut deduplicated_queries_it = sorted_queries.iter();

    let mut current_final_sorted_queue_state =
        take_queue_state_from_simulator(&result_queue_simulator);

    for (
        idx,
        (
            (
                (
                    ((unsorted_sponge_states, sorted_sponge_states), lhs_grand_product),
                    rhs_grand_product,
                ),
                unsorted_states,
            ),
            sorted_states,
        ),
    ) in it.enumerate()
    {
        // we need witnesses to pop elements from the front of the queue
        use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;

        let unsorted_queue_witness: VecDeque<_> = unsorted_states
            .iter()
            .map(|(encoding, old_tail, element)| {
                let as_storage_log = log_query_into_storage_record_witness(element);

                (*encoding, as_storage_log, *old_tail)
            })
            .collect();

        let unsorted_witness = FixedWidthEncodingGenericQueueWitness {
            wit: unsorted_queue_witness,
        };

        let intermediate_sorted_queue_witness: VecDeque<_> = sorted_states
            .iter()
            .map(|(encoding, old_tail, element)| {
                let as_timestamped_storage_witness = log_query_into_storage_record_witness(element);

                (*encoding, as_timestamped_storage_witness, *old_tail)
            })
            .collect();

        let intermediate_sorted_queue_witness = FixedWidthEncodingGenericQueueWitness {
            wit: intermediate_sorted_queue_witness,
        };

        // now we need to have final grand product value that will also become an input for the next circuit

        let is_first = idx == 0;
        let is_last = idx == num_circuits - 1;

        let last_unsorted_state = unsorted_sponge_states.last().unwrap().clone();
        let last_sorted_state = sorted_sponge_states.last().unwrap().clone();

        let accumulated_lhs = *lhs_grand_product.last().unwrap();
        let accumulated_rhs = *rhs_grand_product.last().unwrap();

        // simulate the logic
        let (new_last_packed_key, new_last_item) = {
            let mut new_last_packed_key = previous_packed_key;
            let mut new_last_item = previous_item;
            let mut current_timestamp = previous_item.timestamp.0;

            let num_items_in_chunk = sorted_states.len();
            let mut exhausted = false;

            for (sub_idx, (_encoding, _previous_tail, item)) in sorted_states.iter().enumerate() {
                let first_ever = sub_idx == 0 && is_first;
                let last_iteration = sub_idx == num_items_in_chunk - 1;
                let is_last_ever = last_iteration && is_last;

                // we know that timestamp of 0 is unreachable, so we do not need
                // to have a special first cycle here

                if !first_ever {
                    assert!(item.rw_flag == true);
                    let same_cell = current_timestamp == item.timestamp.0;

                    if same_cell {
                        assert!(item.rollback == true);
                    } else {
                        assert!(item.rollback == false);
                        if new_last_item.rollback == false {
                            // finish with previous one and start a new one
                            if let Some(next_query) = deduplicated_queries_it.next() {
                                assert_eq!(next_query.address, new_last_item.address);
                                assert_eq!(next_query.key, new_last_item.key);
                                assert_eq!(next_query.written_value, new_last_item.written_value);
                                let _ = result_queue_simulator
                                    .push_and_output_intermediate_data(*next_query, round_function);
                            } else {
                                assert!(is_last);
                                assert!(exhausted == false);
                                exhausted = true;
                            }
                        }
                    }
                }

                new_last_packed_key = event_comparison_key::<E>(&item);
                new_last_item = *item;
                current_timestamp = item.timestamp.0;

                // last cycle is special, we do not try to pop if we processed the last item
                if is_last_ever {
                    if !exhausted {
                        if new_last_item.rollback == false {
                            let next_query = deduplicated_queries_it.next().unwrap();
                            let _ = result_queue_simulator
                                .push_and_output_intermediate_data(*next_query, round_function);
                        }
                    }
                }
            }

            (new_last_packed_key, new_last_item)
        };

        use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueState;
        use sync_vm::traits::CSWitnessable;
        let placeholder_witness = FixedWidthEncodingGenericQueueState::placeholder_witness();

        let (current_unsorted_queue_state, current_intermediate_sorted_queue_state) = results
            .last()
            .map(|el: &EventsDeduplicatorInstanceWitness<E>| {
                let tmp = &el.closed_form_input.hidden_fsm_output;

                (
                    tmp.initial_unsorted_queue_state.clone(),
                    tmp.intermediate_sorted_queue_state.clone(),
                )
            })
            .unwrap_or((placeholder_witness.clone(), placeholder_witness));

        // assert_eq!(current_unsorted_queue_state.length, current_sorted_queue_state.length);

        // we use current final state as the intermediate head
        let mut final_unsorted_state = transform_queue_state(last_unsorted_state);
        final_unsorted_state.head_state = final_unsorted_state.tail_state;
        final_unsorted_state.tail_state = unsorted_simulator_final_state.tail_state;
        final_unsorted_state.num_items =
            unsorted_simulator_final_state.num_items - final_unsorted_state.num_items;

        let mut final_intermediate_sorted_state = transform_queue_state(last_sorted_state);
        final_intermediate_sorted_state.head_state = last_sorted_state.tail;
        final_intermediate_sorted_state.tail_state =
            intermediate_sorted_simulator_final_state.tail_state;
        final_intermediate_sorted_state.num_items =
            intermediate_sorted_simulator_final_state.num_items - last_sorted_state.num_items;

        assert_eq!(
            final_unsorted_state.num_items,
            final_intermediate_sorted_state.num_items
        );

        let last_final_sorted_queue_state =
            take_queue_state_from_simulator(&result_queue_simulator);

        let mut instance_witness = EventsDeduplicatorInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                _marker_e: (),
                start_flag: is_first,
                completion_flag: is_last,
                observable_input: EventsDeduplicatorInputDataWitness {
                    initial_log_queue_state: unsorted_simulator_final_state.clone(),
                    intermediate_sorted_queue_state: intermediate_sorted_simulator_final_state
                        .clone(),
                    _marker: std::marker::PhantomData,
                },
                observable_output: EventsDeduplicatorOutputData::placeholder_witness(),
                hidden_fsm_input: EventsDeduplicatorFSMInputOutputWitness {
                    lhs_accumulator: current_lhs_product,
                    rhs_accumulator: current_rhs_product,
                    initial_unsorted_queue_state: current_unsorted_queue_state,
                    intermediate_sorted_queue_state: current_intermediate_sorted_queue_state,
                    final_result_queue_state: current_final_sorted_queue_state.clone(),
                    previous_packed_key,
                    previous_item: log_query_into_storage_record_witness(&previous_item),
                    _marker: std::marker::PhantomData,
                },
                hidden_fsm_output: EventsDeduplicatorFSMInputOutputWitness {
                    lhs_accumulator: accumulated_lhs,
                    rhs_accumulator: accumulated_rhs,
                    initial_unsorted_queue_state: final_unsorted_state,
                    intermediate_sorted_queue_state: final_intermediate_sorted_state,
                    final_result_queue_state: last_final_sorted_queue_state.clone(),
                    previous_packed_key: new_last_packed_key,
                    previous_item: log_query_into_storage_record_witness(&new_last_item),
                    _marker: std::marker::PhantomData,
                },
                _marker: std::marker::PhantomData,
            },
            initial_queue_witness: unsorted_witness,
            intermediate_sorted_queue_witness: intermediate_sorted_queue_witness,
        };

        assert_eq!(
            instance_witness.initial_queue_witness.wit.len(),
            instance_witness.intermediate_sorted_queue_witness.wit.len()
        );

        if sorted_states.len() % per_circuit_capacity != 0 {
            // circuit does padding, so all previous values must be reset
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_packed_key = E::Fr::zero();
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_item = log_query_into_storage_record_witness(&empty_log_item);
        }

        current_lhs_product = accumulated_lhs;
        current_rhs_product = accumulated_rhs;

        previous_packed_key = new_last_packed_key;
        previous_item = new_last_item;

        current_final_sorted_queue_state = last_final_sorted_queue_state;

        results.push(instance_witness);
    }

    assert!(deduplicated_queries_it.next().is_none());

    let final_sorted_queue_state = take_queue_state_from_simulator(&result_queue_simulator);

    results
        .last_mut()
        .unwrap()
        .closed_form_input
        .observable_output
        .final_queue_state = final_sorted_queue_state.clone();

    *target_deduplicated_queries = sorted_queries;

    results
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

                continue;
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
pub fn simulate_events_log_for_commitment(
    history: Vec<LogQuery>,
) -> (Vec<LogQuery>, (u32, sync_vm::testing::Fr)) {
    use sync_vm::recursion::get_prefered_committer;

    let round_function = get_prefered_committer();

    let mut sorted_history = history;
    sorted_history.sort_by(|a, b| match a.timestamp.0.cmp(&b.timestamp.0) {
        Ordering::Equal => {
            if b.rollback {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
        r @ _ => r,
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
