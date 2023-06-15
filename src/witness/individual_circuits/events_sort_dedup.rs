use super::*;
use crate::ethereum_types::U256;
use crate::zk_evm::aux_structures::*;
use crate::zkevm_circuits::base_structures::log_query::{
    LOG_QUERY_ABSORBTION_ROUNDS, LOG_QUERY_PACKED_WIDTH,
};
use crate::zkevm_circuits::base_structures::vm_state::QUEUE_STATE_WIDTH;
use crate::zkevm_circuits::log_sorter::input::*;
use crate::zkevm_circuits::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;
use circuit_definitions::encodings::*;
use rayon::prelude::*;
use smallvec::SmallVec;
use std::cmp::Ordering;

pub fn compute_events_dedup_and_sort<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    unsorted_queries: &Vec<LogQuery>,
    target_deduplicated_queries: &mut Vec<LogQuery>,
    unsorted_simulator: &LogQueueSimulator<F>,
    unsorted_simulator_states: &Vec<
        QueueIntermediateStates<F, QUEUE_STATE_WIDTH, 12, LOG_QUERY_ABSORBTION_ROUNDS>,
    >,
    result_queue_simulator: &mut LogQueueSimulator<F>,
    per_circuit_capacity: usize,
    round_function: &R,
) -> Vec<EventsDeduplicatorInstanceWitness<F>> {
    // trivial case if nothing to process

    if unsorted_queries.is_empty() {
        // return singe dummy witness
        use crate::boojum::gadgets::queue::QueueState;

        let initial_fsm_state = EventsDeduplicatorFSMInputOutput::<F>::placeholder_witness();

        assert_eq!(
            take_queue_state_from_simulator(&unsorted_simulator),
            QueueState::placeholder_witness()
        );

        let mut passthrough_input = EventsDeduplicatorInputData::placeholder_witness();
        passthrough_input.initial_log_queue_state =
            take_queue_state_from_simulator(&unsorted_simulator);
        passthrough_input.intermediate_sorted_queue_state = QueueState::placeholder_witness();

        let final_fsm_state = EventsDeduplicatorFSMInputOutput::<F>::placeholder_witness();

        let mut passthrough_output = EventsDeduplicatorOutputData::placeholder_witness();
        passthrough_output.final_queue_state = QueueState::placeholder_witness();

        let wit = EventsDeduplicatorInstanceWitness {
            closed_form_input: EventsDeduplicatorInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
            },
            initial_queue_witness: CircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
            intermediate_sorted_queue_witness: CircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
        };

        return vec![wit];
    }

    // parallelizable between events and L2 to L1 messages

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

    let mut intermediate_sorted_simulator = LogQueueSimulator::<F>::empty();
    let mut intermediate_sorted_log_simulator_states = Vec::with_capacity(sorted_queries.len());
    for el in sorted_queries.iter() {
        let (_, states) =
            intermediate_sorted_simulator.push_and_output_intermediate_data(*el, round_function);
        intermediate_sorted_log_simulator_states.push(states);
    }

    let intermediate_sorted_simulator_final_state =
        take_queue_state_from_simulator(&intermediate_sorted_simulator);
    let sorted_queries = sort_and_dedup_events_log(sorted_queries);

    let unsorted_simulator_final_state = take_queue_state_from_simulator(unsorted_simulator);

    let challenges = produce_fs_challenges::<
        F,
        R,
        QUEUE_STATE_WIDTH,
        { LOG_QUERY_PACKED_WIDTH + 1 },
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
    >(
        take_queue_state_from_simulator(&unsorted_simulator).tail,
        take_queue_state_from_simulator(&intermediate_sorted_simulator).tail,
        round_function,
    );

    assert_eq!(
        unsorted_simulator_final_state.tail.length,
        intermediate_sorted_simulator_final_state.tail.length
    );

    let lhs_contributions: Vec<_> = unsorted_simulator.witness.iter().map(|el| el.0).collect();
    let rhs_contributions: Vec<_> = intermediate_sorted_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    // --------------------

    let mut lhs_grand_product_chains = vec![];
    let mut rhs_grand_product_chains = vec![];

    for idx in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
        let (lhs_grand_product_chain, rhs_grand_product_chain) = compute_grand_product_chains::<
            F,
            LOG_QUERY_PACKED_WIDTH,
            { LOG_QUERY_PACKED_WIDTH + 1 },
        >(
            &lhs_contributions,
            &rhs_contributions,
            &challenges[idx],
        );

        assert_eq!(
            lhs_grand_product_chain.len(),
            unsorted_simulator.witness.len()
        );
        assert_eq!(
            lhs_grand_product_chain.len(),
            intermediate_sorted_simulator.witness.len()
        );

        lhs_grand_product_chains.push(lhs_grand_product_chain);
        rhs_grand_product_chains.push(rhs_grand_product_chain);
    }

    let transposed_lhs_chains = transpose_chunks(&lhs_grand_product_chains, per_circuit_capacity);
    let transposed_rhs_chains = transpose_chunks(&rhs_grand_product_chains, per_circuit_capacity);

    assert!(unsorted_simulator_states.len() > 0);
    assert!(unsorted_simulator_states.chunks(per_circuit_capacity).len() > 0);
    assert_eq!(
        unsorted_simulator_states.chunks(per_circuit_capacity).len(),
        intermediate_sorted_log_simulator_states
            .chunks(per_circuit_capacity)
            .len()
    );
    assert_eq!(
        unsorted_simulator_states.chunks(per_circuit_capacity).len(),
        transposed_lhs_chains.len()
    );
    assert_eq!(
        unsorted_simulator_states.chunks(per_circuit_capacity).len(),
        transposed_rhs_chains.len()
    );
    assert_eq!(
        unsorted_simulator_states.chunks(per_circuit_capacity).len(),
        unsorted_simulator
            .witness
            .as_slices()
            .0
            .chunks(per_circuit_capacity)
            .len()
    );
    assert_eq!(
        unsorted_simulator_states.chunks(per_circuit_capacity).len(),
        intermediate_sorted_simulator
            .witness
            .as_slices()
            .0
            .chunks(per_circuit_capacity)
            .len()
    );

    let it = unsorted_simulator_states
        .chunks(per_circuit_capacity)
        .zip(intermediate_sorted_log_simulator_states.chunks(per_circuit_capacity))
        .zip(transposed_lhs_chains.into_iter())
        .zip(transposed_rhs_chains.into_iter())
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

    let mut previous_key = 0u32;
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

    let mut current_lhs_product = [F::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut current_rhs_product = [F::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];

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

        let unsorted_queue_witness: VecDeque<_> = unsorted_states
            .iter()
            .map(|(_encoding, old_tail, element)| {
                let as_storage_log = log_query_into_circuit_log_query_witness(element);

                (as_storage_log, *old_tail)
            })
            .collect();

        let unsorted_witness = CircuitQueueRawWitness::<
            F,
            zkevm_circuits::base_structures::log_query::LogQuery<F>,
            4,
            LOG_QUERY_PACKED_WIDTH,
        > {
            elements: unsorted_queue_witness,
        };

        let intermediate_sorted_queue_witness: VecDeque<_> = sorted_states
            .iter()
            .map(|(_encoding, old_tail, element)| {
                let as_timestamped_storage_witness =
                    log_query_into_circuit_log_query_witness(element);

                (as_timestamped_storage_witness, *old_tail)
            })
            .collect();

        let intermediate_sorted_queue_witness = CircuitQueueRawWitness::<
            F,
            zkevm_circuits::base_structures::log_query::LogQuery<F>,
            4,
            LOG_QUERY_PACKED_WIDTH,
        > {
            elements: intermediate_sorted_queue_witness,
        };

        // now we need to have final grand product value that will also become an input for the next circuit

        let is_first = idx == 0;
        let is_last = idx == num_circuits - 1;

        let last_unsorted_state = unsorted_sponge_states.last().unwrap().clone();
        let last_sorted_state = sorted_sponge_states.last().unwrap().clone();

        let accumulated_lhs: [F; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS] = lhs_grand_product
            .iter()
            .map(|el| *el.last().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let accumulated_rhs: [F; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS] = rhs_grand_product
            .iter()
            .map(|el| *el.last().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // simulate the logic
        let (new_last_key, new_last_item) = {
            let mut new_last_key = previous_key;
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

                new_last_key = item.timestamp.0;
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

            (new_last_key, new_last_item)
        };

        use crate::boojum::gadgets::queue::QueueState;
        let placeholder_witness = QueueState::<F, QUEUE_STATE_WIDTH>::placeholder_witness();

        let (current_unsorted_queue_state, current_intermediate_sorted_queue_state) = results
            .last()
            .map(|el: &EventsDeduplicatorInstanceWitness<F>| {
                let tmp = &el.closed_form_input.hidden_fsm_output;

                (
                    tmp.initial_unsorted_queue_state.clone(),
                    tmp.intermediate_sorted_queue_state.clone(),
                )
            })
            .unwrap_or((placeholder_witness.clone(), placeholder_witness));

        // we use current final state as the intermediate head
        let mut final_unsorted_state = transform_queue_state(last_unsorted_state);
        final_unsorted_state.head = final_unsorted_state.tail.tail;
        final_unsorted_state.tail.tail = unsorted_simulator_final_state.tail.tail;
        final_unsorted_state.tail.length =
            unsorted_simulator_final_state.tail.length - final_unsorted_state.tail.length;

        let mut final_intermediate_sorted_state = transform_queue_state(last_sorted_state);
        final_intermediate_sorted_state.head = last_sorted_state.tail;
        final_intermediate_sorted_state.tail.tail =
            intermediate_sorted_simulator_final_state.tail.tail;
        final_intermediate_sorted_state.tail.length =
            intermediate_sorted_simulator_final_state.tail.length - last_sorted_state.num_items;

        assert_eq!(
            final_unsorted_state.tail.length,
            final_intermediate_sorted_state.tail.length
        );

        let last_final_sorted_queue_state =
            take_queue_state_from_simulator(&result_queue_simulator);

        let mut instance_witness = EventsDeduplicatorInstanceWitness::<F> {
            closed_form_input: ClosedFormInputWitness {
                start_flag: is_first,
                completion_flag: is_last,
                observable_input: EventsDeduplicatorInputDataWitness {
                    initial_log_queue_state: unsorted_simulator_final_state.clone(),
                    intermediate_sorted_queue_state: intermediate_sorted_simulator_final_state
                        .clone(),
                },
                observable_output: EventsDeduplicatorOutputData::placeholder_witness(),
                hidden_fsm_input: EventsDeduplicatorFSMInputOutputWitness {
                    lhs_accumulator: current_lhs_product,
                    rhs_accumulator: current_rhs_product,
                    initial_unsorted_queue_state: current_unsorted_queue_state,
                    intermediate_sorted_queue_state: current_intermediate_sorted_queue_state,
                    final_result_queue_state: current_final_sorted_queue_state.clone(),
                    previous_key,
                    previous_item: log_query_into_circuit_log_query_witness(&previous_item),
                },
                hidden_fsm_output: EventsDeduplicatorFSMInputOutputWitness {
                    lhs_accumulator: accumulated_lhs,
                    rhs_accumulator: accumulated_rhs,
                    initial_unsorted_queue_state: final_unsorted_state,
                    intermediate_sorted_queue_state: final_intermediate_sorted_state,
                    final_result_queue_state: last_final_sorted_queue_state.clone(),
                    previous_key: new_last_key,
                    previous_item: log_query_into_circuit_log_query_witness(&new_last_item),
                },
            },
            initial_queue_witness: unsorted_witness,
            intermediate_sorted_queue_witness: intermediate_sorted_queue_witness,
        };

        assert_eq!(
            instance_witness.initial_queue_witness.elements.len(),
            instance_witness
                .intermediate_sorted_queue_witness
                .elements
                .len()
        );

        if sorted_states.len() % per_circuit_capacity != 0 {
            // circuit does padding, so all previous values must be reset
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_key = 0u32;
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_item = log_query_into_circuit_log_query_witness(&empty_log_item);
        }

        current_lhs_product = accumulated_lhs;
        current_rhs_product = accumulated_rhs;

        previous_key = new_last_key;
        previous_item = new_last_item;

        current_final_sorted_queue_state = last_final_sorted_queue_state;

        results.push(instance_witness);
    }

    assert!(results.len() > 0);

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
pub fn simulate_events_log_for_commitment<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    history: Vec<LogQuery>,
    round_function: &R,
) -> (Vec<LogQuery>, (u32, [F; QUEUE_STATE_WIDTH])) {
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

    let mut simulator = LogQueueSimulator::<F>::empty();
    for el in net_history.iter().copied() {
        simulator.push(el, round_function);
    }

    let queue_len = simulator.num_items;
    let tail = simulator.tail;

    (net_history, (queue_len, tail))
}
