use super::*;
use crate::zkevm_circuits::base_structures::log_query::{
    LOG_QUERY_ABSORBTION_ROUNDS, LOG_QUERY_PACKED_WIDTH,
};
use crate::zkevm_circuits::base_structures::vm_state::QUEUE_STATE_WIDTH;
use crate::zkevm_circuits::storage_validity_by_grand_product::input::*;
use crate::zkevm_circuits::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;
use circuit_definitions::encodings::*;
use std::cmp::Ordering;

pub fn compute_storage_dedup_and_sort<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    per_circuit_capacity: usize,
    round_function: &R,
) -> Vec<StorageDeduplicatorInstanceWitness<F>> {
    // trivial case if nothing to process

    const SHARD_ID_TO_PROCEED: u8 = 0; // rollup shard ID

    if artifacts.demuxed_rollup_storage_queries.is_empty() {
        // return singe dummy witness
        use crate::boojum::gadgets::queue::QueueState;

        let initial_fsm_state = StorageDeduplicatorFSMInputOutput::<F>::placeholder_witness();

        assert_eq!(
            take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator),
            QueueState::placeholder_witness()
        );

        let mut passthrough_input = StorageDeduplicatorInputData::placeholder_witness();
        passthrough_input.shard_id_to_process = SHARD_ID_TO_PROCEED;
        passthrough_input.unsorted_log_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);
        passthrough_input.intermediate_sorted_queue_state = QueueState::placeholder_witness();

        let final_fsm_state = StorageDeduplicatorFSMInputOutput::<F>::placeholder_witness();

        let mut passthrough_output = StorageDeduplicatorOutputData::placeholder_witness();
        passthrough_output.final_sorted_queue_state = QueueState::placeholder_witness();

        let wit = StorageDeduplicatorInstanceWitness {
            closed_form_input: StorageDeduplicatorInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
            },
            unsorted_queue_witness: CircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
            intermediate_sorted_queue_witness: CircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
        };

        return vec![wit];
    }

    // first we sort the storage log (only storage now) by composite key

    use crate::witness::sort_storage_access::sort_storage_access_queries;

    let (sorted_storage_queries_with_extra_timestamp, deduplicated_rollup_storage_queries) =
        sort_storage_access_queries(&artifacts.demuxed_rollup_storage_queries);

    // dbg!(&sorted_storage_queries_with_extra_timestamp);
    // dbg!(&deduplicated_rollup_storage_queries);

    artifacts.deduplicated_rollup_storage_queries = deduplicated_rollup_storage_queries;

    let mut intermediate_sorted_log_simulator =
        LogWithExtendedEnumerationQueueSimulator::<F>::empty();
    let mut intermediate_sorted_log_simulator_states =
        Vec::with_capacity(sorted_storage_queries_with_extra_timestamp.len());
    for el in sorted_storage_queries_with_extra_timestamp.iter() {
        let (_, intermediate_state) = intermediate_sorted_log_simulator
            .push_and_output_intermediate_data(el.clone(), round_function);
        intermediate_sorted_log_simulator_states.push(intermediate_state);
    }

    let unsorted_simulator_final_state =
        take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);

    let intermediate_sorted_log_simulator_final_state =
        take_queue_state_from_simulator(&intermediate_sorted_log_simulator);

    // now just implement the logic to sort and deduplicate

    let mut result_queue_simulator = LogQueueSimulator::<F>::empty();

    // compute sequence of states for grand product accumulation

    // --------------------

    // now we should chunk it by circuits but briefly simulating their logic

    let challenges = produce_fs_challenges::<
        F,
        R,
        QUEUE_STATE_WIDTH,
        { LOG_QUERY_PACKED_WIDTH + 1 },
        DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
    >(
        unsorted_simulator_final_state.tail.clone(),
        intermediate_sorted_log_simulator_final_state.tail.clone(),
        round_function,
    );

    // since encodings of the elements provide all the information necessary to perform soring argument,
    // we use them naively

    assert_eq!(
        unsorted_simulator_final_state.tail.length,
        intermediate_sorted_log_simulator_final_state.tail.length
    );

    let lhs_contributions: Vec<_> = artifacts
        .demuxed_rollup_storage_queries
        .iter()
        .enumerate()
        .map(|(idx, el)| {
            let extended_query = LogQueryWithExtendedEnumeration {
                raw_query: *el,
                extended_timestamp: idx as u32,
            };

            <LogQueryWithExtendedEnumeration as OutOfCircuitFixedLengthEncodable<
                F,
                LOG_QUERY_PACKED_WIDTH,
            >>::encoding_witness(&extended_query)
        })
        .collect();

    // let lhs_contributions: Vec<_> = artifacts.demuxed_rollup_storage_queue_simulator.witness.iter().map(|el| el.0).collect();
    let rhs_contributions: Vec<_> = intermediate_sorted_log_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    // --------------------

    // compute chains themselves

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
            artifacts
                .demuxed_rollup_storage_queue_simulator
                .witness
                .len()
        );
        assert_eq!(
            rhs_grand_product_chain.len(),
            intermediate_sorted_log_simulator.witness.len()
        );

        lhs_grand_product_chains.push(lhs_grand_product_chain);
        rhs_grand_product_chains.push(rhs_grand_product_chain);
    }

    let transposed_lhs_chains = transpose_chunks(&lhs_grand_product_chains, per_circuit_capacity);
    let transposed_rhs_chains = transpose_chunks(&rhs_grand_product_chains, per_circuit_capacity);

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    // --------------------

    // in general we have everything ready, just form the witness

    // as usual we simulate logic of the circuit and chunk. It's a little less convenient here than in RAM since we
    // have to chunk based on 2 queues, but also guess the result of the 3rd queue, but managable

    assert!(artifacts
        .demuxed_rollup_storage_queue_simulator
        .witness
        .as_slices()
        .1
        .is_empty());
    assert!(intermediate_sorted_log_simulator
        .witness
        .as_slices()
        .1
        .is_empty());

    let it = artifacts
        .demuxed_rollup_storage_queue_states
        .chunks(per_circuit_capacity)
        .zip(intermediate_sorted_log_simulator_states.chunks(per_circuit_capacity))
        .zip(transposed_lhs_chains.into_iter())
        .zip(transposed_rhs_chains.into_iter())
        .zip(
            artifacts
                .demuxed_rollup_storage_queue_simulator
                .witness
                .as_slices()
                .0
                .chunks(per_circuit_capacity),
        )
        .zip(
            intermediate_sorted_log_simulator
                .witness
                .as_slices()
                .0
                .chunks(per_circuit_capacity),
        );

    // now trivial transformation into desired data structures,
    // and we are all good

    let num_circuits = it.len();
    let mut results = vec![];

    let mut current_lhs_product = [F::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut current_rhs_product = [F::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut previous_comparison_key = [0u32; PACKED_KEY_LENGTH];
    let mut previous_key = U256::zero();
    let mut previous_timestamp = 0u32;
    let mut cycle_idx = 0u32;
    use crate::ethereum_types::Address;
    let mut previous_address = Address::default();

    use crate::ethereum_types::U256;

    let mut this_cell_has_explicit_read_and_rollback_depth_zero = false;
    let mut this_cell_base_value = U256::zero();
    let mut this_cell_current_value = U256::zero();
    let mut this_cell_current_depth = 0u32;

    let mut deduplicated_queries_it = artifacts.deduplicated_rollup_storage_queries.iter();

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

        let unsorted_queue_witness: VecDeque<_> = unsorted_states
            .iter()
            .map(|(_encoding, old_tail, element)| {
                let as_storage_log = element.reflect();

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
                    log_query_into_timestamped_storage_record_witness(element);

                (as_timestamped_storage_witness, *old_tail)
            })
            .collect();

        let intermediate_sorted_queue_witness = CircuitQueueRawWitness::<
            F,
            zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F>,
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

        let last_sorted_query = &sorted_states.last().unwrap().2;
        use circuit_definitions::encodings::log_query::comparison_key;
        let last_comparison_key = comparison_key(&last_sorted_query.raw_query);
        let last_key = last_sorted_query.raw_query.key;
        let last_address = last_sorted_query.raw_query.address;
        let last_timestamp = last_sorted_query.extended_timestamp;

        // simulate the logic
        let (
            new_this_cell_has_explicit_read_and_rollback_depth_zero,
            new_this_cell_base_value,
            new_this_cell_current_value,
            new_this_cell_current_depth,
        ) = {
            let mut current_address = previous_address;
            let mut current_key = previous_key;
            let mut new_this_cell_has_explicit_read_and_rollback_depth_zero =
                this_cell_has_explicit_read_and_rollback_depth_zero;
            let mut new_this_cell_base_value = this_cell_base_value;
            let mut new_this_cell_current_value = this_cell_current_value;
            let mut new_this_cell_current_depth = this_cell_current_depth;

            let num_items_in_chunk = sorted_states.len();

            let mut exhausted = false;

            for (sub_idx, (_encoding, _previous_tail, item)) in sorted_states.iter().enumerate() {
                let first_ever = sub_idx == 0 && is_first;
                let is_last_ever = (sub_idx == num_items_in_chunk - 1) && is_last;

                if first_ever {
                    // only set current values
                    if item.raw_query.rw_flag == true {
                        assert!(item.raw_query.rollback == false);
                        new_this_cell_current_depth = 1;
                        new_this_cell_has_explicit_read_and_rollback_depth_zero = false;
                    } else {
                        new_this_cell_current_depth = 0;
                        new_this_cell_has_explicit_read_and_rollback_depth_zero = true;
                    }

                    new_this_cell_base_value = item.raw_query.read_value;
                    if item.raw_query.rw_flag == true {
                        new_this_cell_current_value = item.raw_query.written_value;
                    } else {
                        new_this_cell_current_value = item.raw_query.read_value;
                    }
                } else {
                    // main cycle

                    let same_cell = current_address == item.raw_query.address
                        && current_key == item.raw_query.key;

                    if same_cell {
                        // proceed previous one
                        if item.raw_query.rw_flag == true {
                            // write or rollback
                            if item.raw_query.rollback == false {
                                new_this_cell_current_depth += 1;
                                new_this_cell_current_value = item.raw_query.written_value;
                            } else {
                                new_this_cell_current_depth -= 1;
                                new_this_cell_current_value = item.raw_query.read_value;
                            }
                        } else {
                            // read
                            if new_this_cell_current_depth == 0 {
                                new_this_cell_has_explicit_read_and_rollback_depth_zero =
                                    true || new_this_cell_has_explicit_read_and_rollback_depth_zero;
                            }
                            new_this_cell_current_value = item.raw_query.read_value;
                        }
                    } else {
                        // finish with previous one and start a new one
                        if new_this_cell_current_depth > 0 {
                            // net write
                            if let Some(next_query) = deduplicated_queries_it.next() {
                                if new_this_cell_current_value == new_this_cell_base_value {
                                    // protective read, to ensure that if we follow
                                    // the claim of initial value and do not overwrite,
                                    // then we are consistent
                                    assert!(next_query.rw_flag == false);
                                    assert!(next_query.shard_id == SHARD_ID_TO_PROCEED);
                                    assert!(next_query.address == current_address);
                                    assert!(next_query.key == current_key);
                                    assert!(next_query.read_value == new_this_cell_current_value);
                                    assert!(
                                        next_query.written_value == new_this_cell_current_value
                                    );
                                } else {
                                    // plain write
                                    assert!(next_query.rw_flag == true);
                                    assert!(next_query.shard_id == SHARD_ID_TO_PROCEED);
                                    assert!(next_query.address == current_address);
                                    assert!(next_query.key == current_key);
                                    assert!(next_query.read_value == new_this_cell_base_value);
                                    assert!(
                                        next_query.written_value == new_this_cell_current_value
                                    );
                                }

                                let _ = result_queue_simulator
                                    .push_and_output_intermediate_data(*next_query, round_function);
                            } else {
                                // empty cycles
                                assert!(is_last);
                                assert!(exhausted == false);
                                exhausted = true;
                            }
                        } else {
                            if new_this_cell_has_explicit_read_and_rollback_depth_zero == true {
                                // protective read
                                if let Some(next_query) = deduplicated_queries_it.next() {
                                    assert!(next_query.rw_flag == false);
                                    assert!(next_query.shard_id == SHARD_ID_TO_PROCEED);
                                    assert!(next_query.address == current_address);
                                    assert!(next_query.key == current_key);
                                    assert!(next_query.read_value == new_this_cell_base_value);
                                    assert!(next_query.written_value == new_this_cell_base_value);
                                    let _ = result_queue_simulator
                                        .push_and_output_intermediate_data(
                                            *next_query,
                                            round_function,
                                        );
                                } else {
                                    assert!(is_last);
                                    assert!(exhausted == false);
                                    exhausted = true;
                                }
                            }
                        }

                        // start for new one
                        if item.raw_query.rw_flag == true {
                            assert!(item.raw_query.rollback == false);
                            new_this_cell_current_depth = 1;
                            new_this_cell_has_explicit_read_and_rollback_depth_zero = false;
                        } else {
                            new_this_cell_current_depth = 0;
                            new_this_cell_has_explicit_read_and_rollback_depth_zero = true;
                        }

                        new_this_cell_base_value = item.raw_query.read_value;
                        if item.raw_query.rw_flag == true {
                            new_this_cell_current_value = item.raw_query.written_value;
                        } else {
                            new_this_cell_current_value = item.raw_query.read_value;
                        }
                    }
                }

                // always update keys
                current_address = item.raw_query.address;
                current_key = item.raw_query.key;

                if is_last_ever {
                    if exhausted == false {
                        if new_this_cell_current_depth > 0 {
                            // net write
                            let next_query = deduplicated_queries_it.next().unwrap();
                            if new_this_cell_current_value == new_this_cell_base_value {
                                // protective read
                                assert!(next_query.rw_flag == false);
                                assert!(next_query.shard_id == SHARD_ID_TO_PROCEED);
                                assert!(next_query.address == current_address);
                                assert!(next_query.key == current_key);
                                assert!(next_query.read_value == new_this_cell_current_value);
                                assert!(next_query.written_value == new_this_cell_current_value);
                            } else {
                                assert!(next_query.rw_flag == true);
                                assert!(next_query.shard_id == SHARD_ID_TO_PROCEED);
                                assert!(next_query.address == current_address);
                                assert!(next_query.key == current_key);
                                assert!(next_query.read_value == new_this_cell_base_value);
                                assert!(next_query.written_value == new_this_cell_current_value);
                            }

                            let _ = result_queue_simulator
                                .push_and_output_intermediate_data(*next_query, round_function);
                        } else {
                            if new_this_cell_has_explicit_read_and_rollback_depth_zero == true {
                                // protective read
                                let next_query = deduplicated_queries_it.next().unwrap();
                                assert!(next_query.rw_flag == false);
                                assert!(next_query.shard_id == SHARD_ID_TO_PROCEED);
                                assert!(next_query.address == current_address);
                                assert!(next_query.key == current_key);
                                assert!(next_query.read_value == new_this_cell_base_value);
                                assert!(next_query.written_value == new_this_cell_base_value);
                                let _ = result_queue_simulator
                                    .push_and_output_intermediate_data(*next_query, round_function);
                            }
                        }
                    }
                }
            }

            (
                new_this_cell_has_explicit_read_and_rollback_depth_zero,
                new_this_cell_base_value,
                new_this_cell_current_value,
                new_this_cell_current_depth,
            )
        };

        use crate::boojum::gadgets::queue::QueueState;
        let placeholder_witness = QueueState::<F, QUEUE_STATE_WIDTH>::placeholder_witness();

        let (current_unsorted_queue_state, current_intermediate_sorted_queue_state) = results
            .last()
            .map(|el: &StorageDeduplicatorInstanceWitness<F>| {
                let tmp = &el.closed_form_input.hidden_fsm_output;

                (
                    tmp.current_unsorted_queue_state.clone(),
                    tmp.current_intermediate_sorted_queue_state.clone(),
                )
            })
            .unwrap_or((placeholder_witness.clone(), placeholder_witness));

        // assert_eq!(current_unsorted_queue_state.length, current_sorted_queue_state.length);

        // we use current final state as the intermediate head
        let mut final_unsorted_state = transform_queue_state(last_unsorted_state);
        final_unsorted_state.head = final_unsorted_state.tail.tail;
        final_unsorted_state.tail.tail = unsorted_simulator_final_state.tail.tail;
        final_unsorted_state.tail.length =
            unsorted_simulator_final_state.tail.length - final_unsorted_state.tail.length;

        let mut final_intermediate_sorted_state = transform_queue_state(last_sorted_state);
        final_intermediate_sorted_state.head = last_sorted_state.tail;
        final_intermediate_sorted_state.tail.tail =
            intermediate_sorted_log_simulator_final_state.tail.tail;
        final_intermediate_sorted_state.tail.length =
            intermediate_sorted_log_simulator_final_state.tail.length - last_sorted_state.num_items;

        assert_eq!(
            final_unsorted_state.tail.length,
            final_intermediate_sorted_state.tail.length
        );

        let final_cycle_idx = cycle_idx + per_circuit_capacity as u32;

        let last_final_sorted_queue_state =
            take_queue_state_from_simulator(&result_queue_simulator);

        let mut instance_witness = StorageDeduplicatorInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: is_first,
                completion_flag: is_last,
                observable_input: StorageDeduplicatorInputDataWitness {
                    shard_id_to_process: SHARD_ID_TO_PROCEED,
                    unsorted_log_queue_state: unsorted_simulator_final_state.clone(),
                    intermediate_sorted_queue_state: intermediate_sorted_log_simulator_final_state
                        .clone(),
                },
                observable_output: StorageDeduplicatorOutputData::placeholder_witness(),
                hidden_fsm_input: StorageDeduplicatorFSMInputOutputWitness {
                    lhs_accumulator: current_lhs_product,
                    rhs_accumulator: current_rhs_product,
                    current_unsorted_queue_state,
                    current_intermediate_sorted_queue_state,
                    current_final_sorted_queue_state: current_final_sorted_queue_state.clone(),
                    cycle_idx: cycle_idx,
                    previous_key: previous_key,
                    previous_address: previous_address,
                    previous_timestamp,
                    previous_packed_key: previous_comparison_key,
                    this_cell_has_explicit_read_and_rollback_depth_zero,
                    this_cell_base_value: this_cell_base_value,
                    this_cell_current_value: this_cell_current_value,
                    this_cell_current_depth,
                },
                hidden_fsm_output: StorageDeduplicatorFSMInputOutputWitness {
                    lhs_accumulator: accumulated_lhs,
                    rhs_accumulator: accumulated_rhs,
                    current_unsorted_queue_state: final_unsorted_state,
                    current_intermediate_sorted_queue_state: final_intermediate_sorted_state,
                    current_final_sorted_queue_state: last_final_sorted_queue_state.clone(),
                    cycle_idx: final_cycle_idx,
                    previous_packed_key: last_comparison_key.0,
                    previous_key: last_key,
                    previous_address: last_address,
                    previous_timestamp: last_timestamp,
                    this_cell_has_explicit_read_and_rollback_depth_zero:
                        new_this_cell_has_explicit_read_and_rollback_depth_zero,
                    this_cell_base_value: new_this_cell_base_value,
                    this_cell_current_value: new_this_cell_current_value,
                    this_cell_current_depth: new_this_cell_current_depth,
                },
            },
            unsorted_queue_witness: unsorted_witness,
            intermediate_sorted_queue_witness: intermediate_sorted_queue_witness,
        };

        assert_eq!(
            instance_witness.unsorted_queue_witness.elements.len(),
            instance_witness
                .intermediate_sorted_queue_witness
                .elements
                .len()
        );

        if sorted_states.len() % per_circuit_capacity != 0 {
            assert!(is_last);
            // circuit does padding, so all previous values must be reset
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_packed_key = [0u32; PACKED_KEY_LENGTH];
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_key = U256::zero();
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_address = Address::default();
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_timestamp = 0u32;
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .this_cell_has_explicit_read_and_rollback_depth_zero = false;
        }

        current_lhs_product = accumulated_lhs;
        current_rhs_product = accumulated_rhs;

        previous_comparison_key = last_comparison_key.0;
        previous_key = last_key;
        previous_timestamp = last_timestamp;
        previous_address = last_address;

        this_cell_has_explicit_read_and_rollback_depth_zero =
            new_this_cell_has_explicit_read_and_rollback_depth_zero;
        this_cell_base_value = new_this_cell_base_value;
        this_cell_current_value = new_this_cell_current_value;
        this_cell_current_depth = new_this_cell_current_depth;

        current_final_sorted_queue_state = last_final_sorted_queue_state;

        cycle_idx = final_cycle_idx;

        results.push(instance_witness);
    }

    assert!(deduplicated_queries_it.next().is_none());

    let final_sorted_queue_state = take_queue_state_from_simulator(&result_queue_simulator);

    results
        .last_mut()
        .unwrap()
        .closed_form_input
        .observable_output
        .final_sorted_queue_state = final_sorted_queue_state.clone();

    artifacts.deduplicated_rollup_storage_queue_simulator = result_queue_simulator;

    results
}
