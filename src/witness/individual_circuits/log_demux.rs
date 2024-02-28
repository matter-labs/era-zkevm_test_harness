use super::*;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::demux_log_queue::input::*;
use circuit_definitions::encodings::*;

/// Take a storage log, output logs separately for events, l1 messages, storage, etc
pub fn compute_logs_demux<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    per_circuit_capacity: usize,
    round_function: &R,
) -> Vec<LogDemuxerCircuitInstanceWitness<F>> {
    // trivial empty case
    if artifacts
        .original_log_queue_simulator
        .witness
        .as_slices()
        .0
        .is_empty()
    {
        // return singe dummy witness
        use crate::boojum::gadgets::queue::QueueState;

        let initial_fsm_state = LogDemuxerFSMInputOutput::<F>::placeholder_witness();

        assert_eq!(
            take_queue_state_from_simulator(&artifacts.original_log_queue_simulator),
            QueueState::placeholder_witness()
        );

        let mut passthrough_input = LogDemuxerInputData::placeholder_witness();
        passthrough_input.initial_log_queue_state = QueueState::placeholder_witness();

        let final_fsm_state = LogDemuxerFSMInputOutput::<F>::placeholder_witness();

        let passthrough_output = LogDemuxerOutputData::placeholder_witness();

        let wit = LogDemuxerCircuitInstanceWitness {
            closed_form_input: LogDemuxerInputOutputWitness {
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
        };

        return vec![wit];
    }

    // parallelizable

    assert!(artifacts
        .original_log_queue_simulator
        .witness
        .as_slices()
        .1
        .is_empty());
    let input_queue_witness = &artifacts.original_log_queue_simulator.witness.as_slices().0;
    let mut states_iter = artifacts.original_log_queue_states.iter();

    let mut results: Vec<LogDemuxerCircuitInstanceWitness<F>> = vec![];

    let num_chunks = input_queue_witness.chunks(per_circuit_capacity).len();

    let mut state_idx = 0;

    let full_log_queue_state =
        take_queue_state_from_simulator(&artifacts.original_log_queue_simulator);

    use crate::zk_evm::zkevm_opcode_defs::system_params::{
        ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    };

    use crate::zk_evm::zkevm_opcode_defs::system_params::{
        EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
    };

    let mut demuxed_rollup_storage_queries_it = artifacts.demuxed_rollup_storage_queries.iter();
    let mut demuxed_event_queries_it = artifacts.demuxed_event_queries.iter();
    let mut demuxed_to_l1_queries_it = artifacts.demuxed_to_l1_queries.iter();
    let mut demuxed_keccak_precompile_queries_it =
        artifacts.demuxed_keccak_precompile_queries.iter();
    let mut demuxed_sha256_precompile_queries_it =
        artifacts.demuxed_sha256_precompile_queries.iter();
    let mut demuxed_ecrecover_queries_it = artifacts.demuxed_ecrecover_queries.iter();

    let mut input_passthrough_data = LogDemuxerInputData::placeholder_witness();
    // we only need the state of the original input
    input_passthrough_data.initial_log_queue_state =
        take_queue_state_from_simulator(&artifacts.original_log_queue_simulator);

    let output_passthrough_data = LogDemuxerOutputData::placeholder_witness();

    for (idx, input_chunk) in input_queue_witness.chunks(per_circuit_capacity).enumerate() {
        let is_first = idx == 0;
        let is_last = idx == num_chunks - 1;

        // simulate the circuit
        for (_encoding, _previous_tail, query) in input_chunk.iter() {
            let (_, _states) = states_iter.next().unwrap();
            match query.aux_byte {
                STORAGE_AUX_BYTE => {
                    // sort rollup and porter
                    match query.shard_id {
                        0 => {
                            let item = demuxed_rollup_storage_queries_it.next().copied().unwrap();
                            let (_old_tail, intermediate_info) = artifacts
                                .demuxed_rollup_storage_queue_simulator
                                .push_and_output_intermediate_data(item, round_function);

                            artifacts
                                .demuxed_rollup_storage_queue_states
                                .push(intermediate_info);
                        }
                        _ => unreachable!(),
                    }
                }
                L1_MESSAGE_AUX_BYTE => {
                    let item = demuxed_to_l1_queries_it.next().copied().unwrap();
                    let (_old_tail, intermediate_info) = artifacts
                        .demuxed_to_l1_queue_simulator
                        .push_and_output_intermediate_data(item, round_function);

                    artifacts.demuxed_to_l1_queue_states.push(intermediate_info);
                }
                EVENT_AUX_BYTE => {
                    let item = demuxed_event_queries_it.next().copied().unwrap();
                    let (_old_tail, intermediate_info) = artifacts
                        .demuxed_events_queue_simulator
                        .push_and_output_intermediate_data(item, round_function);

                    artifacts.demuxed_event_queue_states.push(intermediate_info);
                }
                PRECOMPILE_AUX_BYTE => {
                    assert!(!query.rollback);
                    use crate::zk_evm::zk_evm_abstractions::precompiles::*;
                    match query.address {
                        a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let item = demuxed_keccak_precompile_queries_it
                                .next()
                                .copied()
                                .unwrap();
                            let (_old_tail, intermediate_info) = artifacts
                                .demuxed_keccak_precompile_queue_simulator
                                .push_and_output_intermediate_data(item, round_function);

                            artifacts
                                .demuxed_keccak_precompile_queue_states
                                .push(intermediate_info);
                        }
                        a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let item = demuxed_sha256_precompile_queries_it
                                .next()
                                .copied()
                                .unwrap();
                            let (_old_tail, intermediate_info) = artifacts
                                .demuxed_sha256_precompile_queue_simulator
                                .push_and_output_intermediate_data(item, round_function);

                            artifacts
                                .demuxed_sha256_precompile_queue_states
                                .push(intermediate_info);
                        }
                        a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let item = demuxed_ecrecover_queries_it.next().copied().unwrap();
                            let (_old_tail, intermediate_info) = artifacts
                                .demuxed_ecrecover_queue_simulator
                                .push_and_output_intermediate_data(item, round_function);

                            artifacts
                                .demuxed_ecrecover_queue_states
                                .push(intermediate_info);
                        }
                        _ => {
                            // just burn ergs
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        // make the output

        let input_witness: VecDeque<_> = artifacts
            .original_log_queue_simulator
            .witness
            .iter()
            .skip(state_idx)
            .take(input_chunk.len())
            .map(|(_encoding, old_tail, element)| {
                (log_query_into_circuit_log_query_witness(element), *old_tail)
            })
            .collect();

        state_idx += per_circuit_capacity;

        let idx = std::cmp::min(artifacts.original_log_queue_states.len(), state_idx) - 1;

        let mut fsm_output = LogDemuxerFSMInputOutput::placeholder_witness();
        let mut initial_log_queue_state = full_log_queue_state.clone();
        initial_log_queue_state.head = artifacts.original_log_queue_states[idx].1.tail;
        initial_log_queue_state.tail.length -= artifacts.original_log_queue_states[idx].1.num_items;

        fsm_output.initial_log_queue_state = initial_log_queue_state;
        fsm_output.storage_access_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);
        fsm_output.events_access_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_events_queue_simulator);
        fsm_output.l1messages_access_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_to_l1_queue_simulator);
        fsm_output.keccak256_access_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_keccak_precompile_queue_simulator);
        fsm_output.sha256_access_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_sha256_precompile_queue_simulator);
        fsm_output.ecrecover_access_queue_state =
            take_queue_state_from_simulator(&artifacts.demuxed_ecrecover_queue_simulator);

        let mut witness = LogDemuxerCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: is_first,
                completion_flag: is_last,
                observable_input: input_passthrough_data.clone(),
                observable_output: output_passthrough_data.clone(),
                hidden_fsm_input: LogDemuxerFSMInputOutput::placeholder_witness(),
                hidden_fsm_output: fsm_output,
            },
            initial_queue_witness: CircuitQueueRawWitness::<
                F,
                LogQuery<F>,
                4,
                LOG_QUERY_PACKED_WIDTH,
            > {
                elements: input_witness,
            },
        };

        if is_last {
            witness
                .closed_form_input
                .observable_output
                .storage_access_queue_state =
                take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);
            witness
                .closed_form_input
                .observable_output
                .events_access_queue_state =
                take_queue_state_from_simulator(&artifacts.demuxed_events_queue_simulator);
            witness
                .closed_form_input
                .observable_output
                .l1messages_access_queue_state =
                take_queue_state_from_simulator(&artifacts.demuxed_to_l1_queue_simulator);
            witness
                .closed_form_input
                .observable_output
                .keccak256_access_queue_state = take_queue_state_from_simulator(
                &artifacts.demuxed_keccak_precompile_queue_simulator,
            );
            witness
                .closed_form_input
                .observable_output
                .sha256_access_queue_state = take_queue_state_from_simulator(
                &artifacts.demuxed_sha256_precompile_queue_simulator,
            );
            witness
                .closed_form_input
                .observable_output
                .ecrecover_access_queue_state =
                take_queue_state_from_simulator(&artifacts.demuxed_ecrecover_queue_simulator);
        }

        if is_last {
            assert_eq!(
                &witness
                    .closed_form_input
                    .observable_output
                    .storage_access_queue_state,
                &witness
                    .closed_form_input
                    .hidden_fsm_output
                    .storage_access_queue_state,
            );
        }

        if let Some(previous_witness) = results.last() {
            witness.closed_form_input.hidden_fsm_input =
                previous_witness.closed_form_input.hidden_fsm_output.clone();
        }

        results.push(witness);
    }

    assert!(demuxed_rollup_storage_queries_it.next().is_none());
    assert!(demuxed_event_queries_it.next().is_none());
    assert!(demuxed_to_l1_queries_it.next().is_none());
    assert!(demuxed_keccak_precompile_queries_it.next().is_none());
    assert!(demuxed_sha256_precompile_queries_it.next().is_none());
    assert!(demuxed_ecrecover_queries_it.next().is_none());

    results
}
