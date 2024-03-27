use std::sync::Arc;

use self::toolset::GeometryConfig;
use self::witness::postprocessing::FirstAndLastCircuit;

use super::*;
use crate::witness::full_block_artifact::LogQueue;
use crate::witness::postprocessing::CircuitMaker;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::demux_log_queue::input::*;
use crate::zkevm_circuits::demux_log_queue::NUM_DEMUX_OUTPUTS;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::circuit_definitions::base_layer::{
    LogDemuxInstanceSynthesisFunction, ZkSyncBaseLayerCircuit,
};
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::zkevm_circuits::demux_log_queue::DemuxOutput;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::{encodings::*, Field, RoundFunction};

/// Take a storage log, output logs separately for events, l1 messages, storage, etc
pub fn compute_logs_demux<
    CB: FnMut(ZkSyncBaseLayerCircuit<Field, VmWitnessOracle<Field>, Poseidon2Goldilocks>),
    QSCB: FnMut(u64, RecursionQueueSimulator<Field>, Vec<ClosedFormInputCompactFormWitness<Field>>),
>(
    artifacts: &mut FullBlockArtifacts<Field>,
    per_circuit_capacity: usize,
    round_function: &RoundFunction,
    geometry: &GeometryConfig,
    cs_for_witness_generation: &mut ConstraintSystemImpl<Field, RoundFunction>,
    cycles_used: &mut usize,
    mut circuit_callback: CB,
    mut recursion_queue_callback: QSCB,
) -> (
    FirstAndLastCircuit<LogDemuxInstanceSynthesisFunction<GoldilocksField, Poseidon2Goldilocks>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    [LogQueue<Field>; NUM_DEMUX_OUTPUTS],
) {
    let _ = artifacts
        .original_log_queue_simulator
        .witness
        .make_contiguous();

    let circuit_type = BaseLayerCircuitType::LogDemultiplexer;

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_log_demuxer,
        Arc::new(round_function.clone()),
        cs_for_witness_generation,
        cycles_used,
    );

    // trivial empty case
    if artifacts
        .original_log_queue_simulator
        .witness
        .as_slices()
        .0
        .is_empty()
    {
        let (log_demux_circuits, queue_simulator, log_demux_circuits_compact_forms_witnesses) =
            maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            log_demux_circuits_compact_forms_witnesses.clone(),
        );

        let empty_subqueues = std::array::from_fn(|_| Default::default());
        return (
            log_demux_circuits,
            log_demux_circuits_compact_forms_witnesses,
            empty_subqueues,
        );
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

    let num_chunks = input_queue_witness.chunks(per_circuit_capacity).len();

    let mut state_idx = 0;

    let full_log_queue_state =
        take_queue_state_from_simulator(&artifacts.original_log_queue_simulator);

    use crate::zk_evm::zkevm_opcode_defs::system_params::{
        ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    };

    use crate::zk_evm::zkevm_opcode_defs::system_params::{
        EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE, TRANSIENT_STORAGE_AUX_BYTE,
    };

    let mut demuxed_rollup_storage_queries_it = artifacts.demuxed_rollup_storage_queries.iter();
    let mut demuxed_event_queries_it = artifacts.demuxed_event_queries.iter();
    let mut demuxed_to_l1_queries_it = artifacts.demuxed_to_l1_queries.iter();
    let mut demuxed_keccak_precompile_queries_it =
        artifacts.demuxed_keccak_precompile_queries.iter();
    let mut demuxed_sha256_precompile_queries_it =
        artifacts.demuxed_sha256_precompile_queries.iter();
    let mut demuxed_ecrecover_queries_it = artifacts.demuxed_ecrecover_queries.iter();
    let mut demuxed_secp256r1_verify_queries_it = artifacts.demuxed_secp256r1_verify_queries.iter();
    let mut demuxed_transient_storage_it = artifacts.demuxed_transient_storage_queries.iter();

    let mut input_passthrough_data = LogDemuxerInputData::placeholder_witness();
    // we only need the state of the original input
    input_passthrough_data.initial_log_queue_state =
        take_queue_state_from_simulator(&artifacts.original_log_queue_simulator);

    let output_passthrough_data = LogDemuxerOutputData::placeholder_witness();
    let mut output_queues = std::array::from_fn(|_| LogQueue::<Field>::default());
    let mut previous_hidden_fsm_output = None;

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
                            let (_old_tail, intermediate_info) = output_queues[DemuxOutput::RollupStorage as usize]
                                .simulator
                                .push_and_output_intermediate_data(item, round_function);

                                output_queues[DemuxOutput::RollupStorage as usize].states.push(intermediate_info);
                        }
                        _ => unreachable!(),
                    }
                }
                TRANSIENT_STORAGE_AUX_BYTE => {
                    // sort rollup and porter
                    match query.shard_id {
                        0 => {
                            let item = demuxed_transient_storage_it.next().copied().unwrap();
                            let (_old_tail, intermediate_info) = output_queues[DemuxOutput::TransientStorage as usize]
                                .simulator
                                .push_and_output_intermediate_data(item, round_function);

                                output_queues[DemuxOutput::TransientStorage as usize].states.push(intermediate_info);
                        }
                        _ => unreachable!(),
                    }
                }
                L1_MESSAGE_AUX_BYTE => {
                    let item = demuxed_to_l1_queries_it.next().copied().unwrap();
                    let (_old_tail, intermediate_info) = output_queues[DemuxOutput::L2ToL1Messages as usize]
                        .simulator
                        .push_and_output_intermediate_data(item, round_function);

                    output_queues[DemuxOutput::L2ToL1Messages as usize].states.push(intermediate_info);
                }
                EVENT_AUX_BYTE => {
                    let item = demuxed_event_queries_it.next().copied().unwrap();
                    let (_old_tail, intermediate_info) = output_queues[DemuxOutput::Events as usize]
                        .simulator
                        .push_and_output_intermediate_data(item, round_function);

                    output_queues[DemuxOutput::Events as usize].states.push(intermediate_info);
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
                            let (_old_tail, intermediate_info) = output_queues[DemuxOutput::Keccak as usize]
                                .simulator
                                .push_and_output_intermediate_data(item, round_function);

                            output_queues[DemuxOutput::Keccak as usize]
                                .states
                                .push(intermediate_info);
                        }
                        a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let item = demuxed_sha256_precompile_queries_it
                                .next()
                                .copied()
                                .unwrap();
                            let (_old_tail, intermediate_info) = output_queues[DemuxOutput::Sha256 as usize]
                                .simulator
                                .push_and_output_intermediate_data(item, round_function);

                            output_queues[DemuxOutput::Sha256 as usize]
                                .states
                                .push(intermediate_info);
                        }
                        a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let item = demuxed_ecrecover_queries_it.next().copied().unwrap();
                            let (_old_tail, intermediate_info) = output_queues[DemuxOutput::ECRecover as usize]
                                .simulator
                                .push_and_output_intermediate_data(item, round_function);

                            output_queues[DemuxOutput::ECRecover as usize].states.push(intermediate_info);
                        }
                        a if a == *SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let item = demuxed_secp256r1_verify_queries_it.next().copied().unwrap();
                            let (_old_tail, intermediate_info) = output_queues[DemuxOutput::Secp256r1Verify as usize]
                                .simulator
                                .push_and_output_intermediate_data(item, round_function);

                            output_queues[DemuxOutput::Secp256r1Verify as usize].states.push(intermediate_info);
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
        fsm_output.output_queue_states = std::array::from_fn(|i| {
            take_queue_state_from_simulator(&output_queues[i].simulator)
        });

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
                Field,
                LogQuery<Field>,
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
                .output_queue_states = std::array::from_fn(|i| {
                    take_queue_state_from_simulator(&output_queues[i].simulator)
                });
        }

        if let Some(output) = previous_hidden_fsm_output {
            witness.closed_form_input.hidden_fsm_input = output;
        }
        previous_hidden_fsm_output = Some(witness.closed_form_input.hidden_fsm_output.clone());

        circuit_callback(ZkSyncBaseLayerCircuit::LogDemuxer(
            maker.process(witness, circuit_type),
        ));
    }

    let (log_demux_circuits, queue_simulator, log_demux_circuits_compact_forms_witnesses) =
        maker.into_results();
    recursion_queue_callback(
        circuit_type as u64,
        queue_simulator,
        log_demux_circuits_compact_forms_witnesses.clone(),
    );

    assert!(demuxed_rollup_storage_queries_it.next().is_none());
    assert!(demuxed_event_queries_it.next().is_none());
    assert!(demuxed_to_l1_queries_it.next().is_none());
    assert!(demuxed_keccak_precompile_queries_it.next().is_none());
    assert!(demuxed_sha256_precompile_queries_it.next().is_none());
    assert!(demuxed_ecrecover_queries_it.next().is_none());
    assert!(demuxed_secp256r1_verify_queries_it.next().is_none());
    assert!(demuxed_transient_storage_it.next().is_none());

    (
        log_demux_circuits,
        log_demux_circuits_compact_forms_witnesses,
        output_queues,
    )
}
