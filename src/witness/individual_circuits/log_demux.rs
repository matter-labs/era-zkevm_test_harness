use std::sync::Arc;

use self::toolset::GeometryConfig;
use self::witness::postprocessing::FirstAndLastCircuitWitness;
use crate::witness::postprocessing::observable_witness::LogDemuxerObservableWitness;

use super::*;
use crate::witness::artifacts::{DemuxedLogQueries, LogQueueStates};
use crate::witness::postprocessing::CircuitMaker;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::demux_log_queue::input::*;
use crate::zkevm_circuits::demux_log_queue::NUM_DEMUX_OUTPUTS;
use circuit_definitions::circuit_definitions::base_layer::{
    LogDemuxInstanceSynthesisFunction, ZkSyncBaseLayerCircuit,
};
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::zkevm_circuits::demux_log_queue::DemuxOutput;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::{encodings::*, Field, RoundFunction};
use postprocessing::CsForWitnessGeneration;
use zk_evm::zkevm_opcode_defs::SECP256R1_VERIFY_PRECOMPILE_ADDRESS;
use crate::witness::queue_for_main_vm::QueueLastStatesForCircuits;

use crate::zk_evm::aux_structures::LogQuery as LogQuery_;

pub(crate) struct LogDemuxCircuitArtifacts<F: SmallField> {
    pub applied_log_queue_simulator: LogQueueSimulator<F>,
    pub applied_queue_states_accumulator: QueueLastStatesForCircuits<(u32, LogQueueState<F>)>,
}

pub struct DemuxedQueuesStatesSimulator {
    pub subqueues: [LogQueueStates<Field>; NUM_DEMUX_OUTPUTS],
    round_function: RoundFunction
}

impl DemuxedQueuesStatesSimulator {
    pub fn new(geometry: GeometryConfig, amounts_of_queries: [usize; NUM_DEMUX_OUTPUTS], round_function: RoundFunction) -> Self {
        use crate::zkevm_circuits::demux_log_queue::ALL_DEMUX_OUTPUTS;
        let geometries: Vec<u32> = ALL_DEMUX_OUTPUTS.iter().map(|demux_output| {
            match demux_output {
                DemuxOutput::RollupStorage => geometry.cycles_per_storage_sorter,
                DemuxOutput::TransientStorage => geometry.cycles_per_transient_storage_sorter,
                DemuxOutput::ECRecover => geometry.cycles_per_ecrecover_circuit,
                DemuxOutput::Secp256r1Verify => geometry.cycles_per_secp256r1_verify_circuit,
                DemuxOutput::Keccak => geometry.cycles_per_keccak256_circuit,
                DemuxOutput::Sha256 => geometry.cycles_per_sha256_circuit,
                DemuxOutput::Events => geometry.cycles_per_events_or_l1_messages_sorter,
                DemuxOutput::L2ToL1Messages => geometry.cycles_per_events_or_l1_messages_sorter,
                DemuxOutput::PorterStorage => 0 // NOT IMPLEMENTED
            }
        }).collect();

        let subqueues = std::array::from_fn(|index| {
            if index == DemuxOutput::PorterStorage as usize {
                return LogQueueStates::<Field>::default(); // NOT IMPLEMENTED
            }
            LogQueueStates::<Field>::with_flat_capacity(*geometries.get(index).unwrap() as usize, amounts_of_queries[index])
        });

        Self {
            subqueues,
            round_function
        }
    }

    pub fn simulate_and_push(&mut self, sub_queue: DemuxOutput, item: LogQuery_) {
        let (_old_tail, intermediate_info) = self.subqueues
            [sub_queue as usize]
            .simulator
            .push_and_output_intermediate_data(item, &self.round_function);

            self.subqueues[sub_queue as usize]
            .states_accumulator
            .push(intermediate_info);        
    }
}

/// Take a storage log, output logs separately for events, l1 messages, storage, etc
pub(crate)  fn compute_logs_demux<
    CB: FnMut(ZkSyncBaseLayerCircuit),
    QSCB: FnMut(u64, RecursionQueueSimulator<Field>, Vec<ClosedFormInputCompactFormWitness<Field>>),
>(
    mut log_demux_artifacts: LogDemuxCircuitArtifacts<Field>,
    demuxed_queues: &DemuxedLogQueries,
    per_circuit_capacity: usize,
    round_function: &RoundFunction,
    geometry: &GeometryConfig,
    cs_for_witness_generation: &mut CsForWitnessGeneration,
    mut circuit_callback: CB,
    mut recursion_queue_callback: QSCB,
) -> (
    FirstAndLastCircuitWitness<LogDemuxerObservableWitness<Field>>,
    Vec<ClosedFormInputCompactFormWitness<Field>>,
    [LogQueueStates<Field>; NUM_DEMUX_OUTPUTS],
) {
    let _ = log_demux_artifacts
        .applied_log_queue_simulator
        .witness
        .make_contiguous();

    let circuit_type = BaseLayerCircuitType::LogDemultiplexer;

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_log_demuxer,
        round_function.clone(),
        cs_for_witness_generation,
    );

    // trivial empty case
    if log_demux_artifacts
        .applied_log_queue_simulator
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

    assert!(log_demux_artifacts
        .applied_log_queue_simulator
        .witness
        .as_slices()
        .1
        .is_empty());

    let input_queue_witness = &log_demux_artifacts
        .applied_log_queue_simulator
        .witness
        .as_slices()
        .0;


    assert!(input_queue_witness.len() == log_demux_artifacts.applied_queue_states_accumulator.len());

    let last_applied_log_queue_states_for_chunks = log_demux_artifacts.applied_queue_states_accumulator.into_circuits();

    let num_chunks = input_queue_witness.chunks(per_circuit_capacity).len();

    let mut state_idx = 0;

    let full_log_queue_state =
        take_queue_state_from_simulator(&log_demux_artifacts.applied_log_queue_simulator);

    use crate::zk_evm::zkevm_opcode_defs::system_params::{
        ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
        SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    };

    use crate::zk_evm::zkevm_opcode_defs::system_params::{
        EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
        TRANSIENT_STORAGE_AUX_BYTE,
    };

    let mut demuxed_rollup_storage_queries_it = demuxed_queues.rollup_storage_queries.iter();
    let mut demuxed_event_queries_it = demuxed_queues.event_queries.iter();
    let mut demuxed_to_l1_queries_it = demuxed_queues.to_l1_queries.iter();
    let mut demuxed_keccak_precompile_queries_it = demuxed_queues.keccak_precompile_queries.iter();
    let mut demuxed_sha256_precompile_queries_it = demuxed_queues.sha256_precompile_queries.iter();
    let mut demuxed_ecrecover_queries_it = demuxed_queues.ecrecover_queries.iter();
    let mut demuxed_secp256r1_verify_queries_it = demuxed_queues.secp256r1_verify_queries.iter();
    let mut demuxed_transient_storage_it = demuxed_queues.transient_storage_queries.iter();

    let mut input_passthrough_data = LogDemuxerInputData::placeholder_witness();
    // we only need the state of the original input
    input_passthrough_data.initial_log_queue_state =
        take_queue_state_from_simulator(&log_demux_artifacts.applied_log_queue_simulator);

    let output_passthrough_data = LogDemuxerOutputData::placeholder_witness();
    let mut previous_hidden_fsm_output = None;

    let mut amounts_of_queries: [usize; NUM_DEMUX_OUTPUTS] = std::array::from_fn(|_| 0);
    for (_, _, query) in input_queue_witness.iter() {
        match query.aux_byte {
            STORAGE_AUX_BYTE => amounts_of_queries[DemuxOutput::RollupStorage as usize] += 1,
            TRANSIENT_STORAGE_AUX_BYTE => amounts_of_queries[DemuxOutput::TransientStorage as usize] += 1,
            L1_MESSAGE_AUX_BYTE => amounts_of_queries[DemuxOutput::L2ToL1Messages as usize] += 1, 
            EVENT_AUX_BYTE => amounts_of_queries[DemuxOutput::Events as usize] += 1,
            PRECOMPILE_AUX_BYTE => {
                match query.address {
                    a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => amounts_of_queries[DemuxOutput::Keccak as usize] += 1,
                    a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => amounts_of_queries[DemuxOutput::Sha256 as usize] += 1,
                    a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => amounts_of_queries[DemuxOutput::ECRecover as usize] += 1,
                    a if a == *SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => amounts_of_queries[DemuxOutput::Secp256r1Verify as usize] += 1,
                    _ => {}
                }
            },
            _ => {}
        }
    }

    let mut demuxed_simulator = DemuxedQueuesStatesSimulator::new(
        *geometry,
        amounts_of_queries,
        *round_function
    );

    for (circuit_index, input_chunk) in input_queue_witness.chunks(per_circuit_capacity).enumerate() {
        let is_first = circuit_index == 0;
        let is_last = circuit_index == num_chunks - 1;

        // simulate the circuit
        for (_encoding, _previous_tail, query) in input_chunk.iter() {
            match query.aux_byte {
                STORAGE_AUX_BYTE => {
                    // sort rollup and porter
                    match query.shard_id {
                        0 => {
                            let log_query = demuxed_rollup_storage_queries_it.next().copied().unwrap();
                            demuxed_simulator.simulate_and_push(DemuxOutput::RollupStorage, log_query);
                        }
                        _ => unreachable!(),
                    }
                }
                TRANSIENT_STORAGE_AUX_BYTE => {
                    // sort rollup and porter
                    match query.shard_id {
                        0 => {
                            let log_query = demuxed_transient_storage_it.next().copied().unwrap();
                            demuxed_simulator.simulate_and_push(DemuxOutput::TransientStorage, log_query);
                        }
                        _ => unreachable!(),
                    }
                }
                L1_MESSAGE_AUX_BYTE => {
                    let log_query = demuxed_to_l1_queries_it.next().copied().unwrap();
                    demuxed_simulator.simulate_and_push(DemuxOutput::L2ToL1Messages, log_query);
                }
                EVENT_AUX_BYTE => {
                    let log_query = demuxed_event_queries_it.next().copied().unwrap();
                    demuxed_simulator.simulate_and_push(DemuxOutput::Events, log_query);
                }
                PRECOMPILE_AUX_BYTE => {
                    assert!(!query.rollback);
                    match query.address {
                        a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let log_query = demuxed_keccak_precompile_queries_it
                                .next()
                                .copied()
                                .unwrap();
                            demuxed_simulator.simulate_and_push(DemuxOutput::Keccak, log_query);
                        }
                        a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let log_query = demuxed_sha256_precompile_queries_it
                                .next()
                                .copied()
                                .unwrap();
                            demuxed_simulator.simulate_and_push(DemuxOutput::Sha256, log_query);
                        }
                        a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let log_query = demuxed_ecrecover_queries_it.next().copied().unwrap();
                            demuxed_simulator.simulate_and_push(DemuxOutput::ECRecover, log_query);
                        }
                        a if a == *SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            let log_query = demuxed_secp256r1_verify_queries_it.next().copied().unwrap();
                            demuxed_simulator.simulate_and_push(DemuxOutput::Secp256r1Verify, log_query);
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

        let input_witness: VecDeque<_> = log_demux_artifacts
            .applied_log_queue_simulator
            .witness
            .iter()
            .skip(state_idx)
            .take(input_chunk.len())
            .map(|(_encoding, old_tail, element)| {
                (log_query_into_circuit_log_query_witness(element), *old_tail)
            })
            .collect();

        state_idx += per_circuit_capacity;

        let mut fsm_output = LogDemuxerFSMInputOutput::placeholder_witness();
        let mut initial_log_queue_state = full_log_queue_state.clone();
        initial_log_queue_state.head = last_applied_log_queue_states_for_chunks[circuit_index].1.tail;
        initial_log_queue_state.tail.length -= last_applied_log_queue_states_for_chunks[circuit_index]
            .1
            .num_items;

        fsm_output.initial_log_queue_state = initial_log_queue_state;
        fsm_output.output_queue_states =
            std::array::from_fn(|i| take_queue_state_from_simulator(&demuxed_simulator.subqueues[i].simulator));

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
                take_queue_state_from_simulator(&demuxed_simulator.subqueues[i].simulator)
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
        demuxed_simulator.subqueues,
    )
}
