use std::sync::Arc;

use self::toolset::GeometryConfig;
use self::witness::postprocessing::FirstAndLastCircuitWitness;
use crate::witness::postprocessing::observable_witness::LogDemuxerObservableWitness;

use super::*;
use crate::witness::artifacts::{DemuxedLogQueries, LogQueueStates};
use crate::witness::aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator;
use crate::witness::postprocessing::CircuitMaker;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::demux_log_queue::input::*;
use crate::zkevm_circuits::demux_log_queue::ALL_DEMUX_OUTPUTS;
use crate::zkevm_circuits::demux_log_queue::NUM_DEMUX_OUTPUTS;
use circuit_definitions::circuit_definitions::base_layer::{
    LogDemuxInstanceSynthesisFunction, ZkSyncBaseLayerCircuit,
};
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::zkevm_circuits::demux_log_queue::DemuxOutput;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::{encodings::*, Field, RoundFunction};
use oracle::WitnessGenerationArtifact;
use zk_evm::zkevm_opcode_defs::SECP256R1_VERIFY_PRECOMPILE_ADDRESS;

use crate::zk_evm::aux_structures::LogQuery as LogQuery_;
use std::collections::HashMap;

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

pub(crate) struct LogDemuxCircuitArtifacts<F: SmallField> {
    pub applied_log_queue_simulator: LogQueueSimulator<F>,
    pub applied_queue_states_accumulator: LastPerCircuitAccumulator<(u32, LogQueueState<F>)>,
}

pub(crate) struct PrecompilesQueuesStates {
    pub keccak: LogQueueStates<Field>,
    pub sha256: LogQueueStates<Field>,
    pub ecrecover: LogQueueStates<Field>,
    pub secp256r1_verify: LogQueueStates<Field>,
}

pub(crate) struct IOLogsQueuesStates {
    pub rollup_storage: LogQueueStates<Field>,
    pub transient_storage: LogQueueStates<Field>,
    pub events: LogQueueStates<Field>,
    pub l2_to_l1: LogQueueStates<Field>,
}

pub struct DemuxedQueuesStatesSimulator {
    pub sub_queues: HashMap<DemuxOutput, LogQueueStates<Field>>,
    round_function: RoundFunction,
}

impl DemuxedQueuesStatesSimulator {
    pub fn new(
        geometry: GeometryConfig,
        amounts_of_queries: [usize; NUM_DEMUX_OUTPUTS],
        round_function: RoundFunction,
    ) -> Self {
        use crate::zkevm_circuits::demux_log_queue::ALL_DEMUX_OUTPUTS;
        let mut sub_queues = HashMap::new();
        for output in ALL_DEMUX_OUTPUTS {
            let geometry_for_output = match output {
                DemuxOutput::RollupStorage => geometry.cycles_per_storage_sorter,
                DemuxOutput::TransientStorage => geometry.cycles_per_transient_storage_sorter,
                DemuxOutput::ECRecover => geometry.cycles_per_ecrecover_circuit,
                DemuxOutput::Secp256r1Verify => geometry.cycles_per_secp256r1_verify_circuit,
                DemuxOutput::Keccak => geometry.cycles_per_keccak256_circuit,
                DemuxOutput::Sha256 => geometry.cycles_per_sha256_circuit,
                DemuxOutput::Events => geometry.cycles_per_events_or_l1_messages_sorter,
                DemuxOutput::L2ToL1Messages => geometry.cycles_per_events_or_l1_messages_sorter,
                DemuxOutput::PorterStorage => 0, // NOT IMPLEMENTED
            };

            let state = if let DemuxOutput::PorterStorage = output {
                LogQueueStates::<Field>::default() // NOT IMPLEMENTED
            } else {
                LogQueueStates::<Field>::with_flat_capacity(
                    geometry_for_output as usize,
                    amounts_of_queries[output as usize],
                )
            };

            sub_queues.insert(output, state);
        }

        Self {
            sub_queues,
            round_function,
        }
    }

    pub fn build_empty(
        round_function: Poseidon2Goldilocks,
    ) -> (IOLogsQueuesStates, PrecompilesQueuesStates) {
        let mut sub_queues = HashMap::new();
        for output in ALL_DEMUX_OUTPUTS {
            sub_queues.insert(output, LogQueueStates::<Field>::default());
        }

        Self {
            sub_queues,
            round_function,
        }
        .into_results()
    }

    pub fn get_sub_queue_for_query(query: &LogQuery_) -> Option<DemuxOutput> {
        match query.aux_byte {
            STORAGE_AUX_BYTE => Some(DemuxOutput::RollupStorage),
            TRANSIENT_STORAGE_AUX_BYTE => Some(DemuxOutput::TransientStorage),
            L1_MESSAGE_AUX_BYTE => Some(DemuxOutput::L2ToL1Messages),
            EVENT_AUX_BYTE => Some(DemuxOutput::Events),
            PRECOMPILE_AUX_BYTE => {
                assert!(!query.rollback);
                match query.address {
                    a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        Some(DemuxOutput::Keccak)
                    }
                    a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        Some(DemuxOutput::Sha256)
                    }
                    a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        Some(DemuxOutput::ECRecover)
                    }
                    a if a == *SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        Some(DemuxOutput::Secp256r1Verify)
                    }
                    _ => None,
                }
            }
            _ => unreachable!("Invalid query aux byte"),
        }
    }

    pub fn simulate_and_push(&mut self, demux_output: DemuxOutput, item: LogQuery_) {
        let sub_queue = self.sub_queues.get_mut(&demux_output).unwrap();

        let (_old_tail, intermediate_info) = sub_queue
            .simulator
            .push_and_output_intermediate_data(item, &self.round_function);

        sub_queue.states_accumulator.push(intermediate_info);
    }

    pub fn into_results(self) -> (IOLogsQueuesStates, PrecompilesQueuesStates) {
        let mut queries = self.sub_queues;
        (
            IOLogsQueuesStates {
                rollup_storage: queries.remove(&DemuxOutput::RollupStorage).unwrap(),
                transient_storage: queries.remove(&DemuxOutput::TransientStorage).unwrap(),
                events: queries.remove(&DemuxOutput::Events).unwrap(),
                l2_to_l1: queries.remove(&DemuxOutput::L2ToL1Messages).unwrap(),
            },
            PrecompilesQueuesStates {
                keccak: queries.remove(&DemuxOutput::Keccak).unwrap(),
                sha256: queries.remove(&DemuxOutput::Sha256).unwrap(),
                ecrecover: queries.remove(&DemuxOutput::ECRecover).unwrap(),
                secp256r1_verify: queries.remove(&DemuxOutput::Secp256r1Verify).unwrap(),
            },
        )
    }
}

/// Take a storage log, output logs separately for events, l1 messages, storage, etc
pub(crate) fn process_logs_demux_and_make_circuits<CB: FnMut(WitnessGenerationArtifact)>(
    mut log_demux_artifacts: LogDemuxCircuitArtifacts<Field>,
    demuxed_queues: &DemuxedLogQueries,
    per_circuit_capacity: usize,
    round_function: &RoundFunction,
    geometry: &GeometryConfig,
    mut artifacts_callback: CB,
) -> (
    FirstAndLastCircuitWitness<LogDemuxerObservableWitness<Field>>,
    Vec<ClosedFormInputCompactFormWitness<Field>>,
    IOLogsQueuesStates,
    PrecompilesQueuesStates,
) {
    log_demux_artifacts
        .applied_log_queue_simulator
        .witness
        .make_contiguous();

    let circuit_type = BaseLayerCircuitType::LogDemultiplexer;

    let mut maker = CircuitMaker::new(geometry.cycles_per_log_demuxer, round_function.clone());

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
        artifacts_callback(WitnessGenerationArtifact::RecursionQueue((
            circuit_type as u64,
            queue_simulator,
            log_demux_circuits_compact_forms_witnesses.clone(),
        )));

        let (io_queues_states, precompiles_queues_states) =
            DemuxedQueuesStatesSimulator::build_empty(*round_function);

        return (
            log_demux_circuits,
            log_demux_circuits_compact_forms_witnesses,
            io_queues_states,
            precompiles_queues_states,
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

    assert!(
        input_queue_witness.len() == log_demux_artifacts.applied_queue_states_accumulator.len()
    );

    let last_applied_log_queue_states_for_chunks = log_demux_artifacts
        .applied_queue_states_accumulator
        .into_circuits();

    let num_chunks = input_queue_witness.chunks(per_circuit_capacity).len();

    let full_log_queue_state =
        take_queue_state_from_simulator(&log_demux_artifacts.applied_log_queue_simulator);

    let mut queries_iterators = HashMap::new();
    queries_iterators.insert(
        DemuxOutput::RollupStorage,
        demuxed_queues.io.rollup_storage.iter(),
    );
    queries_iterators.insert(DemuxOutput::Events, demuxed_queues.io.event.iter());
    queries_iterators.insert(DemuxOutput::L2ToL1Messages, demuxed_queues.io.to_l1.iter());
    queries_iterators.insert(
        DemuxOutput::TransientStorage,
        demuxed_queues.io.transient_storage.iter(),
    );

    queries_iterators.insert(
        DemuxOutput::Keccak,
        demuxed_queues.precompiles.keccak.iter(),
    );
    queries_iterators.insert(
        DemuxOutput::Sha256,
        demuxed_queues.precompiles.sha256.iter(),
    );
    queries_iterators.insert(
        DemuxOutput::ECRecover,
        demuxed_queues.precompiles.ecrecover.iter(),
    );
    queries_iterators.insert(
        DemuxOutput::Secp256r1Verify,
        demuxed_queues.precompiles.secp256r1_verify.iter(),
    );

    let mut input_passthrough_data = LogDemuxerInputData::placeholder_witness();
    // we only need the state of the original input
    input_passthrough_data.initial_log_queue_state =
        take_queue_state_from_simulator(&log_demux_artifacts.applied_log_queue_simulator);

    let output_passthrough_data = LogDemuxerOutputData::placeholder_witness();
    let mut previous_hidden_fsm_output = None;

    let mut amounts_of_queries: [usize; NUM_DEMUX_OUTPUTS] = std::array::from_fn(|_| 0);
    for (_, _, query) in input_queue_witness.iter() {
        let sub_queue = DemuxedQueuesStatesSimulator::get_sub_queue_for_query(query);
        if let Some(sub_queue) = sub_queue {
            amounts_of_queries[sub_queue as usize] += 1;
        }
    }

    let mut demuxed_simulator =
        DemuxedQueuesStatesSimulator::new(*geometry, amounts_of_queries, *round_function);

    let simulator_witness_it = log_demux_artifacts
        .applied_log_queue_simulator
        .witness
        .as_slices()
        .0
        .chunks(per_circuit_capacity);

    for (circuit_index, (input_chunk, simulator_witness_chunk)) in input_queue_witness
        .chunks(per_circuit_capacity)
        .zip(simulator_witness_it)
        .enumerate()
    {
        let is_first = circuit_index == 0;
        let is_last = circuit_index == num_chunks - 1;

        // simulate the circuit
        for (_, _, query) in input_chunk.iter() {
            let sub_queue = DemuxedQueuesStatesSimulator::get_sub_queue_for_query(query);
            if let Some(sub_queue) = sub_queue {
                let log_query = queries_iterators
                    .get_mut(&sub_queue)
                    .unwrap()
                    .next()
                    .copied()
                    .unwrap();
                demuxed_simulator.simulate_and_push(sub_queue, log_query);
            } else {
                // just burn ergs
            }
        }

        // make the output

        let input_witness: VecDeque<_> = simulator_witness_chunk
            .into_iter()
            .map(|(_encoding, old_tail, element)| {
                (log_query_into_circuit_log_query_witness(element), *old_tail)
            })
            .collect();

        let mut fsm_output = LogDemuxerFSMInputOutput::placeholder_witness();

        let mut initial_log_queue_state = full_log_queue_state.clone();
        let last_applied_log_queue_state =
            last_applied_log_queue_states_for_chunks[circuit_index].1;
        initial_log_queue_state.head = last_applied_log_queue_state.tail;
        initial_log_queue_state.tail.length -= last_applied_log_queue_state.num_items;

        fsm_output.initial_log_queue_state = initial_log_queue_state;
        fsm_output.output_queue_states = std::array::from_fn(|i| {
            let output = ALL_DEMUX_OUTPUTS[i];
            let sub_queue = demuxed_simulator.sub_queues.get(&output).unwrap();
            take_queue_state_from_simulator(&sub_queue.simulator)
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
                let output = ALL_DEMUX_OUTPUTS[i];
                let sub_queue = demuxed_simulator.sub_queues.get(&output).unwrap();
                take_queue_state_from_simulator(&sub_queue.simulator)
            });
        }

        if let Some(output) = previous_hidden_fsm_output {
            witness.closed_form_input.hidden_fsm_input = output;
        }
        previous_hidden_fsm_output = Some(witness.closed_form_input.hidden_fsm_output.clone());

        artifacts_callback(WitnessGenerationArtifact::BaseLayerCircuit(
            ZkSyncBaseLayerCircuit::LogDemuxer(maker.process(witness, circuit_type)),
        ));
    }

    let (log_demux_circuits, queue_simulator, log_demux_circuits_compact_forms_witnesses) =
        maker.into_results();
    artifacts_callback(WitnessGenerationArtifact::RecursionQueue((
        circuit_type as u64,
        queue_simulator,
        log_demux_circuits_compact_forms_witnesses.clone(),
    )));

    for (sub_queue, mut iter) in queries_iterators {
        assert!(
            iter.next().is_none(),
            "Some queries left not processed in {:?}",
            sub_queue
        );
    }

    let (io_queues_states, precompiles_queues_states) = demuxed_simulator.into_results();

    (
        log_demux_circuits,
        log_demux_circuits_compact_forms_witnesses,
        io_queues_states,
        precompiles_queues_states,
    )
}
