use std::sync::Arc;

use crate::witness::artifacts::{DecommitmentArtifactsForMainVM, MemoryArtifacts};
use crate::witness::aux_data_structs::one_per_circuit_accumulator::CircuitsEntryAccumulatorSparse;
use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulatorSparse;
use crate::witness::individual_circuits::SmallField;
use crate::witness::oracle::FrameLogQueueDetailedState;
use crate::witness::postprocessing::{ClosedFormInputField, FirstAndLastCircuitWitness};
use crate::witness::tracer::vm_snapshot::VmSnapshot;
use crate::witness::utils::simulate_public_input_value_from_encodable_witness;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::vm_state::VmLocalState;
use crate::zkevm_circuits::base_structures::vm_state::{
    GlobalContextWitness, FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH,
};
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::Field;
use circuit_definitions::boojum::field::U64Representable;
use circuit_definitions::boojum::gadgets::queue::{
    QueueState, QueueStateWitness, QueueTailStateWitness,
};
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::boojum::implementations::poseidon2::Poseidon2Goldilocks;
use circuit_definitions::circuit_definitions::base_layer::{VMMainCircuit, ZkSyncBaseLayerCircuit};
use circuit_definitions::encodings::callstack_entry::{
    CallstackSimulatorState, ExtendedCallstackEntry,
};
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::memory_query::MemoryQueueState;
use circuit_definitions::encodings::recursion_request::{
    RecursionQueueSimulator, RecursionRequest,
};
use circuit_definitions::zk_evm::aux_structures::{DecommittmentQuery, LogQuery, PubdataCost};
use circuit_definitions::zk_evm::vm_state::CallStackEntry;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_sequencer_api::toolset::GeometryConfig;
use crossbeam::atomic::AtomicCell;
use derivative::Derivative;

type Cycle = u32;

pub(crate) struct CallstackSimulationResult<F: SmallField> {
    pub entry_callstack_states_accumulator:
        CircuitsEntryAccumulatorSparse<(Cycle, [F; FULL_SPONGE_QUEUE_STATE_WIDTH])>,
    pub callstack_witnesses: PerCircuitAccumulatorSparse<(
        Cycle,
        (ExtendedCallstackEntry<F>, CallstackSimulatorState<F>),
    )>,
    pub entry_frames_storage_log_detailed_states:
        CircuitsEntryAccumulatorSparse<(Cycle, FrameLogQueueDetailedState<F>)>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug)]
pub struct VmInCircuitAuxilaryParameters<F: SmallField> {
    pub callstack_state: ([F; FULL_SPONGE_QUEUE_STATE_WIDTH], CallStackEntry),
    pub decommittment_queue_state: QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    pub storage_log_queue_state: QueueStateWitness<F, QUEUE_STATE_WIDTH>,
    pub current_frame_rollback_queue_tail: [F; QUEUE_STATE_WIDTH],
    pub current_frame_rollback_queue_head: [F; QUEUE_STATE_WIDTH],
    pub current_frame_rollback_queue_segment_length: u32,
}

impl<F: SmallField> std::default::Default for VmInCircuitAuxilaryParameters<F> {
    fn default() -> Self {
        Self {
            callstack_state: (
                [F::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH],
                CallStackEntry::empty_context(),
            ),
            decommittment_queue_state: QueueState::placeholder_witness(),
            memory_queue_state: QueueState::placeholder_witness(),
            storage_log_queue_state: QueueState::placeholder_witness(),
            current_frame_rollback_queue_tail: [F::ZERO; QUEUE_STATE_WIDTH],
            current_frame_rollback_queue_head: [F::ZERO; QUEUE_STATE_WIDTH],
            current_frame_rollback_queue_segment_length: 0,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone)]
pub struct VmInstanceWitness<F: SmallField, O: WitnessOracle<F>> {
    // we need everything to start a circuit from this point of time

    // initial state - just copy the local state in full
    pub initial_state: VmLocalState,
    pub witness_oracle: O,
    pub auxilary_initial_parameters: VmInCircuitAuxilaryParameters<F>,
    pub cycles_range: std::ops::Range<u32>,

    // final state for test purposes
    pub final_state: VmLocalState,
    pub auxilary_final_parameters: VmInCircuitAuxilaryParameters<F>,
}

struct MainVmSimulationInput {
    memory_queue_states_for_entry:
        QueueStateWitness<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    decommittment_queue_states_for_entry:
        QueueStateWitness<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    callstack_state_for_entry: [GoldilocksField; FULL_SPONGE_QUEUE_STATE_WIDTH],
    frame_log_queue_detailed_state_for_entry: FrameLogQueueDetailedState<GoldilocksField>,
    storage_queries_witnesses: Vec<(Cycle, LogQuery)>,
    cold_warm_refund_logs: Vec<(Cycle, LogQuery, u32)>,
    pubdata_cost_logs: Vec<(Cycle, LogQuery, PubdataCost)>,
    decommittment_requests_witness: Vec<(Cycle, DecommittmentQuery)>,
    rollback_queue_initial_tails_for_new_frames: Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    callstack_values_witnesses: Vec<(
        Cycle,
        (
            ExtendedCallstackEntry<GoldilocksField>,
            CallstackSimulatorState<GoldilocksField>,
        ),
    )>,
    rollback_queue_head_segments: Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    callstack_new_frames_witnesses: Vec<(Cycle, CallStackEntry)>,
    memory_read_witnesses: Vec<(Cycle, MemoryQuery)>,
    memory_write_witnesses: Vec<(Cycle, MemoryQuery)>,
}

/// Repack the input data into one structure for each of the MainVM circuits
fn repack_input_for_main_vm(
    geometry: &GeometryConfig,
    vm_snapshots: &Vec<VmSnapshot>,
    memory_artifacts_for_main_vm: MemoryArtifacts<GoldilocksField>,
    decommitment_artifacts_for_main_vm: DecommitmentArtifactsForMainVM<GoldilocksField>,
    callstack_simulation_result: CallstackSimulationResult<GoldilocksField>,
    storage_queries: PerCircuitAccumulatorSparse<(Cycle, LogQuery)>,
    cold_warm_refunds_logs: PerCircuitAccumulatorSparse<(Cycle, LogQuery, u32)>,
    pubdata_cost_logs: PerCircuitAccumulatorSparse<(Cycle, LogQuery, PubdataCost)>,
    log_rollback_tails_for_frames: Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    log_rollback_queue_heads: PerCircuitAccumulatorSparse<(
        Cycle,
        [GoldilocksField; QUEUE_STATE_WIDTH],
    )>,
    flat_new_frames_history: Vec<(Cycle, CallStackEntry)>,
) -> Vec<MainVmSimulationInput> {
    tracing::debug!("Repacking data for MainVM");

    let MemoryArtifacts {
        memory_queue_entry_states,
        memory_queries,
    } = memory_artifacts_for_main_vm;

    let DecommitmentArtifactsForMainVM {
        decommittment_queue_entry_states,
        prepared_decommittment_queries,
    } = decommitment_artifacts_for_main_vm;

    let CallstackSimulationResult {
        entry_callstack_states_accumulator,
        callstack_witnesses,
        entry_frames_storage_log_detailed_states,
    } = callstack_simulation_result;

    let amount_of_circuits = vm_snapshots.windows(2).enumerate().len();
    let mut main_vm_inputs = Vec::with_capacity(amount_of_circuits);

    // split the oracle witness
    let memory_write_witnesses = PerCircuitAccumulatorSparse::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        memory_queries
            .iter()
            .filter(|(_, query)| query.rw_flag)
            .copied(),
    );

    let memory_read_witnesses = PerCircuitAccumulatorSparse::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        memory_queries
            .iter()
            .filter(|(_, query)| !query.rw_flag)
            .copied(),
    );
    drop(memory_queries);

    // prepare some inputs for MainVM circuits

    let last_memory_queue_state = memory_queue_entry_states.last().1.clone();
    let mut memory_queue_entry_states_it = memory_queue_entry_states
        .into_circuits(amount_of_circuits)
        .into_iter();

    let last_decommittment_queue_state = decommittment_queue_entry_states.last().1.clone();
    let mut decommittment_queue_entry_states = decommittment_queue_entry_states
        .into_circuits(amount_of_circuits)
        .into_iter();

    let last_storage_log_state = entry_frames_storage_log_detailed_states.last().1;
    let mut storage_log_states_for_entry_it = entry_frames_storage_log_detailed_states
        .into_circuits(amount_of_circuits)
        .into_iter();

    let last_callstack_state_for_entry = [GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]; // always an empty one
    let mut callstack_sponge_entry_states_it = entry_callstack_states_accumulator
        .into_circuits(amount_of_circuits)
        .into_iter();

    let mut memory_write_witnesses_it = memory_write_witnesses
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut memory_read_witnesses_it = memory_read_witnesses
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut storage_queries_it = storage_queries
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut cold_warm_refunds_logs_it = cold_warm_refunds_logs
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut pubdata_cost_logs_it = pubdata_cost_logs
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut flat_new_frames_history_it = PerCircuitAccumulatorSparse::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        flat_new_frames_history,
    )
    .into_circuits(amount_of_circuits)
    .into_iter();
    let mut rollback_queue_tails_for_frames_it = PerCircuitAccumulatorSparse::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        log_rollback_tails_for_frames,
    )
    .into_circuits(amount_of_circuits)
    .into_iter();
    let mut rollback_queue_head_segments_it = log_rollback_queue_heads
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut callstack_values_witnesses_it = callstack_witnesses
        .into_circuits(amount_of_circuits)
        .into_iter();
    let mut prepared_decommittment_queries_it = prepared_decommittment_queries
        .into_circuits(amount_of_circuits)
        .into_iter();

    for (circuit_idx, _pair) in vm_snapshots.windows(2).enumerate() {
        if amount_of_circuits / 100 != 0 && circuit_idx % (amount_of_circuits / 100) == 0 {
            tracing::debug!("{} / {}", circuit_idx, amount_of_circuits);
        }

        let memory_queue_states_for_entry = memory_queue_entry_states_it.next().unwrap().1;
        let decommittment_queue_states_for_entry =
            decommittment_queue_entry_states.next().unwrap().1;
        let frame_log_queue_detailed_state_for_entry =
            storage_log_states_for_entry_it.next().unwrap().1;
        let callstack_state_for_entry = callstack_sponge_entry_states_it.next().unwrap().1;

        let memory_write_witnesses = memory_write_witnesses_it.next().unwrap();
        let memory_read_witnesses = memory_read_witnesses_it.next().unwrap();
        let storage_queries_witnesses = storage_queries_it.next().unwrap();
        let cold_warm_refund_logs = cold_warm_refunds_logs_it.next().unwrap();
        let pubdata_cost_logs = pubdata_cost_logs_it.next().unwrap();
        let decommittment_requests_witness = prepared_decommittment_queries_it.next().unwrap();
        let rollback_queue_initial_tails_for_new_frames =
            rollback_queue_tails_for_frames_it.next().unwrap();
        let callstack_values_witnesses = callstack_values_witnesses_it.next().unwrap();
        let rollback_queue_head_segments = rollback_queue_head_segments_it.next().unwrap();
        let callstack_new_frames_witnesses = flat_new_frames_history_it.next().unwrap();

        let main_vm_input = MainVmSimulationInput {
            decommittment_queue_states_for_entry,
            memory_queue_states_for_entry,
            frame_log_queue_detailed_state_for_entry,
            callstack_state_for_entry,
            memory_write_witnesses,
            memory_read_witnesses,
            storage_queries_witnesses,
            cold_warm_refund_logs,
            pubdata_cost_logs,
            decommittment_requests_witness,
            rollback_queue_initial_tails_for_new_frames,
            callstack_values_witnesses,
            rollback_queue_head_segments,
            callstack_new_frames_witnesses,
        };

        main_vm_inputs.push(main_vm_input);
    }

    // special pass for last one
    {
        let decommittment_queue_states_for_entry = last_decommittment_queue_state;
        let memory_queue_states_for_entry = last_memory_queue_state;
        let frame_log_queue_detailed_state_for_entry = last_storage_log_state;
        let callstack_state_for_entry = last_callstack_state_for_entry;

        let main_vm_input = MainVmSimulationInput {
            decommittment_queue_states_for_entry,
            memory_queue_states_for_entry,
            frame_log_queue_detailed_state_for_entry,
            callstack_state_for_entry,
            memory_write_witnesses: vec![],
            memory_read_witnesses: vec![],
            storage_queries_witnesses: vec![],
            cold_warm_refund_logs: vec![],
            pubdata_cost_logs: vec![],
            decommittment_requests_witness: vec![],
            rollback_queue_initial_tails_for_new_frames: vec![],
            callstack_values_witnesses: vec![],
            rollback_queue_head_segments: vec![],
            callstack_new_frames_witnesses: vec![],
        };

        main_vm_inputs.push(main_vm_input);
    }

    main_vm_inputs
}

use crate::witness::postprocessing::observable_witness::VmObservableWitness;
use crate::zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmCircuitWitness;

use super::oracle::WitnessGenerationArtifact;
use super::vm_instance_witness_to_circuit_formal_input;

pub(crate) fn process_main_vm<CB: FnMut(WitnessGenerationArtifact)>(
    geometry: &GeometryConfig,
    in_circuit_global_context: GlobalContextWitness<GoldilocksField>,
    memory_artifacts_for_main_vm: MemoryArtifacts<GoldilocksField>,
    decommitment_artifacts_for_main_vm: DecommitmentArtifactsForMainVM<GoldilocksField>,
    storage_queries: PerCircuitAccumulatorSparse<(Cycle, LogQuery)>,
    cold_warm_refunds_logs: PerCircuitAccumulatorSparse<(Cycle, LogQuery, u32)>,
    pubdata_cost_logs: PerCircuitAccumulatorSparse<(Cycle, LogQuery, PubdataCost)>,
    log_rollback_tails_for_frames: Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    log_rollback_queue_heads: PerCircuitAccumulatorSparse<(
        Cycle,
        [GoldilocksField; QUEUE_STATE_WIDTH],
    )>,
    callstack_simulation_result: CallstackSimulationResult<GoldilocksField>,
    flat_new_frames_history: Vec<(Cycle, CallStackEntry)>,
    mut vm_snapshots: Vec<VmSnapshot>,
    round_function: Poseidon2Goldilocks,
    artifacts_callback: &mut CB,
) -> (
    FirstAndLastCircuitWitness<VmObservableWitness<GoldilocksField>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
) {
    let mut main_vm_circuits = FirstAndLastCircuitWitness::default();
    let mut main_vm_circuits_compact_forms_witnesses = vec![];
    let mut queue_simulator = RecursionQueueSimulator::empty();
    let mut observable_input = None;
    let mut process_vm_witness = |vm_instance, is_last| {
        let is_first = observable_input.is_none();
        let mut circuit_input = vm_instance_witness_to_circuit_formal_input(
            vm_instance,
            is_first,
            is_last,
            in_circuit_global_context.clone(),
        );

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_encodable_witness(
                circuit_input.closed_form_input.clone(),
                &round_function,
            );

        let instance = VMMainCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: Arc::new(round_function),
            expected_public_input: Some(proof_system_input),
        };

        if is_first {
            let mut wit = instance.clone_witness().unwrap();
            let wit = wit.closed_form_input();
            main_vm_circuits.first = Some(VmObservableWitness {
                observable_input: wit.observable_input.clone(),
                observable_output: wit.observable_output.clone(),
            });
        }
        if is_last {
            let mut wit = instance.clone_witness().unwrap();
            let wit = wit.closed_form_input();
            main_vm_circuits.last = Some(VmObservableWitness {
                observable_input: wit.observable_input.clone(),
                observable_output: wit.observable_output.clone(),
            });
        }

        let instance = ZkSyncBaseLayerCircuit::MainVM(instance);

        let recursive_request = RecursionRequest {
            circuit_type: GoldilocksField::from_u64_unchecked(
                instance.numeric_circuit_type() as u64
            ),
            public_input: proof_system_input,
        };
        queue_simulator.push(recursive_request, &round_function);

        artifacts_callback(WitnessGenerationArtifact::BaseLayerCircuit(instance));
        main_vm_circuits_compact_forms_witnesses.push(compact_form_witness);
    };

    let mut previous_instance_witness: Option<
        VmInstanceWitness<GoldilocksField, VmWitnessOracle<GoldilocksField>>,
    > = None;

    let main_vm_inputs = repack_input_for_main_vm(
        geometry,
        &vm_snapshots,
        memory_artifacts_for_main_vm,
        decommitment_artifacts_for_main_vm,
        callstack_simulation_result,
        storage_queries,
        cold_warm_refunds_logs,
        pubdata_cost_logs,
        log_rollback_tails_for_frames,
        log_rollback_queue_heads,
        flat_new_frames_history,
    );

    // duplicate last snapshot to process last circuit
    vm_snapshots.push(vm_snapshots.last().unwrap().clone());
    let circuits_len = vm_snapshots.windows(2).len();

    let amount_of_circuits = vm_snapshots.windows(2).enumerate().len();

    tracing::debug!("Processing MainVM circuits");

    // parallelizable
    for ((circuit_idx, pair), main_vm_input) in
        vm_snapshots.windows(2).enumerate().zip(main_vm_inputs)
    {
        if amount_of_circuits / 100 != 0 && circuit_idx % (amount_of_circuits / 100) == 0 {
            tracing::debug!("{} / {}", circuit_idx, amount_of_circuits);
        }

        let is_last = circuit_idx == circuits_len - 1;

        let initial_state = &pair[0];
        let final_state = &pair[1];

        let MainVmSimulationInput {
            memory_queue_states_for_entry: memory_queue_state,
            decommittment_queue_states_for_entry: decommittment_queue_state,
            callstack_state_for_entry,
            frame_log_queue_detailed_state_for_entry: frame_log_queue_detailed_state,
            ..
        } = main_vm_input;

        let storage_log_queue_state = QueueStateWitness {
            head: [GoldilocksField::ZERO; QUEUE_STATE_WIDTH],
            tail: QueueTailStateWitness {
                tail: frame_log_queue_detailed_state.forward_tail,
                length: frame_log_queue_detailed_state.forward_length,
            },
        };

        let auxilary_initial_parameters = VmInCircuitAuxilaryParameters {
            callstack_state: (
                callstack_state_for_entry,
                *initial_state.local_state.callstack.get_current_stack(),
            ),
            decommittment_queue_state,
            memory_queue_state,
            storage_log_queue_state,
            current_frame_rollback_queue_tail: frame_log_queue_detailed_state.rollback_tail,
            current_frame_rollback_queue_head: frame_log_queue_detailed_state.rollback_head,
            current_frame_rollback_queue_segment_length: frame_log_queue_detailed_state
                .rollback_length,
        };

        if let Some(mut prev) = previous_instance_witness {
            prev.auxilary_final_parameters = auxilary_initial_parameters.clone();
            process_vm_witness(prev, is_last);
        }

        if !is_last {
            // we need to get chunks of
            // - memory read witnesses
            // - storage read witnesses
            // - decommittment witnesses
            // - callstack witnesses
            // - rollback queue witnesses

            let MainVmSimulationInput {
                storage_queries_witnesses,
                cold_warm_refund_logs,
                pubdata_cost_logs,
                // here we need all answers from the oracle, not just ones that will be executed
                decommittment_requests_witness,
                rollback_queue_initial_tails_for_new_frames,
                callstack_values_witnesses,
                rollback_queue_head_segments,
                callstack_new_frames_witnesses,
                memory_read_witnesses,
                memory_write_witnesses,
                ..
            } = main_vm_input;

            // construct an oracle
            let witness_oracle = VmWitnessOracle {
                initial_cycle: initial_state.at_cycle,
                final_cycle_inclusive: final_state.at_cycle - 1,
                memory_read_witness: memory_read_witnesses.into(),
                memory_write_witness: Some(memory_write_witnesses.into()),
                rollback_queue_head_segments: rollback_queue_head_segments.into(),
                decommittment_requests_witness: decommittment_requests_witness.into(),
                rollback_queue_initial_tails_for_new_frames:
                    rollback_queue_initial_tails_for_new_frames.into(),
                storage_queries: storage_queries_witnesses.into(),
                storage_access_cold_warm_refunds: cold_warm_refund_logs.into(),
                storage_pubdata_queries: pubdata_cost_logs.into(),
                callstack_values_witnesses: callstack_values_witnesses.into(),
                callstack_new_frames_witnesses: callstack_new_frames_witnesses.into(),
            };

            let instance_witness = VmInstanceWitness {
                initial_state: initial_state.local_state.clone(),
                witness_oracle,
                auxilary_initial_parameters,
                cycles_range: initial_state.at_cycle..final_state.at_cycle,
                final_state: final_state.local_state.clone(),
                auxilary_final_parameters: VmInCircuitAuxilaryParameters::default(), // we will use next circuit's initial as final here!
            };
            previous_instance_witness = Some(instance_witness);
        } else {
            previous_instance_witness = None;
        }
    }

    artifacts_callback(WitnessGenerationArtifact::RecursionQueue((
        BaseLayerCircuitType::VM as u64,
        queue_simulator,
        main_vm_circuits_compact_forms_witnesses.clone(),
    )));

    (main_vm_circuits, main_vm_circuits_compact_forms_witnesses)
}
