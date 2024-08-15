// implement witness oracle to actually compute
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use super::artifacts::LogCircuitsArtifacts;
use super::individual_circuits::main_vm::CallstackSimulationResult;
use super::individual_circuits::memory_related::{ImplicitMemoryQueries, ImplicitMemoryStates};
use super::postprocessing::{
    BlockFirstAndLastBasicCircuitsObservableWitnesses, FirstAndLastCircuitWitness,
};
use super::tracer::callstack_handler::*;
use super::utils::*;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::queue::QueueState;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::witness::artifacts::{DemuxedLogQueries, MemoryArtifacts, MemoryCircuitsArtifacts};
use crate::witness::aux_data_structs::one_per_circuit_accumulator::{
    CircuitsEntryAccumulatorSparse, LastPerCircuitAccumulator,
};
use crate::witness::aux_data_structs::per_circuit_accumulator::{
    PerCircuitAccumulator, PerCircuitAccumulatorSparse,
};
use crate::witness::aux_data_structs::MemoryQueuePerCircuitSimulator;
use crate::witness::individual_circuits::log_demux::LogDemuxCircuitArtifacts;
use crate::witness::postprocessing::make_circuits;
use crate::witness::tracer::tracer::{QueryMarker, WitnessTracer};
use crate::witness::tracer::vm_snapshot::VmSnapshot;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zkevm_circuits::base_structures::vm_state::{
    GlobalContextWitness, FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH,
};
use crate::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::{Field, U64Representable};
use circuit_definitions::boojum::gadgets::queue::QueueStateWitness;
use circuit_definitions::boojum::implementations::poseidon2::Poseidon2Goldilocks;
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::encodings::callstack_entry::ExtendedCallstackEntry;
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::encodings::{CircuitEquivalentReflection, LogQueueSimulator};
use circuit_definitions::zkevm_circuits::base_structures::memory_query::{
    MemoryQueryWitness, MEMORY_QUERY_PACKED_WIDTH,
};
use circuit_definitions::zkevm_circuits::eip_4844::input::EIP4844CircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use derivative::Derivative;
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use zkevm_assembly::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
struct CallframeLogState {
    forward_queue_tail_pointer: usize,
    forward_queue_length: u32,
    rollback_queue_head_pointer: usize,
    rollback_queue_tail_pointer: usize,
    rollback_queue_length: u32,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug)]
pub struct RollbackQueueStateWitness<F: SmallField> {
    pub head: [F; QUEUE_STATE_WIDTH],
    pub tail: [F; QUEUE_STATE_WIDTH],
    pub segment_length: u32,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug,
    PartialEq,
    Eq,
    Default(bound = "")
)]
pub struct FrameLogQueueDetailedState<F: SmallField> {
    pub frame_idx: usize,
    pub forward_tail: [F; QUEUE_STATE_WIDTH],
    pub forward_length: u32,
    pub rollback_head: [F; QUEUE_STATE_WIDTH],
    pub rollback_tail: [F; QUEUE_STATE_WIDTH],
    pub rollback_length: u32,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct CommonLogSponges<F: SmallField> {
    pub rf_0: ([F; 12], [F; 12]),
    pub rf_1: ([F; 12], [F; 12]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct ForwardLogSponge<F: SmallField> {
    pub old_tail: [F; QUEUE_STATE_WIDTH],
    pub new_tail: [F; QUEUE_STATE_WIDTH],
    pub exclusive_rf: ([F; 12], [F; 12]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct RollbackLogSponge<F: SmallField> {
    pub old_head: [F; QUEUE_STATE_WIDTH],
    pub new_head: [F; QUEUE_STATE_WIDTH],
    pub exclusive_rf: ([F; 12], [F; 12]),
}

type Cycle = u32;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct LogAccessSpongesInfo<F: SmallField> {
    pub cycle: Cycle,
    pub common_sponges: CommonLogSponges<F>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
struct FlattenedLogQueueIndexer<F: SmallField> {
    pub current_head: [F; QUEUE_STATE_WIDTH],
    pub current_tail: [F; QUEUE_STATE_WIDTH],
    pub head_offset: usize,
    pub tail_offset: usize,
}

struct LogMuxedStatesData<F: SmallField> {
    /// If any forward query occurs at a given cycle, this map contains indexes of entries in chain_of_states for the query and corresponding rollback.
    forward_and_rollback_pointers: BTreeMap<Cycle, (usize, Option<usize>)>,
    /// The chain of all multiplexed log queue simulator state changes, old_tail -> new_tail
    chain_of_states: Vec<([F; QUEUE_STATE_WIDTH], [F; QUEUE_STATE_WIDTH])>,
}

type LogRollbackTailsForFrames = Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>;

/// Simulates the global multiplexed log queue and produces inputs for log demux circuit processing.
/// Together with simulation, splits the multiplexed log queue into separate queues.
/// Also returns the initial tails of the multiplexed log rollback queue for each call frame
/// and rollback queue heads for cycles
fn process_multiplexed_log_queue(
    geometry: GeometryConfig,
    full_callstack_history: &Vec<CallstackActionHistoryEntry>,
    mut final_callstack_entry: CallstackEntryWithAuxData,
    round_function: Poseidon2Goldilocks,
) -> (
    LogMuxedStatesData<GoldilocksField>,
    LogDemuxCircuitArtifacts<GoldilocksField>,
    DemuxedLogQueries,
    LogRollbackTailsForFrames,
    PerCircuitAccumulatorSparse<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
) {
    // Every execution frame has forward and rollback log queues. Forward queue contains "executed" queries,
    // rollback queue - potential (not executed yet) rollbacks. When a frame ends, its queues are merged to the parent frame queues.
    // Since we finished the VM execution, final callstack entry (root, outermost frame) contains all logs.
    // These queues also contain some additional markers
    let applied_queries = std::mem::take(&mut final_callstack_entry.forward_queue);
    let not_applied_rollbacks = std::mem::take(&mut final_callstack_entry.rollback_queue);
    drop(final_callstack_entry);

    // OutOfScope(Fresh) - record about creating a new execution frame
    let total_amount_of_frames = full_callstack_history
        .iter()
        .filter(|x| x.action == CallstackAction::OutOfScope(OutOfScopeReason::Fresh))
        .count();
    let mut frames_beginnings_and_rollback_tails = Vec::with_capacity(total_amount_of_frames);

    for el in full_callstack_history.iter() {
        match el.action {
            CallstackAction::PushToStack => {}
            CallstackAction::PopFromStack { panic: _ } => {}
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // frame created at el.beginning_cycle, we will find log queue rollback tail later
                frames_beginnings_and_rollback_tails.push((el.beginning_cycle, None));
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: _ }) => {
                el.end_cycle.expect("frame must end"); // sanity check
            }
        }
    }

    // from cycle to first two sponges (common for forwards and rollbacks)
    let mut sponges_data: HashMap<u32, CommonLogSponges<GoldilocksField>> = HashMap::new();

    let mut log_queue_simulator =
        LogQueueSimulator::<GoldilocksField>::with_capacity(applied_queries.len());
    let mut applied_log_queue_simulator = None;

    // struct contains the chain of all multiplexed log queue simulator state changes, old_tail -> new_tail
    // and pointers to corresponding indexes in this chain for forward and rollback queries (if any) at cycle
    let mut states_data = LogMuxedStatesData {
        forward_and_rollback_pointers: BTreeMap::<Cycle, (usize, Option<usize>)>::new(),
        chain_of_states: Vec::with_capacity(applied_queries.len() + not_applied_rollbacks.len()),
    };

    let mut demuxed_queries = DemuxedLogQueries::default();

    // used to accumulate all applied muxed log queue state changes needed for log demux circuit simulation
    let mut applied_queue_states_accumulator = LastPerCircuitAccumulator::with_flat_capacity(
        geometry.cycles_per_log_demuxer as usize,
        applied_queries.len(),
    );

    // Now we will do following:
    // - simulate the states of multiplexed log queue as a sponge
    // - find initial multiplexed log queue rollback tails for every frame (including not applied rollbacks)
    // - demux applied part of the log queue and prepare inputs for log demux circuit processing

    // we use reversed iterator for not_applied_rollbacks here
    for (extended_query, was_applied) in applied_queries
        .into_iter()
        .zip(std::iter::repeat(true))
        .chain(
            not_applied_rollbacks
                .into_iter()
                .rev()
                .zip(std::iter::repeat(false)),
        )
    {
        // Later we will mainle need only the result of "applied" part simulation.
        // So we will save a copy of simulator the first time we encounter an unapplied query.
        if !was_applied {
            if applied_log_queue_simulator.is_none() {
                // save the applied queue simulator
                applied_log_queue_simulator = Some(log_queue_simulator.clone());
            }
        } else {
            // check for no gaps
            assert!(applied_log_queue_simulator.is_none());
        }

        let (query_marker, cycle, query) = match extended_query {
            ExtendedLogQuery::Query {
                marker,
                cycle,
                query,
            } => (marker, cycle, query),
            ExtendedLogQuery::FrameForwardHeadMarker(..) => {
                continue; // not used
            }
            ExtendedLogQuery::FrameForwardTailMarker(..) => {
                continue; // not used
            }
            ExtendedLogQuery::FrameRollbackHeadMarker(..) => {
                continue; // not used
            }
            ExtendedLogQuery::FrameRollbackTailMarker(frame_index) => {
                // special marker, use the last "new" queue simulator tail value from chain_of_states
                // as initial log rollback queue tail for frame

                assert!(frames_beginnings_and_rollback_tails[frame_index]
                    .1
                    .is_none());

                frames_beginnings_and_rollback_tails[frame_index].1 = Some(
                    states_data
                        .chain_of_states
                        .last()
                        .map(|el| el.1)
                        .unwrap_or([GoldilocksField::ZERO; QUEUE_STATE_WIDTH]),
                );

                continue; // we do not have any query to simulate
            }
        };

        // actually simulate new queue state
        let (_, simulator_state) =
            log_queue_simulator.push_and_output_intermediate_data(query, &round_function);

        let pointer_to_chain_of_states = states_data.chain_of_states.len();
        states_data
            .chain_of_states
            .push((simulator_state.previous_tail, simulator_state.tail));

        if was_applied {
            applied_queue_states_accumulator.push((cycle, simulator_state));
            demuxed_queries.sort_and_push(query);
        }

        let timestamp = query.timestamp.0; // special "timestamp-like" value
        if !query.rollback {
            let sponge_data = sponges_data.entry(timestamp).or_default();
            sponge_data.rf_0 = simulator_state.round_function_execution_pairs[0];
            sponge_data.rf_1 = simulator_state.round_function_execution_pairs[1];
            // forward case
            states_data
                .forward_and_rollback_pointers
                .entry(cycle)
                .or_default()
                .0 = pointer_to_chain_of_states;
        } else {
            let sponge_data = sponges_data
                .get_mut(&timestamp)
                .expect("rollbacks always happen after forward case");
            assert_eq!(
                &sponge_data.rf_0,
                &simulator_state.round_function_execution_pairs[0]
            );
            assert_eq!(
                &sponge_data.rf_1,
                &simulator_state.round_function_execution_pairs[1]
            );
            // rollback case
            states_data
                .forward_and_rollback_pointers
                .get_mut(&cycle)
                .expect("rollbacks always happen after forward case")
                .1 = Some(pointer_to_chain_of_states);
        }

        match query_marker {
            QueryMarker::Forward { cycle: c, .. } => {
                assert_eq!(cycle, c);
                assert!(!query.rollback);
            }
            QueryMarker::ForwardNoRollback { cycle: c, .. } => {
                assert_eq!(cycle, c);
                assert!(!query.rollback);
            }
            QueryMarker::Rollback {
                cycle_of_declaration: c,
                ..
            } => {
                assert_eq!(cycle, c);
                assert!(query.rollback);
            }
        }
    }

    let mut log_rollback_tails_for_frames =
        Vec::with_capacity(frames_beginnings_and_rollback_tails.len());
    log_rollback_tails_for_frames.extend(
        frames_beginnings_and_rollback_tails
            .into_iter()
            .enumerate()
            .map(|(frame_index, (beginning_cycle, tail))| {
                (
                    beginning_cycle,
                    tail.unwrap_or_else(|| panic!("No rollback tail for frame {frame_index}")),
                )
            }),
    );

    // we know for every cycle a pointer to the positions of item's forward and rollback action into
    // the flattened queue
    // we also know when each cycle begins/end
    // so we can quickly reconstruct every current state
    let mut log_rollback_queue_heads: PerCircuitAccumulatorSparse<(
        Cycle,
        [GoldilocksField; QUEUE_STATE_WIDTH],
    )> = PerCircuitAccumulatorSparse::new(geometry.cycles_per_vm_snapshot as usize);

    for (cycle, (_forward, rollback)) in states_data.forward_and_rollback_pointers.iter() {
        if let Some(pointer) = rollback {
            let state = &states_data.chain_of_states[*pointer];
            log_rollback_queue_heads.push((*cycle, state.0));
        }
    }

    (
        states_data,
        LogDemuxCircuitArtifacts {
            applied_log_queue_simulator: applied_log_queue_simulator
                .unwrap_or(LogQueueSimulator::<GoldilocksField>::empty()),
            applied_queue_states_accumulator,
        },
        demuxed_queries,
        log_rollback_tails_for_frames,
        log_rollback_queue_heads,
    )
}

use circuit_definitions::encodings::callstack_entry::{
    CallstackSimulator, CallstackSimulatorState,
};

/// Simulate callstack and prepare callstack-related inputs for MainVM circuits processing
fn callstack_simulation(
    geometry: &GeometryConfig,
    full_callstack_history: Vec<CallstackActionHistoryEntry>,
    log_states_data: LogMuxedStatesData<GoldilocksField>,
    log_rollback_tails_for_frames: &Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    round_function: &Poseidon2Goldilocks,
) -> CallstackSimulationResult<GoldilocksField> {
    // we need to simultaneously follow the logic of pushes/joins of the log queue,
    // and encoding of the current callstack state as the sponge state

    let mut callstack_argebraic_simulator = CallstackSimulator::empty();

    // These are "frozen" states that just lie in the callstack for now and can not be modified
    // so we never follow the "current", but add on push/pop
    let mut callstack_witnesses_for_main_vm =
        PerCircuitAccumulatorSparse::new(geometry.cycles_per_vm_snapshot as usize);
    let mut entry_callstack_states_accumulator_for_main_vm = CircuitsEntryAccumulatorSparse::new(
        geometry.cycles_per_vm_snapshot as usize,
        (0, [GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]),
    );

    let global_end_of_storage_log = log_states_data
        .chain_of_states
        .last()
        .map(|el| el.1)
        .unwrap_or([GoldilocksField::ZERO; QUEUE_STATE_WIDTH]);

    // we need some information that spans the whole number of cycles with "what is a frame counter at this time"
    // we have all the spans of when each frame is active, so we can simulate what is saved and when
    let mut log_queue_detailed_states = BTreeMap::new();

    // we start with no rollbacks, but non-trivial tail
    let initial_storage_state = FrameLogQueueDetailedState {
        rollback_tail: global_end_of_storage_log,
        rollback_head: global_end_of_storage_log,
        ..Default::default()
    };

    let mut current_storage_log_state = initial_storage_state;

    let mut storage_logs_states_stack = vec![];

    let mut exited_state_to_merge: Option<(bool, FrameLogQueueDetailedState<GoldilocksField>)> =
        None;

    let apply_frame_log_changes =
        |callstack_history_entry: &CallstackActionHistoryEntry,
         mut storage_log_state: FrameLogQueueDetailedState<GoldilocksField>,
         log_queue_detailed_states: &mut BTreeMap<
            u32,
            FrameLogQueueDetailedState<GoldilocksField>,
        >| {
            let begin_at_cycle = callstack_history_entry.beginning_cycle;
            let end_cycle = callstack_history_entry.end_cycle.expect("frame must end");

            let range_of_interest = (begin_at_cycle + 1)..=end_cycle; // begin_at_cycle is formally bound to the previous one
            let frame_action_span = log_states_data
                .forward_and_rollback_pointers
                .range(range_of_interest);
            for (cycle, (forward_pointer, rollback_pointer)) in frame_action_span {
                // always add to the forward
                let new_forward_tail = log_states_data.chain_of_states[*forward_pointer].1;
                if new_forward_tail != storage_log_state.forward_tail {
                    // edge case of double data on frame boudary, reword later
                    storage_log_state.forward_tail = new_forward_tail;
                    storage_log_state.forward_length += 1;
                }

                // if there is a rollback then let's process it too

                if let Some(rollback_pointer) = rollback_pointer {
                    let new_rollback_head = log_states_data.chain_of_states[*rollback_pointer].0;
                    storage_log_state.rollback_head = new_rollback_head;
                    storage_log_state.rollback_length += 1;
                }

                let previous = log_queue_detailed_states.insert(*cycle, storage_log_state);
                if previous.is_some() {
                    assert_eq!(
                        previous.unwrap(),
                        storage_log_state,
                        "duplicate divergence for cycle {}: previous is {:?}, new is {:?}",
                        cycle,
                        previous.unwrap(),
                        storage_log_state
                    )
                }
            }

            storage_log_state
        };

    let mut save_callstack_witness_for_main_vm =
        |cycle_to_use: u32,
         callstack_entry: ExtendedCallstackEntry<GoldilocksField>,
         callstack_simulator_state: CallstackSimulatorState<GoldilocksField>| {
            if let Some((prev_cycle, _)) = callstack_witnesses_for_main_vm.last() {
                assert!(
                    cycle_to_use != *prev_cycle,
                    "trying to add callstack witness for cycle {}, but previous one is on cycle {}",
                    cycle_to_use,
                    prev_cycle
                );
            }
            callstack_witnesses_for_main_vm
                .push((cycle_to_use, (callstack_entry, callstack_simulator_state)));

            // when we push a new one then we need to "finish" the previous range and start a new one
            entry_callstack_states_accumulator_for_main_vm
                .push((cycle_to_use, callstack_simulator_state.new_state));
        };

    // we simulate a series of actions on the stack starting from the outermost frame
    // each history record contains an information on what was the stack state between points
    // when it potentially came into and out of scope
    for callstack_history_entry in full_callstack_history.iter() {
        let frame_index = callstack_history_entry.frame_index;

        // flow for new frame (push current and create a new one): PushToStack -> OutOfScope(Fresh)
        // flow for frame ending (remove current and pop from stack): OutOfScope(Exited) -> PopFromStack

        match callstack_history_entry.action {
            CallstackAction::PushToStack => {
                // we did push some(!) context to the stack
                // it means that between beginning and end cycles
                // there could have beed some interactions with log

                // `current_storage_log_state` is what we should use for the "current" one,
                // and we can mutate it, bookkeep and then use in the simulator

                current_storage_log_state = apply_frame_log_changes(
                    callstack_history_entry,
                    current_storage_log_state,
                    &mut log_queue_detailed_states,
                );

                // push the item to the stack
                storage_logs_states_stack.push(current_storage_log_state);

                let end_cycle = callstack_history_entry.end_cycle.expect("frame must end");

                // dump it into the entry and dump entry into simulator
                let entry = ExtendedCallstackEntry {
                    callstack_entry: callstack_history_entry.affected_entry,
                    rollback_queue_head: current_storage_log_state.rollback_head,
                    rollback_queue_tail: current_storage_log_state.rollback_tail,
                    rollback_queue_segment_length: current_storage_log_state.rollback_length,
                };

                let intermediate_info = callstack_argebraic_simulator
                    .push_and_output_intermediate_data(entry, round_function);

                // we do push the witness at the cycle numbered at when the element was pushed
                assert!(intermediate_info.is_push);
                save_callstack_witness_for_main_vm(end_cycle, entry, intermediate_info);
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // new frame created

                // we already identified initial rollback tails for new frames
                let rollback_tail = log_rollback_tails_for_frames[frame_index].1;
                // do not reset forward length as it's easy to merge
                current_storage_log_state.frame_idx = frame_index;
                current_storage_log_state.rollback_length = 0;
                current_storage_log_state.rollback_head = rollback_tail;
                current_storage_log_state.rollback_tail = rollback_tail;

                let beginning_cycle = callstack_history_entry.beginning_cycle;

                let previous =
                    log_queue_detailed_states.insert(beginning_cycle, current_storage_log_state);

                if previous.is_some() {
                    // ensure that basic properties hold: we replace the current frame with a new one, so
                    // it should have larger frame_idx and the same forward tail and length
                    let previous = previous.unwrap();
                    assert!(
                        previous.frame_idx < current_storage_log_state.frame_idx,
                        "frame divergence for cycle {}: previous is {:?}, new is {:?}",
                        beginning_cycle,
                        previous,
                        current_storage_log_state
                    );
                    assert_eq!(
                        previous.forward_tail, current_storage_log_state.forward_tail,
                        "frame divergence for cycle {}: previous is {:?}, new is {:?}",
                        beginning_cycle, previous, current_storage_log_state
                    );
                    assert_eq!(
                        previous.forward_length, current_storage_log_state.forward_length,
                        "frame divergence for cycle {}: previous is {:?}, new is {:?}",
                        beginning_cycle, previous, current_storage_log_state
                    );
                }
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic }) => {
                // frame ended
                // we are not too interested, frame just ends, and all the storage log logic was resolved before it
                assert!(exited_state_to_merge.is_none());

                current_storage_log_state = apply_frame_log_changes(
                    callstack_history_entry,
                    current_storage_log_state,
                    &mut log_queue_detailed_states,
                );
                exited_state_to_merge = Some((panic, current_storage_log_state));
            }
            CallstackAction::PopFromStack { panic } => {
                // an item that was in the stack becomes current
                assert!(exited_state_to_merge.is_some());

                let (pending_panic, exited_state_to_merge) = exited_state_to_merge.take().unwrap();
                assert_eq!(panic, pending_panic);

                let popped_state = storage_logs_states_stack.pop().unwrap();

                // we can get a witness for a circuit
                let (entry, intermediate_info) =
                    callstack_argebraic_simulator.pop_and_output_intermediate_data(round_function);

                assert_eq!(
                    entry.rollback_queue_head, popped_state.rollback_head,
                    "divergence at frame {}",
                    frame_index
                );
                assert_eq!(
                    entry.rollback_queue_tail, popped_state.rollback_tail,
                    "divergence at frame {}",
                    frame_index
                );
                assert_eq!(
                    entry.rollback_queue_segment_length, popped_state.rollback_length,
                    "divergence at frame {}",
                    frame_index
                );

                // merge state from exited frame
                current_storage_log_state = popped_state;
                current_storage_log_state.frame_idx = frame_index;
                current_storage_log_state.forward_tail = exited_state_to_merge.forward_tail;
                assert!(
                    current_storage_log_state.forward_length
                        <= exited_state_to_merge.forward_length,
                    "divergence at frame {}",
                    frame_index
                );
                current_storage_log_state.forward_length = exited_state_to_merge.forward_length;

                if panic {
                    assert_eq!(
                        current_storage_log_state.forward_tail, exited_state_to_merge.rollback_head,
                        "divergence at frame {} with panic: {:?}",
                        frame_index, callstack_history_entry
                    );

                    current_storage_log_state.forward_tail = exited_state_to_merge.rollback_tail;
                    current_storage_log_state.forward_length +=
                        exited_state_to_merge.rollback_length;
                } else {
                    assert_eq!(
                        current_storage_log_state.rollback_head,
                        exited_state_to_merge.rollback_tail,
                        "divergence at frame {} without panic: {:?}",
                        frame_index,
                        callstack_history_entry
                    );
                    current_storage_log_state.rollback_head = exited_state_to_merge.rollback_head;
                    current_storage_log_state.rollback_length +=
                        exited_state_to_merge.rollback_length;
                }

                let beginning_cycle = callstack_history_entry.beginning_cycle;

                let previous =
                    log_queue_detailed_states.insert(beginning_cycle, current_storage_log_state);
                if previous.is_some() {
                    assert_eq!(
                        previous.unwrap(),
                        current_storage_log_state,
                        "duplicate divergence for cycle {}: previous is {:?}, new is {:?}",
                        beginning_cycle,
                        previous.unwrap(),
                        current_storage_log_state
                    )
                }

                assert!(!intermediate_info.is_push);

                // we place it at the cycle when it was actually popped, but not one when it became "active"
                save_callstack_witness_for_main_vm(beginning_cycle, entry, intermediate_info);
            }
        }
    }

    let entry_frames_storage_log_detailed_states = CircuitsEntryAccumulatorSparse::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        (0, initial_storage_state),
        log_queue_detailed_states,
    );

    CallstackSimulationResult {
        entry_callstack_states_accumulator: entry_callstack_states_accumulator_for_main_vm,
        callstack_witnesses: callstack_witnesses_for_main_vm,
        entry_frames_storage_log_detailed_states,
    }
}

use crate::witness::artifacts::DemuxedIOLogQueries;
use crate::witness::individual_circuits::log_demux::IOLogsQueuesStates;
use crate::zkevm_circuits::demux_log_queue::DemuxOutput;

/// Process log circuits that do not use memory.
/// Storage, transient storage, events, l2 to l1 queries
/// Precompiles use memory and are processed in 'process_memory_related_circuits'
fn process_io_log_circuits<CB: FnMut(WitnessGenerationArtifact)>(
    geometry: &GeometryConfig,
    tree: impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    demuxed_log_queues_states: IOLogsQueuesStates,
    demuxed_log_queries: DemuxedIOLogQueries,
    round_function: &Poseidon2Goldilocks,
    mut artifacts_callback: &mut CB,
) -> (
    LogCircuitsArtifacts<GoldilocksField>,
    FirstAndLastCircuitWitness<StorageApplicationObservableWitness<GoldilocksField>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
) {
    let mut log_circuits_data = LogCircuitsArtifacts::default();

    // now completely parallel process to reconstruct the states, with internally parallelism in each round function

    use crate::witness::individual_circuits::storage_sort_dedup::compute_storage_dedup_and_sort;

    tracing::debug!("Running storage deduplication simulation");

    let (
        deduplicated_rollup_storage_queue_simulator,
        deduplicated_rollup_storage_queries,
        storage_deduplicator_circuit_data,
    ) = compute_storage_dedup_and_sort(
        demuxed_log_queries.rollup_storage,
        demuxed_log_queues_states.rollup_storage,
        geometry.cycles_per_storage_sorter as usize,
        round_function,
    );
    log_circuits_data.storage_deduplicator_circuit_data = storage_deduplicator_circuit_data;

    use crate::witness::individual_circuits::events_sort_dedup::compute_events_dedup_and_sort;

    tracing::debug!("Running events deduplication simulation");

    let events_deduplicator_circuit_data = compute_events_dedup_and_sort(
        demuxed_log_queries.event,
        demuxed_log_queues_states.events,
        &mut Default::default(),
        geometry.cycles_per_events_or_l1_messages_sorter as usize,
        round_function,
    );

    log_circuits_data.events_deduplicator_circuit_data = events_deduplicator_circuit_data;

    tracing::debug!("Running L1 messages deduplication simulation");

    let mut deduplicated_to_l1_queue_simulator = Default::default();
    let l1_messages_deduplicator_circuit_data = compute_events_dedup_and_sort(
        demuxed_log_queries.to_l1,
        demuxed_log_queues_states.l2_to_l1,
        &mut deduplicated_to_l1_queue_simulator,
        geometry.cycles_per_events_or_l1_messages_sorter as usize,
        round_function,
    );
    log_circuits_data.l1_messages_deduplicator_circuit_data = l1_messages_deduplicator_circuit_data;

    use crate::witness::individual_circuits::transient_storage_sorter::compute_transient_storage_dedup_and_sort;

    tracing::debug!("Running transient storage sorting simulation");

    let transient_storage_sorter_circuit_data = compute_transient_storage_dedup_and_sort(
        demuxed_log_queries.transient_storage,
        demuxed_log_queues_states.transient_storage,
        geometry.cycles_per_transient_storage_sorter as usize,
        round_function,
    );
    log_circuits_data.transient_storage_sorter_circuit_data = transient_storage_sorter_circuit_data;

    // compute flattened hash of all messages

    tracing::debug!("Running L1 messages linear hash simulation");

    assert!(
        deduplicated_to_l1_queue_simulator.num_items
            <= geometry.limit_for_l1_messages_pudata_hasher,
        "too many L1 messages to linearly hash by single circuit"
    );

    use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_linear_keccak256;

    let l1_messages_pubdata_hasher_data = compute_linear_keccak256(
        deduplicated_to_l1_queue_simulator,
        geometry.limit_for_l1_messages_pudata_hasher as usize,
        round_function,
    );
    log_circuits_data.l1_messages_linear_hash_data = l1_messages_pubdata_hasher_data;

    // process the storage application

    // and do the actual storage application
    use crate::witness::individual_circuits::storage_application::decompose_into_storage_application_witnesses;

    let (storage_application_circuits, storage_application_compact_forms) =
        decompose_into_storage_application_witnesses(
            deduplicated_rollup_storage_queue_simulator,
            deduplicated_rollup_storage_queries,
            tree,
            round_function,
            geometry.cycles_per_storage_application as usize,
            geometry,
            &mut artifacts_callback,
        );

    (
        log_circuits_data,
        storage_application_circuits,
        storage_application_compact_forms,
    )
}

use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;

use crate::witness::postprocessing::observable_witness::RamPermutationObservableWitness;
use crate::witness::postprocessing::observable_witness::StorageApplicationObservableWitness;

use crate::blake2::Blake2s256;
use crate::witness::tree::*;

use crate::witness::artifacts::DecommitmentArtifactsForMainVM;
use crate::witness::artifacts::LogQueueStates;
use crate::zkevm_circuits::demux_log_queue::NUM_DEMUX_OUTPUTS;

use circuit_definitions::encodings::memory_query::{MemoryQueueState, MemoryQueueStateWitnesses};

fn simulate_memory_queue(
    geometry: GeometryConfig,
    memory_queries: Arc<Vec<(Cycle, MemoryQuery)>>,
    implicit_memory_queries: Arc<ImplicitMemoryQueries>,
    round_function: Poseidon2Goldilocks,
    channel_sender: Sender<WitnessGenerationArtifact>,
) -> (
    CircuitsEntryAccumulatorSparse<(
        u32,
        QueueStateWitness<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    )>,
    MemoryQueueState<GoldilocksField>,
    LastPerCircuitAccumulator<MemoryQueueState<GoldilocksField>>,
    MemoryQueuePerCircuitSimulator<GoldilocksField>,
    ImplicitMemoryStates<GoldilocksField>,
    Vec<[GoldilocksField; MEMORY_QUERY_PACKED_WIDTH]>,
) {
    // for MainVM circuits
    let mut memory_queue_entry_states = CircuitsEntryAccumulatorSparse::new(
        geometry.cycles_per_vm_snapshot as usize,
        (0, QueueState::placeholder_witness()),
    );

    // for RAM permutation circuits, only last per circuit
    let mut memory_queue_states_accumulator =
        LastPerCircuitAccumulator::<MemoryQueueState<GoldilocksField>>::with_flat_capacity(
            geometry.cycles_per_ram_permutation as usize,
            memory_queries.len(),
        );

    use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulator;
    // simulator states are very RAM-heavy
    let mut memory_queue_simulator =
        MemoryQueuePerCircuitSimulator::using_container(PerCircuitAccumulator::with_flat_capacity(
            geometry.cycles_per_ram_permutation as usize,
            geometry.cycles_per_ram_permutation as usize,
        ));

    // for fs challenges in RAM permutation circuits
    let mut encodings_witnesses_for_fs = vec![];

    // move accumulated full state witnesses from simulator, and process them
    let mut process_simulation_result =
        |mut memory_queue_simulator: MemoryQueuePerCircuitSimulator<GoldilocksField>| {
            let witnesses;
            (memory_queue_simulator, witnesses) = memory_queue_simulator.replace_container(
                PerCircuitAccumulator::with_flat_capacity(
                    geometry.cycles_per_ram_permutation as usize,
                    geometry.cycles_per_ram_permutation as usize,
                ),
            );
            let amount_of_circuits_accumulated = witnesses.amount_of_circuits_accumulated();
            for full_witnesses_for_circuit in
                witnesses.into_circuits(amount_of_circuits_accumulated)
            {
                let mut unsorted_witnesses_for_circuit =
                    Vec::with_capacity(full_witnesses_for_circuit.len());

                // split full witnesses
                for witness in full_witnesses_for_circuit.into_iter() {
                    encodings_witnesses_for_fs.push(witness.0);
                    unsorted_witnesses_for_circuit.push((witness.2.reflect(), witness.1));
                }

                // send to storage
                channel_sender
                    .send(WitnessGenerationArtifact::MemoryQueueWitness((
                        unsorted_witnesses_for_circuit,
                        false, // unsorted
                    )))
                    .unwrap();
            }

            memory_queue_simulator
        };

    // the simulation is mostly a sequential computation of hashes
    // for this reason it is one of the slowest parts
    // we are simulating explicit part of queue (direct memory queries)
    for (cycle, query) in memory_queries.iter() {
        let (_, intermediate_info) =
            memory_queue_simulator.push_and_output_intermediate_data(*query, &round_function);

        memory_queue_states_accumulator.push(intermediate_info);
        memory_queue_entry_states
            .push((*cycle, transform_sponge_like_queue_state(intermediate_info)));

        // if we have collected witnesses for the circuit, we process and send part of them to the storage to free up RAM
        if memory_queue_simulator.witness.len() == geometry.cycles_per_ram_permutation as usize {
            memory_queue_simulator = process_simulation_result(memory_queue_simulator);
        }
    }

    assert_eq!(memory_queries.len(), memory_queue_states_accumulator.len());
    assert_eq!(
        memory_queries.len(),
        memory_queue_simulator.num_items as usize
    );

    let final_explicit_memory_queue_state = memory_queue_states_accumulator.last().unwrap().clone();

    // now we need to handle implicit memory queries produced by decomitter, precompiles etc.

    use crate::witness::individual_circuits::memory_related::simulate_implicit_memory_queues;
    let implicit_memory_states = simulate_implicit_memory_queues(
        &mut memory_queue_simulator,
        &mut memory_queue_states_accumulator,
        &implicit_memory_queries,
        round_function,
    );

    memory_queue_simulator = process_simulation_result(memory_queue_simulator);

    assert_eq!(
        memory_queries.len() + implicit_memory_queries.amount_of_queries(),
        encodings_witnesses_for_fs.len()
    );

    (
        memory_queue_entry_states,
        final_explicit_memory_queue_state,
        memory_queue_states_accumulator,
        memory_queue_simulator,
        implicit_memory_states,
        encodings_witnesses_for_fs,
    )
}

fn simulate_sorted_memory_queue(
    geometry: GeometryConfig,
    memory_queries: Arc<Vec<(Cycle, MemoryQuery)>>,
    implicit_memory_queries: Arc<ImplicitMemoryQueries>,
    round_function: Poseidon2Goldilocks,
    channel_sender: Sender<WitnessGenerationArtifact>,
) -> (
    LastPerCircuitAccumulator<MemoryQueueState<GoldilocksField>>,
    MemoryQueuePerCircuitSimulator<GoldilocksField>,
    Vec<[GoldilocksField; MEMORY_QUERY_PACKED_WIDTH]>,
    Vec<(u32, MemoryQuery, usize)>,
) {
    let mut all_memory_queries_sorted: Vec<&MemoryQuery> = memory_queries
        .iter()
        .map(|(_, query)| query)
        .chain(implicit_memory_queries.iter())
        .collect();

    use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulator;
    use rayon::prelude::*;
    use std::cmp::Ordering;

    // sort by memory location, and then by timestamp
    all_memory_queries_sorted.par_sort_by(|a, b| match a.location.cmp(&b.location) {
        Ordering::Equal => a.timestamp.cmp(&b.timestamp),
        a @ _ => a,
    });

    let amount_of_queries = all_memory_queries_sorted.len();
    assert_eq!(
        memory_queries.len() + implicit_memory_queries.amount_of_queries(),
        amount_of_queries
    );

    // simulator states are very RAM-heavy
    let mut sorted_memory_queries_simulator =
        MemoryQueuePerCircuitSimulator::using_container(PerCircuitAccumulator::with_flat_capacity(
            geometry.cycles_per_ram_permutation as usize,
            amount_of_queries,
        ));

    // for RAM permutation circuits
    let mut sorted_memory_queue_states_accumulator =
        LastPerCircuitAccumulator::<MemoryQueueState<GoldilocksField>>::with_flat_capacity(
            geometry.cycles_per_ram_permutation as usize,
            amount_of_queries,
        );

    // for fs challenges in RAM permutation circuits
    let mut encodings_witnesses_for_fs = Vec::with_capacity(amount_of_queries);

    let amount_of_ram_circuits = (amount_of_queries as u32 + geometry.cycles_per_ram_permutation
        - 1)
        / geometry.cycles_per_ram_permutation;
    // for RAM permutation circuits
    let mut sorted_queries_aux_data_for_chunks =
        Vec::with_capacity(amount_of_ram_circuits as usize);

    // the simulation is mostly a sequential computation of hashes
    // for this reason it is one of the slowest parts
    for (idx, query) in all_memory_queries_sorted.into_iter().enumerate() {
        let (_, intermediate_info) = sorted_memory_queries_simulator
            .push_and_output_intermediate_data(*query, &round_function);
        sorted_memory_queue_states_accumulator.push(intermediate_info);

        // if we have collected witnesses for the circuit, we process and send part of them to the storage to free up RAM
        if sorted_memory_queries_simulator.witness.len()
            == geometry.cycles_per_ram_permutation as usize
            || idx == amount_of_queries - 1
        {
            let witnesses;
            (sorted_memory_queries_simulator, witnesses) = sorted_memory_queries_simulator
                .replace_container(PerCircuitAccumulator::with_flat_capacity(
                    geometry.cycles_per_ram_permutation as usize,
                    geometry.cycles_per_ram_permutation as usize,
                ));

            assert_eq!(witnesses.amount_of_circuits_accumulated(), 1);

            // should be only one iteration
            for full_witnesses_for_circuit in witnesses.into_circuits(1) {
                let sorted_states_len = full_witnesses_for_circuit.len();
                let num_nondet_writes_in_chunk = full_witnesses_for_circuit
                    .iter()
                    .filter(|el| {
                        let query = &el.2;
                        query.rw_flag == true
                            && query.timestamp.0 == 0
                            && query.location.page.0 == BOOTLOADER_HEAP_PAGE
                    })
                    .count();
                let last_sorted_query = full_witnesses_for_circuit.last().unwrap().2;

                sorted_queries_aux_data_for_chunks.push((
                    num_nondet_writes_in_chunk as u32,
                    last_sorted_query,
                    sorted_states_len,
                ));

                let mut sorted_witnesses_for_circuit =
                    Vec::with_capacity(full_witnesses_for_circuit.len());

                // split full witnesses
                for witness in full_witnesses_for_circuit.into_iter() {
                    encodings_witnesses_for_fs.push(witness.0);
                    sorted_witnesses_for_circuit.push((witness.2.reflect(), witness.1));
                }

                // send to storage
                channel_sender
                    .send(WitnessGenerationArtifact::MemoryQueueWitness((
                        sorted_witnesses_for_circuit,
                        true, // sorted
                    )))
                    .unwrap();
            }
        }
    }

    (
        sorted_memory_queue_states_accumulator,
        sorted_memory_queries_simulator,
        encodings_witnesses_for_fs,
        sorted_queries_aux_data_for_chunks,
    )
}

use crate::witness::artifacts::DemuxedPrecompilesLogQueries;
use crate::witness::individual_circuits::log_demux::PrecompilesQueuesStates;

pub(crate) struct PrecompilesInputData {
    pub keccak_round_function_witnesses: Vec<(Cycle, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(Cycle, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(Cycle, LogQuery, ECRecoverRoundWitness)>,
    pub secp256r1_verify_witnesses: Vec<(Cycle, LogQuery, Secp256r1VerifyRoundWitness)>,
    pub logs_queues_states: PrecompilesQueuesStates,
    pub logs_queries: DemuxedPrecompilesLogQueries,
}

fn process_memory_related_circuits<CB: FnMut(WitnessGenerationArtifact)>(
    geometry: &GeometryConfig,
    vm_snapshots: &Vec<VmSnapshot>,
    memory_queries: Vec<(Cycle, MemoryQuery)>,
    num_non_deterministic_heap_queries: usize,
    prepared_decommittment_queries: Vec<(Cycle, DecommittmentQuery)>,
    executed_decommittment_queries: Vec<(Cycle, DecommittmentQuery, Vec<U256>)>,
    precompiles_data: PrecompilesInputData,
    round_function: &Poseidon2Goldilocks,
    mut artifacts_callback: &mut CB,
) -> (
    MemoryCircuitsArtifacts<GoldilocksField>,
    MemoryArtifacts<GoldilocksField>,
    DecommitmentArtifactsForMainVM<GoldilocksField>,
    FirstAndLastCircuitWitness<RamPermutationObservableWitness<GoldilocksField>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
) {
    tracing::debug!("Processing memory related queues");

    let mut circuits_data = MemoryCircuitsArtifacts::default();

    use crate::witness::individual_circuits::memory_related::sort_decommit_requests::compute_decommitts_sorter_circuit_snapshots;

    tracing::debug!("Running code decommittments sorter simulation");

    let (
        decommittment_queue_states,
        decommittments_deduplicator_circuits_data,
        decommiter_circuit_inputs,
    ) = compute_decommitts_sorter_circuit_snapshots(
        executed_decommittment_queries,
        round_function,
        geometry.cycles_code_decommitter_sorter as usize,
    );

    // first decommittment query (for bootloader) must come before the beginning of time
    {
        let initial_cycle = vm_snapshots[0].at_cycle;
        let decommittment_queue_states_before_start_len = decommittment_queue_states
            .iter()
            .take_while(|el| el.0 < initial_cycle)
            .count();

        assert_eq!(decommittment_queue_states_before_start_len, 1);
    }

    let decommitment_artifacts_for_main_vm = DecommitmentArtifactsForMainVM {
        prepared_decommittment_queries: PerCircuitAccumulatorSparse::from_iter(
            geometry.cycles_per_vm_snapshot as usize,
            prepared_decommittment_queries,
        ),
        decommittment_queue_entry_states: CircuitsEntryAccumulatorSparse::from_iter(
            geometry.cycles_per_vm_snapshot as usize,
            (0, QueueState::placeholder_witness()),
            decommittment_queue_states
                .into_iter()
                .map(|el| (el.0, transform_sponge_like_queue_state(el.1))),
        ),
    };
    circuits_data.decommittments_deduplicator_circuits_data =
        decommittments_deduplicator_circuits_data;

    tracing::debug!("Running unsorted memory queue simulation");

    use crate::witness::individual_circuits::memory_related::get_implicit_memory_queries;

    // precompiles and decommiter will produce additional implicit memory queries
    let implicit_memory_queries = get_implicit_memory_queries(
        &decommiter_circuit_inputs.deduplicated_decommit_requests_with_data,
        &precompiles_data,
    );

    let amount_of_explicit_memory_queries = memory_queries.len();
    let amount_of_ram_circuits = ((amount_of_explicit_memory_queries
        + implicit_memory_queries.amount_of_queries()) as u32
        + geometry.cycles_per_ram_permutation
        - 1)
        / geometry.cycles_per_ram_permutation;

    // Memory queues simulation is a slowest part in basic witness generation.
    // Each queue simulation is sequential single-threaded computation of hashes.
    // We will simulate unsorted and sorted queues in separate threads.

    let (tx, rx): (
        Sender<WitnessGenerationArtifact>,
        Receiver<WitnessGenerationArtifact>,
    ) = mpsc::channel();

    let implicit_memory_queries_arc = Arc::new(implicit_memory_queries);
    let memory_queries_arc = Arc::new(memory_queries);

    use std::thread;
    let sorted_handle = {
        let memory_queries_arc = memory_queries_arc.clone();
        let implicit_memory_queries_arc = implicit_memory_queries_arc.clone();
        let geometry = *geometry;
        let round_function = *round_function;
        let tx_thread = tx.clone();
        thread::spawn(move || {
            simulate_sorted_memory_queue(
                geometry,
                memory_queries_arc,
                implicit_memory_queries_arc,
                round_function,
                tx_thread,
            )
        })
    };

    let unsorted_handle = {
        let memory_queries_arc = memory_queries_arc.clone();
        let implicit_memory_queries_arc = implicit_memory_queries_arc.clone();
        let geometry = *geometry;
        let round_function = *round_function;
        let tx_thread = tx.clone();
        thread::spawn(move || {
            simulate_memory_queue(
                geometry,
                memory_queries_arc,
                implicit_memory_queries_arc,
                round_function,
                tx_thread,
            )
        })
    };

    // send "finalized" part of RAM permutations circuits witnesses to storage (parts of simulator states, RAM-heavy)
    // the rest will be processed further
    for _ in 0..amount_of_ram_circuits * 2 {
        let artifact = rx.recv().unwrap();
        artifacts_callback(artifact);
    }

    let (
        memory_queue_entry_states_for_main_vm,
        final_explicit_memory_queue_state,
        memory_queue_states_accumulator,
        memory_queue_simulator,
        implicit_memory_states,
        unsorted_encodings,
    ) = unsorted_handle.join().unwrap();

    let (
        sorted_memory_queue_states_accumulator,
        sorted_memory_queue_simulator,
        sorted_encodings,
        sorted_queries_aux_data_for_chunks,
    ) = sorted_handle.join().unwrap();

    let memory_artifacts_for_main_vm = MemoryArtifacts {
        memory_queries: Arc::into_inner(memory_queries_arc).unwrap(),
        memory_queue_entry_states: memory_queue_entry_states_for_main_vm,
    };
    let implicit_memory_queries = Arc::into_inner(implicit_memory_queries_arc).unwrap();

    // direct VM related part is done, other subcircuit's functionality is moved to other functions
    // that should properly do sorts and memory writes

    assert_eq!(
        implicit_memory_queries.amount_of_queries(),
        implicit_memory_states.amount_of_states()
    );

    use crate::witness::individual_circuits::memory_related::decommit_code::compute_decommitter_circuit_snapshots;

    tracing::debug!("Running code code decommitter simulation");

    let (code_decommitter_circuits_data, amount_of_memory_queries) =
        compute_decommitter_circuit_snapshots(
            amount_of_explicit_memory_queries,
            implicit_memory_queries.decommitter_memory_queries,
            implicit_memory_states.decommitter_simulator_snapshots,
            implicit_memory_states.decommitter_memory_states,
            final_explicit_memory_queue_state,
            decommiter_circuit_inputs,
            round_function,
            geometry.cycles_per_code_decommitter as usize,
        );

    circuits_data.code_decommitter_circuits_data = code_decommitter_circuits_data;

    use crate::zkevm_circuits::demux_log_queue::DemuxOutput;

    // keccak precompile

    use crate::witness::individual_circuits::memory_related::keccak256_round_function::keccak256_decompose_into_per_circuit_witness;

    tracing::debug!("Running keccak simulation");

    let (keccak256_circuits_data, amount_of_memory_queries) =
        keccak256_decompose_into_per_circuit_witness(
            amount_of_memory_queries,
            implicit_memory_queries.keccak256_memory_queries,
            implicit_memory_states.keccak256_simulator_snapshots,
            implicit_memory_states.keccak256_memory_states,
            precompiles_data.keccak_round_function_witnesses,
            precompiles_data.logs_queries.keccak,
            precompiles_data.logs_queues_states.keccak,
            geometry.cycles_per_keccak256_circuit as usize,
            round_function,
        );
    circuits_data.keccak256_circuits_data = keccak256_circuits_data;

    // sha256 precompile

    use crate::witness::individual_circuits::memory_related::sha256_round_function::sha256_decompose_into_per_circuit_witness;

    tracing::debug!("Running sha256 simulation");

    let (sha256_circuits_data, amount_of_memory_queries) =
        sha256_decompose_into_per_circuit_witness(
            amount_of_memory_queries,
            implicit_memory_queries.sha256_memory_queries,
            implicit_memory_states.sha256_simulator_snapshots,
            implicit_memory_states.sha256_memory_states,
            precompiles_data.sha256_round_function_witnesses,
            precompiles_data.logs_queries.sha256,
            precompiles_data.logs_queues_states.sha256,
            geometry.cycles_per_sha256_circuit as usize,
            round_function,
        );
    circuits_data.sha256_circuits_data = sha256_circuits_data;

    // ecrecover precompile

    use crate::witness::individual_circuits::memory_related::ecrecover::ecrecover_decompose_into_per_circuit_witness;

    tracing::debug!("Running ecrecover simulation");

    let (ecrecover_circuits_data, amount_of_memory_queries) =
        ecrecover_decompose_into_per_circuit_witness(
            amount_of_memory_queries,
            implicit_memory_queries.ecrecover_memory_queries,
            implicit_memory_states.ecrecover_simulator_snapshots,
            implicit_memory_states.ecrecover_memory_states,
            precompiles_data.ecrecover_witnesses,
            precompiles_data.logs_queries.ecrecover,
            precompiles_data.logs_queues_states.ecrecover,
            geometry.cycles_per_ecrecover_circuit as usize,
            round_function,
        );
    circuits_data.ecrecover_circuits_data = ecrecover_circuits_data;

    use crate::witness::individual_circuits::memory_related::secp256r1_verify::secp256r1_verify_decompose_into_per_circuit_witness;

    tracing::debug!("Running secp256r1_simulation simulation");

    let (secp256r1_verify_circuits_data, amount_of_memory_queries) =
        secp256r1_verify_decompose_into_per_circuit_witness(
            amount_of_memory_queries,
            implicit_memory_queries.secp256r1_memory_queries,
            implicit_memory_states.secp256r1_simulator_snapshots,
            implicit_memory_states.secp256r1_memory_states,
            precompiles_data.secp256r1_verify_witnesses,
            precompiles_data.logs_queries.secp256r1_verify,
            precompiles_data.logs_queues_states.secp256r1_verify,
            geometry.cycles_per_secp256r1_verify_circuit as usize,
            round_function,
        );
    circuits_data.secp256r1_verify_circuits_data = secp256r1_verify_circuits_data;

    use crate::witness::individual_circuits::memory_related::ram_permutation::compute_ram_circuit_snapshots;

    tracing::debug!("Running RAM permutation simulation");

    let (ram_permutation_circuits, ram_permutation_circuits_compact_forms_witnesses) =
        compute_ram_circuit_snapshots(
            amount_of_memory_queries,
            memory_queue_states_accumulator,
            sorted_memory_queue_states_accumulator,
            memory_queue_simulator,
            sorted_memory_queue_simulator,
            sorted_queries_aux_data_for_chunks,
            sorted_encodings,
            unsorted_encodings,
            round_function,
            num_non_deterministic_heap_queries,
            geometry,
            &mut artifacts_callback,
        );

    (
        circuits_data,
        memory_artifacts_for_main_vm,
        decommitment_artifacts_for_main_vm,
        ram_permutation_circuits,
        ram_permutation_circuits_compact_forms_witnesses,
    )
}

pub enum WitnessGenerationArtifact {
    BaseLayerCircuit(ZkSyncBaseLayerCircuit),
    RecursionQueue(
        (
            u64,
            RecursionQueueSimulator<GoldilocksField>,
            Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
        ),
    ),
    MemoryQueueWitness((MemoryQueueStateWitnesses<GoldilocksField>, bool)), // sorted/unsorted
}

/// Make basic circuits instances and witnesses,
/// create artifacts for recursion layer and scheduler
pub(crate) fn create_artifacts_from_tracer<CB: FnMut(WitnessGenerationArtifact)>(
    tracer: WitnessTracer,
    round_function: &Poseidon2Goldilocks,
    geometry: &GeometryConfig,
    entry_point_decommittment_query: (DecommittmentQuery, Vec<U256>),
    tree: impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    num_non_deterministic_heap_queries: usize,
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    evm_simulator_code_hash: U256,
    eip_4844_repack_inputs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
    trusted_setup_path: &str,
    mut artifacts_callback: CB,
) -> (
    BlockFirstAndLastBasicCircuitsObservableWitnesses,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    Vec<EIP4844CircuitInstanceWitness<GoldilocksField>>,
) {
    // Our goals are:
    // - make instances of basic layer circuits and pass them via circuit_callback (inputs for the base layer proving)
    // - prepare inputs for recursion layer circuits and pass them via recursion_queue_callback (for the recursion layer proving)
    // - prepare observable witnesses of first and last instances of each basic circuit (part of the scheduler inputs)
    // - get all compact form witnesses for layer circuits (part of the scheduler inputs)

    let WitnessTracer {
        memory_queries: vm_memory_queries_accumulated,
        storage_queries,
        cold_warm_refunds_logs,
        pubdata_cost_logs,
        prepared_decommittment_queries,
        executed_decommittment_queries,
        keccak_round_function_witnesses,
        sha256_round_function_witnesses,
        ecrecover_witnesses,
        secp256r1_verify_witnesses,
        mut callstack_with_aux_data,
        vm_snapshots,
        ..
    } = tracer;

    // we should have an initial decommit query somewhat before the time
    assert!(!prepared_decommittment_queries.is_empty());
    assert!(!executed_decommittment_queries.is_empty());
    assert!(prepared_decommittment_queries.len() >= executed_decommittment_queries.len());
    let (timestamp, query, witness) = &executed_decommittment_queries[0];
    assert!(*timestamp < crate::zk_evm::zkevm_opcode_defs::STARTING_TIMESTAMP);
    assert_eq!(query, &entry_point_decommittment_query.0);
    assert_eq!(witness, &entry_point_decommittment_query.1);

    assert!(vm_snapshots.len() >= 2); // we need at least entry point and the last save (after exit)

    assert!(
        callstack_with_aux_data.depth == 0,
        "parent frame didn't exit"
    );

    let full_callstack_history = std::mem::take(&mut callstack_with_aux_data.full_history);
    // Since we finished the VM execution, current callstack entry now should be a root (outermost) frame
    let final_callstack_entry = std::mem::take(&mut callstack_with_aux_data.current_entry);
    let flat_new_frames_history =
        std::mem::take(&mut callstack_with_aux_data.flat_new_frames_history);
    drop(callstack_with_aux_data);

    tracing::debug!("Running multiplexed log queue simulation");

    // We have all log queries in one multiplexed queue. We need to simulate this queue,
    // demultiplex it and get log queue rollback tails for every call frame
    let (
        log_states_data,
        log_demux_circuit_inputs,
        demuxed_log_queries,
        log_rollback_tails_for_frames,
        log_rollback_queue_heads,
    ) = process_multiplexed_log_queue(
        *geometry,
        &full_callstack_history,
        final_callstack_entry,
        *round_function,
    );

    use std::thread;
    let callstack_handle = {
        let log_rollback_tails_for_frames = log_rollback_tails_for_frames.clone();
        let geometry = *geometry;
        let round_function = *round_function;
        thread::spawn(move || {
            // We need to simulate all callstack states and prepare for each MainVM circuit:
            // - entry value of callstack sponge
            // - callstack witnesses (for every callstack state change)
            // - detailed log queue state for entry call frame (frame index, log queue state)
            callstack_simulation(
                &geometry,
                full_callstack_history,
                log_states_data,
                &log_rollback_tails_for_frames,
                &round_function,
            )
        })
    };

    // demux log queue circuit
    use crate::witness::individual_circuits::log_demux::process_logs_demux_and_make_circuits;

    tracing::debug!("Running log demux simulation");

    // Get circuits and witnesses for logs demultiplexer.
    // Also simulate all demuxed log queues states (used for corresponding circuits further)
    let (
        log_demux_circuits,
        log_demux_circuits_compact_forms_witnesses,
        io_logs_queues_states,
        precompiles_logs_queues_states,
    ) = process_logs_demux_and_make_circuits(
        log_demux_circuit_inputs,
        &demuxed_log_queries,
        geometry.cycles_per_log_demuxer as usize,
        round_function,
        geometry,
        &mut artifacts_callback,
    );

    tracing::debug!("Processing log circuits");

    // Process part of log circuits that do not use memory (I/O-like).
    // Precompiles will be processed in process_memory_related_circuits.
    // Also makes storage application circuits and compact form witnesses.
    let (log_circuits_data, storage_application_circuits, storage_application_compact_forms) =
        process_io_log_circuits(
            geometry,
            tree,
            io_logs_queues_states,
            demuxed_log_queries.io,
            round_function,
            &mut artifacts_callback,
        );

    tracing::debug!("Processing memory-related circuits");

    let precompiles_data = PrecompilesInputData {
        keccak_round_function_witnesses,
        sha256_round_function_witnesses,
        ecrecover_witnesses,
        secp256r1_verify_witnesses,
        logs_queues_states: precompiles_logs_queues_states,
        logs_queries: demuxed_log_queries.precompiles,
    };

    // Prepare inputs for processing of all circuits related to memory
    // (decommitts sorter, decommiter, precompiles, ram permutation).
    // Prepare decommitment an memory inputs for MainVM circuits processing.
    // Also makes ram permutation circuits and compact form witnesses.
    // The most RAM- and CPU-demanding part of the witness generation.
    let (
        memory_circuits_data,
        memory_artifacts_for_main_vm,
        decommitment_artifacts_for_main_vm,
        ram_permutation_circuits,
        ram_permutation_circuits_compact_forms_witnesses,
    ) = process_memory_related_circuits(
        geometry,
        &vm_snapshots,
        vm_memory_queries_accumulated,
        num_non_deterministic_heap_queries,
        prepared_decommittment_queries,
        executed_decommittment_queries,
        precompiles_data,
        round_function,
        &mut artifacts_callback,
    );

    tracing::debug!("Waiting for callstack sumulation");

    let callstack_simulation_result = callstack_handle.join().unwrap();

    tracing::debug!(
        "Processing VM snapshots queue (total {:?})",
        vm_snapshots.windows(2).len()
    );

    use crate::witness::individual_circuits::main_vm::process_main_vm;

    let in_circuit_global_context = GlobalContextWitness {
        zkporter_is_available: zk_porter_is_available,
        default_aa_code_hash,
        evm_simulator_code_hash,
    };

    // Prepares inputs and makes circuit instances and compact forms for MainVM circuits
    // Time consuming due to usually large number of circuits
    let (main_vm_circuits, main_vm_circuits_compact_forms_witnesses) = process_main_vm(
        geometry,
        in_circuit_global_context,
        memory_artifacts_for_main_vm,
        decommitment_artifacts_for_main_vm,
        storage_queries,
        cold_warm_refunds_logs,
        pubdata_cost_logs,
        log_rollback_tails_for_frames,
        log_rollback_queue_heads,
        callstack_simulation_result,
        flat_new_frames_history,
        vm_snapshots,
        *round_function,
        &mut artifacts_callback,
    );

    tracing::debug!("Making remaining circuits");

    // Some circuit instances and compact form witnesses have already been made in previous functions
    // Now we'll make the rest

    let LogCircuitsArtifacts {
        storage_deduplicator_circuit_data,
        events_deduplicator_circuit_data,
        l1_messages_deduplicator_circuit_data,
        l1_messages_linear_hash_data,
        transient_storage_sorter_circuit_data,
    } = log_circuits_data;

    let MemoryCircuitsArtifacts {
        code_decommitter_circuits_data,
        decommittments_deduplicator_circuits_data,
        keccak256_circuits_data,
        sha256_circuits_data,
        ecrecover_circuits_data,
        secp256r1_verify_circuits_data,
    } = memory_circuits_data;

    // Code decommitter sorter
    let (
        code_decommittments_sorter_circuits,
        code_decommittments_sorter_circuits_compact_forms_witnesses,
    ) = make_circuits(
        geometry.cycles_code_decommitter_sorter,
        BaseLayerCircuitType::DecommitmentsFilter,
        decommittments_deduplicator_circuits_data,
        *round_function,
        |x| ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(x),
        &mut artifacts_callback,
    );

    // Actual decommitter
    let (code_decommitter_circuits, code_decommitter_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.cycles_per_code_decommitter,
            BaseLayerCircuitType::Decommiter,
            code_decommitter_circuits_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::CodeDecommitter(x),
            &mut artifacts_callback,
        );

    // keccak precompiles
    let (keccak_precompile_circuits, keccak_precompile_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.cycles_per_keccak256_circuit,
            BaseLayerCircuitType::KeccakPrecompile,
            keccak256_circuits_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::KeccakRoundFunction(x),
            &mut artifacts_callback,
        );

    // sha256 precompiles
    let (sha256_precompile_circuits, sha256_precompile_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.cycles_per_sha256_circuit,
            BaseLayerCircuitType::Sha256Precompile,
            sha256_circuits_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::Sha256RoundFunction(x),
            &mut artifacts_callback,
        );

    // ecrecover precompiles
    let (ecrecover_precompile_circuits, ecrecover_precompile_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.cycles_per_ecrecover_circuit,
            BaseLayerCircuitType::EcrecoverPrecompile,
            ecrecover_circuits_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::ECRecover(x),
            &mut artifacts_callback,
        );

    // secp256r1 verify
    let (secp256r1_verify_circuits, secp256r1_verify_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.cycles_per_secp256r1_verify_circuit,
            BaseLayerCircuitType::Secp256r1Verify,
            secp256r1_verify_circuits_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::Secp256r1Verify(x),
            &mut artifacts_callback,
        );

    // storage sorter
    let (storage_sorter_circuits, storage_sorter_circuit_compact_form_witnesses) = make_circuits(
        geometry.cycles_per_storage_sorter,
        BaseLayerCircuitType::StorageFilter,
        storage_deduplicator_circuit_data,
        *round_function,
        |x| ZkSyncBaseLayerCircuit::StorageSorter(x),
        &mut artifacts_callback,
    );

    // events sorter
    let (events_sorter_circuits, events_sorter_circuits_compact_forms_witnesses) = make_circuits(
        geometry.cycles_per_events_or_l1_messages_sorter,
        BaseLayerCircuitType::EventsRevertsFilter,
        events_deduplicator_circuit_data,
        *round_function,
        |x| ZkSyncBaseLayerCircuit::EventsSorter(x),
        &mut artifacts_callback,
    );

    // l1 messages sorter
    let (l1_messages_sorter_circuits, l1_messages_sorter_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.cycles_per_events_or_l1_messages_sorter,
            BaseLayerCircuitType::L1MessagesRevertsFilter,
            l1_messages_deduplicator_circuit_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::L1MessagesSorter(x),
            &mut artifacts_callback,
        );

    // l1 messages pubdata hasher
    let (l1_messages_hasher_circuits, l1_messages_hasher_circuits_compact_forms_witnesses) =
        make_circuits(
            geometry.limit_for_l1_messages_pudata_hasher,
            BaseLayerCircuitType::L1MessagesHasher,
            l1_messages_linear_hash_data,
            *round_function,
            |x| ZkSyncBaseLayerCircuit::L1MessagesHasher(x),
            &mut artifacts_callback,
        );

    // transient storage sorter
    let (
        transient_storage_sorter_circuits,
        transient_storage_sorter_circuits_compact_forms_witnesses,
    ) = make_circuits(
        geometry.cycles_per_transient_storage_sorter,
        BaseLayerCircuitType::TransientStorageChecker,
        transient_storage_sorter_circuit_data,
        *round_function,
        |x| ZkSyncBaseLayerCircuit::TransientStorageSorter(x),
        &mut artifacts_callback,
    );

    // eip 4844 circuits are basic, but they do not need closed form input commitments

    use crate::witness::individual_circuits::eip4844_repack::compute_eip_4844;
    let eip_4844_circuits = compute_eip_4844(eip_4844_repack_inputs, trusted_setup_path);

    let (_eip_4844_circuits, _eip_4844_circuits_compact_forms_witnesses) = make_circuits(
        4096,
        BaseLayerCircuitType::EIP4844Repack,
        eip_4844_circuits.clone(),
        *round_function,
        |x| ZkSyncBaseLayerCircuit::EIP4844Repack(x),
        &mut artifacts_callback,
    );

    // All done!

    let basic_circuits_first_and_last_observable_witnesses =
        BlockFirstAndLastBasicCircuitsObservableWitnesses {
            main_vm_circuits,
            code_decommittments_sorter_circuits,
            code_decommitter_circuits,
            log_demux_circuits,
            keccak_precompile_circuits,
            sha256_precompile_circuits,
            ecrecover_precompile_circuits,
            ram_permutation_circuits,
            storage_sorter_circuits,
            storage_application_circuits,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_hasher_circuits,
            transient_storage_sorter_circuits,
            secp256r1_verify_circuits,
        };

    // NOTE: this should follow in a sequence same as scheduler's work and `SEQUENCE_OF_CIRCUIT_TYPES`

    let all_compact_forms = main_vm_circuits_compact_forms_witnesses
        .into_iter()
        .chain(code_decommittments_sorter_circuits_compact_forms_witnesses)
        .chain(code_decommitter_circuits_compact_forms_witnesses)
        .chain(log_demux_circuits_compact_forms_witnesses)
        .chain(keccak_precompile_circuits_compact_forms_witnesses)
        .chain(sha256_precompile_circuits_compact_forms_witnesses)
        .chain(ecrecover_precompile_circuits_compact_forms_witnesses)
        .chain(ram_permutation_circuits_compact_forms_witnesses)
        .chain(storage_sorter_circuit_compact_form_witnesses)
        .chain(storage_application_compact_forms)
        .chain(events_sorter_circuits_compact_forms_witnesses)
        .chain(l1_messages_sorter_circuits_compact_forms_witnesses)
        .chain(l1_messages_hasher_circuits_compact_forms_witnesses)
        .chain(transient_storage_sorter_circuits_compact_forms_witnesses)
        .chain(secp256r1_verify_circuits_compact_forms_witnesses)
        .collect();

    (
        basic_circuits_first_and_last_observable_witnesses,
        all_compact_forms,
        eip_4844_circuits,
    )
}
