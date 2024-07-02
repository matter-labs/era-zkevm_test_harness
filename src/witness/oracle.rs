// implement witness oracle to actually compute
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use super::callstack_handler::*;
use super::postprocessing::{BlockFirstAndLastBasicCircuitsObservableWitnesses, ClosedFormInputField, CsForWitnessGeneration, FirstAndLastCircuitWitness};
use super::queue_for_main_vm::{MemoryQueueWitnessesForVmCircuitBuilder, QueueForMainVm, QueueLastStatesForCircuits};
use crate::witness::queue_for_main_vm::CircuitlLastStateAccumulator;
use super::utils::*;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::queue::{QueueState, QueueStateWitness, QueueTailStateWitness};
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::witness::artifacts::{
    CircuitArtifacts, DemuxedLogQueries, ImplicitMemoryArtifacts, MemoryArtifacts,
};
use crate::witness::individual_circuits::decommit_code::decommitter_memory_queries_amount;
use crate::witness::individual_circuits::ecrecover::ecrecover_memory_queries_amount;
use crate::witness::individual_circuits::keccak256_round_function::keccak256_memory_queries_amount;
use crate::witness::individual_circuits::secp256r1_verify::secp256r1_memory_queries_amount;
use crate::witness::individual_circuits::sha256_round_function::sha256_memory_queries_amount;
use crate::witness::individual_circuits::log_demux::LogDemuxCircuitArtifacts;
use crate::witness::postprocessing::{make_circuit, CircuitMaker};
use crate::witness::tracer::{QueryMarker, WitnessTracer};
use crate::witness::vm_snapshot::VmSnapshot;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::aux_structures::PubdataCost;
use crate::zk_evm::vm_state::{CallStackEntry, VmLocalState};
use crate::zkevm_circuits::base_structures::vm_state::{
    GlobalContextWitness, FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH,
};
use crate::zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use crate::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::{Field, U64Representable};
use circuit_definitions::boojum::implementations::poseidon2::Poseidon2Goldilocks;
use circuit_definitions::circuit_definitions::base_layer::VmMainInstanceSynthesisFunction;
use circuit_definitions::circuit_definitions::base_layer::{VMMainCircuit, ZkSyncBaseLayerCircuit};
use circuit_definitions::encodings::callstack_entry::ExtendedCallstackEntry;
use circuit_definitions::encodings::recursion_request::{
    RecursionQueueSimulator, RecursionRequest,
};
use circuit_definitions::encodings::{LogQueueSimulator, LogQueueState};
use circuit_definitions::zkevm_circuits::base_structures::vm_state::callstack;
use circuit_definitions::zkevm_circuits::eip_4844::input::EIP4844CircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::zkevm_circuits::scheduler::input;
use crossbeam::atomic::AtomicCell;
use derivative::Derivative;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;


use crate::snapshot_prof;

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
pub struct StorageLogDetailedState<F: SmallField> {
    pub frame_idx: usize,
    pub forward_tail: [F; QUEUE_STATE_WIDTH],
    pub forward_length: u32,
    pub rollback_head: [F; QUEUE_STATE_WIDTH],
    pub rollback_tail: [F; QUEUE_STATE_WIDTH],
    pub rollback_length: u32,
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
    chain_of_states: Vec<(
        [F; QUEUE_STATE_WIDTH], [F; QUEUE_STATE_WIDTH],
    )>
}

type LogRollbackTailsForFrames = Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>;

/// Simulates the global multiplexed log queue and produces inputs for log demux circuit processing. 
/// Together with simulation, splits the multiplexed log queue into separate queues.
/// Also returns the initial tails of the multiplexed log rollback queue for each frame.
fn process_multiplexed_log_queue(
    geometry: GeometryConfig,
    full_callstack_history: &Vec<CallstackActionHistoryEntry>,
    mut last_callstack_entry: CallstackEntryWithAuxData,
    round_function: Poseidon2Goldilocks,
) -> (
    LogMuxedStatesData<GoldilocksField>,
    LogDemuxCircuitArtifacts<GoldilocksField>,
    DemuxedLogQueries,
    LogRollbackTailsForFrames
) {
    // these queues contain all log queries and some additional markers
    let applied_queries = std::mem::take(&mut last_callstack_entry.forward_queue);
    let not_applied_rollbacks = std::mem::take(&mut last_callstack_entry.rollback_queue);
    drop(last_callstack_entry);

    let total_amount_of_frames = full_callstack_history.iter().filter(|x| x.action == CallstackAction::OutOfScope(OutOfScopeReason::Fresh)).count();
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

    let mut log_queue_simulator = LogQueueSimulator::<GoldilocksField>::with_capacity(applied_queries.len());
    let mut applied_log_queue_simulator = None;

    // struct contains the chain of all multiplexed log queue simulator state changes, old_tail -> new_tail
    // and pointers to corresponding indexes in this chain for forward and rollback queries (if any) at cycle
    let mut states_data = LogMuxedStatesData {
        forward_and_rollback_pointers: BTreeMap::<Cycle, (usize, Option<usize>)>::new(),
        chain_of_states: Vec::with_capacity(applied_queries.len() + not_applied_rollbacks.len())
    };

    let mut demuxed_queries = DemuxedLogQueries::default();

    // used to accumulate all applied muxed log queue state changes needed for log demux circuit simulation
    let mut applied_queue_states_accumulator = QueueLastStatesForCircuits::with_flat_capacity(
        geometry.cycles_per_log_demuxer as usize, 
        applied_queries.len()
    );

    // Now we will do following:
    // - simulate the states of multiplexed log queue as a sponge
    // - find initial multiplexed log queue rollback tails for every frame (including not applied rollbacks)
    // - demux applied part of the log queue and prepare inputs for log demux circuit processing

    // we use reversed iterator for not_applied_rollbacks here
    for (extended_query, was_applied) in applied_queries
        .into_iter()
        .zip(std::iter::repeat(true))
        .chain(not_applied_rollbacks.into_iter().rev().zip(std::iter::repeat(false)))
    {
        if !was_applied {
            // save the latest "useful"
            if applied_log_queue_simulator.is_none() {
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

                assert!(frames_beginnings_and_rollback_tails[frame_index].1.is_none());

                frames_beginnings_and_rollback_tails[frame_index].1 = Some(
                    states_data.chain_of_states
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
        states_data.chain_of_states.push((
            simulator_state.previous_tail, simulator_state.tail,
        ));

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
            states_data.forward_and_rollback_pointers.entry(cycle).or_default().0 = pointer_to_chain_of_states;
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
            states_data.forward_and_rollback_pointers
                .get_mut(&cycle)
                .expect("rollbacks always happen after forward case")
                .1 = Some(pointer_to_chain_of_states);
        }

        match query_marker {
            QueryMarker::Forward {
                cycle: c,
                ..
            } => {
                assert_eq!(cycle, c);
                assert!(!query.rollback);
            }
            QueryMarker::ForwardNoRollback {
                cycle: c,
                ..
            } => {
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

    let mut log_rollback_tails_for_frames = Vec::with_capacity(frames_beginnings_and_rollback_tails.len());
    log_rollback_tails_for_frames.extend(
        frames_beginnings_and_rollback_tails
        .into_iter()
        .enumerate()
        .map(|(frame_index, (beginning_cycle, tail))| {
            (beginning_cycle, tail.expect(&format!("No rollback tail for frame {frame_index}")))
        })
    );

    (
        states_data,
        LogDemuxCircuitArtifacts {
            applied_log_queue_simulator: applied_log_queue_simulator.unwrap_or(LogQueueSimulator::<GoldilocksField>::empty()),
            applied_queue_states_accumulator,
        },
        demuxed_queries,
        log_rollback_tails_for_frames
    )
}

use circuit_definitions::encodings::callstack_entry::{
    CallstackSimulator, CallstackSimulatorState,
};

struct CallstackSimulationResult<F: SmallField> {
    callstack_sponge_encoding_ranges: CircuitlLastStateAccumulator<(Cycle, [F; FULL_SPONGE_QUEUE_STATE_WIDTH])>,
    callstack_values_witnesses: QueueForMainVm<(Cycle, (ExtendedCallstackEntry<F>, CallstackSimulatorState<F>))>,
    rollback_queue_head_segments: QueueForMainVm<(Cycle, [F; QUEUE_STATE_WIDTH])>,
    storage_log_states_for_entry: CircuitlLastStateAccumulator<(Cycle, StorageLogDetailedState<F>)>
}

fn callstack_simulation(
    geometry: &GeometryConfig,
    full_callstack_history: Vec<CallstackActionHistoryEntry>,
    log_states_data: LogMuxedStatesData<GoldilocksField>,
    log_rollback_tails_for_frames: &Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    round_function: &Poseidon2Goldilocks,
) -> CallstackSimulationResult<GoldilocksField> {
    let mut callstack_argebraic_simulator = CallstackSimulator::empty();

    // index of cycle -> witness for callstack
    let mut callstack_values_witnesses = QueueForMainVm::new(geometry.cycles_per_vm_snapshot as usize);
    // we need to simultaneously follow the logic of pushes/joins of the storage queues,
    // and encoding of the current callstack state as the sponge state

    // here we are interested in "frozen" elements that are in the stack,
    // so we never follow the "current", but add on push/pop

    // These are "frozen" states that just lie in the callstack for now and can not be modified
    let mut callstack_sponge_encoding_ranges = CircuitlLastStateAccumulator::new(
        geometry.cycles_per_vm_snapshot as usize, 
        (0, [GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH])
    );

    // we need some information that spans the whole number of cycles with "what is a frame counter at this time"

    // we have all the spans of when each frame is active, so we can
    // - simulate what is saved and when
    // - get witnesses for heads when encountering the new spans

    let global_end_of_storage_log = log_states_data
        .chain_of_states
        .last()
        .map(|el| el.1)
        .unwrap_or([GoldilocksField::ZERO; QUEUE_STATE_WIDTH]);

    // we know for every cycle a pointer to the positions of item's forward and rollback action into
    // the flattened queue
    // we also know when each cycle begins/end

    // so we can quickly reconstruct every current state

    let mut rollback_queue_head_segments: QueueForMainVm<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])> = QueueForMainVm::new(geometry.cycles_per_vm_snapshot as usize);

    for (cycle, (_forward, rollback)) in log_states_data.forward_and_rollback_pointers.iter() {
        if let Some(pointer) = rollback {
            let state = &log_states_data.chain_of_states[*pointer];
            rollback_queue_head_segments.push((*cycle, state.0));
        }
    }

    let mut history_of_storage_log_states = BTreeMap::new();

    // we start with no rollbacks, but non-trivial tail
    let mut current_storage_log_state = StorageLogDetailedState::default();
    current_storage_log_state.rollback_head = global_end_of_storage_log;
    current_storage_log_state.rollback_tail = global_end_of_storage_log;

    let mut storage_logs_states_stack = vec![];

    let mut state_to_merge: Option<(bool, StorageLogDetailedState<GoldilocksField>)> = None;

    for (_idx, el) in full_callstack_history.iter().enumerate() {
        let frame_index = el.frame_index;

        match el.action {
            CallstackAction::PushToStack => {
                // we did push some(!) context to the stack
                // it means that between beginning and end cycles
                // there could have beed some interactions with log

                // `current_storage_log_state` is what we should use for the "current" one,
                // and we can mutate it, bookkeep and then use in the simulator

                let begin_at_cycle = el.beginning_cycle;
                let end_cycle = el.end_cycle.expect("frame must end");

                let range_of_interest = (begin_at_cycle + 1)..=end_cycle; // begin_at_cycle is formally bound to the previous one
                let frame_action_span = log_states_data
                    .forward_and_rollback_pointers
                    .range(range_of_interest);
                for (cycle, (_forward_pointer, rollback_pointer)) in frame_action_span {
                    // always add to the forward
                    let new_forward_tail = log_states_data.chain_of_states[*_forward_pointer].1;
                    if new_forward_tail != current_storage_log_state.forward_tail {
                        // edge case of double data on fram boudary, reword later
                        current_storage_log_state.forward_tail = new_forward_tail;
                        current_storage_log_state.forward_length += 1;
                    }

                    // if there is a rollback then let's process it too

                    if let Some(rollback_pointer) = rollback_pointer {
                        let new_rollback_head = log_states_data.chain_of_states
                            [*rollback_pointer].0;
                        current_storage_log_state.rollback_head = new_rollback_head;
                        current_storage_log_state.rollback_length += 1;
                    } else {
                        // we didn't in fact rollback, but it nevertheless can be counted as formal rollback
                    }

                    let previous =
                        history_of_storage_log_states.insert(*cycle, current_storage_log_state);
                    if !previous.is_none() {
                        assert_eq!(
                            previous.unwrap(),
                            current_storage_log_state,
                            "duplicate divergence for cycle {}: previous is {:?}, new is {:?}",
                            cycle,
                            previous.unwrap(),
                            current_storage_log_state
                        )
                    }
                    // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", *cycle, previous.unwrap(), current_storage_log_state);
                }

                // dump it into the entry and dump entry into simulator

                let entry = ExtendedCallstackEntry {
                    callstack_entry: el.affected_entry,
                    rollback_queue_head: current_storage_log_state.rollback_head,
                    rollback_queue_tail: current_storage_log_state.rollback_tail,
                    rollback_queue_segment_length: current_storage_log_state.rollback_length,
                };

                storage_logs_states_stack.push(current_storage_log_state);

                // push the item to the stack
                let intermediate_info = callstack_argebraic_simulator
                    .push_and_output_intermediate_data(entry, round_function);

                assert!(intermediate_info.is_push == true);
                let cycle_to_use = end_cycle;
                if let Some((prev_cycle, _)) = callstack_values_witnesses.last() {
                    assert!(cycle_to_use != *prev_cycle, "trying to add callstack witness for cycle {}, but previous one is on cycle {}", cycle_to_use, prev_cycle);
                }
                // we do push the witness at the cycle numbered at when the element was pushed
                callstack_values_witnesses.push((cycle_to_use, (entry, intermediate_info)));

                // when we push a new one then we need to "finish" the previous range and start a new one
                callstack_sponge_encoding_ranges.push((end_cycle, intermediate_info.new_state));
            }
            CallstackAction::PopFromStack { panic } => {
                // an item that was in the stack becomes current
                assert!(state_to_merge.is_some());

                let (claimed_panic, state_to_merge) = state_to_merge.take().unwrap();
                assert_eq!(panic, claimed_panic);

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

                current_storage_log_state = popped_state;
                current_storage_log_state.frame_idx = frame_index;
                current_storage_log_state.forward_tail = state_to_merge.forward_tail;
                assert!(
                    current_storage_log_state.forward_length <= state_to_merge.forward_length,
                    "divergence at frame {}",
                    frame_index
                );
                current_storage_log_state.forward_length = state_to_merge.forward_length;

                if panic {
                    assert_eq!(
                        current_storage_log_state.forward_tail, state_to_merge.rollback_head,
                        "divergence at frame {} with panic: {:?}",
                        frame_index, el
                    );

                    current_storage_log_state.forward_tail = state_to_merge.rollback_tail;
                    current_storage_log_state.forward_length += state_to_merge.rollback_length;
                } else {
                    assert_eq!(
                        current_storage_log_state.rollback_head, state_to_merge.rollback_tail,
                        "divergence at frame {} without panic: {:?}",
                        frame_index, el
                    );
                    current_storage_log_state.rollback_head = state_to_merge.rollback_head;
                    current_storage_log_state.rollback_length += state_to_merge.rollback_length;
                }

                let beginning_cycle = el.beginning_cycle;

                let previous = history_of_storage_log_states
                    .insert(beginning_cycle, current_storage_log_state);
                if !previous.is_none() {
                    assert_eq!(
                        previous.unwrap(),
                        current_storage_log_state,
                        "duplicate divergence for cycle {}: previous is {:?}, new is {:?}",
                        beginning_cycle,
                        previous.unwrap(),
                        current_storage_log_state
                    )
                }

                // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", beginning_cycle, previous.unwrap(), current_storage_log_state);

                assert!(intermediate_info.is_push == false);
                let cycle_to_use = beginning_cycle;
                if let Some((prev_cycle, _)) = callstack_values_witnesses.last() {
                    assert!(cycle_to_use != *prev_cycle, "trying to add callstack witness for cycle {}, but previous one is on cycle {}", cycle_to_use, prev_cycle);
                }
                // we place it at the cycle when it was actually popped, but not one when it becase "active"
                callstack_values_witnesses.push((cycle_to_use, (entry, intermediate_info)));

                // when we push a new one then we need to "finish" the previous range and start a new one
                callstack_sponge_encoding_ranges
                    .push((beginning_cycle, intermediate_info.new_state));
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // we already identified initial rollback tails for new frames
                let rollback_tail = log_rollback_tails_for_frames[frame_index].1;
                // do not reset forward length as it's easy to merge
                current_storage_log_state.frame_idx = frame_index;
                current_storage_log_state.rollback_length = 0;
                current_storage_log_state.rollback_head = rollback_tail;
                current_storage_log_state.rollback_tail = rollback_tail;

                let cycle = el.beginning_cycle;

                let previous =
                    history_of_storage_log_states.insert(cycle, current_storage_log_state);
                if !previous.is_none() {
                    // ensure that basic properties hold: we replace the current frame with a new one, so
                    // it should have large frame_idx and the same forward tail and length
                    let previous = previous.unwrap();
                    assert!(
                        previous.frame_idx < current_storage_log_state.frame_idx,
                        "frame divergence for cycle {}: previous is {:?}, new is {:?}",
                        cycle,
                        previous,
                        current_storage_log_state
                    );
                    assert_eq!(
                        previous.forward_tail, current_storage_log_state.forward_tail,
                        "frame divergence for cycle {}: previous is {:?}, new is {:?}",
                        cycle, previous, current_storage_log_state
                    );
                    assert_eq!(
                        previous.forward_length, current_storage_log_state.forward_length,
                        "frame divergence for cycle {}: previous is {:?}, new is {:?}",
                        cycle, previous, current_storage_log_state
                    );
                }
                // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", cycle, previous.unwrap(), current_storage_log_state);
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic }) => {
                // we are not too interested, frame just ends, and all the storage log logic was resolved before it

                assert!(state_to_merge.is_none());

                let begin_at_cycle = el.beginning_cycle;
                let end_cycle = el.end_cycle.expect("frame must end");

                let range_of_interest = (begin_at_cycle + 1)..=end_cycle; // begin_at_cycle is formally bound to the previous one
                let frame_action_span = log_states_data
                    .forward_and_rollback_pointers
                    .range(range_of_interest);
                for (cycle, (forward_pointer, rollback_pointer)) in frame_action_span {
                    // always add to the forward
                    let new_forward_tail = log_states_data.chain_of_states[*forward_pointer].1;
                    if new_forward_tail != current_storage_log_state.forward_tail {
                        // edge case of double data on fram boudary, reword later
                        current_storage_log_state.forward_tail = new_forward_tail;
                        current_storage_log_state.forward_length += 1;
                    }

                    // if there is a rollback then let's process it too

                    if let Some(rollback_pointer) = rollback_pointer {
                        let new_rollback_head = log_states_data.chain_of_states
                            [*rollback_pointer]
                             .0;
                        current_storage_log_state.rollback_head = new_rollback_head;
                        current_storage_log_state.rollback_length += 1;
                    }

                    let previous =
                        history_of_storage_log_states.insert(*cycle, current_storage_log_state);
                    if !previous.is_none() {
                        assert_eq!(
                            previous.unwrap(),
                            current_storage_log_state,
                            "duplicate divergence for cycle {}: previous is {:?}, new is {:?}",
                            cycle,
                            previous.unwrap(),
                            current_storage_log_state
                        )
                    }

                    // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", *cycle, previous.unwrap(), current_storage_log_state);
                }

                state_to_merge = Some((panic, current_storage_log_state));
            }
        }
    }

    let mut initial_storage_state = StorageLogDetailedState::default();
    initial_storage_state.rollback_tail = global_end_of_storage_log;
    initial_storage_state.rollback_head = global_end_of_storage_log;

    let storage_log_states_for_entry = CircuitlLastStateAccumulator::from_iter(
        geometry.cycles_per_vm_snapshot as usize, 
        (0, initial_storage_state),
        history_of_storage_log_states.into_iter()
    );

    CallstackSimulationResult {
        callstack_sponge_encoding_ranges,
        callstack_values_witnesses,
        rollback_queue_head_segments,
        storage_log_states_for_entry
    }
}

use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;
use circuit_definitions::circuit_definitions::base_layer::LogDemuxInstanceSynthesisFunction;
use circuit_definitions::circuit_definitions::base_layer::RAMPermutationInstanceSynthesisFunction;
use circuit_definitions::circuit_definitions::base_layer::StorageApplicationInstanceSynthesisFunction;
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;

use crate::zkevm_circuits::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;
use crate::zkevm_circuits::ram_permutation::input::RamPermutationCircuitInstanceWitness;
use crate::zkevm_circuits::storage_application::input::StorageApplicationCircuitInstanceWitness;


use crate::witness::postprocessing::observable_witness::LogDemuxerObservableWitness;
use crate::witness::postprocessing::observable_witness::RamPermutationObservableWitness;
use crate::witness::postprocessing::observable_witness::StorageApplicationObservableWitness;

use crate::blake2::Blake2s256;
use crate::witness::tree::*;

fn process_log_circuits<
    CB: FnMut(ZkSyncBaseLayerCircuit),
    QSCB: FnMut(
        u64,
        RecursionQueueSimulator<GoldilocksField>,
        Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    ),
>(
    geometry: &GeometryConfig,
    tree: impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    vm_memory_queries_accumulated: Vec<(Cycle, MemoryQuery)>,
    prepared_decommittment_queries: Vec<(Cycle, DecommittmentQuery)>,
    executed_decommittment_queries: Vec<(Cycle, DecommittmentQuery, Vec<U256>)>,
    keccak_round_function_witnesses: Vec<(Cycle, LogQuery, Vec<Keccak256RoundWitness>)>,
    sha256_round_function_witnesses: Vec<(Cycle, LogQuery, Vec<Sha256RoundWitness>)>,
    ecrecover_witnesses: Vec<(Cycle, LogQuery, ECRecoverRoundWitness)>,
    secp256r1_verify_witnesses: Vec<(Cycle, LogQuery, Secp256r1VerifyRoundWitness)>,
    log_demux_circuit_inputs: LogDemuxCircuitArtifacts<GoldilocksField>,
    demuxed_log_queries: DemuxedLogQueries,
    round_function: &Poseidon2Goldilocks,
    num_non_deterministic_heap_queries: usize,
    vm_snapshots: &Vec<VmSnapshot>,
    mut cs_for_witness_generation: &mut CsForWitnessGeneration,
    mut circuit_callback: &mut CB,
    mut recursion_queue_callback: &mut QSCB,
) -> (
    CircuitArtifacts<GoldilocksField>,
    MemoryArtifacts<GoldilocksField>,
    FirstAndLastCircuitWitness<LogDemuxerObservableWitness<GoldilocksField>>,
    FirstAndLastCircuitWitness<RamPermutationObservableWitness<GoldilocksField>>,
    FirstAndLastCircuitWitness<StorageApplicationObservableWitness<GoldilocksField>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
) {
    let mut memory_artifacts = MemoryArtifacts {
        prepared_decommittment_queries_per_instance: QueueForMainVm::from_iter(geometry.cycles_per_vm_snapshot as usize, prepared_decommittment_queries.into_iter()),
        vm_memory_queries_accumulated,
        memory_queue_entry_states: vec![],
        decommittment_queue_entry_states: CircuitlLastStateAccumulator::new(geometry.cycles_per_vm_snapshot as usize, (0, QueueState::placeholder_witness()))
    };

    tracing::debug!("Processing artifacts queue");
    
    snapshot_prof("Start mem queue sim");

    // TODO cleanup
    let mut artifacts = CircuitArtifacts::default();

    use crate::witness::individual_circuits::sort_decommit_requests::compute_decommitts_sorter_circuit_snapshots;

    tracing::debug!("Running code decommittments sorter simulation");

    let mut deduplicated_decommitment_queue_simulator = Default::default();
    let mut deduplicated_decommittment_queue_states = Default::default();
    let mut deduplicated_decommit_requests_with_data = Default::default();

    let (all_decommittment_queue_states, decommittments_deduplicator_circuits_data) =
        compute_decommitts_sorter_circuit_snapshots(
            executed_decommittment_queries,
            &mut deduplicated_decommitment_queue_simulator,
            &mut deduplicated_decommittment_queue_states,
            &mut deduplicated_decommit_requests_with_data,
            round_function,
            geometry.cycles_code_decommitter_sorter as usize,
        );

    // first decommittment query (for bootloader) must come before the beginning of time
    {
        let initial_cycle = vm_snapshots[0].at_cycle;
        let decommittment_queue_states_before_start: Vec<_> = all_decommittment_queue_states
            .iter()
            .take_while(|el| el.0 < initial_cycle)
            .collect();

        assert!(decommittment_queue_states_before_start.len() == 1);
    }

    memory_artifacts.decommittment_queue_entry_states.extend(all_decommittment_queue_states.into_iter().map(|el| (el.0, transform_sponge_like_queue_state(el.1))));
    artifacts.decommittments_deduplicator_circuits_data =
        decommittments_deduplicator_circuits_data;

    snapshot_prof("Finished compute_decommitts_sorter_circuit_snapshots");

    tracing::debug!("Running memory queue simulation");

    // TODO rename
    let mut all_memory_queue_states =
    QueueLastStatesForCircuits::<MemoryQueueState<GoldilocksField>>::with_flat_capacity(
        geometry.cycles_per_ram_permutation as usize,
        memory_artifacts.vm_memory_queries_accumulated.len()
    );
    let mut vm_entry_memory_states_builder = MemoryQueueWitnessesForVmCircuitBuilder::new(&vm_snapshots, &memory_artifacts.vm_memory_queries_accumulated);

    let amount_of_implicit_memory_queries = decommitter_memory_queries_amount(&deduplicated_decommit_requests_with_data)
    + ecrecover_memory_queries_amount(&ecrecover_witnesses)
    + keccak256_memory_queries_amount(&keccak_round_function_witnesses)
    + secp256r1_memory_queries_amount(&secp256r1_verify_witnesses)
    + sha256_memory_queries_amount(&sha256_round_function_witnesses);

    // very big data struct inside
    //let mut memory_queue_simulator: MemoryQueueSimulator<GoldilocksField> = MemoryQueueSimulator::with_capacity(
    //    memory_artifacts.vm_memory_queries_accumulated.len() + amount_of_implicit_memory_queries
    //);

    use crate::witness::queue_for_main_vm::MemoryQueuePerCircuitSimulator;
    use crate::witness::queue_for_main_vm::MemoryQueueStatesForRamCircuits;

    let mut memory_queue_simulator = MemoryQueuePerCircuitSimulator::using_container(
        MemoryQueueStatesForRamCircuits::with_flat_capacity(
            geometry.cycles_per_ram_permutation as usize,
            memory_artifacts.vm_memory_queries_accumulated.len()
        )
    );

    // very slow
    for (_, query) in memory_artifacts.vm_memory_queries_accumulated.iter() {
        let (_, intermediate_info) =
            memory_queue_simulator.push_and_output_intermediate_data(*query, round_function);

        all_memory_queue_states
        .push(intermediate_info);
        vm_entry_memory_states_builder.push(intermediate_info);
    }

    // compress huge data structure into smaller one
    memory_artifacts.memory_queue_entry_states = vm_entry_memory_states_builder.into_circuits();



    snapshot_prof("Finished memory queue simulation");

    // ----------------------------

    {
        assert_eq!(
            memory_artifacts.vm_memory_queries_accumulated.len(),
            all_memory_queue_states.len()
        );
        assert_eq!(
            memory_artifacts.vm_memory_queries_accumulated.len(),
            memory_queue_simulator.num_items as usize
        );
    }

    // ----------------------------

    // direct VM related part is done, other subcircuit's functionality is moved to other functions
    // that should properly do sorts and memory writes

    use crate::witness::individual_circuits::decommit_code::compute_decommitter_circuit_snapshots;

    // precompiles and decommiter will produce additional implicit memory queries
    let mut implicit_memory_artifacts: ImplicitMemoryArtifacts<GoldilocksField> =
    ImplicitMemoryArtifacts::default();
    implicit_memory_artifacts.memory_queries_accumulated = Vec::with_capacity(amount_of_implicit_memory_queries);

    tracing::debug!("Running code code decommitter simulation");

    let code_decommitter_circuits_data = compute_decommitter_circuit_snapshots(
        &memory_artifacts,
        &mut implicit_memory_artifacts,
        &all_memory_queue_states,
        &mut memory_queue_simulator,
        deduplicated_decommitment_queue_simulator,
        deduplicated_decommittment_queue_states,
        deduplicated_decommit_requests_with_data,
        round_function,
        geometry.cycles_per_code_decommitter as usize,
    );

    artifacts.code_decommitter_circuits_data = code_decommitter_circuits_data;

    // demux log queue
    use crate::witness::individual_circuits::log_demux::compute_logs_demux;

    tracing::debug!("Running log demux simulation");

    let (log_demux_circuits, log_demux_circuits_compact_forms_witnesses, mut all_demuxed_queues) =
        compute_logs_demux(
            log_demux_circuit_inputs,
            &demuxed_log_queries,
            geometry.cycles_per_log_demuxer as usize,
            round_function,
            geometry,
            &mut cs_for_witness_generation,
            &mut circuit_callback,
            &mut recursion_queue_callback,
        );

    use crate::zkevm_circuits::demux_log_queue::DemuxOutput;

    // keccak precompile

    use crate::witness::individual_circuits::keccak256_round_function::keccak256_decompose_into_per_circuit_witness;

    tracing::debug!("Running keccak simulation");

    let demuxed_keccak_precompile_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::Keccak as usize]);

    let keccak256_circuits_data = keccak256_decompose_into_per_circuit_witness(
        &memory_artifacts,
        &mut implicit_memory_artifacts,
        &all_memory_queue_states,
        &mut memory_queue_simulator,
        keccak_round_function_witnesses,
        demuxed_log_queries.keccak_precompile_queries,
        demuxed_keccak_precompile_queue,
        geometry.cycles_per_keccak256_circuit as usize,
        round_function,
    );
    artifacts.keccak256_circuits_data = keccak256_circuits_data;

    // sha256 precompile

    use crate::witness::individual_circuits::sha256_round_function::sha256_decompose_into_per_circuit_witness;

    tracing::debug!("Running sha256 simulation");

    let demuxed_sha256_precompile_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::Sha256 as usize]);

    let sha256_circuits_data = sha256_decompose_into_per_circuit_witness(
        &memory_artifacts,
        &mut implicit_memory_artifacts,
        &all_memory_queue_states,
        &mut memory_queue_simulator,
        sha256_round_function_witnesses,
        demuxed_log_queries.sha256_precompile_queries,
        demuxed_sha256_precompile_queue,
        geometry.cycles_per_sha256_circuit as usize,
        round_function,
    );
    artifacts.sha256_circuits_data = sha256_circuits_data;

    // ecrecover precompile

    use crate::witness::individual_circuits::ecrecover::ecrecover_decompose_into_per_circuit_witness;

    tracing::debug!("Running ecrecover simulation");

    let demuxed_ecrecover_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::ECRecover as usize]);

    let ecrecover_circuits_data = ecrecover_decompose_into_per_circuit_witness(
        &memory_artifacts,
        &mut implicit_memory_artifacts,
        &all_memory_queue_states,
        &mut memory_queue_simulator,
        ecrecover_witnesses,
        demuxed_log_queries.ecrecover_queries,
        demuxed_ecrecover_queue,
        geometry.cycles_per_ecrecover_circuit as usize,
        round_function,
    );
    artifacts.ecrecover_circuits_data = ecrecover_circuits_data;

    use crate::witness::individual_circuits::secp256r1_verify::secp256r1_verify_decompose_into_per_circuit_witness;

    tracing::debug!("Running secp256r1_simulation simulation");

    let demuxed_secp256r1_verify_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::Secp256r1Verify as usize]);

    let secp256r1_verify_circuits_data = secp256r1_verify_decompose_into_per_circuit_witness(
        &memory_artifacts,
        &mut implicit_memory_artifacts,
        &all_memory_queue_states,
        &mut memory_queue_simulator,
        secp256r1_verify_witnesses,
        demuxed_log_queries.secp256r1_verify_queries,
        demuxed_secp256r1_verify_queue,
        geometry.cycles_per_secp256r1_verify_circuit as usize,
        round_function,
    );
    artifacts.secp256r1_verify_circuits_data = secp256r1_verify_circuits_data;

    assert!(implicit_memory_artifacts.memory_queries_accumulated.len() == amount_of_implicit_memory_queries);

    // we are done with a memory and can do the processing and breaking of the logical arguments into individual circits

    use crate::witness::individual_circuits::ram_permutation::compute_ram_circuit_snapshots;

    tracing::debug!("Running RAM permutation simulation");

    let (ram_permutation_circuits, ram_permutation_circuits_compact_forms_witnesses) =
        compute_ram_circuit_snapshots(
            &memory_artifacts,
            implicit_memory_artifacts,
            all_memory_queue_states,
            memory_queue_simulator,
            round_function,
            num_non_deterministic_heap_queries,
            geometry.cycles_per_ram_permutation as usize,
            geometry,
            &mut cs_for_witness_generation,
            &mut circuit_callback,
            &mut recursion_queue_callback,
        );

    // now completely parallel process to reconstruct the states, with internally parallelism in each round function

    use crate::witness::individual_circuits::storage_sort_dedup::compute_storage_dedup_and_sort;

    tracing::debug!("Running storage deduplication simulation");

    let demuxed_rollup_storage_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::RollupStorage as usize]);

    let (
        deduplicated_rollup_storage_queue_simulator,
        deduplicated_rollup_storage_queries,
        storage_deduplicator_circuit_data,
    ) = compute_storage_dedup_and_sort(
        demuxed_log_queries.rollup_storage_queries,
        demuxed_rollup_storage_queue,
        geometry.cycles_per_storage_sorter as usize,
        round_function,
    );
    artifacts.storage_deduplicator_circuit_data = storage_deduplicator_circuit_data;

    use crate::witness::individual_circuits::events_sort_dedup::compute_events_dedup_and_sort;

    tracing::debug!("Running events deduplication simulation");

    let demuxed_event_queue = std::mem::take(&mut all_demuxed_queues[DemuxOutput::Events as usize]);

    let events_deduplicator_circuit_data = compute_events_dedup_and_sort(
        demuxed_log_queries.event_queries,
        demuxed_event_queue,
        &mut Default::default(),
        geometry.cycles_per_events_or_l1_messages_sorter as usize,
        round_function,
    );

    artifacts.events_deduplicator_circuit_data = events_deduplicator_circuit_data;

    tracing::debug!("Running L1 messages deduplication simulation");

    let demuxed_to_l1_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::L2ToL1Messages as usize]);

    let mut deduplicated_to_l1_queue_simulator = Default::default();
    let l1_messages_deduplicator_circuit_data = compute_events_dedup_and_sort(
        demuxed_log_queries.to_l1_queries,
        demuxed_to_l1_queue,
        &mut deduplicated_to_l1_queue_simulator,
        geometry.cycles_per_events_or_l1_messages_sorter as usize,
        round_function,
    );
    artifacts.l1_messages_deduplicator_circuit_data = l1_messages_deduplicator_circuit_data;

    use crate::witness::individual_circuits::transient_storage_sorter::compute_transient_storage_dedup_and_sort;

    tracing::debug!("Running transient storage sorting simulation");

    let demuxed_transient_storage_queue =
        std::mem::take(&mut all_demuxed_queues[DemuxOutput::TransientStorage as usize]);

    let transient_storage_sorter_circuit_data = compute_transient_storage_dedup_and_sort(
        demuxed_log_queries.transient_storage_queries,
        demuxed_transient_storage_queue,
        geometry.cycles_per_transient_storage_sorter as usize,
        round_function,
    );
    artifacts.transient_storage_sorter_circuit_data = transient_storage_sorter_circuit_data;

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
    artifacts.l1_messages_linear_hash_data = l1_messages_pubdata_hasher_data;

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
            &mut cs_for_witness_generation,
            &mut circuit_callback,
            &mut recursion_queue_callback,
        );

    (
        artifacts,
        memory_artifacts,
        log_demux_circuits,
        ram_permutation_circuits,
        storage_application_circuits,
        log_demux_circuits_compact_forms_witnesses,
        ram_permutation_circuits_compact_forms_witnesses,
        storage_application_compact_forms,
    )
}

struct MainVmSimulationInput {
    memory_queue_states_for_entry:
        QueueStateWitness<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    decommittment_queue_states_for_entry:
        QueueStateWitness<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    callstack_state_for_entry: [GoldilocksField; FULL_SPONGE_QUEUE_STATE_WIDTH],
    storage_log_queue_detailed_state_for_entry: StorageLogDetailedState<GoldilocksField>,
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

use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::memory_query::MemoryQueueState;

fn repack_input_for_main_vm(
    geometry: &GeometryConfig,
    vm_snapshots: &Vec<VmSnapshot>,
    memory_artifacts: MemoryArtifacts<GoldilocksField>,
    callstack_simulation_result: CallstackSimulationResult<GoldilocksField>,
    storage_queries: QueueForMainVm<(Cycle, LogQuery)>,
    cold_warm_refunds_logs: QueueForMainVm<(Cycle, LogQuery, u32)>,
    pubdata_cost_logs: QueueForMainVm<(Cycle, LogQuery, PubdataCost)>,
    log_rollback_tails_for_frames: Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    flat_new_frames_history: Vec<(Cycle, CallStackEntry)>,
) -> Vec<MainVmSimulationInput> {
    let MemoryArtifacts {
        decommittment_queue_entry_states,
        prepared_decommittment_queries_per_instance,
        memory_queue_entry_states,
        vm_memory_queries_accumulated,
    } = memory_artifacts;

    let CallstackSimulationResult {
        callstack_sponge_encoding_ranges,
        callstack_values_witnesses,
        rollback_queue_head_segments,
        storage_log_states_for_entry,
    } = callstack_simulation_result;

    // TODO capacity
    let mut main_vm_inputs = vec![];

    // split the oracle witness
    let memory_write_witnesses = QueueForMainVm::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        vm_memory_queries_accumulated
        .iter()
        .filter(|(_, query)| query.rw_flag)
        .copied()
    );

    let memory_read_witnesses = QueueForMainVm::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        vm_memory_queries_accumulated
        .iter()
        .filter(|(_, query)| !query.rw_flag)
        .copied()
    );
    drop(vm_memory_queries_accumulated);

    snapshot_prof("Repack: splitted witnesses");

    // prepare some inputs for MainVM circuits

    let amount_of_circuits = vm_snapshots.windows(2).enumerate().len(); // TODO clean

    let mut memory_read_witnesses_it = memory_read_witnesses.into_batches(amount_of_circuits).into_iter();
    let mut memory_write_witnesses_it = memory_write_witnesses.into_batches(amount_of_circuits).into_iter();

    let mut storage_queries_it = storage_queries.into_batches(amount_of_circuits).into_iter();
    let mut cold_warm_refunds_logs_it = cold_warm_refunds_logs.into_batches(amount_of_circuits).into_iter();
    let mut pubdata_cost_logs_it = pubdata_cost_logs.into_batches(amount_of_circuits).into_iter();
    let mut flat_new_frames_history_it = QueueForMainVm::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        flat_new_frames_history.into_iter()
        ).into_batches(amount_of_circuits).into_iter();

    let mut rollback_queue_tails_for_frames_it = QueueForMainVm::from_iter(
        geometry.cycles_per_vm_snapshot as usize,
        log_rollback_tails_for_frames.into_iter()
        ).into_batches(amount_of_circuits).into_iter();


    let mut rollback_queue_head_segments_it = rollback_queue_head_segments.into_batches(amount_of_circuits).into_iter();
    let mut callstack_values_witnesses_it = callstack_values_witnesses.into_batches(amount_of_circuits).into_iter();
    let mut memory_queue_entry_states_it = memory_queue_entry_states.into_iter();

    let mut callstack_sponge_encoding_ranges_it = callstack_sponge_encoding_ranges.into_batches(amount_of_circuits).into_iter(); 

    let last_storage_log_state = storage_log_states_for_entry.last().1;
    let mut storage_log_states_for_entry_it = storage_log_states_for_entry.into_batches(amount_of_circuits).into_iter();

    let last_decommittment_queue_state = decommittment_queue_entry_states.last().1.clone();
    let mut decommittment_queue_entry_states = decommittment_queue_entry_states.into_batches(amount_of_circuits).into_iter();

    let mut prepared_decommittment_queries_per_instance_it = prepared_decommittment_queries_per_instance.into_batches(amount_of_circuits).into_iter();
    snapshot_prof("Repack: prepared iters");

    for (circuit_idx, _pair) in vm_snapshots.windows(2).enumerate() {
        if amount_of_circuits / 100 != 0 {
            if circuit_idx % (amount_of_circuits / 100) == 0 {
                println!("{} / {}", circuit_idx, amount_of_circuits);
            }
        }

        let memory_queue_state_for_entry = memory_queue_entry_states_it.next().unwrap();

        let decommitment_queue_state = decommittment_queue_entry_states.next().unwrap().1;

        let storage_log_queue_detailed_state = storage_log_states_for_entry_it.next().unwrap().1;

        let callstack_state_for_entry = callstack_sponge_encoding_ranges_it.next().map(|el| el.1).unwrap();

        let memory_read_witnesses_for_instance = memory_read_witnesses_it.next().unwrap();
        let memory_write_witnesses_for_instance = memory_write_witnesses_it.next().unwrap();

        let storage_queries_witnesses_for_instance = storage_queries_it.next().unwrap();
        let cold_warm_refund_logs_for_instance = cold_warm_refunds_logs_it.next().unwrap();
        let pubdata_cost_logs_for_instance = pubdata_cost_logs_it.next().unwrap();

        let decommittment_requests_witness_for_instance = prepared_decommittment_queries_per_instance_it.next().unwrap();

        let rollback_queue_initial_tails_for_new_frames_for_instance = rollback_queue_tails_for_frames_it.next().unwrap();
        let callstack_values_witnesses_for_instance = callstack_values_witnesses_it.next().unwrap();
        let rollback_queue_head_segments_for_instance = rollback_queue_head_segments_it.next().unwrap();
        let callstack_new_frames_witnesses_for_instance = flat_new_frames_history_it.next().unwrap();

        let main_vm_input = MainVmSimulationInput {
            decommittment_queue_states_for_entry: decommitment_queue_state,
            memory_queue_states_for_entry: memory_queue_state_for_entry,
            storage_log_queue_detailed_state_for_entry: storage_log_queue_detailed_state,
            callstack_state_for_entry,
            memory_write_witnesses: memory_write_witnesses_for_instance,
            memory_read_witnesses: memory_read_witnesses_for_instance,
            storage_queries_witnesses: storage_queries_witnesses_for_instance,
            cold_warm_refund_logs: cold_warm_refund_logs_for_instance,
            pubdata_cost_logs: pubdata_cost_logs_for_instance,
            decommittment_requests_witness: decommittment_requests_witness_for_instance,
            rollback_queue_initial_tails_for_new_frames:
                rollback_queue_initial_tails_for_new_frames_for_instance,
            callstack_values_witnesses: callstack_values_witnesses_for_instance,
            rollback_queue_head_segments: rollback_queue_head_segments_for_instance,
            callstack_new_frames_witnesses: callstack_new_frames_witnesses_for_instance,
        };

        main_vm_inputs.push(main_vm_input);

    }

    // special pass for last one
    {
        let memory_queue_state_for_entry = memory_queue_entry_states_it.next().unwrap();

        let decommitment_queue_state = last_decommittment_queue_state;
        // always an empty one
        let callstack_state_for_entry = [GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH];

        let storage_log_queue_detailed_state = last_storage_log_state;

        let main_vm_input = MainVmSimulationInput {
            decommittment_queue_states_for_entry: decommitment_queue_state,
            memory_queue_states_for_entry: memory_queue_state_for_entry,
            storage_log_queue_detailed_state_for_entry: storage_log_queue_detailed_state,
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

        snapshot_prof("Repack: repacked last circuit");
    }

    main_vm_inputs
}

use crate::zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmCircuitWitness;
use crate::witness::postprocessing::observable_witness::VmObservableWitness;

fn process_main_vm<
    CB: FnMut(ZkSyncBaseLayerCircuit),
    QSCB: FnMut(
        u64,
        RecursionQueueSimulator<GoldilocksField>,
        Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    ),
>(
    geometry: &GeometryConfig,
    in_circuit_global_context: GlobalContextWitness<GoldilocksField>,
    memory_artifacts: MemoryArtifacts<GoldilocksField>,
    storage_queries: QueueForMainVm<(Cycle, LogQuery)>,
    cold_warm_refunds_logs: QueueForMainVm<(Cycle, LogQuery, u32)>,
    pubdata_cost_logs: QueueForMainVm<(Cycle, LogQuery, PubdataCost)>,
    log_rollback_tails_for_frames: Vec<(Cycle, [GoldilocksField; QUEUE_STATE_WIDTH])>,
    callstack_simulation_result: CallstackSimulationResult<GoldilocksField>,
    flat_new_frames_history: Vec<(Cycle, CallStackEntry)>,
    mut vm_snapshots: Vec<VmSnapshot>,
    round_function: Poseidon2Goldilocks,
    cs_for_witness_generation: &mut CsForWitnessGeneration,
    circuit_callback: &mut CB,
    recursion_queue_callback: &mut QSCB,
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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            cs_for_witness_generation.take_cs(),
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
        let _ = queue_simulator.push(recursive_request, &round_function);

        circuit_callback(instance);
        main_vm_circuits_compact_forms_witnesses.push(compact_form_witness);
    };

    let mut previous_instance_witness: Option<
        VmInstanceWitness<GoldilocksField, VmWitnessOracle<GoldilocksField>>,
    > = None;

    snapshot_prof("Before mainVM processing");

    let main_vm_inputs = repack_input_for_main_vm(
        geometry,
        &vm_snapshots,
        memory_artifacts,
        callstack_simulation_result,
        storage_queries,
        cold_warm_refunds_logs,
        pubdata_cost_logs,
        log_rollback_tails_for_frames,
        flat_new_frames_history,
    );

    // duplicate last snapshot to process last circuit
    vm_snapshots.push(vm_snapshots.last().unwrap().clone());
    let circuits_len = vm_snapshots.windows(2).len();

    snapshot_prof("Before mainVM processing cycle");

    let amount_of_circuits = vm_snapshots.windows(2).enumerate().len();
    // parallelizable
    for ((circuit_idx, pair), main_vm_input) in
        vm_snapshots.windows(2).enumerate().zip(main_vm_inputs)
    {
        if amount_of_circuits / 100 != 0 {
            if circuit_idx % (amount_of_circuits / 100) == 0 {
                println!("{} / {}", circuit_idx, amount_of_circuits);
            }
        }

        let is_last = circuit_idx == circuits_len - 1;

        let initial_state = &pair[0];
        let final_state = &pair[1];

        // TODO move all
        let MainVmSimulationInput {
            memory_queue_states_for_entry: memory_queue_state,
            decommittment_queue_states_for_entry: decommittment_queue_state,
            callstack_state_for_entry,
            storage_log_queue_detailed_state_for_entry: storage_log_queue_detailed_state,
            ..
        } = main_vm_input;

        let storage_log_queue_state = QueueStateWitness {
            head: [GoldilocksField::ZERO; QUEUE_STATE_WIDTH],
            tail: QueueTailStateWitness {
                tail: storage_log_queue_detailed_state.forward_tail,
                length: storage_log_queue_detailed_state.forward_length,
            },
        };

        let auxilary_initial_parameters = VmInCircuitAuxilaryParameters {
            callstack_state: (
                callstack_state_for_entry,
                initial_state
                    .local_state
                    .callstack
                    .get_current_stack()
                    .clone(),
            ),
            decommittment_queue_state,
            memory_queue_state,
            storage_log_queue_state,
            current_frame_rollback_queue_tail: storage_log_queue_detailed_state.rollback_tail,
            current_frame_rollback_queue_head: storage_log_queue_detailed_state.rollback_head,
            current_frame_rollback_queue_segment_length: storage_log_queue_detailed_state
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

    snapshot_prof("MainVM processing cycle finished");

    recursion_queue_callback(
        BaseLayerCircuitType::VM as u64,
        queue_simulator,
        main_vm_circuits_compact_forms_witnesses.clone(),
    );

    (main_vm_circuits, main_vm_circuits_compact_forms_witnesses)
}

pub(crate) fn create_artifacts_from_tracer<
    CB: FnMut(ZkSyncBaseLayerCircuit),
    QSCB: FnMut(
        u64,
        RecursionQueueSimulator<GoldilocksField>,
        Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    ),
>(
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
    mut circuit_callback: CB,
    mut recursion_queue_callback: QSCB,
) -> (
    BlockFirstAndLastBasicCircuitsObservableWitnesses,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    Vec<EIP4844CircuitInstanceWitness<GoldilocksField>>,
) {
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
        monotonic_query_counter: _,
        mut callstack_with_aux_data,
        vm_snapshots,
        ..
    } = tracer;

    // we should have an initial query somewhat before the time
    assert!(prepared_decommittment_queries.len() >= 1);
    assert!(executed_decommittment_queries.len() >= 1);
    assert!(prepared_decommittment_queries.len() >= executed_decommittment_queries.len());
    let (ts, q, w) = &executed_decommittment_queries[0];
    assert!(*ts < crate::zk_evm::zkevm_opcode_defs::STARTING_TIMESTAMP);
    assert_eq!(q, &entry_point_decommittment_query.0);
    assert_eq!(w, &entry_point_decommittment_query.1);

    assert!(vm_snapshots.len() >= 2); // we need at least entry point and the last save (after exit)

    assert!(
        callstack_with_aux_data.depth == 0,
        "parent frame didn't exit"
    );

    let full_callstack_history = std::mem::take(&mut callstack_with_aux_data.full_history);
    let last_callstack_entry = std::mem::take(&mut callstack_with_aux_data.current_entry);
    let flat_new_frames_history = std::mem::take(&mut callstack_with_aux_data.flat_new_frames_history);
    drop(callstack_with_aux_data);

    snapshot_prof("Before log sim");

    tracing::debug!("Running multiplexed log queue simulation");

    // can be processed in parallel thread
    let (log_states_data, log_demux_circuit_inputs, demuxed_log_queries, log_rollback_tails_for_frames) =
    process_multiplexed_log_queue(*geometry, &full_callstack_history, last_callstack_entry, *round_function);

    snapshot_prof("Muxed log queue processed");

    // and now do trivial simulation
    tracing::debug!("Running callstack sumulation");

    let callstack_simulation_result = callstack_simulation(
        geometry,
        full_callstack_history,
        log_states_data,
        &log_rollback_tails_for_frames,
        round_function,
    );

    snapshot_prof("Callstack simulated");

    // we simulate a series of actions on the stack starting from the outermost frame
    // each history record contains an information on what was the stack state between points
    // when it potentially came into and out of scope

    let mut cs_for_witness_generation = CsForWitnessGeneration::new();

    snapshot_prof("Cs created");

    // process all circuits related to logs
    let (
        log_circuits_artifacts,
        memory_artifacts,
        log_demux_circuits,
        ram_permutation_circuits,
        storage_application_circuits,
        log_demux_circuits_compact_forms_witnesses,
        ram_permutation_circuits_compact_forms_witnesses,
        storage_application_compact_forms,
    ) = process_log_circuits(
        geometry,
        tree,
        vm_memory_queries_accumulated,
        prepared_decommittment_queries,
        executed_decommittment_queries,
        keccak_round_function_witnesses,
        sha256_round_function_witnesses,
        ecrecover_witnesses,
        secp256r1_verify_witnesses,
        log_demux_circuit_inputs,
        demuxed_log_queries,
        round_function,
        num_non_deterministic_heap_queries,
        &vm_snapshots,
        &mut cs_for_witness_generation,
        &mut circuit_callback,
        &mut recursion_queue_callback,
    );

    snapshot_prof("Log circuits processed");

    // NOTE: here we have all the queues processed in the `process` function (actual pushing is done), so we can
    // just read from the corresponding states

    tracing::debug!(
        "Processing VM snapshots queue (total {:?})",
        vm_snapshots.windows(2).len()
    );

    let in_circuit_global_context = GlobalContextWitness {
        zkporter_is_available: zk_porter_is_available,
        default_aa_code_hash,
        evm_simulator_code_hash,
    };

    let (main_vm_circuits, main_vm_circuits_compact_forms_witnesses) = process_main_vm(
        geometry,
        in_circuit_global_context,
        memory_artifacts,
        storage_queries,
        cold_warm_refunds_logs,
        pubdata_cost_logs,
        log_rollback_tails_for_frames,
        callstack_simulation_result,
        flat_new_frames_history,
        vm_snapshots,
        round_function.clone(),
        &mut cs_for_witness_generation,
        &mut circuit_callback,
        &mut recursion_queue_callback,
    );

    snapshot_prof("After mainVM processing");

    {
        let CircuitArtifacts {
            code_decommitter_circuits_data,
            decommittments_deduplicator_circuits_data,
            storage_deduplicator_circuit_data,
            events_deduplicator_circuit_data,
            l1_messages_deduplicator_circuit_data,
            keccak256_circuits_data,
            sha256_circuits_data,
            ecrecover_circuits_data,
            l1_messages_linear_hash_data,
            transient_storage_sorter_circuit_data,
            secp256r1_verify_circuits_data,
        } = log_circuits_artifacts;

        // Code decommitter sorter
        let (code_decommittments_sorter_circuits, code_decommittments_sorter_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_code_decommitter_sorter, 
            BaseLayerCircuitType::DecommitmentsFilter, 
            decommittments_deduplicator_circuits_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Decommitments dedup");

        // Actual decommitter
        let (code_decommitter_circuits, code_decommitter_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_code_decommitter, 
            BaseLayerCircuitType::Decommiter, 
            code_decommitter_circuits_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::CodeDecommitter(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Decommiter");

        // keccak precompiles
        let (keccak_precompile_circuits, keccak_precompile_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_keccak256_circuit, 
            BaseLayerCircuitType::KeccakPrecompile, 
            keccak256_circuits_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::KeccakRoundFunction(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Keccak");

        // sha256 precompiles
        let (sha256_precompile_circuits, sha256_precompile_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_sha256_circuit, 
            BaseLayerCircuitType::Sha256Precompile, 
            sha256_circuits_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::Sha256RoundFunction(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Sha256");

        // ecrecover precompiles
        let (ecrecover_precompile_circuits, ecrecover_precompile_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_ecrecover_circuit, 
            BaseLayerCircuitType::EcrecoverPrecompile, 
            ecrecover_circuits_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::ECRecover(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Ecrecover");

        // secp256r1 verify
        let (secp256r1_verify_circuits, secp256r1_verify_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_secp256r1_verify_circuit, 
            BaseLayerCircuitType::Secp256r1Verify, 
            secp256r1_verify_circuits_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::Secp256r1Verify(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Secp256 verify");

        // storage sorter
        let (storage_sorter_circuits, storage_sorter_circuit_compact_form_witnesses) = make_circuit(
            geometry.cycles_per_storage_sorter, 
            BaseLayerCircuitType::StorageFilter, 
            storage_deduplicator_circuit_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::StorageSorter(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Storage sorter");

        // events sorter
        let (events_sorter_circuits, events_sorter_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_events_or_l1_messages_sorter, 
            BaseLayerCircuitType::EventsRevertsFilter, 
            events_deduplicator_circuit_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::EventsSorter(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Events sorter");

        // l1 messages sorter
        let (l1_messages_sorter_circuits, l1_messages_sorter_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_events_or_l1_messages_sorter, 
            BaseLayerCircuitType::L1MessagesRevertsFilter, 
            l1_messages_deduplicator_circuit_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::L1MessagesSorter(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("L1 sorter");

        // l1 messages pubdata hasher
        let (l1_messages_hasher_circuits, l1_messages_hasher_circuits_compact_forms_witnesses) = make_circuit(
            geometry.limit_for_l1_messages_pudata_hasher, 
            BaseLayerCircuitType::L1MessagesHasher, 
            l1_messages_linear_hash_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::L1MessagesHasher(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("L1 messages hasher");

        // transient storage sorter
        let (transient_storage_sorter_circuits, transient_storage_sorter_circuits_compact_forms_witnesses) = make_circuit(
            geometry.cycles_per_transient_storage_sorter, 
            BaseLayerCircuitType::TransientStorageChecker, 
            transient_storage_sorter_circuit_data, 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::TransientStorageSorter(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Transient storage sorter");

        // eip 4844 circuits are basic, but they do not need closed form input commitments

        use crate::witness::individual_circuits::eip4844_repack::compute_eip_4844;
        let eip_4844_circuits = compute_eip_4844(eip_4844_repack_inputs, trusted_setup_path);

        let (_eip_4844_circuits, _eip_4844_circuits_compact_forms_witnesses) = make_circuit(
            4096, 
            BaseLayerCircuitType::EIP4844Repack, 
            eip_4844_circuits.clone(), 
            round_function.clone(), 
            |x| circuit_callback(ZkSyncBaseLayerCircuit::EIP4844Repack(x)), 
            &mut recursion_queue_callback, 
            &mut cs_for_witness_generation
        );

        snapshot_prof("Eip 4844");

        // done!

        let basic_circuits = BlockFirstAndLastBasicCircuitsObservableWitnesses {
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

        snapshot_prof("Final");

        (basic_circuits, all_compact_forms, eip_4844_circuits)
    }
}
