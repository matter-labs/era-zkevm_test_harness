// implement witness oracle to actually compute
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use crate::encodings::callstack_entry::{CallstackSimulatorState, ExtendedCallstackEntry};
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::toolset::GeometryConfig;
use crate::witness::tracer::{WitnessTracer, QueryMarker};
use boojum::field::SmallField;
use boojum::implementations::poseidon_goldilocks::PoseidonGoldilocks;
use zkevm_circuits::base_structures::vm_state::{QUEUE_STATE_WIDTH, FULL_SPONGE_QUEUE_STATE_WIDTH, GlobalContextWitness};
use zkevm_circuits::main_vm::main_vm_entry_point;
use derivative::Derivative;
use num_bigint::BigUint;
use rayon::slice::ParallelSliceMut;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::RangeInclusive;
use crate::ethereum_types::U256;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::{
    LogQuery, MemoryIndex, MemoryPage, MemoryQuery,
};
use crate::witness::full_block_artifact::FullBlockArtifacts;
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use zk_evm::reference_impls::event_sink::ApplicationData;
use zk_evm::vm_state::{CallStackEntry, VmLocalState};
use super::callstack_handler::*;
use smallvec::SmallVec;
use super::utils::*;
use boojum::gadgets::queue::{QueueState, QueueStateWitness, QueueTailStateWitness};
use zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use boojum::gadgets::poseidon::CircuitRoundFunction;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::poseidon::BuildableCircuitRoundFunction;

use zk_evm::zkevm_opcode_defs::system_params::{
    KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS
};

use zk_evm::zkevm_opcode_defs::system_params::{
    STORAGE_AUX_BYTE,
    EVENT_AUX_BYTE,
    L1_MESSAGE_AUX_BYTE,
    PRECOMPILE_AUX_BYTE
};


#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
struct CallframeLogState {
    forward_queue_tail_pointer: usize,
    forward_queue_length: u32,
    rollback_queue_head_pointer: usize,
    rollback_queue_tail_pointer: usize,
    rollback_queue_length: u32
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug)]
pub struct RollbackQueueStateWitness<F: SmallField> {
    pub head: [F; QUEUE_STATE_WIDTH],
    pub tail: [F; QUEUE_STATE_WIDTH],
    pub segment_length: u32,
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Default(bound = ""), Clone(bound = ""))]
#[serde(bound = "")]
pub struct VmWitnessOracle<F: SmallField> {
    pub memory_read_witness: VecDeque<(u32, MemoryQuery)>,
    pub memory_write_witness: Option<VecDeque<(u32, MemoryQuery)>>,
    pub rollback_queue_head_segments: VecDeque<(u32, [F; QUEUE_STATE_WIDTH])>,
    pub decommittment_requests_witness: VecDeque<(u32, DecommittmentQuery)>,
    pub rollback_queue_initial_tails_for_new_frames: VecDeque<(u32, [F; QUEUE_STATE_WIDTH])>,
    pub storage_queries: VecDeque<(u32, LogQuery)>, // cycle, query
    pub storage_refund_queries: VecDeque<(u32, LogQuery, u32)>, // cycle, query, pubdata refund
    pub callstack_new_frames_witnesses:
        VecDeque<(u32, CallStackEntry)>,
    pub callstack_values_witnesses:
        VecDeque<(u32, (ExtendedCallstackEntry<F>, CallstackSimulatorState<F>))>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, PartialEq, Eq, Default(bound = ""))]
pub struct StorageLogDetailedState<F: SmallField> {
    pub frame_idx: usize,
    pub forward_tail: [F; QUEUE_STATE_WIDTH],
    pub forward_length: u32,
    pub rollback_head: [F; QUEUE_STATE_WIDTH],
    pub rollback_tail: [F; QUEUE_STATE_WIDTH],
    pub rollback_length: u32,
}

// impl<F: SmallField> Default for StorageLogDetailedState<F> {
//     fn default() -> Self {
//         Self { 
//             frame_idx: 0,
//             forward_tail: [F::ZERO; QUEUE_STATE_WIDTH],
//             forward_length: 0,
//             rollback_head: [F::ZERO; QUEUE_STATE_WIDTH],
//             rollback_tail: [F::ZERO; QUEUE_STATE_WIDTH],
//             rollback_length: 0,
//         }
//     }
// }

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
            callstack_state: ([F::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH], CallStackEntry::empty_context()), 
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
pub struct CommonLogSponges<F: SmallField>{
    pub rf_0: ([F; 12], [F; 12]),
    pub rf_1: ([F; 12], [F; 12]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct ForwardLogSponge<F: SmallField>{
    pub old_tail: [F; QUEUE_STATE_WIDTH],
    pub new_tail: [F; QUEUE_STATE_WIDTH],
    pub exclusive_rf: ([F; 12], [F; 12]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct RollbackLogSponge<F: SmallField>{
    pub old_head: [F; QUEUE_STATE_WIDTH],
    pub new_head: [F; QUEUE_STATE_WIDTH],
    pub exclusive_rf: ([F; 12], [F; 12]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct LogAccessSpongesInfo<F: SmallField>{
    pub cycle: u32,
    pub common_sponges: CommonLogSponges<F>,
    pub forward_info: ForwardLogSponge<F>,
    pub rollback_info: Option<RollbackLogSponge<F>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
struct FlattenedLogQueueIndexer<F: SmallField>{
    pub current_head: [F; QUEUE_STATE_WIDTH],
    pub current_tail: [F; QUEUE_STATE_WIDTH],
    pub head_offset: usize,
    pub tail_offset: usize,
}

use crate::witness::tree::*;
use crate::blake2::Blake2s256;

pub fn create_artifacts_from_tracer<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    tracer: WitnessTracer,
    round_function: &R,
    geometry: &GeometryConfig,
    entry_point_decommittment_query: (DecommittmentQuery, Vec<U256>),
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    num_non_deterministic_heap_queries: usize,
) -> (Vec<VmInstanceWitness<F, VmWitnessOracle<F>>>, FullBlockArtifacts<F>) {
    let WitnessTracer {
        memory_queries,
        storage_queries,
        refunds_logs,
        decommittment_queries,
        keccak_round_function_witnesses,
        sha256_round_function_witnesses,
        ecrecover_witnesses,
        monotonic_query_counter: _,
        callstack_with_aux_data,
        vm_snapshots,
        ..
    } = tracer;

    let callstack_with_aux_data = callstack_with_aux_data;

    // we should have an initial query somewhat before the time
    assert!(decommittment_queries.len() >= 1);
    let (ts, q, w) = &decommittment_queries[0];
    assert!(*ts < zk_evm::zkevm_opcode_defs::STARTING_TIMESTAMP);
    assert_eq!(q, &entry_point_decommittment_query.0);
    assert_eq!(w, &entry_point_decommittment_query.1);

    assert!(vm_snapshots.len() >= 2); // we need at least entry point and the last save (after exit)

    // there can be multiple per cycle, so we need BTreeMap over vectors. For other witnesses it's easier
    let mut memory_read_witness: BTreeMap<u32, SmallVec<[MemoryQuery; 4]>> = BTreeMap::new();
    let mut memory_write_witness: BTreeMap<u32, SmallVec<[MemoryQuery; 4]>> = BTreeMap::new();
    for el in memory_queries.iter() {
        if el.1.rw_flag == false {
            // read
            if let Some(existing) = memory_read_witness.get_mut(&el.0) {
                existing.push(el.1);
            } else {
                memory_read_witness.insert(el.0, smallvec::smallvec![el.1]);
            }
        } else {
            // write
            if let Some(existing) = memory_write_witness.get_mut(&el.0) {
                existing.push(el.1);
            } else {
                memory_write_witness.insert(el.0, smallvec::smallvec![el.1]);
            }
        }
    }
    
    let vm_memory_queries_accumulated = memory_queries;

    // segmentation of the log queue
    // - split into independent queues
    // - compute initial tail segments (with head == tail) for every new call frame
    // - also compute head segments for every write-like actions

    let mut log_queue_simulator = LogQueueSimulator::<F>::empty();
    assert!(callstack_with_aux_data.depth == 0, "parent frame didn't exit");

    let forward = callstack_with_aux_data.current_entry.forward_queue.clone();
    let rollbacks = callstack_with_aux_data.current_entry.rollback_queue.clone();

    let mut query_id_into_cycle_index = BTreeMap::new();

    for (cycle, marker) in callstack_with_aux_data.log_access_history.iter() {
        query_id_into_cycle_index.insert(marker.query_id(), *cycle);
    }

    let num_forwards = forward.len();
    let num_rollbacks = rollbacks.len();

    let mut log_position_mapping = HashMap::new();

    let mut demuxed_rollup_storage_queries = vec![];
    let mut demuxed_porter_storage_queries = vec![];
    let mut demuxed_event_queries = vec![];
    let mut demuxed_to_l1_queries = vec![];
    let mut demuxed_keccak_precompile_queries = vec![];
    let mut demuxed_sha256_precompile_queries = vec![];
    let mut demuxed_ecrecover_queries = vec![];
    let original_log_queue: Vec<_> = forward.iter()
        .filter(|el| {
            match el {
                ExtendedLogQuery::Query{..} => true,
                _ => false,
            }
        })
        .map(|el| 
            match el {
                ExtendedLogQuery::Query{cycle, query, ..} => (*cycle, *query),
                _ => unreachable!(),
            }
        ).collect();

    let mut original_log_queue_states = vec![];
    let mut chain_of_states = vec![];
    let mut original_log_queue_simulator = None;
    let mut marker_into_queue_position_renumeration_index: HashMap<QueryMarker, usize> = HashMap::new();

    // we want to have some hashmap that will indicate
    // that on some specific VM cycle we either read or write

    // from cycle into first two sponges (common), then tail-tail pair and 3rd sponge for forward, then head-head pair and 3rd sponge for rollback
    let mut sponges_data: HashMap<
        u32,
        LogAccessSpongesInfo<F>,
    > = HashMap::new();

    let mut callstack_frames_spans = std::collections::BTreeMap::new();
    let mut global_beginnings_of_frames: BTreeMap<usize, u32> = BTreeMap::new();
    let mut global_ends_of_frames: BTreeMap<usize, u32> = BTreeMap::new();
    let mut actions_in_each_frame: BTreeMap<usize, Vec<(u32, QueryMarker, usize)>> = BTreeMap::new();

    for el in callstack_with_aux_data.full_history.iter() {
        match el.action {
            CallstackAction::PushToStack => {
                // not imporatant, we count by the next one
            },
            CallstackAction::PopFromStack { panic: _ } => {
                // mark
                callstack_frames_spans.insert(el.beginning_cycle, el.frame_index);
            },
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // fresh fram
                callstack_frames_spans.insert(el.beginning_cycle, el.frame_index);
                global_beginnings_of_frames.insert(el.frame_index, el.beginning_cycle);
            },
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: _ }) => {
                // mark when this frame is completely out of scope
                global_ends_of_frames.insert(el.frame_index, el.end_cycle.expect("frame must end"));
            }
        }
    }

    global_beginnings_of_frames.insert(0, 0);
    global_ends_of_frames.insert(0, u32::MAX);

    // now it's going to be fun. We simultaneously will do the following indexing:
    // - simulate the state of callstack as a sponge
    // - follow the call graph and storage queries graph to know exacly the following subset of properties at any
    // range of cycles:
    // - callstack "frozen" part (what is in the callstack). This involves rollback queue head/tail/length!
    // - "active" callstack entry rollback queue's head/tail/length at this cycle

    // first we need to hash the queue itself, and create an index of "where in the final flat queue did log access from this frame end up"
    // If we encounter "read" that implies no reverts we use "None"

    let mut cycle_into_flat_sequence_index = BTreeMap::<u32, (usize, Option<usize>)>::new();

    // we want to know for each of the cycles what is a state of the log queue
    let mut log_actions_spans: std::collections::BTreeMap<u32, Vec<(QueryMarker, usize)>> = std::collections::BTreeMap::new();
    let mut log_declarations_spans: std::collections::BTreeMap<u32, Vec<(QueryMarker, usize)>> = std::collections::BTreeMap::new();

    // in practice we also split out precompile accesses

    let mut unique_query_id_into_chain_positions: HashMap<u64, usize> = HashMap::with_capacity(num_forwards + num_rollbacks);

    tracing::debug!("Running storage log simulation");

    for (extended_query, was_applied) in
        forward.iter().cloned().zip(std::iter::repeat(true)).chain(
            rollbacks
                .iter()
                .rev()
                .cloned()
                .zip(std::iter::repeat(false)),
        )
    {
        if !was_applied {
            // save the latest "usefull"
            if original_log_queue_simulator.is_none() {
                original_log_queue_simulator = Some(log_queue_simulator.clone());
            }
        } else {
            // check for no gaps
            assert!(original_log_queue_simulator.is_none());
        }

        let (query_marker, cycle, query) = match extended_query {
            ExtendedLogQuery::Query{marker, cycle, query} => (marker, cycle, query),
            a @ ExtendedLogQuery::FrameForwardHeadMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            },
            a @ ExtendedLogQuery::FrameForwardTailMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            },
            a @ ExtendedLogQuery::FrameRollbackHeadMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            },
            a @ ExtendedLogQuery::FrameRollbackTailMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            }
        };

        let (_old_tail, intermediate_info) =
            log_queue_simulator.push_and_output_intermediate_data(query, round_function);

        let pointer = chain_of_states.len();
        // we just log all chains of old tail -> new tail, and will interpret them later
        chain_of_states.push((cycle, query_marker, (intermediate_info.previous_tail, intermediate_info.tail)));

        // add renumeration index
        marker_into_queue_position_renumeration_index.insert(query_marker, pointer);

        let query_id = query_marker.query_id();
        unique_query_id_into_chain_positions.insert(query_id, pointer);

        let key = query.timestamp.0;
        if query.rollback {
            let entry = sponges_data
                .get_mut(&key)
                .expect("rollbacks always happen after forward case");
            let common_sponges_pair = entry.common_sponges;
            assert_eq!(
                &common_sponges_pair.rf_0,
                &intermediate_info.round_function_execution_pairs[0]
            );
            assert_eq!(
                &common_sponges_pair.rf_1,
                &intermediate_info.round_function_execution_pairs[1]
            );

            let rollback_info = RollbackLogSponge {
                old_head: intermediate_info.tail,
                new_head: intermediate_info.previous_tail, // it's our convension - we move backwards
                exclusive_rf: intermediate_info.round_function_execution_pairs[2]
            };

            entry.rollback_info = Some(rollback_info);

            cycle_into_flat_sequence_index
                .get_mut(&cycle)
                .expect("rollbacks always happen after forward case")
                .1 = Some(pointer);

            match query_marker {
                QueryMarker::Rollback { in_frame:_, index: _, cycle_of_declaration: c, cycle_of_applied_rollback, .. } => {
                    assert_eq!(cycle, c);
                    if let Some(existing) = log_declarations_spans.get_mut(&cycle) {
                        existing.push((query_marker, pointer));
                    } else {
                        log_declarations_spans.insert(cycle, vec![(query_marker, pointer)]);
                    }

                    match cycle_of_applied_rollback {
                        None => {
                            let cycle_of_applied_rollback = u32::MAX;
                            if let Some(existing) = log_actions_spans.get_mut(&cycle_of_applied_rollback) {
                                existing.push((query_marker, pointer));
                            } else {
                                log_actions_spans.insert(cycle_of_applied_rollback, vec![(query_marker, pointer)]);
                            }
                        },
                        Some(cycle_of_applied_rollback) => {
                            // even if we re-apply, then we are ok
                            if let Some(existing) = log_actions_spans.get_mut(&cycle_of_applied_rollback) {
                                existing.push((query_marker, pointer));
                            } else {
                                log_actions_spans.insert(cycle_of_applied_rollback, vec![(query_marker, pointer)]);
                            }
                        }
                    }
                },
                a @ _ => {unreachable!("encounteted {:?}", a)}
            }
        } else {
            let entry = sponges_data.entry(key).or_default();

            let common_sponges_info = CommonLogSponges {
                rf_0: intermediate_info.round_function_execution_pairs[0],
                rf_1: intermediate_info.round_function_execution_pairs[1]
            };

            let forward_info = ForwardLogSponge {
                old_tail: intermediate_info.previous_tail,
                new_tail: intermediate_info.tail,
                exclusive_rf: intermediate_info.round_function_execution_pairs[2]
            };

            entry.cycle = cycle;
            entry.common_sponges = common_sponges_info;
            entry.forward_info = forward_info;

            cycle_into_flat_sequence_index.entry(cycle).or_default().0 = pointer;

            match query_marker {
                QueryMarker::Forward { in_frame:_, index: _, cycle: c, .. } => {
                    assert_eq!(cycle, c);
                    if let Some(existing) = log_declarations_spans.get_mut(&cycle) {
                        existing.push((query_marker, pointer));
                    } else {
                        log_declarations_spans.insert(cycle, vec![(query_marker, pointer)]);
                    }
                    log_actions_spans.insert(cycle, vec![(query_marker, pointer)]);
                },
                QueryMarker::ForwardNoRollback { in_frame:_, index: _, cycle: c, .. } => {
                    assert_eq!(cycle, c);
                    if let Some(existing) = log_declarations_spans.get_mut(&cycle) {
                        existing.push((query_marker, pointer));
                    } else {
                        log_declarations_spans.insert(cycle, vec![(query_marker, pointer)]);
                    }
                    log_actions_spans.insert(cycle, vec![(query_marker, pointer)]);
                },
                a @ _ => {unreachable!("encounteted {:?}", a)}
            }
        }

        let frame_index = query_marker.frame_index();

        if let Some(existing) = actions_in_each_frame.get_mut(&frame_index) {
            existing.push((cycle, query_marker, pointer));
        } else {
            actions_in_each_frame.insert(frame_index, vec![(cycle, query_marker, pointer)]);
        }

        // and sort
        if was_applied {
            // push state
            original_log_queue_states.push((cycle, intermediate_info));
            match query.aux_byte {
                STORAGE_AUX_BYTE => {
                    // sort rollup and porter
                    match query.shard_id {
                        0 => {
                            demuxed_rollup_storage_queries.push(query);
                        }
                        1 => {
                            demuxed_porter_storage_queries.push(query);
                        }
                        _ => unreachable!(),
                    }
                }
                L1_MESSAGE_AUX_BYTE => {
                    demuxed_to_l1_queries.push(query);
                }
                EVENT_AUX_BYTE => {
                    demuxed_event_queries.push(query);
                }
                PRECOMPILE_AUX_BYTE => {
                    assert!(!query.rollback);
                    use zk_evm::precompiles::*;
                    match query.address {
                        a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            demuxed_keccak_precompile_queries.push(query);
                        }
                        a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            demuxed_sha256_precompile_queries.push(query);
                        }
                        a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            demuxed_ecrecover_queries.push(query);
                        }
                        _ => {
                            // just burn ergs
                        },
                    }
                },
                _ => unreachable!(),
            }
        }
    }
    
    use super::callstack_handler::CallstackAction;
    use crate::encodings::callstack_entry::CallstackSimulator;
    let mut callstack_argebraic_simulator = CallstackSimulator::<F>::empty();
    let mut callstack_values_witnesses = vec![]; // index of cycle -> witness for callstack
    // we need to simultaneously follow the logic of pushes/joins of the storage queues,
    // and encoding of the current callstack state as the sponge state

    // here we are interested in "frozen" elements that are in the stack,
    // so we never follow the "current", but add on push/pop

    // These are "frozen" states that just lie in the callstack for now and can not be modified
    let mut callstack_sponge_encoding_ranges = vec![];
    // pretend initial state
    callstack_sponge_encoding_ranges.push((0, [F::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]));

    // we need some information that spans the whole number of cycles with "what is a frame counter at this time"

    // we have all the spans of when each frame is active, so we can
    // - simulate what is saved and when
    // - get witnesses for heads when encountering the new spans

    let global_end_of_storage_log = chain_of_states.last().map(|el| el.2.1).unwrap_or([F::ZERO; QUEUE_STATE_WIDTH]);
    let mut frame_rollback_tails = BTreeMap::new();

    let mut rollback_queue_initial_tails_for_new_frames = vec![];
    let max_frame_idx = callstack_with_aux_data.monotonic_frame_counter;

    for frame_index in 0..max_frame_idx {
        if frame_index == 0 {
            let tail = global_end_of_storage_log;
            frame_rollback_tails.insert(frame_index, tail);
            let frame_beginning_cycle = global_beginnings_of_frames[&frame_index];
            rollback_queue_initial_tails_for_new_frames.push((frame_beginning_cycle, tail));
            continue;
        }

        let rollback_tail_marker = ExtendedLogQuery::FrameRollbackTailMarker(frame_index);
        // wherever we have this marker we should look at the tail of the item right before it
        let pos = log_position_mapping[&rollback_tail_marker];
        let tail = if pos == -1 {
            // empty
            global_end_of_storage_log
        } else {
            let pointer = pos as usize;
            let element = chain_of_states[pointer].2.1;

            element
        };

        frame_rollback_tails.insert(frame_index, tail);

        let frame_beginning_cycle = global_beginnings_of_frames[&frame_index];
        rollback_queue_initial_tails_for_new_frames.push((frame_beginning_cycle, tail));
    }

    // we know for every cycle a pointer to the positions of item's forward and rollback action into 
    // the flattened queue
    // we also know when each cycle begins/end

    // so we can quickly reconstruct every current state

    let mut rollback_queue_head_segments: Vec<(u32, [F; QUEUE_STATE_WIDTH])> = vec![];

    for (cycle, (_forward, rollback)) in cycle_into_flat_sequence_index.iter() {
        if let Some(pointer) = rollback {
            let state = &chain_of_states[*pointer];
            rollback_queue_head_segments.push((*cycle, state.2.0));
        }
    }

    let mut history_of_storage_log_states = BTreeMap::new();

    // we start with no rollbacks, but non-trivial tail
    let mut current_storage_log_state = StorageLogDetailedState::<F>::default();
    current_storage_log_state.rollback_head = global_end_of_storage_log;
    current_storage_log_state.rollback_tail = global_end_of_storage_log;

    let mut storage_logs_states_stack = vec![];

    let mut state_to_merge: Option<(bool, StorageLogDetailedState<F>)> = None;

    // and now do trivial simulation

    tracing::debug!("Running callstack sumulation");

    for (_idx, el) in callstack_with_aux_data.full_history.iter().cloned().enumerate() {
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

                let range_of_interest = (begin_at_cycle+1)..=end_cycle; // begin_at_cycle is formally bound to the previous one
                let frame_action_span = cycle_into_flat_sequence_index.range(range_of_interest);
                for (cycle, (_forward_pointer, rollback_pointer)) in frame_action_span {
                    // always add to the forward
                    let new_forward_tail = chain_of_states[*_forward_pointer].2.1;
                    if new_forward_tail != current_storage_log_state.forward_tail {
                        // edge case of double data on fram boudary, reword later
                        current_storage_log_state.forward_tail = new_forward_tail;
                        current_storage_log_state.forward_length += 1;
                    }

                    // if there is a rollback then let's process it too

                    if let Some(rollback_pointer) = rollback_pointer {
                        let new_rollback_head = chain_of_states[*rollback_pointer].2.0;
                        current_storage_log_state.rollback_head = new_rollback_head;
                        current_storage_log_state.rollback_length += 1;
                    } else {
                        // we didn't in fact rollback, but it nevertheless can be counted as formal rollback
                    }

                    let previous = history_of_storage_log_states.insert(*cycle, current_storage_log_state);
                    if !previous.is_none() {
                        assert_eq!(previous.unwrap(), current_storage_log_state, "duplicate divergence for cycle {}: previous is {:?}, new is {:?}", cycle, previous.unwrap(), current_storage_log_state)
                    }
                    // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", *cycle, previous.unwrap(), current_storage_log_state);
                }

                // dump it into the entry and dump entry into simulator

                let entry = ExtendedCallstackEntry::<F> {
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
            },
            CallstackAction::PopFromStack { panic } => {
                // an item that was in the stack becomes current
                assert!(state_to_merge.is_some());

                let (claimed_panic, state_to_merge) = state_to_merge.take().unwrap();
                assert_eq!(panic, claimed_panic);

                let popped_state = storage_logs_states_stack.pop().unwrap();
            
                // we can get a witness for a circuit
                let (entry, intermediate_info) =
                    callstack_argebraic_simulator.pop_and_output_intermediate_data(round_function);

                assert_eq!(entry.rollback_queue_head, popped_state.rollback_head, "divergence at frame {}", frame_index);
                assert_eq!(entry.rollback_queue_tail, popped_state.rollback_tail, "divergence at frame {}", frame_index);
                assert_eq!(entry.rollback_queue_segment_length, popped_state.rollback_length, "divergence at frame {}", frame_index);

                current_storage_log_state = popped_state;
                current_storage_log_state.frame_idx = frame_index;
                current_storage_log_state.forward_tail = state_to_merge.forward_tail;
                assert!(current_storage_log_state.forward_length <= state_to_merge.forward_length, "divergence at frame {}", frame_index);
                current_storage_log_state.forward_length = state_to_merge.forward_length;

                if panic {
                    assert_eq!(current_storage_log_state.forward_tail, state_to_merge.rollback_head, "divergence at frame {} with panic: {:?}", frame_index, el);

                    current_storage_log_state.forward_tail = state_to_merge.rollback_tail;
                    current_storage_log_state.forward_length += state_to_merge.rollback_length;
                } else {
                    assert_eq!(current_storage_log_state.rollback_head, state_to_merge.rollback_tail, "divergence at frame {} without panic: {:?}", frame_index, el);
                    current_storage_log_state.rollback_head = state_to_merge.rollback_head;
                    current_storage_log_state.rollback_length += state_to_merge.rollback_length;
                }

                let beginning_cycle = el.beginning_cycle;

                let previous = history_of_storage_log_states.insert(beginning_cycle, current_storage_log_state);
                if !previous.is_none() {
                    assert_eq!(previous.unwrap(), current_storage_log_state, "duplicate divergence for cycle {}: previous is {:?}, new is {:?}", beginning_cycle, previous.unwrap(), current_storage_log_state)
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
                callstack_sponge_encoding_ranges.push((beginning_cycle, intermediate_info.new_state));
            },
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // we already identified initial rollback tails for new frames
                let rollback_tail = frame_rollback_tails[&frame_index];
                // do not reset forward length as it's easy to merge
                current_storage_log_state.frame_idx = frame_index;
                current_storage_log_state.rollback_length = 0;
                current_storage_log_state.rollback_head = rollback_tail;
                current_storage_log_state.rollback_tail = rollback_tail;

                let cycle = el.beginning_cycle;

                let previous = history_of_storage_log_states.insert(cycle, current_storage_log_state);
                if !previous.is_none() {
                    // ensure that basic properties hold: we replace the current frame with a new one, so
                    // it should have large frame_idx and the same forward tail and length
                    let previous = previous.unwrap();
                    assert!(previous.frame_idx < current_storage_log_state.frame_idx, "frame divergence for cycle {}: previous is {:?}, new is {:?}", cycle, previous, current_storage_log_state);
                    assert_eq!(previous.forward_tail, current_storage_log_state.forward_tail, "frame divergence for cycle {}: previous is {:?}, new is {:?}", cycle, previous, current_storage_log_state);
                    assert_eq!(previous.forward_length, current_storage_log_state.forward_length, "frame divergence for cycle {}: previous is {:?}, new is {:?}", cycle, previous, current_storage_log_state);
                }
                // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", cycle, previous.unwrap(), current_storage_log_state);
            },
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic }) => {
                // we are not too interested, frame just ends, and all the storage log logic was resolved before it

                assert!(state_to_merge.is_none());

                let begin_at_cycle = el.beginning_cycle;
                let end_cycle = el.end_cycle.expect("frame must end");

                let range_of_interest = (begin_at_cycle+1)..=end_cycle; // begin_at_cycle is formally bound to the previous one
                let frame_action_span = cycle_into_flat_sequence_index.range(range_of_interest);
                for (cycle, (_forward_pointer, rollback_pointer)) in frame_action_span {
                    // always add to the forward
                    let new_forward_tail = chain_of_states[*_forward_pointer].2.1;
                    if new_forward_tail != current_storage_log_state.forward_tail {
                        // edge case of double data on fram boudary, reword later
                        current_storage_log_state.forward_tail = new_forward_tail;
                        current_storage_log_state.forward_length += 1;
                    }

                    // if there is a rollback then let's process it too

                    if let Some(rollback_pointer) = rollback_pointer {
                        let new_rollback_head = chain_of_states[*rollback_pointer].2.0;
                        current_storage_log_state.rollback_head = new_rollback_head;
                        current_storage_log_state.rollback_length += 1;
                    }

                    let previous = history_of_storage_log_states.insert(*cycle, current_storage_log_state);
                    if !previous.is_none() {
                        assert_eq!(previous.unwrap(), current_storage_log_state, "duplicate divergence for cycle {}: previous is {:?}, new is {:?}", cycle, previous.unwrap(), current_storage_log_state)
                    }

                    // assert!(previous.is_none(), "duplicate for cycle {}: previous is {:?}, new is {:?}", *cycle, previous.unwrap(), current_storage_log_state);
                }

                state_to_merge = Some((panic, current_storage_log_state));
            }
        }
    }



    // we simulate a series of actions on the stack starting from the outermost frame
    // each history record contains an information on what was the stack state between points
    // when it potentially came into and out of scope

    let mut artifacts = FullBlockArtifacts::<F>::default();
    artifacts.vm_memory_queries_accumulated = vm_memory_queries_accumulated;
    artifacts.all_decommittment_queries = decommittment_queries;
    artifacts.keccak_round_function_witnesses = keccak_round_function_witnesses;
    artifacts.sha256_round_function_witnesses = sha256_round_function_witnesses;
    artifacts.ecrecover_witnesses = ecrecover_witnesses;
    artifacts.original_log_queue = original_log_queue;
    artifacts.original_log_queue_simulator = original_log_queue_simulator.unwrap_or(LogQueueSimulator::empty());
    artifacts.original_log_queue_states = original_log_queue_states;

    artifacts.demuxed_rollup_storage_queries = demuxed_rollup_storage_queries;
    artifacts.demuxed_porter_storage_queries = demuxed_porter_storage_queries;
    artifacts.demuxed_event_queries = demuxed_event_queries;
    artifacts.demuxed_to_l1_queries = demuxed_to_l1_queries;
    artifacts.demuxed_keccak_precompile_queries = demuxed_keccak_precompile_queries;
    artifacts.demuxed_sha256_precompile_queries = demuxed_sha256_precompile_queries;
    artifacts.demuxed_ecrecover_queries = demuxed_ecrecover_queries;

    tracing::debug!("Processing artifacts queue");

    artifacts.process(round_function, geometry, tree, num_non_deterministic_heap_queries);

    artifacts.special_initial_decommittment_queries = vec![entry_point_decommittment_query];

    // NOTE: here we have all the queues processed in the `process` function (actual pushing is done), so we can
    // just read from the corresponding states

    let mut all_instances_witnesses = vec![];

    let initial_cycle = vm_snapshots[0].at_cycle;

    // first decommittment query (for bootlaoder) must come before the beginning of time
    let decommittment_queue_states_before_start: Vec<_> = artifacts.all_decommittment_queue_states.iter()
        .take_while(
            |el| el.0 < initial_cycle
        ).collect();

    assert!(decommittment_queue_states_before_start.len() == 1);

    tracing::debug!("Processing VM snapshots queue (total {:?})", vm_snapshots.windows(2).len());

    for (_circuit_idx, pair) in vm_snapshots.windows(2).enumerate() {
        let initial_state = &pair[0];
        let final_state = &pair[1];

        // println!("Operating over range {:?}", initial_state.at_cycle..final_state.at_cycle);

        // we need to get chunks of
        // - memory read witnesses
        // - storage read witnesses
        // - decommittment witnesses
        // - callstack witnesses
        // - rollback queue witnesses

        // first find the memory witness by scanning all the known states
        // and finding the latest one with cycle index < current

        let memory_queue_state_for_entry = artifacts.vm_memory_queue_states.iter()
            .take_while(
                |el| el.0 < initial_state.at_cycle
            )
            .last()
            .map(|el| transform_sponge_like_queue_state(el.2))
            .unwrap_or(QueueState::placeholder_witness());

        let decommittment_queue_state_for_entry = artifacts.all_decommittment_queue_states.iter()
            .take_while(
                |el| el.0 < initial_state.at_cycle
            )
            .last()
            .map(|el| transform_sponge_like_queue_state(el.1))
            .unwrap_or(QueueState::placeholder_witness());

        // and finally we need the callstack current state

        let callstack_state_for_entry = callstack_sponge_encoding_ranges.iter()
            // .skip_while(
            //     |el| el.0 < initial_state.at_cycle
            // )
            .take_while(
                |el| el.0 < initial_state.at_cycle
            )
            .last()
            .map(|el| el.1)
            .unwrap_or([F::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]);

        // initial state is kind of done, now
        // split the oracle witness

        let mut per_instance_memory_read_witnesses = Vec::with_capacity(1 << 16);
        let mut per_instance_memory_write_witnesses = Vec::with_capacity(1 << 16);
        for (k, v) in memory_read_witness.range(initial_state.at_cycle..final_state.at_cycle) {
            for el in v.iter().cloned() {
                per_instance_memory_read_witnesses.push((*k, el));
            }
        }
        for (k, v) in memory_write_witness.range(initial_state.at_cycle..final_state.at_cycle) {
            for el in v.iter().cloned() {
                per_instance_memory_write_witnesses.push((*k, el));
            }
        }

        let per_instance_storage_queries_witnesses: Vec<_> = storage_queries.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .cloned()
            .collect();

        let per_instance_refund_logs: Vec<_> = refunds_logs.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .cloned()
            .collect();

        let decommittment_requests_witness: Vec<_> = artifacts.all_decommittment_queries.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .map(|el| (el.0, el.1))
            .collect();

        let rollback_queue_initial_tails_for_new_frames: Vec<_> = rollback_queue_initial_tails_for_new_frames.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .cloned()
            .collect();

        let callstack_values_witnesses = callstack_values_witnesses.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .cloned()
            .collect();

        let rollback_queue_head_segments = rollback_queue_head_segments.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .cloned()
            .collect();

        let callstack_new_frames_witnesses = callstack_with_aux_data.flat_new_frames_history.iter()
            .skip_while(
                |el| el.0 < initial_state.at_cycle
            )
            .take_while(
                |el| el.0 < final_state.at_cycle
            )
            .cloned()
            .collect();

        // construct an oracle
        let witness_oracle = VmWitnessOracle::<F> {
            memory_read_witness: per_instance_memory_read_witnesses.into(),
            memory_write_witness: Some(per_instance_memory_write_witnesses.into()),
            rollback_queue_head_segments,
            decommittment_requests_witness: decommittment_requests_witness.into(),
            rollback_queue_initial_tails_for_new_frames: rollback_queue_initial_tails_for_new_frames.into(),
            storage_queries: per_instance_storage_queries_witnesses.into(),
            storage_refund_queries: per_instance_refund_logs.into(),
            callstack_values_witnesses,
            callstack_new_frames_witnesses,
        };

        let range = history_of_storage_log_states.range(..initial_state.at_cycle);
        let storage_log_queue_detailed_state_for_entry = range.last().map(|el| el.1).copied().unwrap_or({
            let mut initial = StorageLogDetailedState::default();
            initial.rollback_tail = global_end_of_storage_log;
            initial.rollback_head = global_end_of_storage_log;

            initial
        });

        let storage_log_queue_state_for_entry = QueueStateWitness {
            head: [F::ZERO; QUEUE_STATE_WIDTH],
            tail: QueueTailStateWitness {
                tail: storage_log_queue_detailed_state_for_entry.forward_tail,
                length: storage_log_queue_detailed_state_for_entry.forward_length,
            },
        };

        // for current head it's a little bit more complex, as we need to find 

        let instance_witness = VmInstanceWitness {
            initial_state: initial_state.local_state.clone(),
            witness_oracle,
            auxilary_initial_parameters: VmInCircuitAuxilaryParameters {
                callstack_state: (callstack_state_for_entry, initial_state.local_state.callstack.get_current_stack().clone()),
                decommittment_queue_state: decommittment_queue_state_for_entry,
                memory_queue_state: memory_queue_state_for_entry,
                storage_log_queue_state: storage_log_queue_state_for_entry,
                current_frame_rollback_queue_tail: storage_log_queue_detailed_state_for_entry.rollback_tail,
                current_frame_rollback_queue_head: storage_log_queue_detailed_state_for_entry.rollback_head,
                current_frame_rollback_queue_segment_length: storage_log_queue_detailed_state_for_entry.rollback_length,
            },
            cycles_range: initial_state.at_cycle..final_state.at_cycle,
            final_state: final_state.local_state.clone(),
            auxilary_final_parameters: VmInCircuitAuxilaryParameters::default(), // we will use next circuit's initial as final here!
        };

        all_instances_witnesses.push(instance_witness);
    }

    // make final states of each instance to be an initial state of the next one (actually backwards)

    for idx in 0..(all_instances_witnesses.len() - 1) {
        let initial_aux_of_next = all_instances_witnesses[idx+1].auxilary_initial_parameters.clone();

        all_instances_witnesses[idx].auxilary_final_parameters = initial_aux_of_next;
    }

    // special pass for the last one 
    {
        let final_state = vm_snapshots.last().unwrap();
        let last = all_instances_witnesses.last_mut().unwrap();

        // always an empty one
        last.auxilary_final_parameters.callstack_state = (
            [F::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH],
            final_state.local_state.callstack.get_current_stack().clone()
        );

        let final_memory_queue_state = artifacts.vm_memory_queue_states
        .last()
            .map(|el| transform_sponge_like_queue_state(el.2))
            .unwrap_or(QueueState::placeholder_witness());

        let final_decommittment_queue_state = artifacts.all_decommittment_queue_states.iter()
            .last()
            .map(|el| transform_sponge_like_queue_state(el.1))
            .unwrap_or(QueueState::placeholder_witness());

        let range = history_of_storage_log_states.range(..);
        let latest_log_queue_state = range.last().map(|el| el.1).copied().unwrap_or(StorageLogDetailedState::default());

        let final_storage_log_queue_state = QueueStateWitness {
            head: [F::ZERO; QUEUE_STATE_WIDTH],
            tail: QueueTailStateWitness {
                tail: latest_log_queue_state.forward_tail,
                length: latest_log_queue_state.forward_length,
            },
        };

        last.auxilary_final_parameters.decommittment_queue_state = final_decommittment_queue_state;
        last.auxilary_final_parameters.memory_queue_state = final_memory_queue_state;
        last.auxilary_final_parameters.storage_log_queue_state = final_storage_log_queue_state;
        last.auxilary_final_parameters.current_frame_rollback_queue_tail = latest_log_queue_state.rollback_tail;
        last.auxilary_final_parameters.current_frame_rollback_queue_head = latest_log_queue_state.rollback_head;
        last.auxilary_final_parameters.current_frame_rollback_queue_segment_length = latest_log_queue_state.rollback_length;
    }

    // quick and dirty check that we properly transfer registers
    for pair in all_instances_witnesses.windows(2) {
        for (o, i) in pair[0].final_state.registers.iter().zip(pair[1].initial_state.registers.iter()) {
            assert_eq!(o, i);
        }
    }

    (all_instances_witnesses, artifacts)
}

use crate::INITIAL_MONOTONIC_CYCLE_COUNTER;
use zkevm_circuits::main_vm::witness_oracle::MemoryWitness;
use zkevm_circuits::base_structures::memory_query::MemoryQueryWitness;
use zkevm_circuits::base_structures::log_query::LogQueryWitness;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecordWitness;
use zkevm_circuits::base_structures::decommit_query::DecommitQueryWitness;

impl<F: SmallField> WitnessOracle<F> for VmWitnessOracle<F> {
    fn get_memory_witness_for_read(
        &mut self,
        timestamp: u32,
        memory_page: u32,
        index: u32,
        execute: bool,
    ) -> MemoryWitness {
        if execute {
            if self.memory_read_witness.is_empty() {
                panic!(
                    "should have a witness to read at timestamp {}, page {}, index {}",
                    timestamp,
                    memory_page,
                    index,
                );
            }
            let (_cycle, query) = self.memory_read_witness.pop_front().unwrap();

            // tracing::debug!("Query value = 0x{:064x}", query.value);
            assert_eq!(
                timestamp,
                query.timestamp.0,
                "invalid memory access location at cycle {:?}: VM asks at timestamp {}, witness has timestamp {}. Page = {}, index = {}, query = {:?}",
                _cycle,
                timestamp,
                query.timestamp.0,
                memory_page,
                index,
                query,
            );

            assert_eq!(
                memory_page,
                query.location.page.0,
                "invalid memory access location at timestamp {:?}: VM asks for page {}, witness has page {}",
                timestamp,
                memory_page,
                query.location.page.0,
            );
            assert_eq!(
                index,
                query.location.index.0,
                "invalid memory access location at timestamp {:?}: VM asks for index {}, witness has index {}",
                timestamp,
                index,
                query.location.index.0,
            );

            // tracing::debug!("memory word = 0x{:x}", query.value);

            MemoryWitness {
                value: query.value,
                is_ptr: query.value_is_pointer,
            }
        } else {
            MemoryWitness {
                value: U256::zero(),
                is_ptr: false,
            }
        }
    }
    fn push_memory_witness(
        &mut self, 
        memory_query: &MemoryQueryWitness<F>,
        execute: bool
    ) {
        if let Some(write_witness) = self.memory_write_witness.as_mut() {
            if execute {
                let wit = memory_query;

                if write_witness.is_empty() {
                    panic!(
                        "should have a self-check witness to write at timestamp {}, page {}, index {}",
                        wit.timestamp,
                        wit.memory_page,
                        wit.index,
                    );
                }
                let (_cycle, query) = write_witness.pop_front().unwrap();

                assert_eq!(
                    wit.timestamp,
                    query.timestamp.0,
                    "invalid memory access location at timestamp {:?}: VM writes into timestamp {}, witness has timestamp {}",
                    wit.timestamp,
                    wit.timestamp,
                    query.timestamp.0,
                );

                assert_eq!(
                    wit.memory_page,
                    query.location.page.0,
                    "invalid memory access location at timestamp {:?}: VM writes into page {}, witness has page {}",
                    wit.timestamp,
                    wit.memory_page,
                    query.location.page.0,
                );

                assert_eq!(
                    wit.index,
                    query.location.index.0,
                    "invalid memory access location at timestamp {:?}: VM writes into index {}, witness has index {}",
                    wit.timestamp,
                    wit.index,
                    query.location.index.0,
                );

                // compare values
                assert_eq!(
                    wit.value,
                    query.value,
                    "invalid memory access location at timestamp {:?}: VM writes value {}, witness has value {}",
                    wit.timestamp,
                    wit.value,
                    query.value,
                );

                assert_eq!(
                    wit.is_ptr,
                    query.value_is_pointer,
                    "invalid memory access location at timestamp {:?}: VM writes pointer {}, witness has pointer {}",
                    wit.timestamp,
                    wit.is_ptr,
                    query.value_is_pointer,
                );
            }
        }
    }
    fn get_storage_read_witness(
        &mut self,
        key: &LogQueryWitness<F>,
        needs_witness: bool,
        execute: bool,
    ) -> U256 {
        if execute && needs_witness {
            if self.storage_queries.is_empty() {
                panic!(
                    "should have a witness for storage read at {:?}",
                    key
                );
            }
            let (_cycle, query) = self.storage_queries.pop_front().unwrap();

            let record = key;
            assert_eq!(record.aux_byte, query.aux_byte);
            assert_eq!(record.address, query.address);
            assert_eq!(record.key, query.key);
            assert_eq!(record.rw_flag, query.rw_flag);
            if record.rw_flag == true {
                // check written value
                assert_eq!(record.written_value, query.written_value);
            }
            assert_eq!(record.rollback, false);
            assert_eq!(record.rollback, query.rollback);
            assert_eq!(record.is_service, query.is_service);
            assert_eq!(record.shard_id, query.shard_id);
            assert_eq!(record.tx_number_in_block, query.tx_number_in_block as u32);
            assert_eq!(record.timestamp, query.timestamp.0);

            query.read_value
        } else {
            U256::zero()
        }
    }
    fn get_refunds(&mut self, query: &LogQueryWitness<F>, is_write: bool, execute: bool) -> u32 {
        if execute && is_write {
            if self.storage_refund_queries.is_empty() {
                panic!(
                    "should have a refund witness for storage write attempt at {:?}",
                    query,
                );
            }
            let (_cycle, query, refund) = self.storage_refund_queries.pop_front().unwrap();
            let record = query;
            assert_eq!(record.aux_byte, query.aux_byte);
            assert_eq!(record.address, query.address);
            assert_eq!(record.key, query.key);
            assert_eq!(record.rw_flag, query.rw_flag);
            assert!(record.rw_flag == true);
            assert_eq!(record.written_value, query.written_value);
            assert_eq!(record.rollback, false);
            assert_eq!(record.rollback, query.rollback);
            assert_eq!(record.shard_id, query.shard_id);
            // the rest are not filled in out-of-circuit implementations
            assert_eq!(record.is_service, query.is_service);

            refund
        } else {
            0u32
        }
    }
    fn push_storage_witness(&mut self, _key: &LogQueryWitness<F>, _execute: bool) {
        // logic is captured in read for a reason that we NEED
        // previous value of the cell for rollback to work
        unreachable!()
    }
    fn get_rollback_queue_witness(&mut self, _key: &LogQueryWitness<F>, execute: bool) -> [F; 4] {
        if execute {
            let (_cycle, head) = self.rollback_queue_head_segments.pop_front().unwrap();
            // dbg!(head);

            head
        } else {
            [F::ZERO; 4]
        }
    }
    fn get_rollback_queue_tail_witness_for_call(&mut self, _timestamp: u32, execute: bool)
        -> [F; 4] 
    {
        if execute {
            let (_cycle_idx, tail) = self
                .rollback_queue_initial_tails_for_new_frames
                .pop_front()
                .unwrap();
            // dbg!(tail);

            tail
        } else {
            [F::ZERO; 4]
        }
    }
    fn push_callstack_witness(
        &mut self,
        current_record: &ExecutionContextRecordWitness<F>,
        current_depth: u32,
        execute: bool,
    ) {
        // we do not care, but we can do self-check

        if execute {
            let (_cycle_idx, (extended_entry, internediate_info)) =
                self.callstack_values_witnesses.pop_front().unwrap();

            let CallstackSimulatorState {
                is_push,
                previous_state: _,
                new_state: _,
                depth: witness_depth,
                round_function_execution_pairs: _,
            } = internediate_info;
            // compare
            let witness = current_record;

            assert!(
                is_push,
                "divergence at callstack push at cycle {}:\n pushing {:?}\n in circuit, but got POP of \n{:?}\n in oracle",
                _cycle_idx,
                &witness,
                &extended_entry,
            );
            
            assert_eq!(
                current_depth + 1,
                witness_depth as u32,
                "depth diverged at callstack push at cycle {}:\n pushing {:?}\n, got \n{:?}\n in oracle",
                _cycle_idx,
                &witness,
                &extended_entry,
            );

            let ExtendedCallstackEntry {
                callstack_entry: entry,
                rollback_queue_head,
                rollback_queue_tail,
                rollback_queue_segment_length,
            } = extended_entry;

            assert_eq!(entry.this_address, witness.this);
            assert_eq!(entry.msg_sender, witness.caller);
            assert_eq!(entry.code_address, witness.code_address);

            assert_eq!(entry.code_page.0, witness.code_page);
            assert_eq!(entry.base_memory_page.0, witness.base_page);

            assert_eq!(rollback_queue_head, witness.reverted_queue_head);
            assert_eq!(rollback_queue_tail, witness.reverted_queue_tail);
            assert_eq!(rollback_queue_segment_length, witness.reverted_queue_segment_len);

            assert_eq!(entry.pc, witness.pc);
            assert_eq!(entry.sp, witness.sp);

            assert_eq!(entry.heap_bound, witness.heap_upper_bound);
            assert_eq!(entry.aux_heap_bound, witness.aux_heap_upper_bound);

            assert_eq!(entry.exception_handler_location, witness.exception_handler_loc);
            assert_eq!(entry.ergs_remaining, witness.ergs_remaining);

            assert_eq!(entry.is_static, witness.is_static_execution);
            assert_eq!(entry.is_kernel_mode(), witness.is_kernel_mode);

            assert_eq!(entry.this_shard_id, witness.this_shard_id);
            assert_eq!(entry.caller_shard_id, witness.caller_shard_id);
            assert_eq!(entry.code_shard_id, witness.code_shard_id);

            let witness_composite = [
                (witness.context_u128_value_composite[0] as u64) + ((witness.context_u128_value_composite[1] as u64) << 32),
                (witness.context_u128_value_composite[2] as u64) + ((witness.context_u128_value_composite[3] as u64) << 32),
            ];

            assert_eq!([entry.context_u128_value as u64, (entry.context_u128_value >> 64) as u64], witness_composite);

            assert_eq!(entry.is_local_frame, witness.is_local_call);
        }
    }
    fn get_callstack_witness(
        &mut self,
        execute: bool,
        depth: u32,
    ) -> (ExecutionContextRecordWitness<F>, [F; 12]) {
        if execute {
            let (_cycle_idx, (extended_entry, internediate_info)) =
                self.callstack_values_witnesses.pop_front().unwrap();
            let CallstackSimulatorState {
                is_push,
                previous_state: _,
                new_state,
                depth: witness_depth,
                round_function_execution_pairs: _,
            } = internediate_info;

            assert!(
                !is_push,
                "divergence at callstack pop at cycle {}: POP in circuit, but got PUSH of \n{:?}\n in oracle",
                _cycle_idx,
                &extended_entry,
            );
            
            assert_eq!(
                depth - 1,
                witness_depth as u32,
                "depth diverged at callstack pop at cycle {}, got \n{:?}\n in oracle",
                _cycle_idx,
                &extended_entry,
            );

            // dbg!(new_state);

            let ExtendedCallstackEntry {
                callstack_entry: entry,
                rollback_queue_head,
                rollback_queue_tail,
                rollback_queue_segment_length,
            } = extended_entry;

            let witness = ExecutionContextRecordWitness {
                this: entry.this_address,
                caller: entry.msg_sender,
                code_address: entry.code_address,
                code_page: entry.code_page.0,
                base_page: entry.base_memory_page.0,
                reverted_queue_head: rollback_queue_head,
                reverted_queue_tail: rollback_queue_tail,
                reverted_queue_segment_len: rollback_queue_segment_length,
                pc: entry.pc,
                sp: entry.sp,
                exception_handler_loc: entry.exception_handler_location,
                ergs_remaining: entry.ergs_remaining,
                is_static_execution: entry.is_static,
                is_kernel_mode: entry.is_kernel_mode(),
                this_shard_id: entry.this_shard_id,
                caller_shard_id: entry.caller_shard_id,
                code_shard_id: entry.code_shard_id,
                context_u128_value_composite: [
                    entry.context_u128_value as u32, 
                    (entry.context_u128_value >> 32) as u32,
                    (entry.context_u128_value >> 64) as u32,
                    (entry.context_u128_value >> 96) as u32,
                ],
                heap_upper_bound: entry.heap_bound,
                aux_heap_upper_bound: entry.aux_heap_bound,
                is_local_call: entry.is_local_frame,
            };

            (witness, new_state)
        } else {
            use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;

            (
                ExecutionContextRecord::placeholder_witness(),
                [F::ZERO; 12],
            )
        }
    }
    fn report_new_callstack_frame(
        &mut self,
        new_record: &ExecutionContextRecordWitness<F>,
        new_depth: u32,
        is_call: bool,
        execute: bool,
    ) {
        if execute && is_call {
            let (_cycle_idx, entry) = 
                self.callstack_new_frames_witnesses.pop_front().unwrap();

            // compare
            let witness = new_record;

            assert_eq!(entry.this_address, witness.this);
            assert_eq!(entry.msg_sender, witness.caller);
            assert_eq!(entry.code_address, witness.code_address);

            assert_eq!(entry.code_page.0, witness.code_page);
            assert_eq!(entry.base_memory_page.0, witness.base_page);

            assert_eq!(entry.pc, witness.pc);
            assert_eq!(entry.sp, witness.sp);

            assert_eq!(entry.heap_bound, witness.heap_upper_bound);
            assert_eq!(entry.aux_heap_bound, witness.aux_heap_upper_bound);

            assert_eq!(entry.exception_handler_location, witness.exception_handler_loc);
            assert_eq!(entry.ergs_remaining, witness.ergs_remaining);

            assert_eq!(entry.is_static, witness.is_static_execution);
            assert_eq!(entry.is_kernel_mode(), witness.is_kernel_mode);

            assert_eq!(entry.this_shard_id, witness.this_shard_id);
            assert_eq!(entry.caller_shard_id, witness.caller_shard_id);
            assert_eq!(entry.code_shard_id, witness.code_shard_id);

            assert_eq!(crate::utils::u128_as_u32_le(entry.context_u128_value), witness.context_u128_value_composite);

            assert_eq!(entry.is_local_frame, witness.is_local_call);
        }
    }
    fn get_decommittment_request_suggested_page(
        &mut self,
        request: &DecommitQueryWitness<F>,
        execute: bool,
    ) -> u32 {
        if execute {
            if self.decommittment_requests_witness.is_empty() {
                panic!("Witness value is missing for {:?}", request);
            }

            let (_frame_idx, query) = self
                .decommittment_requests_witness
                .pop_front()
                .unwrap_or_else(|| {
                    panic!("Witness value is missing for {:?}", request);
                });

            assert_eq!(request.timestamp, query.timestamp.0);
            assert!(request.code_hash == query.hash, "circuit expected hash 0x{:064x}, while witness had 0x{:064x}", request.code_hash, query.hash);

            query.memory_page.0
        } else {
            0
        }
    }
    fn at_completion(self) {
        if self.memory_read_witness.is_empty() == false {
            panic!("Too many memory queries in witness: have left\n{:?}", self.memory_read_witness);
        }

        if let Some(memory_write_witness) = self.memory_write_witness {
            if memory_write_witness.is_empty() == false {
                panic!("Too many memory write queries in witness: have left\n{:?}", memory_write_witness);
            }
        }

        if self.storage_queries.is_empty() == false {
            panic!("Too many storage queries in witness: have left\n{:?}", self.storage_queries);
        }

        if self.storage_refund_queries.is_empty() == false {
            panic!("Too many storage queries for refunds in witness: have left\n{:?}", self.storage_refund_queries);
        }

        if self.callstack_values_witnesses.is_empty() == false {
            panic!("Too many callstack sponge witnesses: have left\n{:?}", self.callstack_values_witnesses);
        }

        if self.decommittment_requests_witness.is_empty() == false {
            panic!("Too many decommittment request witnesses: have left\n{:?}", self.decommittment_requests_witness);
        }

        if self.rollback_queue_head_segments.is_empty() == false {
            panic!("Too many rollback queue heads in witnesses: have left\n{:?}", self.rollback_queue_head_segments);
        }

        if self.rollback_queue_initial_tails_for_new_frames.is_empty() == false {
            panic!("Too many rollback queue heads new stack frames in witnesses: have left\n{:?}", self.rollback_queue_initial_tails_for_new_frames);
        }
    }
}
