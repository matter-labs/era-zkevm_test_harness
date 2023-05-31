// implement witness oracle to actually compute
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use super::callstack_handler::*;
use super::utils::*;
use crate::encodings::callstack_entry::{CallstackSimulatorState, ExtendedCallstackEntry};
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::ethereum_types::U256;
use crate::ff::Field;
use crate::toolset::GeometryConfig;
use crate::u160_from_address;
use crate::witness::tracer::{QueryMarker, WitnessTracer};
use derivative::Derivative;
use num_bigint::BigUint;
use rayon::slice::ParallelSliceMut;
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::RangeInclusive;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueState;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueStateWitness;
use sync_vm::scheduler::queues::FullSpongeLikeQueueStateWitness;
use sync_vm::scheduler::queues::{FullSpongeLikeQueueState, QueueStateWitness};
use sync_vm::traits::CSWitnessable;
use sync_vm::vm::vm_cycle::memory::MemoryLocation;
use sync_vm::vm::vm_cycle::memory_view::write_query::MemoryWriteQuery;
use sync_vm::vm::vm_cycle::witness_oracle::{u256_to_biguint, MemoryWitness, WitnessOracle};
use sync_vm::{
    circuit_structures::traits::CircuitArithmeticRoundFunction,
    franklin_crypto::bellman::pairing::Engine,
};
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::{LogQuery, MemoryIndex, MemoryPage, MemoryQuery};
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use zk_evm::reference_impls::event_sink::ApplicationData;
use zk_evm::vm_state::{CallStackEntry, VmLocalState};

use zk_evm::zkevm_opcode_defs::system_params::{
    ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
};

use zk_evm::zkevm_opcode_defs::system_params::{
    EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
};

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
pub struct RollbackQueueStateWitness<E: Engine> {
    pub head: E::Fr,
    pub tail: E::Fr,
    pub segment_length: u32,
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Default(bound = ""), Clone(bound = ""))]
#[serde(bound = "")]
pub struct VmWitnessOracle<E: Engine> {
    pub memory_read_witness: VecDeque<(u32, MemoryQuery)>,
    pub memory_write_witness: Option<VecDeque<(u32, MemoryQuery)>>,
    pub rollback_queue_head_segments: VecDeque<(u32, E::Fr)>,
    pub decommittment_requests_witness: VecDeque<(u32, DecommittmentQuery)>,
    pub rollback_queue_initial_tails_for_new_frames: VecDeque<(u32, E::Fr)>,
    pub storage_queries: VecDeque<(u32, LogQuery)>, // cycle, query
    pub storage_refund_queries: VecDeque<(u32, LogQuery, u32)>, // cycle, query, pubdata refund
    pub callstack_new_frames_witnesses:
        VecDeque<(u32, CallStackEntry)>,
    pub callstack_values_witnesses:
        VecDeque<(u32, (ExtendedCallstackEntry<E>, CallstackSimulatorState<E>))>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default, PartialEq, Eq)]
pub struct StorageLogDetailedState<E: Engine> {
    pub frame_idx: usize,
    pub forward_tail: E::Fr,
    pub forward_length: u32,
    pub rollback_head: E::Fr,
    pub rollback_tail: E::Fr,
    pub rollback_length: u32,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug)]
pub struct VmInCircuitAuxilaryParameters<E: Engine> {
    pub callstack_state: ([E::Fr; 3], CallStackEntry),
    pub decommittment_queue_state: FullSpongeLikeQueueStateWitness<E>,
    pub memory_queue_state: FullSpongeLikeQueueStateWitness<E>,
    pub storage_log_queue_state: FixedWidthEncodingGenericQueueStateWitness<E>,
    pub current_frame_rollback_queue_tail: E::Fr,
    pub current_frame_rollback_queue_head: E::Fr,
    pub current_frame_rollback_queue_segment_length: u32,
}

impl<E: Engine> std::default::Default for VmInCircuitAuxilaryParameters<E> {
    fn default() -> Self {
        Self {
            callstack_state: ([E::Fr::zero(); 3], CallStackEntry::empty_context()),
            decommittment_queue_state: FullSpongeLikeQueueState::<E>::placeholder_witness(),
            memory_queue_state: FullSpongeLikeQueueState::<E>::placeholder_witness(),
            storage_log_queue_state: FixedWidthEncodingGenericQueueState::placeholder_witness(),
            current_frame_rollback_queue_tail: E::Fr::zero(),
            current_frame_rollback_queue_head: E::Fr::zero(),
            current_frame_rollback_queue_segment_length: 0,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone)]
pub struct VmInstanceWitness<E: Engine, O: WitnessOracle<E>> {
    // we need everything to start a circuit from this point of time

    // initial state - just copy the local state in full
    pub initial_state: VmLocalState,
    pub witness_oracle: O,
    pub auxilary_initial_parameters: VmInCircuitAuxilaryParameters<E>,
    pub cycles_range: std::ops::Range<u32>,

    // final state for test purposes
    pub final_state: VmLocalState,
    pub auxilary_final_parameters: VmInCircuitAuxilaryParameters<E>,
}

use super::full_block_artifact::FullBlockArtifacts;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct CommonLogSponges<E: Engine> {
    pub rf_0: ([E::Fr; 3], [E::Fr; 3]),
    pub rf_1: ([E::Fr; 3], [E::Fr; 3]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct ForwardLogSponge<E: Engine> {
    pub old_tail: E::Fr,
    pub new_tail: E::Fr,
    pub exclusive_rf: ([E::Fr; 3], [E::Fr; 3]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct RollbackLogSponge<E: Engine> {
    pub old_head: E::Fr,
    pub new_head: E::Fr,
    pub exclusive_rf: ([E::Fr; 3], [E::Fr; 3]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct LogAccessSpongesInfo<E: Engine> {
    pub cycle: u32,
    pub common_sponges: CommonLogSponges<E>,
    pub forward_info: ForwardLogSponge<E>,
    pub rollback_info: Option<RollbackLogSponge<E>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
struct FlattenedLogQueueIndexer<E: Engine> {
    pub current_head: E::Fr,
    pub current_tail: E::Fr,
    pub head_offset: usize,
    pub tail_offset: usize,
}

use crate::witness::tree::*;
use crate::blake2::Blake2s256;

pub fn create_artifacts_from_tracer<E: Engine, R: CircuitArithmeticRoundFunction<E, 2, 3>>(
    tracer: WitnessTracer,
    round_function: &R,
    geometry: &GeometryConfig,
    entry_point_decommittment_query: (DecommittmentQuery, Vec<U256>),
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    num_non_deterministic_heap_queries: usize,
) -> (
    Vec<VmInstanceWitness<E, VmWitnessOracle<E>>>,
    FullBlockArtifacts<E>,
) {
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

    let mut log_queue_simulator = LogQueueSimulator::<E>::empty();
    assert!(
        callstack_with_aux_data.depth == 0,
        "parent frame didn't exit"
    );

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
    let original_log_queue: Vec<_> = forward
        .iter()
        .filter(|el| match el {
            ExtendedLogQuery::Query { .. } => true,
            _ => false,
        })
        .map(|el| match el {
            ExtendedLogQuery::Query { cycle, query, .. } => (*cycle, *query),
            _ => unreachable!(),
        })
        .collect();

    let mut original_log_queue_states = vec![];
    let mut chain_of_states = vec![];
    let mut original_log_queue_simulator = None;
    let mut marker_into_queue_position_renumeration_index: HashMap<QueryMarker, usize> =
        HashMap::new();

    // we want to have some hashmap that will indicate
    // that on some specific VM cycle we either read or write

    // from cycle into first two sponges (common), then tail-tail pair and 3rd sponge for forward, then head-head pair and 3rd sponge for rollback
    let mut sponges_data: HashMap<u32, LogAccessSpongesInfo<E>> = HashMap::new();

    let mut callstack_frames_spans = std::collections::BTreeMap::new();
    let mut global_beginnings_of_frames: BTreeMap<usize, u32> = BTreeMap::new();
    let mut global_ends_of_frames: BTreeMap<usize, u32> = BTreeMap::new();
    let mut actions_in_each_frame: BTreeMap<usize, Vec<(u32, QueryMarker, usize)>> =
        BTreeMap::new();

    for el in callstack_with_aux_data.full_history.iter() {
        match el.action {
            CallstackAction::PushToStack => {
                // not imporatant, we count by the next one
            }
            CallstackAction::PopFromStack { panic: _ } => {
                // mark
                callstack_frames_spans.insert(el.beginning_cycle, el.frame_index);
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // fresh fram
                callstack_frames_spans.insert(el.beginning_cycle, el.frame_index);
                global_beginnings_of_frames.insert(el.frame_index, el.beginning_cycle);
            }
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
    let mut log_actions_spans: std::collections::BTreeMap<u32, Vec<(QueryMarker, usize)>> =
        std::collections::BTreeMap::new();
    let mut log_declarations_spans: std::collections::BTreeMap<u32, Vec<(QueryMarker, usize)>> =
        std::collections::BTreeMap::new();

    // in practice we also split out precompile accesses

    let mut unique_query_id_into_chain_positions: HashMap<u64, usize> =
        HashMap::with_capacity(num_forwards + num_rollbacks);

    tracing::debug!("Running storage log simulation");

    for (extended_query, was_applied) in forward.iter().cloned().zip(std::iter::repeat(true)).chain(
        rollbacks
            .iter()
            .rev()
            .cloned()
            .zip(std::iter::repeat(false)),
    ) {
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
            ExtendedLogQuery::Query {
                marker,
                cycle,
                query,
            } => (marker, cycle, query),
            a @ ExtendedLogQuery::FrameForwardHeadMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            }
            a @ ExtendedLogQuery::FrameForwardTailMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            }
            a @ ExtendedLogQuery::FrameRollbackHeadMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            }
            a @ ExtendedLogQuery::FrameRollbackTailMarker(..) => {
                log_position_mapping.insert(a, chain_of_states.len() as isize - 1);
                continue;
            }
        };

        let (_old_tail, intermediate_info) =
            log_queue_simulator.push_and_output_intermediate_data(query, round_function);

        let pointer = chain_of_states.len();
        // we just log all chains of old tail -> new tail, and will interpret them later
        chain_of_states.push((
            cycle,
            query_marker,
            (intermediate_info.previous_tail, intermediate_info.tail),
        ));

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
                exclusive_rf: intermediate_info.round_function_execution_pairs[2],
            };

            entry.rollback_info = Some(rollback_info);

            cycle_into_flat_sequence_index
                .get_mut(&cycle)
                .expect("rollbacks always happen after forward case")
                .1 = Some(pointer);

            match query_marker {
                QueryMarker::Rollback {
                    in_frame: _,
                    index: _,
                    cycle_of_declaration: c,
                    cycle_of_applied_rollback,
                    ..
                } => {
                    assert_eq!(cycle, c);
                    if let Some(existing) = log_declarations_spans.get_mut(&cycle) {
                        existing.push((query_marker, pointer));
                    } else {
                        log_declarations_spans.insert(cycle, vec![(query_marker, pointer)]);
                    }

                    match cycle_of_applied_rollback {
                        None => {
                            let cycle_of_applied_rollback = u32::MAX;
                            if let Some(existing) =
                                log_actions_spans.get_mut(&cycle_of_applied_rollback)
                            {
                                existing.push((query_marker, pointer));
                            } else {
                                log_actions_spans.insert(
                                    cycle_of_applied_rollback,
                                    vec![(query_marker, pointer)],
                                );
                            }
                        }
                        Some(cycle_of_applied_rollback) => {
                            // even if we re-apply, then we are ok
                            if let Some(existing) =
                                log_actions_spans.get_mut(&cycle_of_applied_rollback)
                            {
                                existing.push((query_marker, pointer));
                            } else {
                                log_actions_spans.insert(
                                    cycle_of_applied_rollback,
                                    vec![(query_marker, pointer)],
                                );
                            }
                        }
                    }
                }
                a @ _ => {
                    unreachable!("encounteted {:?}", a)
                }
            }
        } else {
            let entry = sponges_data.entry(key).or_default();

            let common_sponges_info = CommonLogSponges {
                rf_0: intermediate_info.round_function_execution_pairs[0],
                rf_1: intermediate_info.round_function_execution_pairs[1],
            };

            let forward_info = ForwardLogSponge {
                old_tail: intermediate_info.previous_tail,
                new_tail: intermediate_info.tail,
                exclusive_rf: intermediate_info.round_function_execution_pairs[2],
            };

            entry.cycle = cycle;
            entry.common_sponges = common_sponges_info;
            entry.forward_info = forward_info;

            cycle_into_flat_sequence_index.entry(cycle).or_default().0 = pointer;

            match query_marker {
                QueryMarker::Forward {
                    in_frame: _,
                    index: _,
                    cycle: c,
                    ..
                } => {
                    assert_eq!(cycle, c);
                    if let Some(existing) = log_declarations_spans.get_mut(&cycle) {
                        existing.push((query_marker, pointer));
                    } else {
                        log_declarations_spans.insert(cycle, vec![(query_marker, pointer)]);
                    }
                    log_actions_spans.insert(cycle, vec![(query_marker, pointer)]);
                }
                QueryMarker::ForwardNoRollback {
                    in_frame: _,
                    index: _,
                    cycle: c,
                    ..
                } => {
                    assert_eq!(cycle, c);
                    if let Some(existing) = log_declarations_spans.get_mut(&cycle) {
                        existing.push((query_marker, pointer));
                    } else {
                        log_declarations_spans.insert(cycle, vec![(query_marker, pointer)]);
                    }
                    log_actions_spans.insert(cycle, vec![(query_marker, pointer)]);
                }
                a @ _ => {
                    unreachable!("encounteted {:?}", a)
                }
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
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    use super::callstack_handler::CallstackAction;
    use crate::encodings::callstack_entry::CallstackSimulator;
    let mut callstack_argebraic_simulator = CallstackSimulator::<E>::empty();
    let mut callstack_values_witnesses = vec![]; // index of cycle -> witness for callstack
                                                 // we need to simultaneously follow the logic of pushes/joins of the storage queues,
                                                 // and encoding of the current callstack state as the sponge state

    // here we are interested in "frozen" elements that are in the stack,
    // so we never follow the "current", but add on push/pop

    // These are "frozen" states that just lie in the callstack for now and can not be modified
    let mut callstack_sponge_encoding_ranges = vec![];
    // pretend initial state
    callstack_sponge_encoding_ranges.push((0, [E::Fr::zero(); 3]));

    // we need some information that spans the whole number of cycles with "what is a frame counter at this time"

    // we have all the spans of when each frame is active, so we can
    // - simulate what is saved and when
    // - get witnesses for heads when encountering the new spans

    let global_end_of_storage_log = chain_of_states
        .last()
        .map(|el| el.2 .1)
        .unwrap_or(E::Fr::zero());
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
            let element = chain_of_states[pointer].2 .1;

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

    let mut rollback_queue_head_segments: Vec<(u32, E::Fr)> = vec![];

    for (cycle, (_forward, rollback)) in cycle_into_flat_sequence_index.iter() {
        if let Some(pointer) = rollback {
            let state = &chain_of_states[*pointer];
            rollback_queue_head_segments.push((*cycle, state.2 .0));
        }
    }

    let mut history_of_storage_log_states = BTreeMap::new();

    // we start with no rollbacks, but non-trivial tail
    let mut current_storage_log_state = StorageLogDetailedState::<E>::default();
    current_storage_log_state.rollback_head = global_end_of_storage_log;
    current_storage_log_state.rollback_tail = global_end_of_storage_log;

    let mut storage_logs_states_stack = vec![];

    let mut state_to_merge: Option<(bool, StorageLogDetailedState<E>)> = None;

    // and now do trivial simulation

    tracing::debug!("Running callstack sumulation");

    for (_idx, el) in callstack_with_aux_data
        .full_history
        .iter()
        .cloned()
        .enumerate()
    {
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
                let frame_action_span = cycle_into_flat_sequence_index.range(range_of_interest);
                for (cycle, (_forward_pointer, rollback_pointer)) in frame_action_span {
                    // always add to the forward
                    let new_forward_tail = chain_of_states[*_forward_pointer].2 .1;
                    if new_forward_tail != current_storage_log_state.forward_tail {
                        // edge case of double data on fram boudary, reword later
                        current_storage_log_state.forward_tail = new_forward_tail;
                        current_storage_log_state.forward_length += 1;
                    }

                    // if there is a rollback then let's process it too

                    if let Some(rollback_pointer) = rollback_pointer {
                        let new_rollback_head = chain_of_states[*rollback_pointer].2 .0;
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

                let entry = ExtendedCallstackEntry::<E> {
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
                let rollback_tail = frame_rollback_tails[&frame_index];
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
                let frame_action_span = cycle_into_flat_sequence_index.range(range_of_interest);
                for (cycle, (_forward_pointer, rollback_pointer)) in frame_action_span {
                    // always add to the forward
                    let new_forward_tail = chain_of_states[*_forward_pointer].2 .1;
                    if new_forward_tail != current_storage_log_state.forward_tail {
                        // edge case of double data on fram boudary, reword later
                        current_storage_log_state.forward_tail = new_forward_tail;
                        current_storage_log_state.forward_length += 1;
                    }

                    // if there is a rollback then let's process it too

                    if let Some(rollback_pointer) = rollback_pointer {
                        let new_rollback_head = chain_of_states[*rollback_pointer].2 .0;
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

    // we simulate a series of actions on the stack starting from the outermost frame
    // each history record contains an information on what was the stack state between points
    // when it potentially came into and out of scope

    let mut artifacts = FullBlockArtifacts::<E>::default();
    artifacts.vm_memory_queries_accumulated = vm_memory_queries_accumulated;
    artifacts.all_decommittment_queries = decommittment_queries;
    artifacts.keccak_round_function_witnesses = keccak_round_function_witnesses;
    artifacts.sha256_round_function_witnesses = sha256_round_function_witnesses;
    artifacts.ecrecover_witnesses = ecrecover_witnesses;
    artifacts.original_log_queue = original_log_queue;
    artifacts.original_log_queue_simulator =
        original_log_queue_simulator.unwrap_or(LogQueueSimulator::empty());
    artifacts.original_log_queue_states = original_log_queue_states;

    artifacts.demuxed_rollup_storage_queries = demuxed_rollup_storage_queries;
    artifacts.demuxed_porter_storage_queries = demuxed_porter_storage_queries;
    artifacts.demuxed_event_queries = demuxed_event_queries;
    artifacts.demuxed_to_l1_queries = demuxed_to_l1_queries;
    artifacts.demuxed_keccak_precompile_queries = demuxed_keccak_precompile_queries;
    artifacts.demuxed_sha256_precompile_queries = demuxed_sha256_precompile_queries;
    artifacts.demuxed_ecrecover_queries = demuxed_ecrecover_queries;

    tracing::debug!("Processing artifacts queue");

    artifacts.process(
        round_function,
        geometry,
        tree,
        num_non_deterministic_heap_queries,
    );

    artifacts.special_initial_decommittment_queries = vec![entry_point_decommittment_query];

    // NOTE: here we have all the queues processed in the `process` function (actual pushing is done), so we can
    // just read from the corresponding states

    let mut all_instances_witnesses = vec![];

    let initial_cycle = vm_snapshots[0].at_cycle;

    // first decommittment query (for bootlaoder) must come before the beginning of time
    let decommittment_queue_states_before_start: Vec<_> = artifacts
        .all_decommittment_queue_states
        .iter()
        .take_while(|el| el.0 < initial_cycle)
        .collect();

    assert!(decommittment_queue_states_before_start.len() == 1);

    tracing::debug!(
        "Processing VM snapshots queue (total {:?})",
        vm_snapshots.windows(2).len()
    );

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

        let memory_queue_state_for_entry = artifacts
            .vm_memory_queue_states
            .iter()
            .take_while(|el| el.0 < initial_state.at_cycle)
            .last()
            .map(|el| transform_sponge_like_queue_state(el.2))
            .unwrap_or(FullSpongeLikeQueueState::<E>::placeholder_witness());

        let decommittment_queue_state_for_entry = artifacts
            .all_decommittment_queue_states
            .iter()
            .take_while(|el| el.0 < initial_state.at_cycle)
            .last()
            .map(|el| transform_sponge_like_queue_state(el.1))
            .unwrap_or(FullSpongeLikeQueueState::<E>::placeholder_witness());

        // and finally we need the callstack current state

        let callstack_state_for_entry = callstack_sponge_encoding_ranges
            .iter()
            // .skip_while(
            //     |el| el.0 < initial_state.at_cycle
            // )
            .take_while(|el| el.0 < initial_state.at_cycle)
            .last()
            .map(|el| el.1)
            .unwrap_or([E::Fr::zero(); 3]);

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

        let per_instance_storage_queries_witnesses: Vec<_> = storage_queries
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        let per_instance_refund_logs: Vec<_> = refunds_logs
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        let decommittment_requests_witness: Vec<_> = artifacts
            .all_decommittment_queries
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .map(|el| (el.0, el.1))
            .collect();

        let rollback_queue_initial_tails_for_new_frames: Vec<_> =
            rollback_queue_initial_tails_for_new_frames
                .iter()
                .skip_while(|el| el.0 < initial_state.at_cycle)
                .take_while(|el| el.0 < final_state.at_cycle)
                .cloned()
                .collect();

        let callstack_values_witnesses = callstack_values_witnesses
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
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
        let witness_oracle = VmWitnessOracle::<E> {
            memory_read_witness: per_instance_memory_read_witnesses.into(),
            memory_write_witness: Some(per_instance_memory_write_witnesses.into()),
            rollback_queue_head_segments,
            decommittment_requests_witness: decommittment_requests_witness.into(),
            rollback_queue_initial_tails_for_new_frames:
                rollback_queue_initial_tails_for_new_frames.into(),
            storage_queries: per_instance_storage_queries_witnesses.into(),
            storage_refund_queries: per_instance_refund_logs.into(),
            callstack_values_witnesses,
            callstack_new_frames_witnesses,
        };

        let range = history_of_storage_log_states.range(..initial_state.at_cycle);
        let storage_log_queue_detailed_state_for_entry =
            range.last().map(|el| el.1).copied().unwrap_or({
                let mut initial = StorageLogDetailedState::default();
                initial.rollback_tail = global_end_of_storage_log;
                initial.rollback_head = global_end_of_storage_log;

                initial
            });

        let storage_log_queue_state_for_entry = FixedWidthEncodingGenericQueueStateWitness::<E> {
            num_items: storage_log_queue_detailed_state_for_entry.forward_length,
            head_state: E::Fr::zero(),
            tail_state: storage_log_queue_detailed_state_for_entry.forward_tail,
            _marker: std::marker::PhantomData,
        };

        // for current head it's a little bit more complex, as we need to find

        let instance_witness = VmInstanceWitness {
            initial_state: initial_state.local_state.clone(),
            witness_oracle,
            auxilary_initial_parameters: VmInCircuitAuxilaryParameters {
                callstack_state: (
                    callstack_state_for_entry,
                    initial_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .clone(),
                ),
                decommittment_queue_state: decommittment_queue_state_for_entry,
                memory_queue_state: memory_queue_state_for_entry,
                storage_log_queue_state: storage_log_queue_state_for_entry,
                current_frame_rollback_queue_tail: storage_log_queue_detailed_state_for_entry
                    .rollback_tail,
                current_frame_rollback_queue_head: storage_log_queue_detailed_state_for_entry
                    .rollback_head,
                current_frame_rollback_queue_segment_length:
                    storage_log_queue_detailed_state_for_entry.rollback_length,
            },
            cycles_range: initial_state.at_cycle..final_state.at_cycle,
            final_state: final_state.local_state.clone(),
            auxilary_final_parameters: VmInCircuitAuxilaryParameters::default(), // we will use next circuit's initial as final here!
        };

        all_instances_witnesses.push(instance_witness);
    }

    // make final states of each instance to be an initial state of the next one (actually backwards)

    for idx in 0..(all_instances_witnesses.len() - 1) {
        let initial_aux_of_next = all_instances_witnesses[idx + 1]
            .auxilary_initial_parameters
            .clone();

        all_instances_witnesses[idx].auxilary_final_parameters = initial_aux_of_next;
    }

    // special pass for the last one
    {
        let final_state = vm_snapshots.last().unwrap();
        let last = all_instances_witnesses.last_mut().unwrap();

        // always an empty one
        last.auxilary_final_parameters.callstack_state = (
            [E::Fr::zero(); 3],
            final_state
                .local_state
                .callstack
                .get_current_stack()
                .clone(),
        );

        let final_memory_queue_state = artifacts
            .vm_memory_queue_states
            .last()
            .map(|el| transform_sponge_like_queue_state(el.2))
            .unwrap_or(FullSpongeLikeQueueState::<E>::placeholder_witness());

        let final_decommittment_queue_state = artifacts
            .all_decommittment_queue_states
            .iter()
            .last()
            .map(|el| transform_sponge_like_queue_state(el.1))
            .unwrap_or(FullSpongeLikeQueueState::<E>::placeholder_witness());

        let range = history_of_storage_log_states.range(..);
        let latest_log_queue_state = range
            .last()
            .map(|el| el.1)
            .copied()
            .unwrap_or(StorageLogDetailedState::default());

        let final_storage_log_queue_state = FixedWidthEncodingGenericQueueStateWitness::<E> {
            num_items: latest_log_queue_state.forward_length,
            head_state: E::Fr::zero(),
            tail_state: latest_log_queue_state.forward_tail,
            _marker: std::marker::PhantomData,
        };

        last.auxilary_final_parameters.decommittment_queue_state = final_decommittment_queue_state;
        last.auxilary_final_parameters.memory_queue_state = final_memory_queue_state;
        last.auxilary_final_parameters.storage_log_queue_state = final_storage_log_queue_state;
        last.auxilary_final_parameters
            .current_frame_rollback_queue_tail = latest_log_queue_state.rollback_tail;
        last.auxilary_final_parameters
            .current_frame_rollback_queue_head = latest_log_queue_state.rollback_head;
        last.auxilary_final_parameters
            .current_frame_rollback_queue_segment_length = latest_log_queue_state.rollback_length;
    }

    // quick and dirty check that we properly transfer registers
    for pair in all_instances_witnesses.windows(2) {
        for (o, i) in pair[0]
            .final_state
            .registers
            .iter()
            .zip(pair[1].initial_state.registers.iter())
        {
            assert_eq!(o, i);
        }
    }

    (all_instances_witnesses, artifacts)
}

use crate::franklin_crypto::plonk::circuit::boolean::*;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::scheduler::data_access_functions::StorageLogRecord;
use sync_vm::scheduler::queues::DecommitQuery;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::vm::primitives::*;
use sync_vm::vm::vm_state::saved_contract_context::ExecutionContextRecord;
use sync_vm::vm::vm_state::saved_contract_context::ExecutionContextRecordWitness;

use crate::INITIAL_MONOTONIC_CYCLE_COUNTER;

impl<E: Engine> WitnessOracle<E> for VmWitnessOracle<E> {
    fn get_memory_witness_for_read(
        &mut self,
        timestamp: UInt32<E>,
        key: &MemoryLocation<E>,
        execute: &Boolean,
    ) -> Option<MemoryWitness> {
        if execute.get_value().unwrap_or(false) {
            if self.memory_read_witness.is_empty() {
                panic!(
                    "should have a witness to read at timestamp {:?}, location {:?}",
                    timestamp.get_value(),
                    key.create_witness()
                );
            }
            let (_cycle, query) = self.memory_read_witness.pop_front().unwrap();

            // tracing::debug!("Query value = 0x{:064x}", query.value);
            if let Some(ts) = timestamp.get_value() {
                assert_eq!(
                    ts,
                    query.timestamp.0,
                    "invalid memory access location at cycle {:?}: VM asks at timestamp {}, witness has timestamp {}. Witness key = {:?}, query = {:?}",
                    _cycle,
                    ts,
                    query.timestamp.0,
                    key.create_witness().unwrap(),
                    query,
                );
            }

            if let Some(location) = key.create_witness() {
                assert_eq!(
                    location.page,
                    query.location.page.0,
                    "invalid memory access location at timestamp {:?}: VM asks for page {}, witness has page {}",
                    timestamp.get_value(),
                    location.page,
                    query.location.page.0,
                );
                assert_eq!(
                    location.index,
                    query.location.index.0,
                    "invalid memory access location at timestamp {:?}: VM asks for index {}, witness has index {}",
                    timestamp.get_value(),
                    location.index,
                    query.location.index.0,
                );
            }

            // tracing::debug!("memory word = 0x{:x}", query.value);

            Some(MemoryWitness {
                value: u256_to_biguint(query.value),
                is_ptr: query.value_is_pointer,
            })
        } else {
            Some(MemoryWitness {
                value: BigUint::from(0u64),
                is_ptr: false,
            })
        }
    }

    fn push_memory_witness(&mut self, memory_query: &MemoryWriteQuery<E>, execute: &Boolean) {
        if let Some(write_witness) = self.memory_write_witness.as_mut() {
            if execute.get_value().unwrap_or(false) {
                let wit = memory_query.create_witness().unwrap();

                if write_witness.is_empty() {
                    panic!(
                        "should have a self-check witness to write at timestamp {}, page {}, index {}",
                        wit.timestamp,
                        wit.memory_page,
                        wit.memory_index,
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
                    wit.memory_index,
                    query.location.index.0,
                    "invalid memory access location at timestamp {:?}: VM writes into index {}, witness has index {}",
                    wit.timestamp,
                    wit.memory_index,
                    query.location.index.0,
                );

                // compare values

                let mut wit_value = U256::from(wit.lowest_128);
                wit_value.0[2] = wit.u64_word_2;
                wit_value.0[3] = wit.u64_word_3;

                assert_eq!(
                    wit_value,
                    query.value,
                    "invalid memory access location at timestamp {:?}: VM writes value {}, witness has value {}",
                    wit.timestamp,
                    wit_value,
                    query.value,
                );

                assert_eq!(
                    wit.value_is_ptr,
                    query.value_is_pointer,
                    "invalid memory access location at timestamp {:?}: VM writes pointer {}, witness has pointer {}",
                    wit.timestamp,
                    wit.value_is_ptr,
                    query.value_is_pointer,
                );
            }
        }

        // we do not care
    }

    fn get_storage_read_witness(
        &mut self,
        record: &StorageLogRecord<E>,
        needs_read_witness: &Boolean,
        execute: &Boolean,
    ) -> Option<num_bigint::BigUint> {
        if execute.get_value().unwrap_or(false) && needs_read_witness.get_value().unwrap_or(false) {
            if self.storage_queries.is_empty() {
                panic!(
                    "should have a witness for storage read at {:?}",
                    record.create_witness()
                );
            }
            let (_cycle, query) = self.storage_queries.pop_front().unwrap();

            if let Some(record) = record.create_witness() {
                assert_eq!(record.aux_byte, query.aux_byte);
                assert_eq!(record.address, u160_from_address(query.address));
                assert_eq!(record.key, u256_to_biguint(query.key));
                assert_eq!(record.r_w_flag, query.rw_flag);
                if record.r_w_flag == true {
                    // check written value
                    assert_eq!(record.written_value, u256_to_biguint(query.written_value));
                }
                assert_eq!(record.rollback, false);
                assert_eq!(record.rollback, query.rollback);
                assert_eq!(record.is_service, query.is_service);
                assert_eq!(record.shard_id, query.shard_id);
                assert_eq!(record.tx_number_in_block, query.tx_number_in_block);
                assert_eq!(record.timestamp, query.timestamp.0);
            }

            Some(u256_to_biguint(query.read_value))
        } else {
            Some(BigUint::from(0u64))
        }
    }

    fn get_refunds(
        &mut self,
        record: &StorageLogRecord<E>,
        is_write: &Boolean,
        execute: &Boolean,
    ) -> Option<u32> {
        if execute.get_value().unwrap_or(false) && is_write.get_value().unwrap_or(false) {
            if self.storage_refund_queries.is_empty() {
                panic!(
                    "should have a refund witness for storage write attempt at {:?}",
                    record.create_witness()
                );
            }
            let (_cycle, query, refund) = self.storage_refund_queries.pop_front().unwrap();

            if let Some(record) = record.create_witness() {
                assert_eq!(record.aux_byte, query.aux_byte);
                assert_eq!(record.address, u160_from_address(query.address));
                assert_eq!(record.key, u256_to_biguint(query.key));
                assert_eq!(record.r_w_flag, query.rw_flag);
                assert!(record.r_w_flag == true);
                assert_eq!(record.written_value, u256_to_biguint(query.written_value));
                assert_eq!(record.rollback, false);
                assert_eq!(record.rollback, query.rollback);
                assert_eq!(record.shard_id, query.shard_id);
                // the rest are not filled in out-of-circuit implementations
                assert_eq!(record.is_service, query.is_service);
            }

            Some(refund)
        } else {
            Some(0u32)
        }
    }

    fn push_storage_witness(
        &mut self,
        _record: &StorageLogRecord<E>,
        _is_write: &Boolean,
        _execute: &Boolean,
    ) {
        // logic is captured in read for a reason that we NEED
        // previous value of the cell for rollback to work
        unreachable!()
    }

    // may be should also track key for debug purposes
    fn get_rollback_queue_witness(
        &mut self,
        _key: &StorageLogRecord<E>,
        execute: &Boolean,
    ) -> Option<<E>::Fr> {
        if execute.get_value().unwrap_or(false) {
            let (_cycle, head) = self.rollback_queue_head_segments.pop_front().unwrap();
            // dbg!(head);

            Some(head)
        } else {
            Some(E::Fr::zero())
        }
    }

    fn get_rollback_queue_tail_witness_for_call(
        &mut self,
        _timestamp: UInt32<E>,
        execute: &Boolean,
    ) -> Option<E::Fr> {
        if execute.get_value().unwrap_or(false) {
            let (_cycle_idx, tail) = self
                .rollback_queue_initial_tails_for_new_frames
                .pop_front()
                .unwrap();
            // dbg!(tail);

            Some(tail)
        } else {
            Some(E::Fr::zero())
        }
    }

    fn report_new_callstack_frame(
        &mut self,
        new_callstack: &ExecutionContextRecord<E>,
        _new_depth: UInt32<E>,
        is_call: &Boolean,
        execute: &Boolean,
    ) {
        if execute.get_value().unwrap_or(false) && is_call.get_value().unwrap_or(false) {
            let (_cycle_idx, entry) = 
                self.callstack_new_frames_witnesses.pop_front().unwrap();

            // compare
            let witness = new_callstack.create_witness().unwrap();

            assert_eq!(u160_from_address(entry.this_address), witness.common_part.this);
            assert_eq!(u160_from_address(entry.msg_sender), witness.common_part.caller);
            assert_eq!(u160_from_address(entry.code_address), witness.common_part.code_address);

            assert_eq!(entry.code_page.0, witness.common_part.code_page);
            assert_eq!(entry.base_memory_page.0, witness.common_part.base_page);

            assert_eq!(entry.pc, witness.common_part.pc);
            assert_eq!(entry.sp, witness.common_part.sp);

            assert_eq!(entry.heap_bound, witness.common_part.heap_upper_bound);
            assert_eq!(entry.aux_heap_bound, witness.common_part.aux_heap_upper_bound);

            assert_eq!(entry.exception_handler_location, witness.common_part.exception_handler_loc);
            assert_eq!(entry.ergs_remaining, witness.common_part.ergs_remaining);

            assert_eq!(entry.is_static, witness.common_part.is_static_execution);
            assert_eq!(entry.is_kernel_mode(), witness.common_part.is_kernel_mode);

            assert_eq!(entry.this_shard_id, witness.common_part.this_shard_id);
            assert_eq!(entry.caller_shard_id, witness.common_part.caller_shard_id);
            assert_eq!(entry.code_shard_id, witness.common_part.code_shard_id);

            assert_eq!([entry.context_u128_value as u64, (entry.context_u128_value >> 64) as u64], witness.common_part.context_u128_value_composite);

            assert_eq!(entry.is_local_frame, witness.extension.is_local_call);
        }
    }

    fn push_callstack_witness(
        &mut self,
        current_record: &ExecutionContextRecord<E>,
        current_depth: &UInt32<E>,
        execute: &Boolean,
    ) {
        // we do not care, but we can do self-check

        if execute.get_value().unwrap_or(false) {
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
            let witness = current_record.create_witness().unwrap();

            assert!(
                is_push,
                "divergence at callstack push at cycle {}:\n pushing {:?}\n in circuit, but got POP of \n{:?}\n in oracle",
                _cycle_idx,
                &witness,
                &extended_entry,
            );

            if let Some(depth) = current_depth.get_value() {
                assert_eq!(
                    depth + 1,
                    witness_depth as u32,
                    "depth diverged at callstack push at cycle {}:\n pushing {:?}\n, got \n{:?}\n in oracle",
                    _cycle_idx,
                    &witness,
                    &extended_entry,
                );
            }

            let ExtendedCallstackEntry {
                callstack_entry: entry,
                rollback_queue_head,
                rollback_queue_tail,
                rollback_queue_segment_length,
            } = extended_entry;

            assert_eq!(
                u160_from_address(entry.this_address),
                witness.common_part.this
            );
            assert_eq!(
                u160_from_address(entry.msg_sender),
                witness.common_part.caller
            );
            assert_eq!(
                u160_from_address(entry.code_address),
                witness.common_part.code_address
            );

            assert_eq!(entry.code_page.0, witness.common_part.code_page);
            assert_eq!(entry.base_memory_page.0, witness.common_part.base_page);

            assert_eq!(rollback_queue_head, witness.common_part.reverted_queue_head);
            assert_eq!(rollback_queue_tail, witness.common_part.reverted_queue_tail);
            assert_eq!(
                rollback_queue_segment_length,
                witness.common_part.reverted_queue_segment_len
            );

            assert_eq!(entry.pc, witness.common_part.pc);
            assert_eq!(entry.sp, witness.common_part.sp);

            assert_eq!(entry.heap_bound, witness.common_part.heap_upper_bound);
            assert_eq!(
                entry.aux_heap_bound,
                witness.common_part.aux_heap_upper_bound
            );

            assert_eq!(
                entry.exception_handler_location,
                witness.common_part.exception_handler_loc
            );
            assert_eq!(entry.ergs_remaining, witness.common_part.ergs_remaining);

            assert_eq!(entry.is_static, witness.common_part.is_static_execution);
            assert_eq!(entry.is_kernel_mode(), witness.common_part.is_kernel_mode);

            assert_eq!(entry.this_shard_id, witness.common_part.this_shard_id);
            assert_eq!(entry.caller_shard_id, witness.common_part.caller_shard_id);
            assert_eq!(entry.code_shard_id, witness.common_part.code_shard_id);

            assert_eq!(
                [
                    entry.context_u128_value as u64,
                    (entry.context_u128_value >> 64) as u64
                ],
                witness.common_part.context_u128_value_composite
            );

            assert_eq!(entry.is_local_frame, witness.extension.is_local_call);
        }
    }

    fn get_callstack_witness(
        &mut self,
        execute: &Boolean,
        depth: &UInt32<E>,
    ) -> (
        Option<ExecutionContextRecordWitness<E>>,
        Option<[<E>::Fr; 3]>,
    ) {
        if execute.get_value().unwrap_or(false) {
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

            if let Some(depth) = depth.get_value() {
                assert_eq!(
                    depth - 1,
                    witness_depth as u32,
                    "depth diverged at callstack pop at cycle {}, got \n{:?}\n in oracle",
                    _cycle_idx,
                    &extended_entry,
                );
            }

            // dbg!(new_state);

            let ExtendedCallstackEntry {
                callstack_entry: entry,
                rollback_queue_head,
                rollback_queue_tail,
                rollback_queue_segment_length,
            } = extended_entry;

            use sync_vm::vm::vm_state::saved_contract_context::ExecutionContextRecordCommomPartWitness;
            use sync_vm::vm::vm_state::saved_contract_context::ExecutionContextRecordExtensionWitness;

            let witness = ExecutionContextRecordWitness {
                common_part: ExecutionContextRecordCommomPartWitness {
                    this: u160_from_address(entry.this_address),
                    caller: u160_from_address(entry.msg_sender),
                    code_address: u160_from_address(entry.code_address),
                    code_page: entry.code_page.0,
                    base_page: entry.base_memory_page.0,
                    reverted_queue_head: rollback_queue_head,
                    reverted_queue_tail: rollback_queue_tail,
                    reverted_queue_segment_len: rollback_queue_segment_length,
                    pc: entry.pc,
                    sp: entry.sp,
                    exception_handler_loc: entry.exception_handler_location,
                    ergs_remaining: entry.ergs_remaining,
                    pubdata_bytes_remaining: 0, // UNUSED
                    is_static_execution: entry.is_static,
                    is_kernel_mode: entry.is_kernel_mode(),
                    this_shard_id: entry.this_shard_id,
                    caller_shard_id: entry.caller_shard_id,
                    code_shard_id: entry.code_shard_id,
                    context_u128_value_composite: [
                        entry.context_u128_value as u64,
                        (entry.context_u128_value >> 64) as u64,
                    ],
                    heap_upper_bound: entry.heap_bound,
                    aux_heap_upper_bound: entry.aux_heap_bound,
                    _marker: std::marker::PhantomData,
                },
                extension: ExecutionContextRecordExtensionWitness {
                    is_local_call: entry.is_local_frame,
                    marker: (),
                    _marker: std::marker::PhantomData,
                },
                _marker: std::marker::PhantomData,
            };

            (Some(witness), Some(new_state))
        } else {
            (
                Some(ExecutionContextRecord::placeholder_witness()),
                Some([E::Fr::zero(); 3]),
            )
        }
    }

    fn get_decommittment_request_witness(
        &mut self,
        request: &DecommitQuery<E>,
        execute: &Boolean,
    ) -> Option<DecommitQueryWitness<E>> {
        if execute.get_value().unwrap_or(false) {
            if self.decommittment_requests_witness.is_empty() {
                if let Some(wit) = request.create_witness() {
                    panic!("Witness value is missing for {:?}", wit);
                }
                panic!("Witness value is missing");
            }

            let (_frame_idx, query) = self
                .decommittment_requests_witness
                .pop_front()
                .unwrap_or_else(|| {
                    if let Some(wit) = request.create_witness() {
                        panic!("Witness value is missing for {:?}", wit);
                    }
                    panic!("Witness value is missing");
                });

            if let Some(wit) = request.create_witness() {
                assert_eq!(wit.timestamp, query.timestamp.0);
                assert!(
                    wit.root_hash.clone() == u256_to_biguint(query.hash),
                    "circuit expected hash 0x{:064x}, while witness had 0x{:064x}",
                    wit.root_hash,
                    u256_to_biguint(query.hash)
                );
            }

            let wit = DecommitQueryWitness::<E> {
                root_hash: u256_to_biguint(query.hash),
                page: query.memory_page.0,
                is_first: query.is_fresh,
                timestamp: query.timestamp.0,
                _marker: std::marker::PhantomData,
            };

            Some(wit)
        } else {
            Some(DecommitQuery::placeholder_witness())
        }
    }

    fn at_completion(self) {
        if self.memory_read_witness.is_empty() == false {
            panic!(
                "Too many memory queries in witness: have left\n{:?}",
                self.memory_read_witness
            );
        }

        if let Some(memory_write_witness) = self.memory_write_witness {
            if memory_write_witness.is_empty() == false {
                panic!(
                    "Too many memory write queries in witness: have left\n{:?}",
                    memory_write_witness
                );
            }
        }

        if self.storage_queries.is_empty() == false {
            panic!(
                "Too many storage queries in witness: have left\n{:?}",
                self.storage_queries
            );
        }

        if self.storage_refund_queries.is_empty() == false {
            panic!(
                "Too many storage queries for refunds in witness: have left\n{:?}",
                self.storage_refund_queries
            );
        }

        if self.callstack_values_witnesses.is_empty() == false {
            panic!(
                "Too many callstack sponge witnesses: have left\n{:?}",
                self.callstack_values_witnesses
            );
        }

        if self.decommittment_requests_witness.is_empty() == false {
            panic!(
                "Too many decommittment request witnesses: have left\n{:?}",
                self.decommittment_requests_witness
            );
        }

        if self.rollback_queue_head_segments.is_empty() == false {
            panic!(
                "Too many rollback queue heads in witnesses: have left\n{:?}",
                self.rollback_queue_head_segments
            );
        }

        if self.rollback_queue_initial_tails_for_new_frames.is_empty() == false {
            panic!(
                "Too many rollback queue heads new stack frames in witnesses: have left\n{:?}",
                self.rollback_queue_initial_tails_for_new_frames
            );
        }
    }
}
