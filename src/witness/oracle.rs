// implement witness oracle to actually compute
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use super::callstack_handler::*;
use super::postprocessing::BlockFirstAndLastBasicCircuits;
use super::utils::*;
use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::queue::{QueueState, QueueStateWitness, QueueTailStateWitness};
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::boojum::gadgets::traits::round_function::*;
use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::postprocessing::{CircuitMaker, FirstAndLastCircuit};
use crate::witness::tracer::{QueryMarker, WitnessTracer};
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::{LogQuery, MemoryIndex, MemoryPage, MemoryQuery};
use crate::zk_evm::reference_impls::event_sink::ApplicationData;
use crate::zk_evm::vm_state::{CallStackEntry, VmLocalState};
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;
use crate::zkevm_circuits::base_structures::vm_state::{
    GlobalContextWitness, FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH,
};
use crate::zkevm_circuits::main_vm::main_vm_entry_point;
use crate::zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::{Field, U64Representable};
use circuit_definitions::boojum::implementations::poseidon2::Poseidon2Goldilocks;
use circuit_definitions::circuit_definitions::base_layer::{VMMainCircuit, ZkSyncBaseLayerCircuit};
use circuit_definitions::encodings::callstack_entry::ExtendedCallstackEntry;
use circuit_definitions::encodings::recursion_request::{
    RecursionQueueSimulator, RecursionRequest,
};
use circuit_definitions::encodings::LogQueueSimulator;
use circuit_definitions::zk_evm::zkevm_opcode_defs::system_params::{SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS, TRANSIENT_STORAGE_AUX_BYTE};
use circuit_definitions::zkevm_circuits::eip_4844::input::EIP4844CircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use crossbeam::atomic::AtomicCell;
use derivative::Derivative;
use rayon::slice::ParallelSliceMut;
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::RangeInclusive;
use std::sync::Arc;
use crate::zkevm_circuits::eip_4844::input::ENCODABLE_BYTES_PER_BLOB;
use crate::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;

use crate::zk_evm::zkevm_opcode_defs::system_params::{
    ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
};

use crate::zk_evm::zkevm_opcode_defs::system_params::{
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

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
pub struct LogAccessSpongesInfo<F: SmallField> {
    pub cycle: u32,
    pub common_sponges: CommonLogSponges<F>,
    pub forward_info: ForwardLogSponge<F>,
    pub rollback_info: Option<RollbackLogSponge<F>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default)]
struct FlattenedLogQueueIndexer<F: SmallField> {
    pub current_head: [F; QUEUE_STATE_WIDTH],
    pub current_tail: [F; QUEUE_STATE_WIDTH],
    pub head_offset: usize,
    pub tail_offset: usize,
}

use crate::blake2::Blake2s256;
use crate::witness::tree::*;

pub fn create_artifacts_from_tracer<
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
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    num_non_deterministic_heap_queries: usize,
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    evm_simulator_code_hash: U256,
    eip_4844_repack_inputs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
    mut circuit_callback: CB,
    mut recursion_queue_callback: QSCB,
) -> (
    BlockFirstAndLastBasicCircuits,
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
        monotonic_query_counter: _,
        callstack_with_aux_data,
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

    // segmentation of the log queue
    // - split into independent queues
    // - compute initial tail segments (with head == tail) for every new call frame
    // - also compute head segments for every write-like actions

    let mut log_queue_simulator = LogQueueSimulator::empty();
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

    let mut log_position_mapping = HashMap::new();

    let mut demuxed_rollup_storage_queries = vec![];
    let mut demuxed_porter_storage_queries = vec![];
    let mut demuxed_event_queries = vec![];
    let mut demuxed_to_l1_queries = vec![];
    let mut demuxed_keccak_precompile_queries = vec![];
    let mut demuxed_sha256_precompile_queries = vec![];
    let mut demuxed_ecrecover_queries = vec![];
    let mut demuxed_secp256r1_verify_queries = vec![];
    let mut demuxed_transient_storage_queries = vec![];

    let mut original_log_queue_states = vec![];
    let mut chain_of_states = vec![];
    let mut original_log_queue_simulator = None;
    let mut marker_into_queue_position_renumeration_index: HashMap<QueryMarker, usize> =
        HashMap::new();

    // we want to have some hashmap that will indicate
    // that on some specific VM cycle we either read or write

    // from cycle into first two sponges (common), then tail-tail pair and 3rd sponge for forward, then head-head pair and 3rd sponge for rollback
    let mut sponges_data: HashMap<u32, LogAccessSpongesInfo<GoldilocksField>> = HashMap::new();

    let mut global_beginnings_of_frames: BTreeMap<usize, u32> = BTreeMap::new();
    let mut actions_in_each_frame: BTreeMap<usize, Vec<(u32, QueryMarker, usize)>> =
        BTreeMap::new();

    for el in callstack_with_aux_data.full_history.iter() {
        match el.action {
            CallstackAction::PushToStack => {
                // not imporatant, we count by the next one
            }
            CallstackAction::PopFromStack { panic: _ } => {}
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // fresh fram
                global_beginnings_of_frames.insert(el.frame_index, el.beginning_cycle);
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: _ }) => {
                el.end_cycle.expect("frame must end");
            }
        }
    }

    global_beginnings_of_frames.insert(0, 0);

    // now it's going to be fun. We simultaneously will do the following indexing:
    // - simulate the state of callstack as a sponge
    // - follow the call graph and storage queries graph to know exacly the following subset of properties at any
    // range of cycles:
    // - callstack "frozen" part (what is in the callstack). This involves rollback queue head/tail/length!
    // - "active" callstack entry rollback queue's head/tail/length at this cycle

    // first we need to hash the queue itself, and create an index of "where in the final flat queue did log access from this frame end up"
    // If we encounter "read" that implies no reverts we use "None"

    let mut cycle_into_flat_sequence_index = BTreeMap::<u32, (usize, Option<usize>)>::new();

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
                    ..
                } => {
                    assert_eq!(cycle, c);
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
                }
                QueryMarker::ForwardNoRollback {
                    in_frame: _,
                    index: _,
                    cycle: c,
                    ..
                } => {
                    assert_eq!(cycle, c);
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
                TRANSIENT_STORAGE_AUX_BYTE => {
                    demuxed_transient_storage_queries.push(query);
                }
                L1_MESSAGE_AUX_BYTE => {
                    demuxed_to_l1_queries.push(query);
                }
                EVENT_AUX_BYTE => {
                    demuxed_event_queries.push(query);
                }
                PRECOMPILE_AUX_BYTE => {
                    assert!(!query.rollback);
                    use crate::zk_evm::zk_evm_abstractions::precompiles::*;
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
                        a if a == *SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            demuxed_secp256r1_verify_queries.push(query);
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
    use circuit_definitions::encodings::callstack_entry::CallstackSimulator;
    let mut callstack_argebraic_simulator = CallstackSimulator::empty();
    let mut callstack_values_witnesses = vec![]; // index of cycle -> witness for callstack
                                                 // we need to simultaneously follow the logic of pushes/joins of the storage queues,
                                                 // and encoding of the current callstack state as the sponge state

    // here we are interested in "frozen" elements that are in the stack,
    // so we never follow the "current", but add on push/pop

    // These are "frozen" states that just lie in the callstack for now and can not be modified
    let mut callstack_sponge_encoding_ranges = vec![];
    // pretend initial state
    callstack_sponge_encoding_ranges
        .push((0, [GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]));

    // we need some information that spans the whole number of cycles with "what is a frame counter at this time"

    // we have all the spans of when each frame is active, so we can
    // - simulate what is saved and when
    // - get witnesses for heads when encountering the new spans

    let global_end_of_storage_log = chain_of_states
        .last()
        .map(|el| el.2 .1)
        .unwrap_or([GoldilocksField::ZERO; QUEUE_STATE_WIDTH]);
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

    let mut rollback_queue_head_segments: Vec<(u32, [GoldilocksField; QUEUE_STATE_WIDTH])> = vec![];

    for (cycle, (_forward, rollback)) in cycle_into_flat_sequence_index.iter() {
        if let Some(pointer) = rollback {
            let state = &chain_of_states[*pointer];
            rollback_queue_head_segments.push((*cycle, state.2 .0));
        }
    }

    let mut history_of_storage_log_states = BTreeMap::new();

    // we start with no rollbacks, but non-trivial tail
    let mut current_storage_log_state = StorageLogDetailedState::default();
    current_storage_log_state.rollback_head = global_end_of_storage_log;
    current_storage_log_state.rollback_tail = global_end_of_storage_log;

    let mut storage_logs_states_stack = vec![];

    let mut state_to_merge: Option<(bool, StorageLogDetailedState<GoldilocksField>)> = None;

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

    let CallstackWithAuxData {
        flat_new_frames_history,
        ..
    } = callstack_with_aux_data;

    // we simulate a series of actions on the stack starting from the outermost frame
    // each history record contains an information on what was the stack state between points
    // when it potentially came into and out of scope

    let mut cs_for_witness_generation =
        create_cs_for_witness_generation::<GoldilocksField, Poseidon2Goldilocks>(
            TRACE_LEN_LOG_2_FOR_CALCULATION,
            MAX_VARS_LOG_2_FOR_CALCULATION,
        );
    let mut cycles_used: usize = 0;

    let storage_application_circuits;
    let storage_application_compact_forms;
    let ram_permutation_circuits;
    let ram_permutation_circuits_compact_forms_witnesses;
    let log_demux_circuits;
    let log_demux_circuits_compact_forms_witnesses;
    let mut vm_memory_query_cycles = vec![];

    let artifacts = {
        let mut artifacts = FullBlockArtifacts::default();
        artifacts.all_prepared_decommittment_queries = prepared_decommittment_queries;
        artifacts.all_executed_decommittment_queries = executed_decommittment_queries;
        artifacts.keccak_round_function_witnesses = keccak_round_function_witnesses;
        artifacts.sha256_round_function_witnesses = sha256_round_function_witnesses;
        artifacts.ecrecover_witnesses = ecrecover_witnesses;
        artifacts.original_log_queue_simulator =
            original_log_queue_simulator.unwrap_or(LogQueueSimulator::empty());
        artifacts.original_log_queue_states = original_log_queue_states;

        artifacts.demuxed_rollup_storage_queries = demuxed_rollup_storage_queries;
        artifacts.demuxed_event_queries = demuxed_event_queries;
        artifacts.demuxed_to_l1_queries = demuxed_to_l1_queries;
        artifacts.demuxed_keccak_precompile_queries = demuxed_keccak_precompile_queries;
        artifacts.demuxed_sha256_precompile_queries = demuxed_sha256_precompile_queries;
        artifacts.demuxed_ecrecover_queries = demuxed_ecrecover_queries;
        artifacts.demuxed_secp256r1_verify_queries = demuxed_secp256r1_verify_queries;
        artifacts.demuxed_transient_storage_queries = demuxed_transient_storage_queries;

        tracing::debug!("Processing artifacts queue");

        let ref mut this = artifacts;
        let geometry = geometry;
        // this is parallelizable internally by the factor of 3 in round function implementation later on

        tracing::debug!("Running memory queue simulation");

        for (cycle, query) in vm_memory_queries_accumulated {
            this.all_memory_queries_accumulated.push(query.clone());

            let (_old_tail, intermediate_info) = this
                .memory_queue_simulator
                .push_and_output_intermediate_data(query, round_function);

            vm_memory_query_cycles.push(cycle);
            this.all_memory_queue_states.push(intermediate_info);
        }

        assert!(
            this.memory_queue_simulator.num_items as usize
                == this.all_memory_queries_accumulated.len()
        );

        // ----------------------------

        {
            assert_eq!(
                this.all_memory_queries_accumulated.len(),
                this.all_memory_queue_states.len()
            );
            assert_eq!(
                this.all_memory_queries_accumulated.len(),
                this.memory_queue_simulator.num_items as usize
            );
        }

        // ----------------------------

        // direct VM related part is done, other subcircuit's functionality is moved to other functions
        // that should properly do sorts and memory writes

        use crate::witness::individual_circuits::sort_decommit_requests::compute_decommitts_sorter_circuit_snapshots;

        tracing::debug!("Running code decommittments sorter simulation");

        let mut deduplicated_decommitment_queue_simulator = Default::default();
        let mut deduplicated_decommittment_queue_states = Default::default();
        let mut deduplicated_decommit_requests_with_data = Default::default();

        this.decommittments_deduplicator_circuits_data =
            compute_decommitts_sorter_circuit_snapshots(
                this,
                &mut deduplicated_decommitment_queue_simulator,
                &mut deduplicated_decommittment_queue_states,
                &mut deduplicated_decommit_requests_with_data,
                round_function,
                geometry.cycles_code_decommitter_sorter as usize,
            );

        use crate::witness::individual_circuits::decommit_code::compute_decommitter_circuit_snapshots;

        tracing::debug!("Running code code decommitter simulation");

        let code_decommitter_circuits_data = compute_decommitter_circuit_snapshots(
            this,
            &mut deduplicated_decommitment_queue_simulator,
            &mut deduplicated_decommittment_queue_states,
            &mut deduplicated_decommit_requests_with_data,
            round_function,
            geometry.cycles_per_code_decommitter as usize,
        );

        this.code_decommitter_circuits_data = code_decommitter_circuits_data;

        // demux log queue
        use crate::witness::individual_circuits::log_demux::compute_logs_demux;

        tracing::debug!("Running log demux simulation");

        let (
            log_demux_circuits_,
            log_demux_circuits_compact_forms_witnesses_,
            mut all_demuxed_queues,
        ) = compute_logs_demux(
            this,
            geometry.cycles_per_log_demuxer as usize,
            round_function,
            geometry,
            &mut cs_for_witness_generation,
            &mut cycles_used,
            &mut circuit_callback,
            &mut recursion_queue_callback,
        );
        log_demux_circuits = log_demux_circuits_;
        log_demux_circuits_compact_forms_witnesses = log_demux_circuits_compact_forms_witnesses_;

        use crate::zkevm_circuits::demux_log_queue::DemuxOutput;

        // keccak precompile

        use crate::witness::individual_circuits::keccak256_round_function::keccak256_decompose_into_per_circuit_witness;

        tracing::debug!("Running keccak simulation");

        let demuxed_keccak_precompile_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::Keccak as usize], Default::default());

        let keccak256_circuits_data = keccak256_decompose_into_per_circuit_witness(
            this,
            demuxed_keccak_precompile_queue,
            geometry.cycles_per_keccak256_circuit as usize,
            round_function,
        );
        this.keccak256_circuits_data = keccak256_circuits_data;

        // sha256 precompile

        use crate::witness::individual_circuits::sha256_round_function::sha256_decompose_into_per_circuit_witness;

        tracing::debug!("Running sha256 simulation");

        let demuxed_sha256_precompile_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::Sha256 as usize], Default::default());

        let sha256_circuits_data = sha256_decompose_into_per_circuit_witness(
            this,
            demuxed_sha256_precompile_queue,
            geometry.cycles_per_sha256_circuit as usize,
            round_function,
        );
        this.sha256_circuits_data = sha256_circuits_data;

        // ecrecover precompile

        use crate::witness::individual_circuits::ecrecover::ecrecover_decompose_into_per_circuit_witness;

        tracing::debug!("Running ecrecover simulation");

        let demuxed_ecrecover_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::ECRecover as usize], Default::default());

        let ecrecover_circuits_data = ecrecover_decompose_into_per_circuit_witness(
            this,
            demuxed_ecrecover_queue,
            geometry.cycles_per_ecrecover_circuit as usize,
            round_function,
        );
        this.ecrecover_circuits_data = ecrecover_circuits_data;

        use crate::witness::individual_circuits::secp256r1_verify::secp256r1_verify_decompose_into_per_circuit_witness;

        tracing::debug!("Running secp256r1_simulation simulation");

        let demuxed_secp256r1_verify_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::Secp256r1Verify as usize], Default::default());

        let secp256r1_verify_circuits_data = secp256r1_verify_decompose_into_per_circuit_witness(
            this,
            demuxed_secp256r1_verify_queue,
            geometry.cycles_per_secp256r1_verify_circuit as usize,
            round_function,
        );
        this.secp256r1_verify_circuits_data = secp256r1_verify_circuits_data;

        // we are done with a memory and can do the processing and breaking of the logical arguments into individual circits

        use crate::witness::individual_circuits::ram_permutation::compute_ram_circuit_snapshots;

        tracing::debug!("Running RAM permutation simulation");

        (
            ram_permutation_circuits,
            ram_permutation_circuits_compact_forms_witnesses,
        ) = compute_ram_circuit_snapshots(
            this,
            round_function,
            num_non_deterministic_heap_queries,
            geometry.cycles_per_ram_permutation as usize,
            geometry,
            &mut cs_for_witness_generation,
            &mut cycles_used,
            &mut circuit_callback,
            &mut recursion_queue_callback,
        );

        // now completely parallel process to reconstruct the states, with internally parallelism in each round function

        use crate::witness::individual_circuits::storage_sort_dedup::compute_storage_dedup_and_sort;

        tracing::debug!("Running storage deduplication simulation");

        let demuxed_rollup_storage_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::RollupStorage as usize], Default::default());

        let storage_deduplicator_circuit_data = compute_storage_dedup_and_sort(
            this,
            demuxed_rollup_storage_queue,
            geometry.cycles_per_storage_sorter as usize,
            round_function,
        );
        this.storage_deduplicator_circuit_data = storage_deduplicator_circuit_data;

        use crate::witness::individual_circuits::events_sort_dedup::compute_events_dedup_and_sort;

        tracing::debug!("Running events deduplication simulation");

        let demuxed_event_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::Events as usize], Default::default());

        let events_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &this.demuxed_event_queries,
            &demuxed_event_queue,
            &mut Default::default(),
            geometry.cycles_per_events_or_l1_messages_sorter as usize,
            round_function,
        );

        this.events_deduplicator_circuit_data = events_deduplicator_circuit_data;

        tracing::debug!("Running L1 messages deduplication simulation");

        let demuxed_to_l1_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::L2ToL1Messages as usize], Default::default());

        let mut deduplicated_to_l1_queue_simulator = Default::default();
        let l1_messages_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &this.demuxed_to_l1_queries,
            &demuxed_to_l1_queue,
            &mut deduplicated_to_l1_queue_simulator,
            geometry.cycles_per_events_or_l1_messages_sorter as usize,
            round_function,
        );

        this.l1_messages_deduplicator_circuit_data = l1_messages_deduplicator_circuit_data;

        use crate::witness::individual_circuits::transient_storage_sorter::compute_transient_storage_dedup_and_sort;

        tracing::debug!("Running transient storage sorting simulation");

        let demuxed_transient_storage_queue = std::mem::replace(&mut all_demuxed_queues[DemuxOutput::TransientStorage as usize], Default::default());

        let transient_storage_sorter_circuit_data = compute_transient_storage_dedup_and_sort(
            this,
            demuxed_transient_storage_queue,
            geometry.cycles_per_transient_storage_sorter as usize,
            round_function,
        );
        this.transient_storage_sorter_circuit_data = transient_storage_sorter_circuit_data;

        // compute flattened hash of all messages

        tracing::debug!("Running L1 messages linear hash simulation");

        assert!(
            deduplicated_to_l1_queue_simulator.num_items
                <= geometry.limit_for_l1_messages_pudata_hasher,
            "too many L1 messages to linearly hash by single circuit"
        );

        use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_linear_keccak256;

        let l1_messages_pubdata_hasher_data = compute_linear_keccak256(
            &deduplicated_to_l1_queue_simulator,
            geometry.limit_for_l1_messages_pudata_hasher as usize,
            round_function,
        );

        this.l1_messages_linear_hash_data = l1_messages_pubdata_hasher_data;

        // process the storage application

        // and do the actual storage application
        use crate::witness::individual_circuits::storage_application::decompose_into_storage_application_witnesses;

        (
            storage_application_circuits,
            storage_application_compact_forms,
        ) = decompose_into_storage_application_witnesses(
            this,
            tree,
            round_function,
            geometry.cycles_per_storage_application as usize,
            geometry,
            &mut cs_for_witness_generation,
            &mut cycles_used,
            &mut circuit_callback,
            &mut recursion_queue_callback,
        );

        artifacts
    };

    // NOTE: here we have all the queues processed in the `process` function (actual pushing is done), so we can
    // just read from the corresponding states

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

    let in_circuit_global_context = GlobalContextWitness {
        zkporter_is_available: zk_porter_is_available,
        default_aa_code_hash: default_aa_code_hash,
        evm_simulator_code_hash: evm_simulator_code_hash,
    };
    let round_function = Arc::new(*round_function);

    let mut main_vm_circuits = FirstAndLastCircuit::default();
    let mut main_vm_circuits_compact_forms_witnesses = vec![];
    let mut queue_simulator = RecursionQueueSimulator::empty();
    let mut observable_input = None;
    let mut process_vm_witness = |vm_instance, is_last| {
        use crate::witness::utils::vm_instance_witness_to_circuit_formal_input;
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
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation =
                create_cs_for_witness_generation::<GoldilocksField, Poseidon2Goldilocks>(
                    TRACE_LEN_LOG_2_FOR_CALCULATION,
                    MAX_VARS_LOG_2_FOR_CALCULATION,
                );
            cycles_used = 0;
        }

        let instance = VMMainCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        if is_first {
            main_vm_circuits.first = Some(instance.clone());
        }
        if is_last {
            main_vm_circuits.last = Some(instance.clone());
        }

        let instance = ZkSyncBaseLayerCircuit::MainVM(instance);

        let recursive_request = RecursionRequest {
            circuit_type: GoldilocksField::from_u64_unchecked(
                instance.numeric_circuit_type() as u64
            ),
            public_input: proof_system_input,
        };
        let _ = queue_simulator.push(recursive_request, &*round_function);

        circuit_callback(instance);
        main_vm_circuits_compact_forms_witnesses.push(compact_form_witness);
    };

    let mut previous_instance_witness: Option<
        VmInstanceWitness<GoldilocksField, VmWitnessOracle<GoldilocksField>>,
    > = None;
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

        let index_plus_one = vm_memory_query_cycles
            .iter()
            .take_while(|cycle| **cycle < initial_state.at_cycle)
            .count();
        let memory_queue_state_for_entry = if index_plus_one == 0 {
            QueueState::placeholder_witness()
        } else {
            transform_sponge_like_queue_state(artifacts.all_memory_queue_states[index_plus_one - 1])
        };

        let decommittment_queue_state_for_entry = artifacts
            .all_decommittment_queue_states
            .iter()
            .take_while(|el| el.0 < initial_state.at_cycle)
            .last()
            .map(|el| transform_sponge_like_queue_state(el.1))
            .unwrap_or(QueueState::placeholder_witness());

        // and finally we need the callstack current state

        let callstack_state_for_entry = callstack_sponge_encoding_ranges
            .iter()
            // .skip_while(
            //     |el| el.0 < initial_state.at_cycle
            // )
            .take_while(|el| el.0 < initial_state.at_cycle)
            .last()
            .map(|el| el.1)
            .unwrap_or([GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]);

        // initial state is kind of done, now
        // split the oracle witness

        let mut per_instance_memory_read_witnesses = Vec::with_capacity(1 << 16);
        let mut per_instance_memory_write_witnesses = Vec::with_capacity(1 << 16);

        let start = vm_memory_query_cycles.partition_point(|x| *x < initial_state.at_cycle);
        let end = vm_memory_query_cycles.partition_point(|x| *x < final_state.at_cycle);
        for (&cycle, &query) in vm_memory_query_cycles[start..end]
            .iter()
            .zip(&artifacts.all_memory_queries_accumulated[start..end])
        {
            if query.rw_flag {
                per_instance_memory_write_witnesses.push((cycle, query));
            } else {
                per_instance_memory_read_witnesses.push((cycle, query));
            }
        }

        let per_instance_storage_queries_witnesses: Vec<_> = storage_queries
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        let per_instance_cold_warm_refund_logs: Vec<_> = cold_warm_refunds_logs
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        let per_instance_pubdata_cost_logs: Vec<_> = pubdata_cost_logs
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        // here we need all answers from the oracle, not just ones that will be executed
        let decommittment_requests_witness: Vec<_> = artifacts
            .all_prepared_decommittment_queries
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

        let rollback_queue_head_segments = rollback_queue_head_segments
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        let callstack_new_frames_witnesses = flat_new_frames_history
            .iter()
            .skip_while(|el| el.0 < initial_state.at_cycle)
            .take_while(|el| el.0 < final_state.at_cycle)
            .cloned()
            .collect();

        // construct an oracle
        let witness_oracle = VmWitnessOracle {
            initial_cycle: initial_state.at_cycle,
            final_cycle_inclusive: final_state.at_cycle - 1,
            memory_read_witness: per_instance_memory_read_witnesses.into(),
            memory_write_witness: Some(per_instance_memory_write_witnesses.into()),
            rollback_queue_head_segments,
            decommittment_requests_witness: decommittment_requests_witness.into(),
            rollback_queue_initial_tails_for_new_frames:
                rollback_queue_initial_tails_for_new_frames.into(),
            storage_queries: per_instance_storage_queries_witnesses.into(),
            storage_access_cold_warm_refunds: per_instance_cold_warm_refund_logs.into(),
            storage_pubdata_queries: per_instance_pubdata_cost_logs.into(),
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

        let storage_log_queue_state_for_entry = QueueStateWitness {
            head: [GoldilocksField::ZERO; QUEUE_STATE_WIDTH],
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

        if let Some(mut prev) = previous_instance_witness {
            prev.auxilary_final_parameters = instance_witness.auxilary_initial_parameters.clone();
            process_vm_witness(prev, false);
        }
        previous_instance_witness = Some(instance_witness);
    }

    // special pass for the last one
    {
        let final_state = vm_snapshots.last().unwrap();
        let mut last = previous_instance_witness.unwrap();

        // always an empty one
        last.auxilary_final_parameters.callstack_state = (
            [GoldilocksField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH],
            final_state
                .local_state
                .callstack
                .get_current_stack()
                .clone(),
        );

        let final_memory_queue_state = if vm_memory_query_cycles.is_empty() {
            QueueState::placeholder_witness()
        } else {
            transform_sponge_like_queue_state(
                artifacts.all_memory_queue_states[vm_memory_query_cycles.len() - 1],
            )
        };

        let final_decommittment_queue_state = artifacts
            .all_decommittment_queue_states
            .iter()
            .last()
            .map(|el| transform_sponge_like_queue_state(el.1))
            .unwrap_or(QueueState::placeholder_witness());

        let range = history_of_storage_log_states.range(..);
        let latest_log_queue_state = range
            .last()
            .map(|el| el.1)
            .copied()
            .unwrap_or(StorageLogDetailedState::default());

        let final_storage_log_queue_state = QueueStateWitness {
            head: [GoldilocksField::ZERO; QUEUE_STATE_WIDTH],
            tail: QueueTailStateWitness {
                tail: latest_log_queue_state.forward_tail,
                length: latest_log_queue_state.forward_length,
            },
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

        process_vm_witness(last, true);
    }

    recursion_queue_callback(
        BaseLayerCircuitType::VM as u64,
        queue_simulator,
        main_vm_circuits_compact_forms_witnesses.clone(),
    );

    {
        let FullBlockArtifacts {
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
            ..
        } = artifacts;

        // Code decommitter sorter
        let circuit_type = BaseLayerCircuitType::DecommitmentsFilter;

        let mut maker = CircuitMaker::new(
            geometry.cycles_code_decommitter_sorter,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in decommittments_deduplicator_circuits_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            code_decommittments_sorter_circuits,
            queue_simulator,
            code_decommittments_sorter_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            code_decommittments_sorter_circuits_compact_forms_witnesses.clone(),
        );

        // Actual decommitter
        let circuit_type = BaseLayerCircuitType::Decommiter;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_code_decommitter,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in code_decommitter_circuits_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::CodeDecommitter(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            code_decommitter_circuits,
            queue_simulator,
            code_decommitter_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            code_decommitter_circuits_compact_forms_witnesses.clone(),
        );

        // keccak precompiles
        let circuit_type = BaseLayerCircuitType::KeccakPrecompile;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_keccak256_circuit,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in keccak256_circuits_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::KeccakRoundFunction(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            keccak_precompile_circuits,
            queue_simulator,
            keccak_precompile_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            keccak_precompile_circuits_compact_forms_witnesses.clone(),
        );

        // sha256 precompiles
        let circuit_type = BaseLayerCircuitType::Sha256Precompile;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_sha256_circuit,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in sha256_circuits_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::Sha256RoundFunction(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            sha256_precompile_circuits,
            queue_simulator,
            sha256_precompile_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            sha256_precompile_circuits_compact_forms_witnesses.clone(),
        );

        // ecrecover precompiles
        let circuit_type = BaseLayerCircuitType::EcrecoverPrecompile;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_ecrecover_circuit,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in ecrecover_circuits_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::ECRecover(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            ecrecover_precompile_circuits,
            queue_simulator,
            ecrecover_precompile_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            ecrecover_precompile_circuits_compact_forms_witnesses.clone(),
        );

        // storage sorter
        let circuit_type = BaseLayerCircuitType::StorageFilter;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_storage_sorter,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in storage_deduplicator_circuit_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::StorageSorter(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            storage_sorter_circuits,
            queue_simulator,
            storage_sorter_circuit_compact_form_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            storage_sorter_circuit_compact_form_witnesses.clone(),
        );

        // events sorter
        let circuit_type = BaseLayerCircuitType::EventsRevertsFilter;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_events_or_l1_messages_sorter,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in events_deduplicator_circuit_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::EventsSorter(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            events_sorter_circuits,
            queue_simulator,
            events_sorter_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            events_sorter_circuits_compact_forms_witnesses.clone(),
        );

        // l1 messages sorter
        let circuit_type = BaseLayerCircuitType::L1MessagesRevertsFilter;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_events_or_l1_messages_sorter,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in l1_messages_deduplicator_circuit_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::L1MessagesSorter(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            l1_messages_sorter_circuits,
            queue_simulator,
            l1_messages_sorter_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            l1_messages_sorter_circuits_compact_forms_witnesses.clone(),
        );

        // l1 messages pubdata hasher
        let circuit_type = BaseLayerCircuitType::L1MessagesHasher;

        let mut maker = CircuitMaker::new(
            geometry.limit_for_l1_messages_pudata_hasher,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in l1_messages_linear_hash_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::L1MessagesHasher(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            l1_messages_hasher_circuits,
            queue_simulator,
            l1_messages_hasher_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            l1_messages_hasher_circuits_compact_forms_witnesses.clone(),
        );

        // transient storage sorter
        let circuit_type = BaseLayerCircuitType::TransientStorageChecker;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_transient_storage_sorter,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in transient_storage_sorter_circuit_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::TransientStorageSorter(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            transient_storage_sorter_circuits,
            queue_simulator,
            transient_storage_sorter_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            transient_storage_sorter_circuits_compact_forms_witnesses.clone(),
        );

        // secp256r1 verify
        let circuit_type = BaseLayerCircuitType::Secp256r1Verify;

        let mut maker = CircuitMaker::new(
            geometry.cycles_per_secp256r1_verify_circuit,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        for circuit_input in secp256r1_verify_circuits_data.into_iter() {
            circuit_callback(ZkSyncBaseLayerCircuit::Secp256r1Verify(
                maker.process(circuit_input, circuit_type),
            ));
        }

        let (
            secp256r1_verify_circuits,
            queue_simulator,
            secp256r1_verify_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            secp256r1_verify_circuits_compact_forms_witnesses.clone(),
        );

        // eip 4844 circuits are basic, but they do not need closed form input commitments
        let circuit_type = BaseLayerCircuitType::EIP4844Repack;
        let mut maker = CircuitMaker::new(
            1,
            round_function.clone(),
            &mut cs_for_witness_generation,
            &mut cycles_used,
        );

        let mut eip_4844_circuits = Vec::new();
        for el in eip_4844_repack_inputs.into_iter() {
            let Some(input_witness) = el else {
                continue;
            };
            use crate::generate_eip4844_witness;
            let (chunks, linear_hash, versioned_hash, output_hash) = generate_eip4844_witness::<GoldilocksField>(
                &input_witness[..],
                "src/kzg/trusted_setup.json"
            );
            let data_chunks: VecDeque<_> = chunks.iter().map(|el| BlobChunkWitness {
                inner: *el,
            }).collect();
            use crate::zkevm_circuits::eip_4844::input::*;
            use crate::zkevm_circuits::fsm_input_output::ClosedFormInputWitness;
            let output_data = EIP4844OutputDataWitness {
                linear_hash,
                output_hash,
            };
            let eip_4844_circuit_input = EIP4844CircuitInstanceWitness::<GoldilocksField> {
                closed_form_input: ClosedFormInputWitness {
                    start_flag: true,
                    completion_flag: true,
                    observable_input: (),
                    observable_output: output_data,
                    hidden_fsm_input: (),
                    hidden_fsm_output: (),
                },
                versioned_hash,
                linear_hash_output: linear_hash,
                data_chunks,
            };
            eip_4844_circuits.push(eip_4844_circuit_input);
        }
        for circuit_input in eip_4844_circuits.iter().cloned() {
            circuit_callback(ZkSyncBaseLayerCircuit::EIP4844Repack(
                maker.process(circuit_input, circuit_type),
            ));
        }
        let (
            _eip_4844_circuits,
            queue_simulator,
            eip_4844_circuits_compact_forms_witnesses,
        ) = maker.into_results();
        recursion_queue_callback(
            circuit_type as u64,
            queue_simulator,
            eip_4844_circuits_compact_forms_witnesses,
        );

        // done!

        let basic_circuits = BlockFirstAndLastBasicCircuits {
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

        (basic_circuits, all_compact_forms, eip_4844_circuits)
    }
}

use crate::INITIAL_MONOTONIC_CYCLE_COUNTER;
