// implement witness oracle to actually compute
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use crate::encodings::callstack_entry::{CallstackSimulatorState, ExtendedCallstackEntry};
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::ff::Field;
use crate::u160_from_address;
use crate::witness::tracer::WitnessTracer;
use derivative::Derivative;
use num_bigint::BigUint;
use rayon::slice::ParallelSliceMut;
use std::collections::{BTreeMap, HashMap};
use std::ops::RangeInclusive;
use sync_vm::traits::CSWitnessable;
use sync_vm::vm::vm_cycle::memory::MemoryLocation;
use sync_vm::vm::vm_cycle::witness_oracle::{u256_to_biguint, WitnessOracle};
use sync_vm::{
    circuit_structures::traits::CircuitArithmeticRoundFunction,
    franklin_crypto::bellman::pairing::Engine,
};
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::{
    LogQuery, MemoryIndex, MemoryPage, MemoryQuery, EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE,
    PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
};
use sync_vm::scheduler::queues::{FullSpongeLikeQueueState, QueueStateWitness};
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use zk_evm::precompiles::KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS;
use zk_evm::testing::event_sink::ApplicationData;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueState;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueStateWitness;
use zk_evm::vm_state::{CallStackEntry, TIMESTAMPS_PER_CYCLE, VmLocalState};
use crate::witness::callstack_handler::OutOfScopeReason;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug)]
pub struct RollbackQueueStateWitness<E: Engine> {
    pub head: E::Fr,
    pub tail: E::Fr,
    pub segment_length: u32,
}

pub struct VmWitnessOracle<E: Engine> {
    pub memory_read_witness: Vec<(u32, MemoryQuery)>,
    pub rollback_queue_head_segments: Vec<(u32, E::Fr)>,
    pub decommittment_requests_witness: Vec<(u32, DecommittmentQuery)>,
    pub rollback_queue_initial_tails_for_new_frames: Vec<(u32, (usize, E::Fr))>,
    pub storage_read_queries: Vec<(u32, LogQuery)>,
    pub callstack_values_for_returns:
        Vec<(u32, (ExtendedCallstackEntry<E>, CallstackSimulatorState<E>))>,
    // pub initial_tail_for_entry_point: E::Fr,
    // pub initial_callstack_state_for_start: ([E::Fr; 3], CallStackEntry),
    // pub initial_context_for_start: CallStackEntry,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug)]
pub struct StorageLogDetailedState<E: Engine> {
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
#[derivative(Debug)]
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
pub struct CommonLogSponges<E: Engine>{
    pub rf_0: ([E::Fr; 3], [E::Fr; 3]),
    pub rf_1: ([E::Fr; 3], [E::Fr; 3]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct ForwardLogSponge<E: Engine>{
    pub old_tail: E::Fr,
    pub new_tail: E::Fr,
    pub exclusive_rf: ([E::Fr; 3], [E::Fr; 3]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct RollbackLogSponge<E: Engine>{
    pub old_head: E::Fr,
    pub new_head: E::Fr,
    pub exclusive_rf: ([E::Fr; 3], [E::Fr; 3]),
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
pub struct LogAccessSpongesInfo<E: Engine>{
    pub cycle: u32,
    pub common_sponges: CommonLogSponges<E>,
    pub forward_info: ForwardLogSponge<E>,
    pub rollback_info: Option<RollbackLogSponge<E>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""), Debug, Default(bound = ""))]
struct FlattenedLogQueueIndexer<E: Engine>{
    pub current_head: E::Fr,
    pub current_tail: E::Fr,
    pub head_offset: usize,
    pub tail_offset: usize,
}

pub fn create_artifacts_from_tracer<E: Engine, R: CircuitArithmeticRoundFunction<E, 2, 3>>(
    tracer: WitnessTracer,
    round_function: &R,
) -> (Vec<VmInstanceWitness<E, VmWitnessOracle<E>>>, FullBlockArtifacts<E>) {
    let WitnessTracer {
        memory_queries,
        storage_read_queries,
        decommittment_queries,
        keccak_round_function_witnesses,
        sha256_round_function_witnesses,
        ecrecover_witnesses,
        log_frames_stack,
        monotonic_query_counter: _,
        callstack_with_aux_data,
        vm_snapshots,
        ..
    } = tracer;

    assert!(vm_snapshots.len() >= 2); // we need at least entry point and the last save (after exit)

    let memory_read_witness: Vec<_> = memory_queries
        .iter()
        .filter(|el| !el.1.rw_flag)
        .cloned()
        .collect();
    let vm_memory_queries_accumulated = memory_queries;

    // segmentation of the log queue
    // - split into independent queues
    // - compute initial tail segments (with head == tail) for every new call frame
    // - also compute head segments for every write-like actions

    let mut log_queue_simulator = LogQueueSimulator::<E>::empty();
    let mut log_frames_stack = log_frames_stack;
    assert_eq!(log_frames_stack.len(), 1, "VM trace didn't exit the root frame"); // we must have exited the root
    let ApplicationData { forward, rollbacks } = log_frames_stack.drain(0..1).next().unwrap();
    drop(log_frames_stack);

    let num_forwards = forward.len();
    let num_rollbacks = rollbacks.len();
    dbg!(num_forwards);
    dbg!(num_rollbacks);

    let mut sorted_rollup_storage_queries = vec![];
    let mut sorted_porter_storage_queries = vec![];
    let mut sorted_event_queries = vec![];
    let mut sorted_to_l1_queries = vec![];
    let mut sorted_keccak_precompile_queries = vec![];
    let mut sorted_sha256_precompile_queries = vec![];
    let mut sorted_ecrecover_queries = vec![];
    let original_log_queue: Vec<_> = forward.iter().map(|(_, b)| (b.1, b.2.clone())).collect();
    let mut original_log_queue_states = vec![];

    let mut chain_of_states = vec![];

    // we want to have some hashmap that will indicate
    // that on some specific VM cycle we either read or write

    // from cycle into first two sponges (common), then tail-tail pair and 3rd sponge for forward, then head-head pair and 3rd sponge for rollback
    let mut sponges_data: HashMap<
        u32,
        LogAccessSpongesInfo<E>,
    > = HashMap::new();

    // now it's going to be fun. We simultaneously will do the following indexing:
    // - simulate the state of callstack as a sponge
    // - follow the call graph and storage queries graph to know exacly the following subset of properties at any
    // range of cycles:
    // - callstack "frozen" part (what is in the callstack). This involves rollback queue head/tail/length!
    // - "active" callstack entry rollback queue's head/tail/length at this cycle

    // first we need to hash the queue itself, and create an index of "where in the final flat queue did log access from this frame end up"
    // If we encounter "read" that implies no reverts we use "None"

    let mut cycle_into_flat_sequence_index = HashMap::<u32, (usize, Option<usize>)>::with_capacity(num_forwards + num_rollbacks);

    // for some cycle we point to the elements in the flattened history - to when forward operation ended up, and where rollback ended up
    // let mut cycle_pointers = HashMap::<u32, (usize, usize)>::new();

    // in practive we also split out precompile accesses

    for ((_, (frame_marker, cycle, query)), was_applied) in
        forward.iter().cloned().zip(std::iter::repeat(true)).chain(
            rollbacks
                .iter()
                .rev()
                .cloned()
                .zip(std::iter::repeat(false)),
        )
    {
        let (_old_tail, intermediate_info) =
            log_queue_simulator.push_and_output_intermediate_data(query, round_function);

        let pointer = chain_of_states.len();
        // we just log all chains of old tail -> new tail, and will interpret them later
        chain_of_states.push((cycle, frame_marker, (intermediate_info.previous_tail, intermediate_info.tail)));

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
        }

        // and sort
        if was_applied {
            original_log_queue_states.push((cycle, intermediate_info));
            match query.aux_byte {
                STORAGE_AUX_BYTE => {
                    // sort rollup and porter
                    match query.shard_id {
                        0 => {
                            sorted_rollup_storage_queries.push(query);
                        }
                        1 => {
                            sorted_porter_storage_queries.push(query);
                        }
                        _ => unreachable!(),
                    }
                }
                L1_MESSAGE_AUX_BYTE => {
                    sorted_to_l1_queries.push(query);
                }
                EVENT_AUX_BYTE => {
                    sorted_event_queries.push(query);
                }
                PRECOMPILE_AUX_BYTE => {
                    assert!(!query.rollback);
                    use zk_evm::precompiles::*;
                    match query.address {
                        a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            sorted_keccak_precompile_queries.push(query);
                        }
                        a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            sorted_sha256_precompile_queries.push(query);
                        }
                        a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                            sorted_ecrecover_queries.push(query);
                        }
                        _ => {
                            // just burn ergs
                        },
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    let full_log_length = chain_of_states.len();
    assert_eq!(full_log_length, num_forwards + num_rollbacks);

    let mut indexer = FlattenedLogQueueIndexer::<E>::default();
    indexer.current_tail = chain_of_states.last().map(|el| el.2.1).unwrap_or(E::Fr::zero());
    indexer.tail_offset = full_log_length - 1;

    let log_accesses_history: Vec<_> = callstack_with_aux_data
        .log_queue_access_snapshots
        .iter()
        .cloned()
        .map(|mut el| {
            if let Some(rollback_pointer) = el.1.monotonic_rollback_query_counter.as_mut() {
                *rollback_pointer = full_log_length - *rollback_pointer;
            }

            el
        }).collect();

    let full_history = callstack_with_aux_data
        .full_history
        .iter()
        .cloned()
        .map(|mut el| {
            // renumerate
            let new_end = full_log_length - el.rollback_queue_ranges_at_entry.start;
            let new_start = full_log_length - el.rollback_queue_ranges_at_entry.end;

            el.rollback_queue_ranges_at_entry = new_start..new_end;


            let new_end = full_log_length - el.rollback_queue_ranges_change.start;
            let new_start = full_log_length - el.rollback_queue_ranges_change.end;

            el.rollback_queue_ranges_change = new_start..new_end;

            el.monotonic_rollback_query_counter_on_first_entry = full_log_length - el.monotonic_rollback_query_counter_on_first_entry;
            if let Some(monotonic_rollback_query_counter_on_exit) = el.monotonic_rollback_query_counter_on_exit.as_mut() {
                *monotonic_rollback_query_counter_on_exit = full_log_length - *monotonic_rollback_query_counter_on_exit;
            }

            el
        });

    dbg!(&chain_of_states);
    
    use super::callstack_handler::CallstackAction;
    use crate::encodings::callstack_entry::CallstackSimulator;
    let mut callstack_argebraic_simulator = CallstackSimulator::<E>::empty();
    let mut callstack_values_for_returns = vec![]; // index of cycle -> witness for callstack pop
    let mut rollback_queue_initial_tails_for_new_frames = vec![];
    let mut rollback_queue_head_segments = vec![];

    // we need to simultaneously follow the logic of pushes/joins of the storage queues,
    // and encoding of the current callstack state as the sponge state

    // here we are interested in "frozen" elements that are in the stack,
    // so we never follow the "current", but add on push/pop

    // These are "frozen" states that just lie in the callstack for now and can not be modified
    let mut callstack_sponge_encoding_ranges = vec![];
    let mut current_range = 0..0;

    let mut enriched_log_access_history = vec![];
    let end_of_queue = chain_of_states
        .last()
        .map(|el| el.2.1)
        .unwrap_or(E::Fr::zero());

    use crate::witness::callstack_handler::LogQueueAccessAuxData;

    let mut current_enriched_history_offset = 0;

    let full_history: Vec<_> = full_history.collect();

    for (idx, el) in full_history.iter().cloned().enumerate() {
        match el.action {
            CallstackAction::PushToStack => {
                dbg!(&el);
                // this is a point where need to substitue a state of the computed chain
                // we mainly need the length of the segment of the rollback queue and the current point
                // and head/tail parts of the queue

                // everything was joined for us, so we need to only ask what is a current state

                assert!(el.forward_queue_ranges_changes.is_empty(), "changes must have been merged into `on entry` part, got {:?}", el.forward_queue_ranges_changes);

                let segment = el.rollback_queue_ranges_at_entry;
                let head = chain_of_states[segment.start - 1].2 .1;
                let tail = chain_of_states[segment.end - 1].2 .1;
                let len = segment.len();

                let entry = ExtendedCallstackEntry {
                    callstack_entry: el.affected_entry,
                    rollback_queue_head: head,
                    rollback_queue_tail: tail,
                    rollback_queue_segment_length: len as u32,
                };

                let states = callstack_argebraic_simulator
                    .push_and_output_intermediate_data(entry, round_function);

                // when we push a new one then we need to "finish" the previous range and start a new one
                let active_range = current_range.start..el.cycle_index;
                current_range = el.cycle_index..el.cycle_index;

                callstack_sponge_encoding_ranges.push((active_range, states.new_state));
            }
            CallstackAction::PopFromStack { panic: _ } => {
                // here we actually get witness

                dbg!(&el);

                let (entry, intermediate_info) =
                    callstack_argebraic_simulator.pop_and_output_intermediate_data(round_function);
                callstack_values_for_returns.push((el.cycle_index, (entry, intermediate_info)));

                // some older frame became current

                // when we push a new one then we need to "finish" the previous range and start a new one
                let active_range = current_range.start..el.cycle_index;
                current_range = el.cycle_index..el.cycle_index;

                callstack_sponge_encoding_ranges.push((active_range, intermediate_info.new_state));

                // we have created a new frame and can determine all the states before any next call

                let rollback_head_idx = el.rollback_queue_ranges_change.start - 1;
                let rollback_tail_idx = el.rollback_queue_ranges_at_entry.end - 1;

                let head = chain_of_states[rollback_head_idx].2 .1;
                let tail = chain_of_states[rollback_tail_idx].2 .1;

                let current_rollback_len = el.rollback_queue_ranges_at_entry.len() + el.rollback_queue_ranges_change.len();

                let segment = &el.forward_queue_ranges_changes;
                let mut current_forward_tail = E::Fr::zero();
                if segment.end != 0 {
                    current_forward_tail = chain_of_states[segment.end-1].2 .1;
                } 
                let mut current_forward_length = segment.end as u32;

                // this frame can be current and have some interactions, unless it's root
                if let Some(next) = full_history.get(idx+1) {
                    let next_action_cycle = next.cycle_index;
                    let cycle_idx = el.cycle_index;
    
                    let interactions_in_this_frame = log_accesses_history
                        .iter()
                        .skip(current_enriched_history_offset)
                        .take_while(|el| el.0 < next_action_cycle);
    
                    let mut current_enriched_history = StorageLogDetailedState::<E> {
                        forward_tail: current_forward_tail,
                        forward_length: current_forward_length as u32,
                        rollback_head: head,
                        rollback_tail: tail,
                        rollback_length: current_rollback_len as u32,
                    };
    
                    enriched_log_access_history.push((cycle_idx, current_enriched_history));

                    for (cycle, log_interaction) in interactions_in_this_frame.cloned() {
                        current_enriched_history_offset += 1;
                        let LogQueueAccessAuxData { monotonic_forward_query_counter, monotonic_rollback_query_counter } = log_interaction;
    
                        // forward queue interaction
                        let (_cycle, _,  (_, forward_tail)) = chain_of_states[monotonic_forward_query_counter];

                        current_forward_length += 1;
                        current_forward_tail = forward_tail;
                        current_enriched_history.forward_tail = current_forward_tail;
                        current_enriched_history.forward_length = current_forward_length;
    
                        if let Some(monotonic_rollback_query_counter) = monotonic_rollback_query_counter {
                            let (_cycle, _, (rollback_head, _)) = chain_of_states[monotonic_rollback_query_counter];
    
                            current_enriched_history.rollback_head = rollback_head;
                            current_enriched_history.rollback_length += 1;
                            rollback_queue_head_segments.push((cycle, rollback_head));
                        }
    
                        enriched_log_access_history.push((cycle, current_enriched_history));
                    }
                } else {
                    let cycle_idx = el.cycle_index;

                    // log just the info
                    let current_enriched_history = StorageLogDetailedState::<E> {
                        forward_tail: current_forward_tail,
                        forward_length: current_forward_length as u32,
                        rollback_head: head,
                        rollback_tail: tail,
                        rollback_length: current_rollback_len as u32,
                    };
    
                    enriched_log_access_history.push((cycle_idx, current_enriched_history));
                }
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
                // we have created a new frame and can determine all the states before any next call

                dbg!(&el);
                // we can determine the tail right now
                let first_entry_rollback_counter = el.monotonic_rollback_query_counter_on_first_entry; 
                let initial_rollback_tail = chain_of_states[first_entry_rollback_counter-1].2.1;

                // save rollback tail state on entry into new frame
                rollback_queue_initial_tails_for_new_frames.push((el.cycle_index, initial_rollback_tail));

                assert!(el.rollback_queue_ranges_at_entry.is_empty());

                let segment = el.rollback_queue_ranges_at_entry;
                let head = chain_of_states[segment.start - 1].2.1;
                let tail = chain_of_states[segment.end - 1].2.1;
                let len = segment.len();
                assert_eq!(initial_rollback_tail, tail);
                assert_eq!(head, tail);
                assert!(len == 0);

                let segment = &el.forward_queue_ranges_at_entry;
                
                let mut current_forward_tail = E::Fr::zero();
                if segment.end != 0 {
                    current_forward_tail = chain_of_states[segment.end-1].2 .1;
                } 
                let mut current_forward_length = segment.end as u32;

                // we can expect some actions while this frame is active

                let next = &full_history[idx+1];
                let next_action_cycle = next.cycle_index;
                let cycle_idx = el.cycle_index;

                let interactions_in_this_frame = log_accesses_history
                    .iter()
                    .skip(current_enriched_history_offset)
                    .take_while(|el| el.0 < next_action_cycle);

                let mut current_enriched_history =  StorageLogDetailedState {
                    forward_tail: current_forward_tail,
                    forward_length: current_forward_length as u32,
                    rollback_head: initial_rollback_tail,
                    rollback_tail: initial_rollback_tail,
                    rollback_length: 0,
                };

                enriched_log_access_history.push((cycle_idx, current_enriched_history));

                for (cycle, log_interaction) in interactions_in_this_frame.cloned() {
                    current_enriched_history_offset += 1;
                    let LogQueueAccessAuxData { monotonic_forward_query_counter, monotonic_rollback_query_counter } = log_interaction;

                    // forward queue interaction
                    let (_cycle, _,  (_, forward_tail)) = chain_of_states[monotonic_forward_query_counter];

                    current_forward_length += 1;
                    current_forward_tail = forward_tail;
                    current_enriched_history.forward_tail = current_forward_tail;
                    current_enriched_history.forward_length = current_forward_length;

                    if let Some(monotonic_rollback_query_counter) = monotonic_rollback_query_counter {
                        let (_cycle, _, (rollback_head, _)) = chain_of_states[monotonic_rollback_query_counter-1];

                        current_enriched_history.rollback_head = rollback_head;
                        current_enriched_history.rollback_length += 1;
                        rollback_queue_head_segments.push((cycle, rollback_head));
                    }

                    enriched_log_access_history.push((cycle, current_enriched_history));
                }
            }
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: _ }) => {
                dbg!(&el);
                // we are not too interested
            }
        }
    }

    dbg!(&enriched_log_access_history);

    todo!();


    // // let mut callstack_log_part_ranges = vec![]; // cycle, rollback head, rollback tail, segment length

    // // this is a state on top of the callstack
    // let mut current_context = None;

    // // let mut peekckable_iterator_over_chain_of_states = chain_of_states.iter().peekable();
    // let mut peekckable_forward_log_iter = forward.iter().peekable();
    // let mut peekckable_rollback_log_iter = rollbacks.iter().rev().peekable();



    // let mut full_history_peekable_iter = full_history.iter().peekable();

    // let mut map = HashMap::<u32, (E::Fr, E::Fr, u32)>::new();

    // let mut current_callstack_item_props = (E::Fr::zero(), E::Fr::zero(), 0u32);
    // let el = full_history_peekable_iter.next().cloned().unwrap();
    // assert!(el.action == CallstackAction::PushToStack);
    // let (head, tail, segment_len) =
    //     if let Some(segment) = el.rollback_queue_ranges_at_entry.last() {
    //         let head = chain_of_states[segment.start - 1].2 .1;
    //         let tail = chain_of_states[segment.end - 1].2 .1;
    //         let len = segment.len();

    //         (head, tail, len)
    //     } else {
    //         // it's the end
    //         let t = chain_of_states
    //             .last()
    //             .map(|el| el.2 .1)
    //             .unwrap_or(E::Fr::zero());
    //         (t, t, 0)
    //     };

    // let entry = ExtendedCallstackEntry {
    //     callstack_entry: el.affected_entry,
    //     rollback_queue_head: head,
    //     rollback_queue_tail: tail,
    //     rollback_queue_segment_length: segment_len as u32,
    // };

    // let states = callstack_argebraic_simulator
    //     .push_and_output_intermediate_data(entry, round_function);

    // // when we push a new one then we need to "finish" the previous range and start a new one
    // let active_range = current_range.start..el.cycle_index;
    // current_range = el.cycle_index..el.cycle_index;

    // callstack_sponge_encoding_ranges.push((active_range, states.new_state));

    // dbg!(&chain_of_states);

    // current_callstack_item_props.0 = head;
    // current_callstack_item_props.1 = tail;
    // current_callstack_item_props.2 = segment_len as u32;

    // map.insert(0, current_callstack_item_props);

    // loop {
    //     if let Some(_next_action) = full_history_peekable_iter.peek().cloned() {
    //         let el = full_history_peekable_iter.next().cloned().unwrap();

    //         dbg!(&el);

    //         match el.action {
    //             CallstackAction::PushToStack => {
    //                 // this is a point where need to substitue a state of the computed chain
    //                 // we mainly need the length of the segment of the rollback queue and the current point
    //                 // and head/tail parts of the queue
    
    //                 // assert!(el.rollback_queue_ranges_at_entry.len() <= 1);
    //                 assert!(
    //                     el.rollback_queue_ranges_change.len() == 0,
    //                     "expected merged changes for push, got {:?}",
    //                     &el.rollback_queue_ranges_change
    //                 );
    
    //                 // everything was joined for us, so we need to only ask what is a current state
    
    //                 let (head, tail, segment_len) =
    //                     if let Some(segment) = el.rollback_queue_ranges_at_entry.last() {
    //                         let head = chain_of_states[segment.start - 1].2 .1;
    //                         let tail = chain_of_states[segment.end - 1].2 .1;
    //                         let len = segment.len();
    
    //                         (head, tail, len)
    //                     } else {
    //                         // it's the end
    //                         let t = chain_of_states
    //                             .last()
    //                             .map(|el| el.2 .1)
    //                             .unwrap_or(E::Fr::zero());
    //                         (t, t, 0)
    //                     };
    
    //                 let entry = ExtendedCallstackEntry {
    //                     callstack_entry: el.affected_entry,
    //                     rollback_queue_head: head,
    //                     rollback_queue_tail: tail,
    //                     rollback_queue_segment_length: segment_len as u32,
    //                 };
    
    //                 let states = callstack_argebraic_simulator
    //                     .push_and_output_intermediate_data(entry, round_function);
    
    //                 // when we push a new one then we need to "finish" the previous range and start a new one
    //                 let active_range = current_range.start..el.cycle_index;
    //                 current_range = el.cycle_index..el.cycle_index;
    
    //                 callstack_sponge_encoding_ranges.push((active_range, states.new_state));
    //             }
    //             CallstackAction::PopFromStack { panic: _ } => {
    //                 // here we actually get witness
    
    //                 let (entry, intermediate_info) =
    //                     callstack_argebraic_simulator.pop_and_output_intermediate_data(round_function);
    //                 callstack_values_for_returns.push((el.cycle_index, (entry, intermediate_info)));

    //                 // some older frame became current

    //                 // we have created a new frame and can determine all the states before any next call

    //                 let (head, tail, segment_len) =
    //                 if let Some(segment) = el.rollback_queue_ranges_at_entry.first() {
    //                     let head = chain_of_states[segment.start - 1].2 .1;
    //                     let tail = chain_of_states[segment.end - 1].2 .1;
    //                     let len = segment.len();

    //                     (head, tail, len)
    //                 } else {
    //                     // it's the end
    //                     let t = chain_of_states
    //                         .last()
    //                         .map(|el| el.2 .1)
    //                         .unwrap_or(E::Fr::zero());
    //                     (t, t, 0)
    //                 };

    //                 current_callstack_item_props.0 = head;
    //                 current_callstack_item_props.1 = tail;
    //                 current_callstack_item_props.2 = segment_len as u32;

    //                 rollback_queue_initial_tails_for_new_frames.push((el.cycle_index, current_callstack_item_props.1));

    //                 if let Some(_next_action) = full_history_peekable_iter.peek().cloned() {
    //                     let next_call_cycle = _next_action.cycle_index;

    //                     while let Some(peek_next_forward) = peekckable_forward_log_iter.peek().cloned() {
    //                         if peek_next_forward.1.1 < next_call_cycle {
    //                             // we will have a sequence of calls in this frame
    //                             let next_forward = peekckable_forward_log_iter.next().cloned().unwrap();
    //                             let (_, (_, cycle_idx, query)) = next_forward;
    //                             indexer.head_offset += 1;
    //                             if query.rollback {
    //                                 assert!(peekckable_rollback_log_iter.next().is_some());
    //                                 indexer.tail_offset -= 1;
    //                                 current_callstack_item_props.2 += 1;
    //                                 let new_head = chain_of_states[indexer.tail_offset].2.0;
    //                                 current_callstack_item_props.0 = new_head;
    //                                 rollback_queue_head_segments.push((cycle_idx, new_head));
    //                             }

    //                             map.insert(cycle_idx, current_callstack_item_props);
    //                         } else {
    //                             break;
    //                         }
    //                     }
    //                 } else {
    //                     // it's the exit from the root frame, not too interesting
    //                 }

    //                 // when we push a new one then we need to "finish" the previous range and start a new one
    //                 let active_range = current_range.start..el.cycle_index;
    //                 current_range = el.cycle_index..el.cycle_index;
    
    //                 callstack_sponge_encoding_ranges.push((active_range, intermediate_info.new_state));
    //             }
    //             CallstackAction::OutOfScope(OutOfScopeReason::Fresh) => {
    //                 if current_context.is_none() {
    //                     current_context = Some(el.affected_entry);
    //                 }

    //                 // we have created a new frame and can determine all the states before any next call

    //                 let (head, tail, segment_len) =
    //                 if let Some(segment) = el.rollback_queue_ranges_at_entry.first() {
    //                     let head = chain_of_states[segment.start - 1].2 .1;
    //                     let tail = chain_of_states[segment.end - 1].2 .1;
    //                     let len = segment.len();

    //                     (head, tail, len)
    //                 } else {
    //                     // it's the end
    //                     let t = chain_of_states
    //                         .last()
    //                         .map(|el| el.2 .1)
    //                         .unwrap_or(E::Fr::zero());
    //                     (t, t, 0)
    //                 };

    //                 assert!(segment_len == 0);

    //                 current_callstack_item_props.0 = head;
    //                 current_callstack_item_props.1 = tail;
    //                 current_callstack_item_props.2 = segment_len as u32;

    //                 dbg!(&current_callstack_item_props);

    //                 let next_action = full_history_peekable_iter.peek().cloned().unwrap(); // will always exists, as there is something on callstack
    //                 let next_call_cycle = next_action.cycle_index;

    //                 while let Some(peek_next_forward) = peekckable_forward_log_iter.peek().cloned() {
    //                     if peek_next_forward.1.1 < next_call_cycle {
    //                         // we will have a sequence of calls in this frame
    //                         let next_forward = peekckable_forward_log_iter.next().cloned().unwrap();
    //                         let (_, (_, cycle_idx, query)) = next_forward;
    //                         if !query.rollback {
    //                             let (forward_offset, rollback_offset) = cycle_into_flat_sequence_index[&cycle_idx];
    //                             assert_eq!(forward_offset, indexer.head_offset);
    //                             if let Some(rollback_offset) = rollback_offset {
    //                                 let new_head = chain_of_states[rollback_offset].2.0;
    //                                 current_callstack_item_props.0 = new_head;
    //                                 current_callstack_item_props.2 += 1;
    //                                 rollback_queue_head_segments.push((cycle_idx, new_head));
    //                             }
    //                         }
    //                         indexer.head_offset += 1;
    //                         // if query.rollback {
    //                         //     assert!(peekckable_rollback_log_iter.next().is_some());
    //                         //     indexer.tail_offset -= 1;
    //                         //     current_callstack_item_props.2 += 1;
    //                         //     let new_head = chain_of_states[indexer.tail_offset].2.0;
    //                         //     current_callstack_item_props.0 = new_head;
    //                         // }

    //                         dbg!(&current_callstack_item_props);

    //                         map.insert(cycle_idx, current_callstack_item_props);
    //                     } else {
    //                         // next access will be in another frame
    //                         break
    //                     }
    //                 }
    //                 // 
    //             }
    //             CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: _ }) => {
    //                 assert!(current_context.is_some());

    //                 // 
    //             }
    //         }

    //     } else {
    //         // we should only walk the remaining logs and index them
    //         if let Some(next_forward) = peekckable_forward_log_iter.next().cloned() {
    //             let (_, (_, cycle_idx, query)) = next_forward;
    //             if !query.rollback {
    //                 let (forward_offset, rollback_offset) = cycle_into_flat_sequence_index[&cycle_idx];
    //                 assert_eq!(forward_offset, indexer.head_offset);
    //                 if let Some(rollback_offset) = rollback_offset {
    //                     let new_head = chain_of_states[rollback_offset].2.0;
    //                     current_callstack_item_props.0 = new_head;
    //                     current_callstack_item_props.2 += 1;
    //                 }
    //             }
    //             indexer.head_offset += 1;

    //             map.insert(cycle_idx, current_callstack_item_props);
    //         } else {
    //             break;
    //         }
    //     }
    // }

    // dbg!(&map);

    // // we simulate a series of actions on the stack starting from the outermost frame
    // // each history record contains an information on what was the stack state between points
    // // when it potentially came into and out of scope

    // let mut artifacts = FullBlockArtifacts::<E>::default();
    // artifacts.vm_memory_queries_accumulated = vm_memory_queries_accumulated;
    // artifacts.all_decommittment_queries = decommittment_queries;
    // artifacts.keccak_round_function_witnesses = keccak_round_function_witnesses;
    // artifacts.sha256_round_function_witnesses = sha256_round_function_witnesses;
    // artifacts.ecrecover_witnesses = ecrecover_witnesses;
    // artifacts.original_log_queue = original_log_queue;
    // artifacts.original_log_queue_states = original_log_queue_states;

    // artifacts.sorted_rollup_storage_queries = sorted_rollup_storage_queries;
    // artifacts.sorted_porter_storage_queries = sorted_porter_storage_queries;
    // artifacts.sorted_event_queries = sorted_event_queries;
    // artifacts.sorted_to_l1_queries = sorted_to_l1_queries;
    // artifacts.demuxed_keccak_precompile_queries = sorted_keccak_precompile_queries;
    // artifacts.demuxed_sha256_precompile_queries = sorted_sha256_precompile_queries;
    // artifacts.demuxed_ecrecover_queries = sorted_ecrecover_queries;

    // artifacts.process(round_function);

    // let mut all_instances_witnesses = vec![];

    // for pair in vm_snapshots.windows(2) {
    //     let initial_state = &pair[0];
    //     let final_state = &pair[1];

    //     // we need to get chunks of
    //     // - memory read witnesses
    //     // - storage read witnesses
    //     // - decommittment witnesses
    //     // - callstack witnesses
    //     // - rollback queue witnesses

    //     // first find the memory witness by scanning all the known states
    //     // and finding the latest one with cycle index < current
    //     use crate::witness_structures::{transform_queue_state, transform_sponge_like_queue_state};

    //     let memory_queue_state_for_entry = artifacts.vm_memory_queue_states.iter().take_while(
    //         |el| el.0 < initial_state.at_cycle
    //     )
    //     .last()
    //     .map(|el| transform_sponge_like_queue_state(el.2))
    //     .unwrap_or(FullSpongeLikeQueueState::<E>::placeholder_witness());

    //     let decommittment_queue_state_for_entry = artifacts.all_decommittment_queue_states.iter().take_while(
    //         |el| el.0 < initial_state.at_cycle
    //     )
    //     .last()
    //     .map(|el| transform_sponge_like_queue_state(el.1))
    //     .unwrap_or(FullSpongeLikeQueueState::<E>::placeholder_witness());

    //     // we also need forward storage log queue
    //     let storage_log_queue_state_for_entry = artifacts.original_log_queue_states.iter().take_while(
    //         |el| el.0 < initial_state.at_cycle
    //     )
    //     .last()
    //     .map(|el| transform_queue_state(el.1))
    //     .unwrap_or(FixedWidthEncodingGenericQueueState::<E>::placeholder_witness());

    //     // and finally we need the callstack current state

    //     let mut el = None;
    //     for (range, state) in callstack_sponge_encoding_ranges.iter() {
    //         if range.contains(&initial_state.at_cycle) {
    //             el = Some(*state);
    //             break;
    //         }
    //     }

    //     let callstack_state_for_entry = el.unwrap_or([E::Fr::zero(); 3]);

    //     // initial state is kind of done, now
    //     // split the oracle witness

    //     let per_isntance_memory_read_witnesses: Vec<_> = memory_read_witness.iter()
    //         .take_while(
    //             |el| el.0 < initial_state.at_cycle
    //         ).cloned().collect();

    //     let per_isntance_storage_read_witnesses: Vec<_> = storage_read_queries.iter()
    //         .take_while(
    //             |el| el.0 < initial_state.at_cycle
    //         ).cloned().collect();

    //     let decommittment_requests_witness: Vec<_> = artifacts.all_decommittment_queries.iter()
    //         .take_while(
    //             |el| el.0 < initial_state.at_cycle
    //         )
    //         .map(|el| (el.0, el.1))
    //         .collect();

    //     let rollback_queue_initial_tails_for_new_frames: Vec<_> = rollback_queue_initial_tails_for_new_frames.iter()
    //         .take_while(
    //             |el| el.0 < initial_state.at_cycle
    //         )
    //         .cloned()
    //         .collect();
    //     let callstack_values_for_returns = callstack_values_for_returns.iter()
    //         .take_while(
    //             |el| el.0 < initial_state.at_cycle
    //         )
    //         .cloned()
    //         .collect();
    //     let rollback_queue_head_segments = rollback_queue_head_segments.iter()
    //         .take_while(
    //             |el| el.0 < initial_state.at_cycle
    //         )
    //         .cloned()
    //         .collect();


    //     // construct an oracle
    //     let witness_oracle = VmWitnessOracle::<E> {
    //         memory_read_witness: per_isntance_memory_read_witnesses,
    //         rollback_queue_head_segments,
    //         decommittment_requests_witness,
    //         rollback_queue_initial_tails_for_new_frames,
    //         storage_read_queries: per_isntance_storage_read_witnesses,
    //         callstack_values_for_returns,
    //         // initial_tail_for_entry_point,
    //         // initial_callstack_state_for_start,
    //         // initial_context_for_start,
    //     };

    //     // continue into full witness for this instance of VM trace

    //     // it's easy to find the tail for the current frame as we have already prepared non-deterministic witnesses for it
    //     let rollback_queue_tail: E::Fr = rollback_queue_initial_tails_for_new_frames.iter().take_while(
    //         |el| el.0 < initial_state.at_cycle
    //     )
    //     .last()
    //     .map(|el| el.1.1)
    //     .unwrap();

    //     // for current head it's a little bit more complex, as we need to find 

    //     let mut instance_witness = VmInstanceWitness {
    //         initial_state: initial_state.local_state.clone(),
    //         witness_oracle,
    //         auxilary_initial_parameters: VmInCircuitAuxilaryParameters {
    //             callstack_state: (callstack_state_for_entry, initial_state.local_state.callstack.get_current_stack().clone()),
    //             decommittment_queue_state: decommittment_queue_state_for_entry,
    //             memory_queue_state: memory_queue_state_for_entry,
    //             storage_log_queue_state: storage_log_queue_state_for_entry,
    //             current_frame_rollback_queue_tail: rollback_queue_tail,
    //             current_frame_rollback_queue_head: ,
    //             current_frame_rollback_queue_segment_length
    //         },
    //         cycles_range: initial_state.at_cycle..final_state.at_cycle,
    //         final_state: final_state.local_state.clone(),
    //         auxilary_final_parameters: VmInCircuitAuxilaryParameters::default(), // TODO
    //     };

    //     dbg!(&instance_witness.initial_state);
    //     dbg!(&instance_witness.auxilary_initial_parameters);

    //     all_instances_witnesses.push(instance_witness);
    // }


    // let oracle = VmWitnessOracle::<E> {
    //     memory_read_witness,
    //     rollback_queue_head_segments,
    //     decommittment_requests_witness: decommittment_queries
    //         .iter()
    //         .map(|el| (el.0, el.1))
    //         .collect(),
    //     rollback_queue_initial_tails_for_new_frames,
    //     storage_read_queries,
    //     callstack_values_for_returns,
    //     initial_tail_for_entry_point,
    //     initial_callstack_state_for_start,
    //     initial_context_for_start,
    // };


    // (all_instances_witnesses, artifacts)
}

use crate::franklin_crypto::plonk::circuit::boolean::*;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::scheduler::data_access_functions::StorageLogRecord;
use sync_vm::scheduler::queues::{DecommitQueryWitness, FullSpongeLikeQueueStateWitness};
use sync_vm::scheduler::queues::{DecommitQuery};
use sync_vm::vm::primitives::*;
use sync_vm::vm::vm_state::saved_contract_context::ExecutionContextRecord;
use sync_vm::vm::vm_state::saved_contract_context::ExecutionContextRecordWitness;

use crate::entry_point::INITIAL_MONOTONIC_CYCLE_COUNTER;
use crate::entry_point::STARTING_TIMESTAMP;

impl<E: Engine> WitnessOracle<E> for VmWitnessOracle<E> {
    fn get_memory_witness_for_read(
        &mut self,
        timestamp: UInt32<E>,
        key: &MemoryLocation<E>,
        execute: &Boolean,
    ) -> Option<num_bigint::BigUint> {
        if execute.get_value().unwrap_or(false) {
            if self.memory_read_witness.is_empty() {
                panic!(
                    "should have a witness to read at timestamp {:?}, location {:?}",
                    timestamp.get_value(),
                    key.create_witness()
                );
            }
            let (_cycle, query) = self.memory_read_witness.drain(..1).next().unwrap();

            // println!("Query value = 0x{:x}", query.value);
            if let Some(ts) = timestamp.get_value() {
                let _roughly_a_cycle = (ts - STARTING_TIMESTAMP) / TIMESTAMPS_PER_CYCLE
                    + INITIAL_MONOTONIC_CYCLE_COUNTER;
                // assert_eq!(_cycle, _roughly_a_cycle);
            }

            if let Some(location) = key.create_witness() {
                assert_eq!(
                    location.page,
                    query.location.page.0,
                    "invalid memory access location at cycle {:?}",
                    timestamp.get_value()
                );
                // assert_eq!(location.index, query.location.index.0);
            }

            // println!("memory word = 0x{:x}", query.value);

            Some(u256_to_biguint(query.value))
        } else {
            Some(BigUint::from(0u64))
        }
    }

    fn push_memory_witness(&mut self, _memory_query: &RawMemoryQuery<E>, _execute: &Boolean) {
        // we do not care
    }

    fn get_storage_read_witness(
        &mut self,
        key: &StorageLogRecord<E>,
        execute: &Boolean,
    ) -> Option<num_bigint::BigUint> {
        if execute.get_value().unwrap_or(false) {
            let (_cycle, query) = self.storage_read_queries.drain(..1).next().unwrap();

            if let Some(location) = key.create_witness() {
                assert_eq!(location.address, u160_from_address(query.address));
                assert_eq!(location.key, u256_to_biguint(query.key));
            }

            Some(u256_to_biguint(query.read_value))
        } else {
            Some(BigUint::from(0u64))
        }
    }

    fn push_storage_witness(&mut self, _key: &StorageLogRecord<E>, _execute: &Boolean) {
        // we do not care
    }

    // may be should also track key for debug purposes
    fn get_rollback_queue_witness(
        &mut self,
        _key: &StorageLogRecord<E>,
        execute: &Boolean,
    ) -> Option<<E>::Fr> {
        if execute.get_value().unwrap_or(false) {
            let (_cycle, head) = self.rollback_queue_head_segments.drain(..1).next().unwrap();
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
            let (_cycle_idx, (_frame_idx, tail)) = self
                .rollback_queue_initial_tails_for_new_frames
                .drain(..1)
                .next()
                .unwrap();
            dbg!(tail);

            Some(tail)
        } else {
            Some(E::Fr::zero())
        }
    }

    fn push_callstack_witness(
        &mut self,
        current_record: &ExecutionContextRecord<E>,
        execute: &Boolean,
    ) {
        if execute.get_value().unwrap_or(false) {
            let wit = current_record.create_witness();
            dbg!(wit.as_ref().map(|el| el.common_part.reverted_queue_head));
            dbg!(wit.as_ref().map(|el| el.common_part.reverted_queue_tail));
            dbg!(wit
                .as_ref()
                .map(|el| el.common_part.reverted_queue_segment_len));
        }

        // we do not care
    }

    fn get_callstack_witness(
        &mut self,
        execute: &Boolean,
    ) -> (
        Option<ExecutionContextRecordWitness<E>>,
        Option<[<E>::Fr; 3]>,
    ) {
        if execute.get_value().unwrap_or(false) {
            let (_cycle_idx, (extended_entry, internediate_info)) =
                self.callstack_values_for_returns.drain(..1).next().unwrap();
            let CallstackSimulatorState {
                is_push,
                previous_state: _,
                new_state,
                depth: _,
                round_function_execution_pairs: _,
            } = internediate_info;

            assert!(!is_push);

            dbg!(new_state);

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
                    calldata_page: entry.calldata_page.0,
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
            let (_frame_idx, query) = self
                .decommittment_requests_witness
                .drain(..1)
                .next()
                .unwrap();

            if let Some(wit) = request.create_witness() {
                assert_eq!(wit.root_hash, u256_to_biguint(query.hash));
                assert_eq!(wit.timestamp, query.timestamp.0);
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
}
