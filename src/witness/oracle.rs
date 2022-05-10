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
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use zk_evm::precompiles::KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS;
use zk_evm::testing::event_sink::ApplicationData;
use zk_evm::vm_state::{CallStackEntry, TIMESTAMPS_PER_CYCLE};

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
    pub rollback_queue_initial_tails_for_new_frames: Vec<(usize, E::Fr)>,
    pub storage_read_queries: Vec<(u32, LogQuery)>,
    pub callstack_values_for_returns:
        Vec<(u32, (ExtendedCallstackEntry<E>, CallstackSimulatorState<E>))>,
    pub initial_tail_for_entry_point: E::Fr,
    pub initial_callstack_state_for_start: ([E::Fr; 3], CallStackEntry),
    pub initial_context_for_start: CallStackEntry,
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

pub fn create_artifacts_from_tracer<E: Engine, R: CircuitArithmeticRoundFunction<E, 2, 3>>(
    tracer: WitnessTracer,
    round_function: &R,
) -> (VmWitnessOracle<E>, FullBlockArtifacts<E>) {
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
        ..
    } = tracer;
    // this one we will later on split and re-arrange into sponge cycles, as well as use for
    // VmState snapshot reconstruction

    // dbg!(&callstack_with_aux_data);

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

    // for some cycle we point to the elements in the flattened history - to when forward operation ended up, and where rollback ended up
    let mut cycle_pointers = HashMap::<u32, (usize, usize)>::new();

    // for some frame index we point to the range of flattened history that is a sequence of all it's forward ops,
    // and to the range (it will always be continuos) of where it's rollbacks ended up
    let mut frame_pointers =
        HashMap::<usize, (RangeInclusive<usize>, Option<RangeInclusive<usize>>)>::new();

    let mut frames_sequence = vec![];

    for (((_parent_frame_index, this_frame_index), (_frame_marker, cycle, query)), was_applied) in
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
        chain_of_states.push((cycle, this_frame_index, (intermediate_info.previous_tail, intermediate_info.tail)));

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

            cycle_pointers
                .get_mut(&cycle)
                .expect("rollbacks always happen after forward case")
                .1 = pointer;

            if let Some(frame_pointers_pair) = frame_pointers.get_mut(&this_frame_index) {
                if let Some(revert_range) = frame_pointers_pair.1.as_mut() {
                    let start = *revert_range.start();
                    let end = *revert_range.end();
                    assert!(pointer > end);
                    frame_pointers_pair.1 = Some(start..=pointer);
                } else {
                    frame_pointers_pair.1 = Some(pointer..=pointer);
                }
            } else {
                unreachable!()
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

            cycle_pointers.entry(cycle).or_default().0 = pointer;

            if let Some(frame_pointers_pair) = frame_pointers.get_mut(&this_frame_index) {
                let start = *frame_pointers_pair.0.start();
                let end = *frame_pointers_pair.0.end();
                assert!(pointer > end);
                frame_pointers_pair.0 = start..=pointer;
            } else {
                frame_pointers.insert(this_frame_index, (pointer..=pointer, None));
            }
        }

        if was_applied {
            frames_sequence.push((this_frame_index, cycle, query.rollback));
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
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    dbg!(&chain_of_states);
    dbg!(&frame_pointers);

    let mut rollback_queue_head_segments = vec![];
    // we should go over the sequence of sorted cycle indexes and look at the pointers of the actually applied rollbacks
    let mut keys: Vec<_> = cycle_pointers.keys().copied().collect();
    keys.sort();
    for cycle_idx in keys.into_iter() {
        let (_, pointer) = cycle_pointers.remove(&cycle_idx).unwrap();
        let (cycle, _frame, (head, _)) = chain_of_states[pointer]; // we reinterpret "previous tail" as head
        assert!(cycle == cycle_idx);
        rollback_queue_head_segments.push((cycle_idx, head));
    }
    dbg!(&rollback_queue_head_segments);

    let mut rollback_queue_initial_tails_for_new_frames = vec![];
    // let initial_tail_for_entry_point = chain_of_states.last().map(|el| el.2.1).unwrap_or(E::Fr::zero());
    // dbg!(initial_tail_for_entry_point);

    let mut previous_frame = 0;

    // only keep necessary information by walking over the frames sequence
    for (this_frame, _cycle_idx, is_explicit_rollback) in frames_sequence.into_iter() {
        dbg!(this_frame);
        if this_frame != previous_frame {
            // we start a new frame, or return
            if this_frame > previous_frame {
                assert!(!is_explicit_rollback);
                // near/far call
                let (_, revert_segment) = frame_pointers
                    .get_mut(&this_frame)
                    .expect("must be present in frame pointers");
                if let Some(revert_segment) = revert_segment.as_mut() {
                    dbg!(&revert_segment);
                    // there were rollbacks in the frame we just started, so we need to properly
                    // for a new tail
                    if !revert_segment.is_empty() {
                        let pointer = *revert_segment.end();
                        let (_cycle, frame, (_, tail)) = chain_of_states[pointer];
                        assert!(frame == this_frame);
                        rollback_queue_initial_tails_for_new_frames.push((this_frame, tail));
                    }
                }
            } else {
            }

            previous_frame = this_frame;
        } else {
            // also don't care
        }
    }

    let initial_tail_for_entry_point = rollback_queue_initial_tails_for_new_frames
        .drain(..1)
        .next()
        .map(|el| el.1)
        .unwrap_or(E::Fr::zero());
    dbg!(initial_tail_for_entry_point);

    // more witness
    let mut callstack_values_for_returns = vec![];
    use super::callstack_handler::CallstackAction;

    let full_history = callstack_with_aux_data
        .full_history
        .iter()
        .cloned()
        .map(|mut el| {
            // dbg!(&el);
            // renumerate
            for t in el.rollback_queue_ranges_at_entry.iter_mut() {
                let new_end = num_forwards + num_rollbacks - t.start;
                let new_start = num_forwards + num_rollbacks - t.end;

                *t = new_start..new_end;
            }

            for t in el.rollback_queue_ranges_change.iter_mut() {
                let new_end = num_forwards + num_rollbacks - t.start;
                let new_start = num_forwards + num_rollbacks - t.end;

                *t = new_start..new_end;
            }

            // dbg!(&el);

            el
        });

    use crate::encodings::callstack_entry::CallstackSimulator;
    let mut callstack_argebraic_simulator = CallstackSimulator::<E>::empty();

    let mut initial_callstack_state_for_start = None;
    let mut initial_context_for_start = None;

    for el in full_history {
        match el.action {
            CallstackAction::PushToStack => {
                // this is a point where need to substitue a state of the computed chain
                // we mainly need the length of the segment of the rollback queue and the current point
                // and head/tail parts of the queue

                assert!(el.rollback_queue_ranges_at_entry.len() <= 1);
                assert!(
                    el.rollback_queue_ranges_change.len() == 0,
                    "expected merged changes for push, got {:?}",
                    &el.rollback_queue_ranges_change
                );

                // everything was joined for us, so we need to only ask what is a current state

                let (head, tail, segment_len) =
                    if let Some(segment) = el.rollback_queue_ranges_at_entry.first() {
                        let head = chain_of_states[segment.start - 1].2 .1;
                        let tail = chain_of_states[segment.end - 1].2 .1;
                        let len = segment.len();

                        (head, tail, len)
                    } else {
                        // it's the end
                        let t = chain_of_states
                            .last()
                            .map(|el| el.2 .1)
                            .unwrap_or(E::Fr::zero());
                        (t, t, 0)
                    };

                let entry = ExtendedCallstackEntry {
                    callstack_entry: el.affected_entry,
                    rollback_queue_head: head,
                    rollback_queue_tail: tail,
                    rollback_queue_segment_length: segment_len as u32,
                };

                let _states = callstack_argebraic_simulator
                    .push_and_output_intermediate_data(entry, round_function);

                if initial_callstack_state_for_start.is_none() {
                    initial_callstack_state_for_start =
                        Some((_states.new_state, el.affected_entry));
                }
            }
            CallstackAction::PopFromStack { panic: _ } => {
                // here we actually get witness

                let (entry, intermediate_info) =
                    callstack_argebraic_simulator.pop_and_output_intermediate_data(round_function);
                callstack_values_for_returns.push((el.cycle_index, (entry, intermediate_info)));
            }
            CallstackAction::OutOfScope { panic: _ } => {
                if initial_context_for_start.is_none() {
                    initial_context_for_start = Some(el.affected_entry);
                }
            }
            _ => {}
        }
    }

    let initial_callstack_state_for_start = initial_callstack_state_for_start.unwrap();
    let initial_context_for_start = initial_context_for_start.unwrap();

    dbg!(&initial_callstack_state_for_start);
    dbg!(&initial_context_for_start);

    // for witness we need only frames after the initial entrypoint
    // let _ = callstack_values_for_returns.drain(0..1);

    dbg!(&callstack_values_for_returns);

    // we simulate a series of actions on the stack starting from the outermost frame
    // each history record contains an information on what was the stack state between points
    // when it potentially came into and out of scope

    // for (idx, el) in memory_read_witness.iter().enumerate() {
    //     println!("Memory witness {} = 0x{:x}", idx, el.1.value);
    // }

    dbg!(&rollback_queue_initial_tails_for_new_frames);

    dbg!(&memory_read_witness);

    let oracle = VmWitnessOracle::<E> {
        memory_read_witness,
        rollback_queue_head_segments,
        decommittment_requests_witness: decommittment_queries
            .iter()
            .map(|el| (el.0, el.1))
            .collect(),
        rollback_queue_initial_tails_for_new_frames,
        storage_read_queries,
        callstack_values_for_returns,
        initial_tail_for_entry_point,
        initial_callstack_state_for_start,
        initial_context_for_start,
    };

    let mut artifacts = FullBlockArtifacts::<E>::default();
    artifacts.vm_memory_queries_accumulated = vm_memory_queries_accumulated;
    artifacts.all_decommittment_queries = decommittment_queries;
    artifacts.keccak_round_function_witnesses = keccak_round_function_witnesses;
    artifacts.sha256_round_function_witnesses = sha256_round_function_witnesses;
    artifacts.ecrecover_witnesses = ecrecover_witnesses;
    artifacts.original_log_queue = original_log_queue;
    artifacts.original_log_queue_states = original_log_queue_states;

    artifacts.sorted_rollup_storage_queries = sorted_rollup_storage_queries;
    artifacts.sorted_porter_storage_queries = sorted_porter_storage_queries;
    artifacts.sorted_event_queries = sorted_event_queries;
    artifacts.sorted_to_l1_queries = sorted_to_l1_queries;
    artifacts.demuxed_keccak_precompile_queries = sorted_keccak_precompile_queries;
    artifacts.demuxed_sha256_precompile_queries = sorted_sha256_precompile_queries;
    artifacts.demuxed_ecrecover_queries = sorted_ecrecover_queries;

    (oracle, artifacts)
}

use crate::franklin_crypto::plonk::circuit::boolean::*;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::scheduler::data_access_functions::StorageLogRecord;
use sync_vm::scheduler::queues::DecommitQueryWitness;
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
            let (_frame_idx, tail) = self
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
