use crate::boojum::field::SmallField;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::encodings::callstack_entry::*;
use crate::ethereum_types::U256;
use derivative::*;
use std::collections::VecDeque;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::LogQuery;
use zk_evm::aux_structures::MemoryQuery;
use zk_evm::vm_state::CallStackEntry;
use zkevm_circuits::base_structures::vm_state::QUEUE_STATE_WIDTH;

pub fn u128_as_u32_le(value: u128) -> [u32; 4] {
    [
        value as u32,
        (value >> 32) as u32,
        (value >> 64) as u32,
        (value >> 96) as u32,
    ]
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
    pub callstack_new_frames_witnesses: VecDeque<(u32, CallStackEntry)>,
    pub callstack_values_witnesses:
        VecDeque<(u32, (ExtendedCallstackEntry<F>, CallstackSimulatorState<F>))>,
}

use zkevm_circuits::base_structures::decommit_query::DecommitQueryWitness;
use zkevm_circuits::base_structures::log_query::LogQueryWitness;
use zkevm_circuits::base_structures::memory_query::MemoryQueryWitness;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecordWitness;
use zkevm_circuits::main_vm::witness_oracle::MemoryWitness;
use zkevm_circuits::main_vm::witness_oracle::WitnessOracle;

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
                    timestamp, memory_page, index,
                );
            }
            let (_cycle, query) = self.memory_read_witness.pop_front().unwrap();

            // tracing::debug!("Query value = 0x{:064x}", query.value);
            assert_eq!(
                timestamp,
                query.timestamp.0,
                "invalid memory access location at cycle {:?}: VM asks at timestamp {}, witness has timestamp {}. VM reads page = {}, index = {}, witness query = {:?}",
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
    fn push_memory_witness(&mut self, memory_query: &MemoryQueryWitness<F>, execute: bool) {
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
                panic!("should have a witness for storage read at {:?}", key);
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
    fn get_rollback_queue_tail_witness_for_call(
        &mut self,
        _timestamp: u32,
        execute: bool,
    ) -> [F; 4] {
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
            assert_eq!(
                rollback_queue_segment_length,
                witness.reverted_queue_segment_len
            );

            assert_eq!(entry.pc, witness.pc);
            assert_eq!(entry.sp, witness.sp);

            assert_eq!(entry.heap_bound, witness.heap_upper_bound);
            assert_eq!(entry.aux_heap_bound, witness.aux_heap_upper_bound);

            assert_eq!(
                entry.exception_handler_location,
                witness.exception_handler_loc
            );
            assert_eq!(entry.ergs_remaining, witness.ergs_remaining);

            assert_eq!(entry.is_static, witness.is_static_execution);
            assert_eq!(entry.is_kernel_mode(), witness.is_kernel_mode);

            assert_eq!(entry.this_shard_id, witness.this_shard_id);
            assert_eq!(entry.caller_shard_id, witness.caller_shard_id);
            assert_eq!(entry.code_shard_id, witness.code_shard_id);

            let witness_composite = [
                (witness.context_u128_value_composite[0] as u64)
                    + ((witness.context_u128_value_composite[1] as u64) << 32),
                (witness.context_u128_value_composite[2] as u64)
                    + ((witness.context_u128_value_composite[3] as u64) << 32),
            ];

            assert_eq!(
                [
                    entry.context_u128_value as u64,
                    (entry.context_u128_value >> 64) as u64
                ],
                witness_composite
            );

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
                is_push == false,
                "divergence at callstack pop at cycle {}: POP in circuit, but we expect PUSH of \n{:?}\n in oracle",
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
                context_u128_value_composite: u128_as_u32_le(entry.context_u128_value),
                heap_upper_bound: entry.heap_bound,
                aux_heap_upper_bound: entry.aux_heap_bound,
                is_local_call: entry.is_local_frame,
            };

            (witness, new_state)
        } else {
            use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;

            (ExecutionContextRecord::placeholder_witness(), [F::ZERO; 12])
        }
    }
    fn report_new_callstack_frame(
        &mut self,
        new_record: &ExecutionContextRecordWitness<F>,
        _new_depth: u32,
        is_call: bool,
        execute: bool,
    ) {
        if execute && is_call {
            let (_cycle_idx, entry) = self.callstack_new_frames_witnesses.pop_front().unwrap();

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

            assert_eq!(
                entry.exception_handler_location,
                witness.exception_handler_loc
            );
            assert_eq!(entry.ergs_remaining, witness.ergs_remaining);

            assert_eq!(entry.is_static, witness.is_static_execution);
            assert_eq!(entry.is_kernel_mode(), witness.is_kernel_mode);

            assert_eq!(entry.this_shard_id, witness.this_shard_id);
            assert_eq!(entry.caller_shard_id, witness.caller_shard_id);
            assert_eq!(entry.code_shard_id, witness.code_shard_id);

            assert_eq!(
                u128_as_u32_le(entry.context_u128_value),
                witness.context_u128_value_composite
            );

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
            assert!(
                request.code_hash == query.hash,
                "circuit expected hash 0x{:064x}, while witness had 0x{:064x}",
                request.code_hash,
                query.hash
            );

            query.memory_page.0
        } else {
            0
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
