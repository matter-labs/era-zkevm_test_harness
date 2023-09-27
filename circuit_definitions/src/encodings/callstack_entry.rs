use crate::{aux_definitions::witness_oracle::u128_as_u32_le, boojum::field::SmallField};
use zk_evm::vm_state::CallStackEntry;

use super::*;

// we need some extra data to preserve
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct ExtendedCallstackEntry<F: SmallField> {
    pub callstack_entry: CallStackEntry,
    pub rollback_queue_head: [F; QUEUE_STATE_WIDTH],
    pub rollback_queue_tail: [F; QUEUE_STATE_WIDTH],
    pub rollback_queue_segment_length: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CallstackEntryRollbackState<F: SmallField> {
    pub rollback_queue_head: [F; QUEUE_STATE_WIDTH],
    pub rollback_queue_tail: [F; QUEUE_STATE_WIDTH],
    pub rollback_queue_segment_length: u32,
}

use zkevm_circuits::base_structures::vm_state::saved_context::EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH;

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<F, EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH>
    for ExtendedCallstackEntry<F>
{
    fn encoding_witness(&self) -> [F; EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH] {
        debug_assert!(F::CAPACITY_BITS >= 57);
        // full field elements first for simplicity
        let v0 = self.rollback_queue_head[0];
        let v1 = self.rollback_queue_head[1];
        let v2 = self.rollback_queue_head[2];
        let v3 = self.rollback_queue_head[3];

        let v4 = self.rollback_queue_tail[0];
        let v5 = self.rollback_queue_tail[1];
        let v6 = self.rollback_queue_tail[2];
        let v7 = self.rollback_queue_tail[3];

        let code_address = decompose_address_as_u32x5(self.callstack_entry.code_address);
        let v8 = code_address[0].into_field();
        let v9 = code_address[1].into_field();
        let v10 = code_address[2].into_field();
        let v11 = code_address[3].into_field();
        let v12 = code_address[4].into_field();

        let this = decompose_address_as_u32x5(self.callstack_entry.this_address);
        let v13 = this[0].into_field();
        let v14 = this[1].into_field();
        let v15 = this[2].into_field();
        let v16 = this[3].into_field();
        let v17 = this[4].into_field();

        let caller_address = decompose_address_as_u32x5(self.callstack_entry.msg_sender);
        let v18 = caller_address[0].into_field();
        let v19 = caller_address[1].into_field();
        let v20 = caller_address[2].into_field();
        let v21 = caller_address[3].into_field();
        let v22 = caller_address[4].into_field();

        let context_u128_value_composite = u128_as_u32_le(self.callstack_entry.context_u128_value);

        let v23 = context_u128_value_composite[0].into_field();
        let v24 = context_u128_value_composite[1].into_field();
        let v25 = context_u128_value_composite[2].into_field();
        let v26 = context_u128_value_composite[3].into_field();

        // now we have left
        // - code_page
        // - base_page
        // - heap_upper_bound
        // - aux_heap_upper_bound
        // - ergs_remaining
        // - sp
        // - pc
        // - eh
        // - reverted_queue_segment_len
        // - shard ids
        // - few boolean flags

        // as usual, take u32 and add something on top

        let v27 = linear_combination(&[
            (self.callstack_entry.code_page.0.into_field(), F::ONE),
            (
                self.callstack_entry.pc.into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                self.callstack_entry.this_shard_id.into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
            (
                self.callstack_entry.is_static.into_field(),
                F::from_u64_unchecked(1u64 << 56),
            ),
        ]);

        let is_kernel_mode = self.callstack_entry.is_kernel_mode();

        let v28 = linear_combination(&[
            (self.callstack_entry.base_memory_page.0.into_field(), F::ONE),
            (
                self.callstack_entry.sp.into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                self.callstack_entry.caller_shard_id.into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
            (
                is_kernel_mode.into_field(),
                F::from_u64_unchecked(1u64 << 56),
            ),
        ]);

        let v29 = linear_combination(&[
            (self.callstack_entry.ergs_remaining.into_field(), F::ONE),
            (
                self.callstack_entry.exception_handler_location.into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                self.callstack_entry.code_shard_id.into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
            (
                self.callstack_entry.is_local_frame.into_field(),
                F::from_u64_unchecked(1u64 << 56),
            ),
        ]);

        // now we have left
        // - heap_upper_bound
        // - aux_heap_upper_bound
        // - reverted_queue_segment_len

        let reverted_queue_segment_len_decomposition =
            self.rollback_queue_segment_length.to_le_bytes();
        let v30 = linear_combination(&[
            (self.callstack_entry.heap_bound.into_field(), F::ONE),
            (
                reverted_queue_segment_len_decomposition[0].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                reverted_queue_segment_len_decomposition[1].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
        ]);

        let v31 = linear_combination(&[
            (self.callstack_entry.aux_heap_bound.into_field(), F::ONE),
            (
                reverted_queue_segment_len_decomposition[2].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                reverted_queue_segment_len_decomposition[3].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
        ]);

        [
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18,
            v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31,
        ]
    }
}

pub type CallstackSimulator<F> = FullWidthStackSimulator<
    F,
    ExtendedCallstackEntry<F>,
    EXECUTION_CONTEXT_RECORD_ENCODING_WIDTH,
    FULL_SPONGE_QUEUE_STATE_WIDTH,
    4,
>;
pub type CallstackSimulatorState<F> =
    FullWidthStackIntermediateStates<F, FULL_SPONGE_QUEUE_STATE_WIDTH, 4>;
