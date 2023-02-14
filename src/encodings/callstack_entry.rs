use crate::utils::{address_to_fe, u256_to_fe};
use sync_vm::circuit_structures::utils::compute_shifts;
use zk_evm::vm_state::CallStackEntry;

use super::*;

// we need some extra data to preserve
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct ExtendedCallstackEntry<E: Engine> {
    pub callstack_entry: CallStackEntry,
    pub rollback_queue_head: E::Fr,
    pub rollback_queue_tail: E::Fr,
    pub rollback_queue_segment_length: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CallstackEntryRollbackState<E: Engine> {
    pub rollback_queue_head: E::Fr,
    pub rollback_queue_tail: E::Fr,
    pub rollback_queue_segment_length: u32,
}

// from circuit VM
// let val_0 = self.reverted_queue_head;
// let val_1 = self.reverted_queue_tail;
// let val_2 = self.this.inner;
// let val_3 = self.caller.inner;
// let val_4 = self.code_address.inner;

// let shifts = compute_shifts::<E::Fr>();

// let mut lc = LinearCombination::<E>::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.code_page.inner, shifts[shift]);
// shift += 32;
// lc.add_assign_number_with_coeff(&self.base_page.inner, shifts[shift]);
// shift += 32;
// // 64
// lc.add_assign_number_with_coeff(&self.calldata_page.inner, shifts[shift]);
// shift += 32;
// lc.add_assign_number_with_coeff(&self.reverted_queue_segment_len.inner, shifts[shift]);
// shift += 32;
// // 128
// lc.add_assign_number_with_coeff(&self.ergs_remaining.inner, shifts[shift]);
// shift += 32;
// lc.add_assign_number_with_coeff(&self.sp.inner, shifts[shift]);
// shift += 16;
// lc.add_assign_number_with_coeff(&self.exception_handler_loc.inner, shifts[shift]);
// shift += 16;
// // 192
// lc.add_assign_number_with_coeff(&self.pc.inner, shifts[shift]);
// shift += 16;
// lc.add_assign_number_with_coeff(&self.this_shard_id.inner, shifts[shift]);
// shift += 8;
// lc.add_assign_number_with_coeff(&self.caller_shard_id.inner, shifts[shift]);
// shift += 8;
// // 224
// lc.add_assign_number_with_coeff(&self.pubdata_bytes_remaining.inner, shifts[shift]);
// shift += 16;
// // 240
// lc.add_assign_number_with_coeff(&self.code_shard_id.inner, shifts[shift]);
// shift += 8;
// lc.add_assign_boolean_with_coeff(&self.is_static_execution, shifts[shift]);
// shift += 1;
// lc.add_assign_boolean_with_coeff(&self.is_kernel_mode, shifts[shift]);
// shift += 1;
// // 250
// let val_5 = lc.into_num(cs)?;
// assert!(shift <= E::Fr::CAPACITY as usize);
// assert_eq!(CONTEXT_EXTENSION_OFFSET, shift);

// Ok([val_0, val_1, val_2, val_3, val_4, val_5])

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 6> for ExtendedCallstackEntry<E> {
    fn encoding_witness(&self) -> [<E>::Fr; 6] {
        use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

        let val_0 = self.rollback_queue_head;
        let val_1 = self.rollback_queue_tail;

        use crate::utils::*;

        let shifts = compute_shifts::<E::Fr>();

        let mut lc = E::Fr::zero();
        let mut shift = 0;

        scale_and_accumulate::<E, _>(
            &mut lc,
            u160_from_address(self.callstack_entry.this_address),
            &shifts,
            shift,
        );
        shift += 160;
        scale_and_accumulate::<E, _>(
            &mut lc,
            self.callstack_entry.context_u128_value as u64, // low
            &shifts,
            shift,
        );
        shift += 64;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let val_2 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;

        scale_and_accumulate::<E, _>(
            &mut lc,
            u160_from_address(self.callstack_entry.msg_sender),
            &shifts,
            shift,
        );
        shift += 160;
        scale_and_accumulate::<E, _>(
            &mut lc,
            (self.callstack_entry.context_u128_value >> 64) as u64, // high
            &shifts,
            shift,
        );
        shift += 64;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let val_3 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;

        scale_and_accumulate::<E, _>(
            &mut lc,
            u160_from_address(self.callstack_entry.code_address),
            &shifts,
            shift,
        );
        shift += 160;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.heap_bound, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.aux_heap_bound, &shifts, shift);
        shift += 32;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let val_4 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;

        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.code_page.0, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(
            &mut lc,
            self.callstack_entry.base_memory_page.0,
            &shifts,
            shift,
        );
        shift += 32;
        // 64
        scale_and_accumulate::<E, _>(&mut lc, self.rollback_queue_segment_length, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.ergs_remaining, &shifts, shift);
        shift += 32;
        // 128
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.sp, &shifts, shift);
        shift += 16;
        scale_and_accumulate::<E, _>(
            &mut lc,
            self.callstack_entry.exception_handler_location,
            &shifts,
            shift,
        );
        shift += 16;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.pc, &shifts, shift);
        shift += 16;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.this_shard_id, &shifts, shift);
        shift += 8;
        scale_and_accumulate::<E, _>(
            &mut lc,
            self.callstack_entry.caller_shard_id,
            &shifts,
            shift,
        );
        shift += 8;
        scale_and_accumulate::<E, _>(&mut lc, 0u16, &shifts, shift);
        shift += 16;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.code_shard_id, &shifts, shift);
        shift += 8;
        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.is_static, &shifts, shift);
        shift += 1;
        scale_and_accumulate::<E, _>(
            &mut lc,
            self.callstack_entry.is_kernel_mode(),
            &shifts,
            shift,
        );
        shift += 1;
        use sync_vm::vm::vm_state::saved_contract_context::CONTEXT_EXTENSION_OFFSET;
        assert_eq!(CONTEXT_EXTENSION_OFFSET, shift);

        scale_and_accumulate::<E, _>(&mut lc, self.callstack_entry.is_local_frame, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);

        let val_5 = lc;

        // dbg!(&[val_0, val_1, val_2, val_3, val_4, val_5]);

        [val_0, val_1, val_2, val_3, val_4, val_5]
    }
}

pub type CallstackSimulator<E> = SpongeLikeStackSimulator<E, ExtendedCallstackEntry<E>, 6, 3, 3>;
pub type CallstackSimulatorState<E> = SpongeLikeStackIntermediateStates<E, 3, 3>;
