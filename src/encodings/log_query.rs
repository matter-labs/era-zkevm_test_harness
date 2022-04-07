use sync_vm::utils::compute_shifts;
use zk_evm::aux_structures::LogQuery;
use zk_evm::ethereum_types::H160;

use super::*;

use sync_vm::vm::primitives::small_uints::IntoFr;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

// impl<E: Engine> IntoFr<E> for H160 {
//     fn into_fr(self) -> E::Fr {
//         let lowest = u64::from_be_bytes(self.0[0..8].try_into().unwrap());
//         let mid = u64::from_be_bytes(self.0[8..16].try_into().unwrap());
//         let highest = u32::from_be_bytes(self.0[16..20].try_into().unwrap());

//         let mut repr = E::Fr::zero().into_repr();
//         repr.as_mut()[0] = lowest;
//         repr.as_mut()[1] = mid;
//         repr.as_mut()[2] = highest as u32;

//         E::Fr::from_repr(repr).unwrap()
//     }
// }


// // BE order:
// // the whole structure can be placed in five field elements:
// // el0 = [r_w_flag | aux_byte | log_idx | key0 | actor_address]
// // el1 = [trx_idx | key1 | target_address]
// // el2 = [rvalue32 | rvalue31 | rvalue30 | rvalue2 | rvalue1 | rvalue0]
// // el3 = [wvalue32 | wvalue31 | wvalue30 | wvalue2 | wvalue1 | wvalue0]
// // el4 = [target_is_zkporter | is_service | is_revert | wvalue33 | rvalue33 | key3 | key2]

// let shifts = compute_shifts::<E::Fr>();

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.address.inner, shifts[shift]);
// shift += 160;
// lc.add_assign_number_with_coeff(&self.key.inner[0].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.shard_id.inner, shifts[shift]);
// shift += 8;
// lc.add_assign_number_with_coeff(&self.aux_byte.inner, shifts[shift]);
// shift += 8;
// lc.add_assign_boolean_with_coeff(&self.r_w_flag, shifts[shift]);
// shift += 1;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el0 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.key.inner[1].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.key.inner[2].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.key.inner[3].inner, shifts[shift]);
// shift += 64;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el1 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.read_value.inner[0].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.read_value.inner[1].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.read_value.inner[2].inner, shifts[shift]);
// shift += 64;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el2 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.written_value.inner[0].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.written_value.inner[1].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.written_value.inner[2].inner, shifts[shift]);
// shift += 64;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el3 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.read_value.inner[2].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.written_value.inner[3].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.tx_number_in_block.inner, shifts[shift]);
// shift += 16;
// lc.add_assign_number_with_coeff(&self.timestamp.inner, shifts[shift]);
// shift += 32;
// lc.add_assign_boolean_with_coeff(&self.is_service, shifts[shift]);
// shift += 1;
// if with_revert {
//     lc.add_assign_boolean_with_coeff(&self.rollback, shifts[shift]);
// }
// let revert_falg_offset = shifts[shift];    
// shift += 1;

// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);

// let el4 = lc.into_num(cs)?;

// Ok(([el0, el1, el2, el3, el4], revert_falg_offset))

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 5> for LogQuery {
    fn encoding_witness(&self) -> [<E>::Fr; 5] {
        use crate::utils::*;

        let shifts = compute_shifts::<E::Fr>();

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, u160_from_address(self.address), &shifts, shift);
        shift += 160;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.shard_id, &shifts, shift);
        shift += 8;
        scale_and_accumulate::<E, _>(&mut lc, self.aux_byte, &shifts, shift);
        shift += 8;
        scale_and_accumulate::<E, _>(&mut lc, self.rw_flag, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el0 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[2], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[3], &shifts, shift);
        shift += 64;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el1 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[2], &shifts, shift);
        shift += 64;
        //dbg!(shift);
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el2 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.written_value.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[2], &shifts, shift);
        shift += 64;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el3 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[3], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.written_value.0[3], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.tx_number_in_block, &shifts, shift);
        shift += 16;
        scale_and_accumulate::<E, _>(&mut lc, self.timestamp.0, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.is_service, &shifts, shift);
        shift += 1;
        scale_and_accumulate::<E, _>(&mut lc, self.rollback, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);

        let el4 = lc;

        [el0, el1, el2, el3, el4]
    }
}


// pub struct LogQueueSimulator<E: Engine> {
//     pub head: E::Fr,
//     pub tail: E::Fr,
//     pub num_items: u32,
//     pub witness: Vec<([E::Fr; 5], E::Fr, LogQuery)>, 
// }

// impl<E: Engine> LogQueueSimulator<E> {
//     pub fn empty() -> Self {
//         Self {
//             head: E::Fr::zero(),
//             tail: E::Fr::zero(),
//             num_items: 0,
//             witness: vec![]
//         }
//     }

//     pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize, const SW: usize>(
//         &mut self, 
//         element: LogQuery,
//         round_function: &R
//     ) {
//         let _ = self.push_and_output_intermediate_data(element, round_function);
//     }

//     pub fn push_and_output_intermediate_data<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize, const SW: usize>(
//         &mut self, 
//         element: LogQuery,
//         round_function: &R
//     ) -> ((E::Fr, E::Fr), Vec<([E::Fr; SW], [E::Fr; SW])>) {
//         let old_tail = self.tail;
//         let encoding = element.encoding_witness();
//         let mut to_hash = vec![];
//         to_hash.extend_from_slice(&encoding);

//         let mut to_hash = vec![self.tail];


//         let states = round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(
//             &to_hash
//         );
//         let new_tail = R::simulate_state_into_commitment(states.last().map(|el| el.1).unwrap());

//         self.witness.push((encoding, new_tail, element));
//         self.num_items += 1;
//         self.tail = new_tail;

//         ((old_tail, new_tail), states)
//     }
// }

pub type LogQueueSimulator<E> = QueueSimulator<E, LogQuery, 5>;