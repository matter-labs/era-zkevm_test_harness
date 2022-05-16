use super::*;
use sync_vm::utils::compute_shifts;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

use zk_evm::aux_structures::MemoryQuery;

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 2> for MemoryQuery {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        let shifts = compute_shifts::<E::Fr>();

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.value.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.value.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.value.0[2], &shifts, shift);
        shift += 64;

        assert!(shift <= E::Fr::CAPACITY as usize);
        let el0 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.value.0[3], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.location.index.0 as u32, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.location.page.0 as u32, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.timestamp.0, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.rw_flag, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el1 = lc;

        // dbg!([el0, el1]);

        [el0, el1]
    }
}

pub type MemoryQueueSimulator<E> = SpongeLikeQueueSimulator<E, MemoryQuery, 2, 3, 1>;
pub type MemoryQueueState<E> = SpongeLikeQueueIntermediateStates<E, 3, 1>;
