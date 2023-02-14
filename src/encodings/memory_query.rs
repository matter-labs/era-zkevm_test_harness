use super::*;
use num_bigint::BigUint;
use sync_vm::franklin_crypto::plonk::circuit::bigint::biguint_to_fe;
use sync_vm::utils::compute_shifts;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

use zk_evm::aux_structures::MemoryQuery;

pub fn sorting_key<E: Engine>(query: &MemoryQuery) -> E::Fr {
    let mut key = BigUint::from(0u64);
    // page | index | timestamp
    key += BigUint::from(query.location.page.0 as u64);
    key <<= 32;
    key += BigUint::from(query.location.index.0 as u64);
    key <<= 32;
    key += BigUint::from(query.timestamp.0 as u64);

    biguint_to_fe::<E::Fr>(key)
}

pub fn comparison_key<E: Engine>(query: &MemoryQuery) -> E::Fr {
    let mut key = BigUint::from(0u64);
    // page | index
    key += BigUint::from(query.location.page.0 as u64);
    key <<= 32;
    key += BigUint::from(query.location.index.0 as u64);

    biguint_to_fe::<E::Fr>(key)
}

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
        scale_and_accumulate::<E, _>(&mut lc, self.value_is_pointer, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el1 = lc;

        // dbg!([el0, el1]);

        [el0, el1]
    }
}

pub type MemoryQueueSimulator<E> = SpongeLikeQueueSimulator<E, MemoryQuery, 2, 3, 1>;
pub type MemoryQueueState<E> = SpongeLikeQueueIntermediateStates<E, 3, 1>;

use super::initial_storage_write::CircuitEquivalentReflection;
use sync_vm::traits::CSWitnessable;

impl<E: Engine> CircuitEquivalentReflection<E> for MemoryQuery {
    type Destination = sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQuery<E>;
    fn reflect(&self) -> <Self::Destination as CSWitnessable<E>>::Witness {
        sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueryWitness::<E> {
            timestamp: self.timestamp.0,
            memory_page: self.location.page.0,
            memory_index: self.location.index.0,
            rw_flag: self.rw_flag,
            value: u256_to_biguint(self.value),
            value_is_ptr: self.value_is_pointer,
            _marker: std::marker::PhantomData,
        }
    }
}
