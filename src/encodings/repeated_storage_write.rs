use super::*;
use sync_vm::utils::compute_shifts;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug)]
pub struct RepeatedStorageWrite {
    pub index: u64,
    pub value: [u8; 32],
}

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 2> for RepeatedStorageWrite {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        let shifts = compute_shifts::<E::Fr>();

        let index_as_be = self.index.to_le_bytes(); // ! As we do LE equivalent packing in a circuit

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        for el in index_as_be.iter().chain(self.value[..16].iter()) {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el0 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        for el in self.value[16..].iter() {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el1 = lc;

        [el0, el1]
    }
}

pub type RepeatedStorageWritesSimulator<E> = QueueSimulator<E, RepeatedStorageWrite, 2, 2>;
pub type RepeatedStorageWritesState<E> = QueueIntermediateStates<E, 2, 2>;

use super::initial_storage_write::*;

impl BytesSerializable<40> for RepeatedStorageWrite {
    fn serialize(&self) -> [u8; 40] {
        let mut result = [0u8; 40];
        result[0..8].copy_from_slice(&self.index.to_be_bytes());
        result[8..40].copy_from_slice(&self.value);

        result
    }
}

use sync_vm::glue::pubdata_hasher::storage_write_data::*;
use sync_vm::traits::CSWitnessable;

impl<E: Engine> CircuitEquivalentReflection<E> for RepeatedStorageWrite {
    type Destination = RepeatedStorageWriteData<E>;
    fn reflect(&self) -> <Self::Destination as CSWitnessable<E>>::Witness {
        RepeatedStorageWriteDataWitness {
            index: self.index,
            value: self.value,
            _marker: std::marker::PhantomData,
        }
    }
}
