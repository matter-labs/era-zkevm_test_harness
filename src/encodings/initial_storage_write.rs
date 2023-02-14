use super::*;
use sync_vm::utils::compute_shifts;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

pub trait BytesSerializable<const N: usize>: Clone {
    fn serialize(&self) -> [u8; N];
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug)]
pub struct InitialStorageWrite {
    pub key: [u8; 32],
    pub value: [u8; 32],
}

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 3> for InitialStorageWrite {
    fn encoding_witness(&self) -> [<E>::Fr; 3] {
        let shifts = compute_shifts::<E::Fr>();

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        for el in self.key[..30].iter() {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el0 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        for el in self.key[30..].iter().chain(self.value[..28].iter()) {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el1 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        for el in self.value[28..].iter() {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el2 = lc;

        [el0, el1, el2]
    }
}

pub type InitialStorageWritesSimulator<E> = QueueSimulator<E, InitialStorageWrite, 3, 2>;
pub type InitialStorageWritesState<E> = QueueIntermediateStates<E, 3, 2>;

impl BytesSerializable<64> for InitialStorageWrite {
    fn serialize(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[0..32].copy_from_slice(&self.key);
        result[32..64].copy_from_slice(&self.value);

        result
    }
}

use sync_vm::glue::traits::CSWitnessable;

pub trait CircuitEquivalentReflection<E: Engine>: Clone {
    type Destination: Clone + CSWitnessable<E>;
    fn reflect(&self) -> <Self::Destination as CSWitnessable<E>>::Witness;
}

use sync_vm::glue::pubdata_hasher::storage_write_data::*;

impl<E: Engine> CircuitEquivalentReflection<E> for InitialStorageWrite {
    type Destination = InitialStorageWriteData<E>;
    fn reflect(&self) -> <Self::Destination as CSWitnessable<E>>::Witness {
        InitialStorageWriteDataWitness {
            key: self.key,
            value: self.value,
            _marker: std::marker::PhantomData,
        }
    }
}
