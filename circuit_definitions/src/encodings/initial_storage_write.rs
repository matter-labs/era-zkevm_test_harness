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
    pub value: [u8; 32]
}

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<E, 3> for InitialStorageWrite {
    fn encoding_witness(&self) -> [<E>::Fr; 3] {
        let shifts = compute_shifts::<F>();

        let mut lc = F::zero();
        let mut shift = 0;
        for el in self.key[..30].iter() {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= F::CAPACITY as usize);
        let el0 = lc;

        let mut lc = F::zero();
        let mut shift = 0;
        for el in self.key[30..].iter().chain(self.value[..28].iter()) {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= F::CAPACITY as usize);
        let el1 = lc;

        let mut lc = F::zero();
        let mut shift = 0;
        for el in self.value[28..].iter() {
            scale_and_accumulate::<E, _>(&mut lc, *el, &shifts, shift);
            shift += 8;
        }
        assert!(shift <= F::CAPACITY as usize);
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