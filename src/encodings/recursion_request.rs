use super::*;
use num_bigint::BigUint;
use sync_vm::franklin_crypto::plonk::circuit::bigint::biguint_to_fe;
use sync_vm::utils::compute_shifts;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct RecursionRequest<E: Engine> {
    pub circuit_type: u8,
    pub public_input: E::Fr,
}

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 2> for RecursionRequest<E> {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        let shifts = compute_shifts::<E::Fr>();

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.circuit_type, &shifts, shift);
        shift += 8;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el0 = lc;

        let el1 = self.public_input;

        [el0, el1]
    }
}

pub type RecursionQueueSimulator<E> = QueueSimulator<E, RecursionRequest<E>, 2, 2>;
pub type RecursionQueueState<E> = QueueIntermediateStates<E, 3, 2>;
