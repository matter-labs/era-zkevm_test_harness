use super::*;
use num_bigint::BigUint;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct RecursionRequest<F: SmallField> {
    pub circuit_type: u8,
    pub public_input: F,
}

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<E, 2> for RecursionRequest<E> {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        let shifts = compute_shifts::<F>();

        let mut lc = F::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.circuit_type, &shifts, shift);
        shift += 8;
        assert!(shift <= F::CAPACITY as usize);
        let el0 = lc;

        let el1 = self.public_input;

        [el0, el1]
    }
}

pub type RecursionQueueSimulator<E> = QueueSimulator<E, RecursionRequest<E>, 2, 2>;
pub type RecursionQueueState<E> = QueueIntermediateStates<E, 3, 2>;
