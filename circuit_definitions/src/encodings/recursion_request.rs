use super::*;
use zkevm_circuits::base_structures::recursion_query::*;
use zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug)]
#[serde(bound = "")]
pub struct RecursionRequest<F: SmallField> {
    pub circuit_type: F,
    pub public_input: [F; INPUT_OUTPUT_COMMITMENT_LENGTH],
}

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<F, RECURSION_QUERY_PACKED_WIDTH>
    for RecursionRequest<F>
{
    fn encoding_witness(&self) -> [F; RECURSION_QUERY_PACKED_WIDTH] {
        [
            self.circuit_type,
            self.public_input[0],
            self.public_input[1],
            self.public_input[2],
            self.public_input[3],
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]
    }
}

impl<F: SmallField> CircuitEquivalentReflection<F> for RecursionRequest<F> {
    type Destination = zkevm_circuits::base_structures::recursion_query::RecursionQuery<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness {
        zkevm_circuits::base_structures::recursion_query::RecursionQueryWitness {
            circuit_type: self.circuit_type,
            input_commitment: self.public_input,
        }
    }
}

pub type RecursionQueueSimulator<F> = FullWidthQueueSimulator<
    F,
    RecursionRequest<F>,
    RECURSION_QUERY_PACKED_WIDTH,
    FULL_SPONGE_QUEUE_STATE_WIDTH,
    1,
>;
pub type RecursionQueueState<F> =
    FullWidthQueueIntermediateStates<F, FULL_SPONGE_QUEUE_STATE_WIDTH, 1>;
