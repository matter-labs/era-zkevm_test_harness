use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct RAMPermutationInstanceSynthesisFunction;

use zkevm_circuits::ram_permutation::RamPermutationCircuitInstanceWitness;
use zkevm_circuits::ram_permutation::ram_permutation_entry_point;

impl<F: SmallField> ZkSyncUniformSynthesisFunction<E> for RAMPermutationInstanceSynthesisFunction {
    type Witness = RamPermutationCircuitInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = Poseidon2Goldilocks;

    fn description() -> String {
        "RAM permutation".to_string()
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<E> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Option<Self::Witness>, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(ram_permutation_entry_point)
    }
}