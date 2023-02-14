use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct RAMPermutationInstanceSynthesisFunction;

use sync_vm::glue::ram_permutation::ram_permutation_entry_point;
use sync_vm::glue::ram_permutation::RamPermutationCircuitInstanceWitness;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for RAMPermutationInstanceSynthesisFunction {
    type Witness = RamPermutationCircuitInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "RAM permutation".to_string()
    }

    fn get_synthesis_function_dyn<'a, CS: ConstraintSystem<E> + 'a>() -> Box<
        dyn FnOnce(
                &mut CS,
                Option<Self::Witness>,
                &Self::RoundFunction,
                Self::Config,
            ) -> Result<AllocatedNum<E>, SynthesisError>
            + 'a,
    > {
        Box::new(ram_permutation_entry_point)
    }
}
