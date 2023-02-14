use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct Keccak256RoundFunctionInstanceSynthesisFunction;

use sync_vm::glue::keccak256_round_function_circuit::input::Keccak256RoundFunctionInstanceWitness;
use sync_vm::glue::keccak256_round_function_circuit::keccak256_round_function_entry_point;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E>
    for Keccak256RoundFunctionInstanceSynthesisFunction
{
    type Witness = Keccak256RoundFunctionInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Keccak256 round function".to_string()
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
        Box::new(keccak256_round_function_entry_point)
    }
}
