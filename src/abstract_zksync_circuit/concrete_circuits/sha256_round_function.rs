use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct Sha256RoundFunctionInstanceSynthesisFunction;

use sync_vm::glue::sha256_round_function_circuit::input::*;
use sync_vm::glue::sha256_round_function_circuit::sha256_round_function_entry_point;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for Sha256RoundFunctionInstanceSynthesisFunction {
    type Witness = Sha256RoundFunctionCircuitInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "SHA256 round function".to_string()
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
        Box::new(sha256_round_function_entry_point)
    }
}
