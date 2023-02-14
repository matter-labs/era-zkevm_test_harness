use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct CodeDecommitterInstanceSynthesisFunction;

use sync_vm::glue::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use sync_vm::glue::code_unpacker_sha256::unpack_code_into_memory_entry_point;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for CodeDecommitterInstanceSynthesisFunction {
    type Witness = CodeDecommitterCircuitInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Code decommitter".to_string()
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
        Box::new(unpack_code_into_memory_entry_point)
    }
}
