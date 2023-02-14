use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct StorageApplicationInstanceSynthesisFunction;

use sync_vm::glue::storage_application::input::StorageApplicationCircuitInstanceWitness;
use sync_vm::glue::storage_application::storage_applicator_entry_point;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for StorageApplicationInstanceSynthesisFunction {
    type Witness = StorageApplicationCircuitInstanceWitness<E>;
    type Config = (usize, bool);
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Storage application".to_string()
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
        Box::new(storage_applicator_entry_point)
    }
}
