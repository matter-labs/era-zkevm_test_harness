use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct StorageSortAndDedupInstanceSynthesisFunction;

use sync_vm::glue::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use sync_vm::glue::storage_validity_by_grand_product::sort_and_deduplicate_storage_access_entry_point;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for StorageSortAndDedupInstanceSynthesisFunction {
    type Witness = StorageDeduplicatorInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Storage access sort and dedup".to_string()
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
        Box::new(sort_and_deduplicate_storage_access_entry_point)
    }
}
