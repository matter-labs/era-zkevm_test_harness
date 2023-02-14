use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct CodeDecommittmentsSorterSynthesisFunction;

use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use sync_vm::glue::sort_decommittment_requests::sort_and_deduplicate_code_decommittments_entry_point;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for CodeDecommittmentsSorterSynthesisFunction {
    type Witness = CodeDecommittmentsDeduplicatorInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Decommittment requests sorter".to_string()
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
        Box::new(sort_and_deduplicate_code_decommittments_entry_point)
    }
}
