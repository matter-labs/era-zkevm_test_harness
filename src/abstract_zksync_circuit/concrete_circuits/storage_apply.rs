
use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct StorageApplicationInstanceSynthesisFunction<
F: SmallField, 
R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
> {
_marker: std::marker::PhantomData<(F, R)>
}

use zkevm_circuits::storage_application::input::StorageApplicationCircuitInstanceWitness;
use zkevm_circuits::storage_application::storage_applicator_entry_point;

impl<
    F: SmallField,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
> ZkSyncUniformSynthesisFunction<F> for StorageApplicationInstanceSynthesisFunction<F, R>
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]: 
{
    type Witness = StorageApplicationCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "Storage application".to_string()
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(storage_applicator_entry_point)
    }
}