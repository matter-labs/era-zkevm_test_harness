use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct Sha256RoundFunctionInstanceSynthesisFunction<
F: SmallField, 
R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
> {
_marker: std::marker::PhantomData<(F, R)>
}

use zkevm_circuits::sha256_round_function::input::*;
use zkevm_circuits::sha256_round_function::sha256_round_function_entry_point;

impl<
    F: SmallField,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
> ZkSyncUniformSynthesisFunction<F> for Sha256RoundFunctionInstanceSynthesisFunction<F, R>
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
[(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]: 
{
    type Witness = Sha256RoundFunctionCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "SHA256 round function".to_string()
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(sha256_round_function_entry_point)
    }
}