
use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
#[serde(bound = "")]
pub struct VmMainInstanceSynthesisFunction<
    F: SmallField, 
    W: WitnessOracle<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
> {
    _marker: std::marker::PhantomData<(F, W, R)>
}

use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmCircuitWitness;
use zkevm_circuits::main_vm::main_vm_entry_point;

impl<
    F: SmallField, 
    W: WitnessOracle<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>
> ZkSyncUniformSynthesisFunction<F> for VmMainInstanceSynthesisFunction<F, W, R>  
    where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    type Witness = VmCircuitWitness<F, W>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "VM main circuit".to_string()
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(main_vm_entry_point)
    }
}