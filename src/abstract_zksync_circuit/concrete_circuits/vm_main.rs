use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
#[serde(bound = "")]
pub struct VmMainInstanceSynthesisFunction<E: Engine, W: WitnessOracle<E>> {
    _marker: std::marker::PhantomData<(E, W)>,
}

use sync_vm::vm::vm_cycle::input::VmCircuitWitness;

impl<E: Engine, W: WitnessOracle<E>> ZkSyncUniformSynthesisFunction<E>
    for VmMainInstanceSynthesisFunction<E, W>
{
    type Witness = VmCircuitWitness<E, W>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "VM main circuit".to_string()
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
        Box::new(vm_circuit_entry_point)
    }
}
