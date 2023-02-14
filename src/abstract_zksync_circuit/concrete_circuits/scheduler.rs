use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct SchedulerInstanceSynthesisFunction;

use crate::franklin_crypto::plonk::circuit::bigint::RnsParameters;
use sync_vm::recursion::node_aggregation::*;
use sync_vm::recursion::recursion_tree::AggregationParameters;
use sync_vm::recursion::recursion_tree::NUM_LIMBS;
use sync_vm::recursion::transcript::GenericTranscriptGadget;
use sync_vm::scheduler::scheduler_function;
use sync_vm::scheduler::SchedulerCircuitInstanceWitness;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for SchedulerInstanceSynthesisFunction {
    type Witness = SchedulerCircuitInstanceWitness<E>;
    type Config = (
        u32,
        RnsParameters<E, E::Fq>,
        AggregationParameters<
            E,
            GenericTranscriptGadget<E, RescueParams<E, 2, 3>, 2, 3>,
            RescueParams<E, 2, 3>,
            2,
            3,
        >,
        Vec<E::Fr>,
        ZkSyncParametricProof<E>,
        Option<[E::G2Affine; 2]>,
    );
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Scheduler".to_string()
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
        Box::new(scheduler_outer_function)
    }
}

#[track_caller]
fn scheduler_outer_function<
    E: Engine,
    CS: ConstraintSystem<E>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    witness: Option<SchedulerCircuitInstanceWitness<E>>,
    round_function: &R,
    params: (
        u32,
        RnsParameters<E, E::Fq>,
        AggregationParameters<
            E,
            GenericTranscriptGadget<E, RescueParams<E, 2, 3>, 2, 3>,
            RescueParams<E, 2, 3>,
            2,
            3,
        >,
        Vec<E::Fr>,
        ZkSyncParametricProof<E>,
        Option<[E::G2Affine; 2]>,
    ),
) -> Result<AllocatedNum<E>, SynthesisError> {
    let (limit, rns_params, aggregation_params, padding_vk_encoding, padding_proof, g2_elements) =
        params;

    let padding_vk_encoding_fixed: [E::Fr;
        sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] =
        padding_vk_encoding.try_into().unwrap();

    let params = (
        limit,
        rns_params,
        aggregation_params,
        padding_vk_encoding_fixed,
        padding_proof,
        g2_elements,
    );

    let input = scheduler_function(cs, witness, None, round_function, params)?;

    Ok(input)
}
