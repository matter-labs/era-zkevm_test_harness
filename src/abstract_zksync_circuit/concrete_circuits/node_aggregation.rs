use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct NodeAggregationInstanceSynthesisFunction;

use crate::franklin_crypto::plonk::circuit::bigint::RnsParameters;
use sync_vm::recursion::node_aggregation::*;
use sync_vm::recursion::recursion_tree::AggregationParameters;
use sync_vm::recursion::recursion_tree::NUM_LIMBS;
use sync_vm::recursion::transcript::GenericTranscriptGadget;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for NodeAggregationInstanceSynthesisFunction {
    type Witness = NodeAggregationCircuitInstanceWitness<E>;
    type Config = (
        usize, // num proofs this circuit aggregates
        usize, // num proofs that each leaf aggregates
        RnsParameters<E, E::Fq>,
        AggregationParameters<
            E,
            GenericTranscriptGadget<E, RescueParams<E, 2, 3>, 2, 3>,
            RescueParams<E, 2, 3>,
            2,
            3,
        >,
        E::Fr,
        Vec<E::Fr>,
        Vec<E::Fr>,
        Vec<ZkSyncParametricProof<E>>,
        Vec<(
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
        )>,
        Option<[E::G2Affine; 2]>,
    );
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Node recursive aggregation".to_string()
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
        Box::new(node_aggregation_outer_function)
    }
}

#[track_caller]
fn node_aggregation_outer_function<
    E: Engine,
    CS: ConstraintSystem<E>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    witness: Option<NodeAggregationCircuitInstanceWitness<E>>,
    round_function: &R,
    params: (
        usize,
        usize,
        RnsParameters<E, E::Fq>,
        AggregationParameters<
            E,
            GenericTranscriptGadget<E, RescueParams<E, 2, 3>, 2, 3>,
            RescueParams<E, 2, 3>,
            2,
            3,
        >,
        E::Fr,
        Vec<E::Fr>,
        Vec<E::Fr>,
        Vec<ZkSyncParametricProof<E>>,
        Vec<(
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
            [E::Fr; NUM_LIMBS],
        )>,
        Option<[E::G2Affine; 2]>,
    ),
) -> Result<AllocatedNum<E>, SynthesisError> {
    let (
        num_proofs_to_aggregate,
        num_proofs_aggregated_by_leaf,
        rns_params,
        aggregation_params,
        padding_vk_committment,
        padding_vk_encoding,
        padding_public_input,
        padding_proof,
        padding_aggregation_result,
        g2_elements,
    ) = params;

    let padding_vk_encoding_fixed: [E::Fr;
        sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] =
        padding_vk_encoding.try_into().unwrap();

    let params = (
        num_proofs_to_aggregate,
        num_proofs_aggregated_by_leaf,
        rns_params,
        aggregation_params,
        padding_vk_committment,
        padding_vk_encoding_fixed,
        padding_public_input,
        padding_proof,
        padding_aggregation_result,
        g2_elements,
    );

    let (input, _, _, _) = aggregate_at_node_level_entry_point::<_, _, _, _, _, true>(
        cs,
        witness,
        round_function,
        params,
    )?;

    Ok(input)
}
