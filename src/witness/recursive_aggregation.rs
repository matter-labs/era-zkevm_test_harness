use super::*;
use crate::bellman::Engine;
use sync_vm::testing::{Bn256, Fr};
use crate::franklin_crypto::plonk::circuit::allocated_num::Num;
use sync_vm::{recursion::recursion_tree::NUM_LIMBS, circuit_structures::traits::CircuitArithmeticRoundFunction};
use crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit;
use crate::bellman::plonk::better_better_cs::proof::Proof;
use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
use crate::witness::oracle::VmWitnessOracle;
use sync_vm::circuit_structures::utils::bn254_rescue_params;
use sync_vm::recursion::get_prefered_rns_params;
use sync_vm::recursion::transcript::GenericTranscriptGadget;
use sync_vm::recursion::recursion_tree::AggregationParameters;
use sync_vm::recursion::get_base_placeholder_point_for_accumulators;

#[derive(Clone, Debug)]
pub struct AggregationResult<E: Engine> {
    pub pairing_with_gen_x_limbs: [E::Fr; NUM_LIMBS],
    pub pairing_with_gen_y_limbs: [E::Fr; NUM_LIMBS],
    pub pairing_with_x_x_limbs: [E::Fr; NUM_LIMBS],
    pub pairing_with_x_y_limbs: [E::Fr; NUM_LIMBS],
}

// we need any points that have e(p1, g2)*e(p2, g2^x) == 0, so we basically can use two first elements
// of the trusted setup
pub fn padding_aggregations(
    num_elements: usize
) -> Vec<([Fr; NUM_LIMBS], [Fr; NUM_LIMBS], [Fr; NUM_LIMBS], [Fr; NUM_LIMBS])> {
    use crate::franklin_crypto::plonk::circuit::bigint::split_into_limbs;
    let rns_params = get_prefered_rns_params();

    let crs_mons = circuit_testing::get_trusted_setup::<Bn256>(1<<26);
    let mut p1 = crs_mons.g1_bases[1];
    use sync_vm::franklin_crypto::bellman::CurveAffine;
    p1.negate();
    let mut p2 = crs_mons.g1_bases[0];

    let mut all_aggregations = vec![];

    use sync_vm::franklin_crypto::bellman::PrimeField;
    let scalar = Fr::multiplicative_generator();

    for _ in 0..num_elements {
        let (pair_with_generator_x, pair_with_generator_y) = p1.into_xy_unchecked();
        let (pair_with_x_x, pair_with_x_y) = p2.into_xy_unchecked();

        let pair_with_generator_x = split_into_limbs(pair_with_generator_x, &rns_params).0.try_into().unwrap();
        let pair_with_generator_y = split_into_limbs(pair_with_generator_y, &rns_params).0.try_into().unwrap();
        let pair_with_x_x = split_into_limbs(pair_with_x_x, &rns_params).0.try_into().unwrap();
        let pair_with_x_y = split_into_limbs(pair_with_x_y, &rns_params).0.try_into().unwrap();

        let tuple = (
            pair_with_generator_x,
            pair_with_generator_y,
            pair_with_x_x,
            pair_with_x_y,
        );

        all_aggregations.push(tuple);

        use sync_vm::franklin_crypto::bellman::CurveProjective;

        let tmp = p1.mul(scalar);
        p1 = tmp.into_affine();

        let tmp = p2.mul(scalar);
        p2 = tmp.into_affine();
    }

    all_aggregations
}

use sync_vm::recursion::node_aggregation::ZkSyncParametricCircuit;


// sets up basic parameters for leaf aggregation circuit by committing to
// all verification keys of basic circuits
pub fn form_base_circuits_committment(
    vks: Vec<VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>,
) -> (Vec<Vec<sync_vm::testing::Fr>>, Vec<sync_vm::testing::Fr>, std::option::Option<[bellman::pairing::bn256::G2Affine; 2]>) {
    // walk over keys, ensure sorting, uniqueness and that it's only basic circuits
    let mut checker = std::collections::HashSet::new();

    let mut g2_points = None;
    let mut all_vk_encodings = vec![];
    let mut all_vk_committments = vec![];

    let rns_params = get_prefered_rns_params();
    use sync_vm::recursion::aggregation::VkInRns;

    use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
    use sync_vm::traits::ArithmeticEncodable;
    use sync_vm::recursion::get_prefered_committer;

    let round_function = get_prefered_committer();

    for vk in vks.iter().cloned() {
        if g2_points.is_none() {
            g2_points = Some(vk.g2_elements);
        }

        let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = unsafe {std::mem::transmute(vk)}; // only transmute marker

        // add
        let vk_in_rns = VkInRns {
            vk: Some(vk.clone()),
            rns_params: &rns_params
        };
        let encoding = vk_in_rns.encode().unwrap();
        let committment = simulate_variable_length_hash(&encoding, &round_function);
        all_vk_encodings.push(encoding);
        all_vk_committments.push(committment);

        let is_unique = checker.insert(committment);
        assert!(is_unique);
    }

    (all_vk_encodings, all_vk_committments, g2_points)
}

pub fn prepare_node_aggregations(
    individual_proofs: Vec<Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>,
    verfication_keys: Vec<VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>,
    splitting_factor: usize,
    padding_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>>,
    padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>>,
) -> () {
    todo!()
    // // we pick proof number 0 as a padding element for circuit. In general it can be any valid proof
    // let padding_vk_encoding: [_; sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] = all_vk_encodings[0].to_vec().try_into().unwrap();

    // let padding_proof_public_input = padding_proof.inputs[0];

    // let mut padding_public_inputs = vec![];
    // let mut padding_proofs = vec![];

    // let sponge_params = bn254_rescue_params();
    // let rns_params = get_prefered_rns_params();
    // let transcript_params = (&sponge_params, &rns_params);

    // use sync_vm::recursion::get_prefered_hash_params;

    // let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
    //     base_placeholder_point: get_base_placeholder_point_for_accumulators(),
    //     // hash_params: get_prefered_hash_params(),
    //     hash_params: sponge_params.clone(),
    //     transcript_params: sponge_params.clone(),
    // };

    // use sync_vm::recursion::RescueTranscriptForRecursion;
}