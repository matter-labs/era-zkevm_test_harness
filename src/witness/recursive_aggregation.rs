use super::*;
use super::full_block_artifact::{BlockBasicCircuits, BlockBasicCircuitsPublicInputs};
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
) -> (Vec<Vec<sync_vm::testing::Fr>>, Vec<sync_vm::testing::Fr>, [bellman::pairing::bn256::G2Affine; 2]) {
    // walk over keys, ensure sorting, uniqueness and that it's only basic circuits
    let mut checker = std::collections::HashSet::new();

    assert_eq!(vks.len(), sync_vm::scheduler::NUM_CIRCUIT_TYPES_TO_SCHEDULE);

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

    (all_vk_encodings, all_vk_committments, g2_points.unwrap())
}


// create individual circuits to prove as leaf aggregations,
// and some artifacts to prepare for node aggregation
pub fn prepare_leaf_aggregations(
    basic_block_circuits: BlockBasicCircuits<Bn256>, // basic circuits
    basic_block_circuits_inputs: BlockBasicCircuitsPublicInputs<Bn256>, // their computed inputs
    individual_proofs: Vec<Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>, // proofs of those basic circuits
    verification_keys: Vec<VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>, // corresponding verification keys
    splitting_factor: usize, // how many proofs go into each aggregation
    padding_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>>, // vk that we use for padding. In general can be for any valid circuit of our geometry (gates, lookups)
    padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>>, // proof to use for paddings
    leaf_vks_committments_set: Vec<Fr>, // committments to individual VKs, use `form_base_circuits_committment` to get
    leaf_vks_committment: Fr, // committment to the full set of VKs
    g2_points: [bellman::pairing::bn256::G2Affine; 2], // G2 points for self-verification
) -> (
    Vec<crate::encodings::QueueSimulator<sync_vm::testing::Bn256, crate::encodings::recursion_request::RecursionRequest<sync_vm::testing::Bn256>, 2, 2>>, 
    Vec<sync_vm::recursion::leaf_aggregation::LeafAggregationOutputDataWitness<sync_vm::testing::Bn256>>, 
    Vec<crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit<sync_vm::testing::Bn256, VmWitnessOracle<sync_vm::testing::Bn256>>>
) {
    // first we simulate the queue that we expect from scheduler
    use sync_vm::recursion::get_prefered_committer;
    let round_function = get_prefered_committer();

    let padding_public_inputs = vec![padding_proof.inputs[0]; splitting_factor];
    let padding_proofs = vec![padding_proof.clone(); splitting_factor];

    let flattened = basic_block_circuits.clone().into_flattened_set();

    use crate::encodings::recursion_request::*;
    let mut recursion_requests_queue_simulator = RecursionQueueSimulator::empty();
    // form a queue of recursive verification requests in the same manner as scheduler does it
    let mut all_requests = vec![];

    for (idx, (circuit, public_input)) in basic_block_circuits.into_flattened_set().into_iter().zip(basic_block_circuits_inputs.into_flattened_set().into_iter()).enumerate() {
        let req = RecursionRequest {
            circuit_type: circuit.numeric_circuit_type(),
            public_input,
        };

        let _ = recursion_requests_queue_simulator.push(req.clone(), &round_function);

        all_requests.push((idx, req));
    }

    let rns_params = get_prefered_rns_params();
    use sync_vm::recursion::aggregation::VkInRns;

    // we pick proof number 0 as a padding element for circuit. In general it can be any valid proof
    let padding_vk_encoding: [_; sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] = {
        // add
        let vk_in_rns = VkInRns {
            vk: Some(padding_vk.clone()),
            rns_params: &rns_params
        };
        use sync_vm::traits::ArithmeticEncodable;
        let encoding = vk_in_rns.encode().unwrap();

        encoding.try_into().unwrap()
    };

    use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
    let padding_vk_committment = simulate_variable_length_hash(&padding_vk_encoding, &round_function);

    let padding_proof_public_input = padding_proof.inputs[0];

    let sponge_params = bn254_rescue_params();
    let transcript_params = (&sponge_params, &rns_params);

    use sync_vm::recursion::get_prefered_hash_params;

    let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
        base_placeholder_point: get_base_placeholder_point_for_accumulators(),
        // hash_params: get_prefered_hash_params(),
        hash_params: sponge_params.clone(),
        transcript_params: sponge_params.clone(),
    };

    use sync_vm::recursion::RescueTranscriptForRecursion;

    // split into N subcircuits based on the splitting factor

    let leaf_layer_requests: Vec<_> = all_requests.chunks(splitting_factor).map(|el| el.to_vec()).collect();
    let mut leaf_layer_subqueues = vec![];
    let mut queue = recursion_requests_queue_simulator.clone();
    for _ in 0..(leaf_layer_requests.len() - 1) {
        let (chunk, rest) = queue.split(splitting_factor as u32);
        leaf_layer_subqueues.push(chunk);
        queue = rest;
    }
    leaf_layer_subqueues.push(queue);

    let leaf_layer_flattened_set: Vec<_> = flattened.chunks(splitting_factor).map(|el| el.to_vec()).collect();

    let mut individual_proofs_it = individual_proofs.into_iter();
    let mut verification_keys_it = verification_keys.into_iter();

    let mut aggregation_outputs = vec![];
    let mut leaf_circuits = vec![];

    for (idx, (subset, circuits)) in leaf_layer_requests.into_iter().zip(leaf_layer_flattened_set.into_iter()).enumerate() {
        assert_eq!(subset.len(), circuits.len());
        
        use sync_vm::scheduler::RecursiveProofQueryWitness;

        let queue_wit: Vec<_> = leaf_layer_subqueues[idx].witness.iter().map(|el| {
            let (enc, prev_tail, el) = el.clone();
            let w = RecursiveProofQueryWitness {
                cicruit_type: el.circuit_type,
                closed_form_input_hash: el.public_input,
                _marker: std::marker::PhantomData
            };

            (enc, w, prev_tail)
        }).collect();

        use sync_vm::recursion::leaf_aggregation::*;
        use crate::witness::utils::take_queue_state_from_simulator;
        use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;
        use sync_vm::traits::CSWitnessable;

        let mut wit = LeafAggregationCircuitInstanceWitness::<Bn256> {
            closed_form_input: LeafAggregationInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                hidden_fsm_input: (),
                hidden_fsm_output: (),
                observable_input: LeafAggregationInputDataWitness {
                    initial_log_queue_state: take_queue_state_from_simulator(&leaf_layer_subqueues[idx]),
                    leaf_vk_committment: leaf_vks_committment,
                    _marker: std::marker::PhantomData,
                },
                observable_output: LeafAggregationOutputData::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            initial_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: queue_wit}, 
            leaf_vks_committments_set: leaf_vks_committments_set.clone(),
            proof_witnesses: vec![],
            vk_encoding_witnesses: vec![],
        };

        // dbg!(&wit.closed_form_input.observable_input.initial_log_queue_state);

        let this_aggregation_subqueue = &leaf_layer_subqueues[idx];

        for (i, ((req_idx, req), el)) in subset.into_iter().zip(circuits.into_iter()).enumerate() {
            let proof = individual_proofs_it.next().unwrap();
            let vk = verification_keys_it.next().unwrap();

            // type erasure for easier life
            let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = unsafe {std::mem::transmute(vk)};
            let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = unsafe {std::mem::transmute(proof)};

            assert_eq!(proof.inputs[0], req.public_input, "failed for req_idx = {}, i = {}, aggregation_idx = {}", req_idx, i, idx);
            assert_eq!(proof.inputs[0], this_aggregation_subqueue.witness[i].2.public_input, "failed for req_idx = {}, i = {}, aggregation_idx = {}", req_idx, i, idx);

            let vk_in_rns = VkInRns {
                vk: Some(vk.clone()),
                rns_params: &rns_params
            };
            use sync_vm::traits::ArithmeticEncodable;
            let encoding = vk_in_rns.encode().unwrap();
            wit.vk_encoding_witnesses.push(encoding);
            wit.proof_witnesses.push(proof);
        }

        drop(this_aggregation_subqueue);

        // we use the circuit itself to output some witness
        use sync_vm::testing::create_test_artifacts_with_optimized_gate;
        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let (aggregated_public_input, output_data) = aggregate_at_leaf_level_entry_point::<_, _, _, _, _, true>(
            &mut cs,
            Some(wit.clone()),
            &round_function,
            (
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.clone(),
                padding_public_inputs.clone(),
                padding_proofs.clone(),
                Some(g2_points.clone()),
            ),
        ).unwrap();

        let public_input_value = aggregated_public_input.get_value().unwrap();
        let result_observable_output = output_data.create_witness().unwrap();

        wit.closed_form_input.observable_output = result_observable_output.clone();

        aggregation_outputs.push(result_observable_output);

        use crate::abstract_zksync_circuit::concrete_circuits::LeafAggregationCircuit;

        let circuit = LeafAggregationCircuit::new(
            Some(wit),
            (
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.to_vec(),
                padding_public_inputs.clone(),
                padding_proofs.clone(),
                Some(g2_points.clone()),
            ),
            round_function.clone()
        );

        let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::LeafAggregation(circuit);
        leaf_circuits.push(circuit);
    }

    assert!(individual_proofs_it.next().is_none());
    assert!(verification_keys_it.next().is_none());

    // we need to propagate:
    // chunks of requests queues
    // simulated aggregation results
    // circuits themselves

    (leaf_layer_subqueues, aggregation_outputs, leaf_circuits)
}