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
use sync_vm::recursion::{get_prefered_rns_params, get_prefered_committer};
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

// helper function. Erases type internally
pub fn compute_vk_encoding_and_committment(
    vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>>,
) -> (Vec<sync_vm::testing::Fr>, sync_vm::testing::Fr) {
    let rns_params = get_prefered_rns_params();
    use sync_vm::recursion::aggregation::VkInRns;

    use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
    use sync_vm::traits::ArithmeticEncodable;
    use sync_vm::recursion::get_prefered_committer;

    let round_function = get_prefered_committer();

    let vk_in_rns = VkInRns {
        vk: Some(vk),
        rns_params: &rns_params
    };
    let encoding = vk_in_rns.encode().unwrap();
    let committment = simulate_variable_length_hash(&encoding, &round_function);

    (encoding, committment)
}

// helper function. Erases type internally
pub fn erase_vk_type(
    vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>,
) -> VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> {
    unsafe {std::mem::transmute(vk)} // only transmute marker
}

// helper function. Erases type internally
pub fn erase_proof_type(
    proof: Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>,
) -> Proof<Bn256, ZkSyncParametricCircuit<Bn256>> {
    unsafe {std::mem::transmute(proof)} // only transmute marker
}

// sets up basic parameters for leaf aggregation circuit by committing to
// all verification keys of basic circuits. it MUST be in the order of
// let sequence_of_circuit_types = [
//     CircuitType::VM,
//     CircuitType::DecommitmentsFilter,
//     CircuitType::Decommiter,
//     CircuitType::LogDemultiplexer,
//     CircuitType::KeccakPrecompile,
//     CircuitType::Sha256Precompile,
//     CircuitType::EcrecoverPrecompile,
//     CircuitType::RamValidation,
//     CircuitType::StorageFilter,
//     CircuitType::StorageApplicator,
//     CircuitType::StorageFreshWritesHasher,
//     CircuitType::StorageRepeatedWritesHasher,
//     CircuitType::EventsRevertsFilter,
//     CircuitType::L1MessagesRevertsFilter,
//     CircuitType::L1MessagesMerkelization,
// ];
// where CircuitType::EventsRevertsFilter and CircuitType::L1MessagesRevertsFilter are the same circuit
// The number of vks is checked
pub fn form_base_circuits_committment(
    vks: Vec<VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>,
) -> (Vec<sync_vm::testing::Fr>, sync_vm::testing::Fr, [bellman::pairing::bn256::G2Affine; 2]) {
    // walk over keys, ensure sorting, uniqueness and that it's only basic circuits
    let mut checker = std::collections::HashSet::new();

    assert_eq!(vks.len(), sync_vm::scheduler::NUM_CIRCUIT_TYPES_TO_SCHEDULE);

    let mut g2_points = None;
    let mut all_vk_committments = vec![];

    let rns_params = get_prefered_rns_params();
    use sync_vm::recursion::aggregation::VkInRns;

    use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
    use sync_vm::traits::ArithmeticEncodable;
    use sync_vm::recursion::get_prefered_committer;

    let round_function = get_prefered_committer();

    for (idx, vk) in vks.iter().cloned().enumerate() {
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
        all_vk_committments.push(committment);

        let is_unique = checker.insert(committment);
        if idx != 13 {
            // events and L1 messages sorts are the same thing
            assert!(is_unique);
        }

    }

    let set_committment = simulate_variable_length_hash(&all_vk_committments, &round_function);

    (all_vk_committments, set_committment, g2_points.unwrap())
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
    let sponge_params = bn254_rescue_params();

    let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
        base_placeholder_point: get_base_placeholder_point_for_accumulators(),
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
        let (_aggregated_public_input, output_data) = aggregate_at_leaf_level_entry_point::<_, _, _, _, _, true>(
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

use sync_vm::recursion::leaf_aggregation::LeafAggregationOutputDataWitness;
use sync_vm::recursion::node_aggregation::NodeAggregationOutputDataWitness;

// create individual circuits to prove as leaf aggregations,
// and some artifacts to prepare for node aggregation
pub fn prepare_node_aggregations(
    previous_level_proofs: Vec<Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>>, // proofs of previous level of aggregations
    previous_level_vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>, // only 1 verification key needed
    previous_level_are_leafs: bool,
    depth: u32,
    previous_level_leafs_aggregations: Vec<LeafAggregationOutputDataWitness<Bn256>>, // must be non-empty if we aggregate over leafs
    previous_level_node_aggregations: Vec<NodeAggregationOutputDataWitness<Bn256>>, // must be non-empty if we aggregate over nodes
    previous_sequence: Vec<crate::encodings::QueueSimulator<sync_vm::testing::Bn256, crate::encodings::recursion_request::RecursionRequest<sync_vm::testing::Bn256>, 2, 2>>,
    splitting_factor_for_leafs: usize,
    splitting_factor_for_nodes: usize,
    padding_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>>, // vk that we use for padding. In general can be for any valid circuit of our geometry (gates, lookups)
    padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>>, // proof to use for paddings
    padding_aggregations: Vec<([Fr; NUM_LIMBS], [Fr; NUM_LIMBS], [Fr; NUM_LIMBS], [Fr; NUM_LIMBS])>,
    leaf_vks_committment: Fr, // committment to the full set of VKs
    node_aggregation_vk_committment: Fr,
    leaf_aggregation_vk_committment: Fr,
    g2_points: [bellman::pairing::bn256::G2Affine; 2], // G2 points for self-verification
) -> (
    Vec<crate::encodings::QueueSimulator<sync_vm::testing::Bn256, crate::encodings::recursion_request::RecursionRequest<sync_vm::testing::Bn256>, 2, 2>>, 
    Vec<NodeAggregationOutputDataWitness<sync_vm::testing::Bn256>>, 
    Vec<crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit<sync_vm::testing::Bn256, VmWitnessOracle<sync_vm::testing::Bn256>>>
) {
    if depth == 0 {
        assert!(previous_level_are_leafs);
        assert!(previous_level_leafs_aggregations.is_empty() == false);
        assert!(previous_level_node_aggregations.is_empty() == true);
    } else {
        assert!(!previous_level_are_leafs);
        assert!(previous_level_leafs_aggregations.is_empty() == true);
        assert!(previous_level_node_aggregations.is_empty() == false);
    }

    let padding_public_inputs = vec![padding_proof.inputs[0]; splitting_factor_for_nodes];
    let padding_proofs = vec![padding_proof.clone(); splitting_factor_for_nodes];

    let rns_params = get_prefered_rns_params();
    use sync_vm::recursion::aggregation::VkInRns;
    use crate::encodings::QueueSimulator;
    use sync_vm::scheduler::RecursiveProofQueryWitness;
    use crate::witness::utils::take_queue_state_from_simulator;
    use sync_vm::traits::CSWitnessable;
    use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;
    use sync_vm::recursion::leaf_aggregation::LeafAggregationOutputDataWitness;

    let mut aggregation_outputs = vec![];
    let mut node_circuits = vec![];

    let round_function = get_prefered_committer();
    let sponge_params = bn254_rescue_params();

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

    let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
        base_placeholder_point: get_base_placeholder_point_for_accumulators(),
        hash_params: sponge_params.clone(),
        transcript_params: sponge_params.clone(),
    };

    use sync_vm::recursion::RescueTranscriptForRecursion;

    // the procedure is largely recursive - we join subrequests and output a circuit

    let num_previous_level_proofs = previous_sequence.len();

    assert_eq!(num_previous_level_proofs, previous_level_proofs.len());

    let mut merged = vec![];
    for chunk in previous_sequence.chunks(splitting_factor_for_nodes) {
        let mut first = chunk[0].clone();
        for second in chunk[1..].iter().cloned() {
            first = QueueSimulator::merge(first, second);
        }

        merged.push(first);
    }

    let mut proofs_it = previous_level_proofs.into_iter();
    let mut previous_level_leafs_aggregations_it = previous_level_leafs_aggregations.into_iter();
    let mut previous_level_node_aggregations_it = previous_level_node_aggregations.into_iter();

    use crate::abstract_zksync_circuit::concrete_circuits::NodeAggregationCircuit;
    use sync_vm::recursion::node_aggregation::NodeAggregationCircuitInstanceWitness;
    use sync_vm::recursion::node_aggregation::NodeAggregationInputOutputWitness;
    use sync_vm::recursion::node_aggregation::NodeAggregationInputDataWitness;
    use sync_vm::recursion::node_aggregation::NodeAggregationOutputData;

    let previous_level_vk = erase_vk_type(previous_level_vk);

    let mut circuit_to_aggregate_index = 0;

    for (_idx, subset) in merged.iter().cloned().enumerate() {
        let queue_wit: Vec<_> = subset.witness.iter().map(|el| {
            let (enc, prev_tail, el) = el.clone();
            let w = RecursiveProofQueryWitness {
                cicruit_type: el.circuit_type,
                closed_form_input_hash: el.public_input,
                _marker: std::marker::PhantomData
            };

            (enc, w, prev_tail)
        }).collect();

        let mut wit = NodeAggregationCircuitInstanceWitness::<Bn256> {
            closed_form_input: NodeAggregationInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                hidden_fsm_input: (),
                hidden_fsm_output: (),
                observable_input: NodeAggregationInputDataWitness {
                    initial_log_queue_state: take_queue_state_from_simulator(&subset),
                    leaf_vk_committment: leaf_aggregation_vk_committment,
                    node_vk_committment: node_aggregation_vk_committment,
                    all_circuit_types_committment_for_leaf: leaf_vks_committment,
                    _marker: std::marker::PhantomData,
                },
                observable_output: NodeAggregationOutputData::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            initial_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: queue_wit}, 
            proof_witnesses: vec![],
            vk_encoding_witnesses: vec![],
            leaf_aggregation_results: vec![],
            node_aggregation_results: vec![],
            depth: depth,
        };

        for _ in 0..splitting_factor_for_nodes {
            if circuit_to_aggregate_index >= num_previous_level_proofs {
                break;
            }

            let proof = proofs_it.next().unwrap();
            let proof = erase_proof_type(proof);

            if depth == 0 {
                let output: LeafAggregationOutputDataWitness<Bn256> = previous_level_leafs_aggregations_it.next().unwrap();
                wit.leaf_aggregation_results.push(output);
            } else {
                use sync_vm::recursion::node_aggregation::NodeAggregationOutputDataWitness;
                let output: NodeAggregationOutputDataWitness<Bn256> = previous_level_node_aggregations_it.next().unwrap();
                wit.node_aggregation_results.push(output);
            }

            let vk_in_rns = VkInRns {
                vk: Some(previous_level_vk.clone()),
                rns_params: &rns_params
            };
            use sync_vm::traits::ArithmeticEncodable;
            let encoding = vk_in_rns.encode().unwrap();
            wit.vk_encoding_witnesses.push(encoding);
            wit.proof_witnesses.push(proof);
            circuit_to_aggregate_index += 1;
        }

        use sync_vm::recursion::node_aggregation::aggregate_at_node_level_entry_point;
        use sync_vm::testing::create_test_artifacts_with_optimized_gate;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let (_aggregated_public_input, _leaf_aggregation_output_data, _node_aggregation_output_data, output_data) = aggregate_at_node_level_entry_point::<_, _, _, _, _, true>(
            &mut cs,
            Some(wit.clone()),
            &round_function,
            (
                splitting_factor_for_nodes,
                splitting_factor_for_leafs,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.clone(),
                padding_public_inputs.clone(),
                padding_proofs.clone(),
                padding_aggregations.clone(),
                Some(g2_points.clone()),
            ),
        ).unwrap();

        let result_observable_output = output_data.create_witness().unwrap();

        wit.closed_form_input.observable_output = result_observable_output.clone();

        aggregation_outputs.push(result_observable_output);

        let circuit = NodeAggregationCircuit::new(
            Some(wit),
            (
                splitting_factor_for_nodes,
                splitting_factor_for_leafs,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.to_vec(),
                padding_public_inputs.clone(),
                padding_proofs.clone(),
                padding_aggregations.clone(),
                Some(g2_points.clone()),
            ),
            round_function.clone()
        );

        let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::NodeAggregation(circuit);

        node_circuits.push(circuit);
    }

    assert!(proofs_it.next().is_none());

    (merged, aggregation_outputs, node_circuits)
}

// outputs final scheduler circuit (to be proven using Keccak256 transcript as it will be verified in Ethereum),
// as well as final aggregation result as 32 bytes for every cordinate as [pair_with_generator_x, pair_with_generator_y, pair_with_x_x, pair_with_x_y]
pub fn prepare_scheduler_circuit(
    incomplete_scheduler_witness: SchedulerCircuitInstanceWitness<Bn256>,
    node_final_proof_level_proofs: Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>, // proofs of final level of aggregations
    node_aggregation_vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>, // only 1 verification key needed
    final_node_aggregations: NodeAggregationOutputDataWitness<Bn256>,
    leaf_vks_committment: Fr, // committment to the full set of VKs
    node_aggregation_vk_committment: Fr,
    leaf_aggregation_vk_committment: Fr,
    previous_aux_hash: [u8; 32],
    previous_meta_hash: [u8; 32],
    padding_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>>, // even though we do NOT use it in fact, but it affects the synthesis as we reuse a function that can do the padding
    padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>>, // same for proof
    scheduler_upper_bound: u32, // is a maximum number of circuits to scheduler. Should be in a form of splitting_per_leafs * splitting_per_node^K
    g2_points: [bellman::pairing::bn256::G2Affine; 2], // G2 points for self-verification
) -> (
    crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit<sync_vm::testing::Bn256, VmWitnessOracle<sync_vm::testing::Bn256>>,
    [[u8; 32]; 4],
) {
    let rns_params = get_prefered_rns_params();
    use sync_vm::recursion::aggregation::VkInRns;
    use crate::encodings::QueueSimulator;
    use sync_vm::scheduler::RecursiveProofQueryWitness;
    use crate::witness::utils::take_queue_state_from_simulator;
    use sync_vm::traits::CSWitnessable;
    use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;
    use sync_vm::recursion::leaf_aggregation::LeafAggregationOutputDataWitness;

    let mut scheduler_witness = incomplete_scheduler_witness;

    let node_final_proof_level_proofs = erase_proof_type(node_final_proof_level_proofs);
    let node_aggregation_vk = erase_vk_type(node_aggregation_vk);

    scheduler_witness.aggregation_result = final_node_aggregations;
    scheduler_witness.proof_witnesses = vec![node_final_proof_level_proofs];
    let vk_in_rns = VkInRns {
        vk: Some(node_aggregation_vk.clone()),
        rns_params: &rns_params
    };
    use sync_vm::traits::ArithmeticEncodable;
    let encoding = vk_in_rns.encode().unwrap();
    scheduler_witness.vk_encoding_witnesses = vec![encoding];

    scheduler_witness.previous_block_aux_hash = Bytes32Witness::from_bytes_array(&previous_aux_hash);
    scheduler_witness.previous_block_meta_hash = Bytes32Witness::from_bytes_array(&previous_meta_hash);

    // now also all the key sets
    use crate::bellman::{PrimeField, PrimeFieldRepr};
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;

    let mut buffer = vec![];
    leaf_vks_committment.into_repr().write_be(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_witness.all_different_circuits_keys_hash = Bytes32Witness::from_bytes_array(&all_keys);

    let mut buffer = vec![];
    leaf_aggregation_vk_committment.into_repr().write_be(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_witness.recursion_leaf_verification_key_hash = Bytes32Witness::from_bytes_array(&all_keys);

    let mut buffer = vec![];
    node_aggregation_vk_committment.into_repr().write_be(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_witness.recursion_node_verification_key_hash = Bytes32Witness::from_bytes_array(&all_keys);

    use crate::abstract_zksync_circuit::concrete_circuits::SchedulerCircuit;
    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    use sync_vm::scheduler::scheduler_function;
    let round_function = get_prefered_committer();
    let sponge_params = bn254_rescue_params();

    let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
        base_placeholder_point: get_base_placeholder_point_for_accumulators(),
        hash_params: sponge_params.clone(),
        transcript_params: sponge_params.clone(),
    };

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

    let aggregation_coords_bytes = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
    let clone_to_send = std::sync::Arc::clone(&aggregation_coords_bytes);
    let reporting_function = Box::new(move |result: Vec<[u8; 32]>| {
        *clone_to_send.lock().unwrap() = result;
    }) as Box<dyn FnOnce(Vec<[u8; 32]>) -> ()>;

    let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
    let _ = scheduler_function(
        &mut cs, 
        Some(scheduler_witness.clone()), 
        Some(reporting_function),
        &round_function, 
        (
            scheduler_upper_bound,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding,
            padding_proof.clone(),
            Some(g2_points.clone()),
        )
    );

    // now we can unwrap and get the values we want
    let final_aggregation_result = aggregation_coords_bytes.lock().unwrap().clone();

    let circuit = SchedulerCircuit::new(
        Some(scheduler_witness),
        (
            scheduler_upper_bound,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding.to_vec(),
            padding_proof.clone(),
            Some(g2_points.clone()),
        ),
        round_function.clone()
    );

    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::Scheduler(circuit);

    (circuit, final_aggregation_result.try_into().unwrap())
}
