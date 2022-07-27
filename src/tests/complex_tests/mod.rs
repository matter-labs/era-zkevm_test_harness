mod utils;
mod serialize_utils;

use std::collections::HashMap;

use super::*;
use crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit;
use crate::encodings::QueueSimulator;
use crate::entry_point::{create_out_of_circuit_global_context};

use crate::ethereum_types::*;
use crate::pairing::bn256::Bn256;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::oracle::VmWitnessOracle;
use crate::witness_structures::take_queue_state_from_simulator;
use num_integer::Integer;
use sync_vm::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use sync_vm::franklin_crypto::plonk::circuit::verifier_circuit::utils::verification_key_into_allocated_limb_witnesses;
use sync_vm::glue::traits::GenericHasher;
use sync_vm::recursion::leaf_aggregation::LeafAggregationCircuitInstanceWitness;
use sync_vm::recursion::recursion_tree::AggregationParameters;
use sync_vm::recursion::{get_prefered_rns_params, get_base_placeholder_point_for_accumulators, get_prefered_committer};
use sync_vm::rescue_poseidon::rescue::params::RescueParams;
use sync_vm::traits::CSWitnessable;
use sync_vm::utils::bn254_rescue_params;
use sync_vm::vm::vm_cycle::cycle::vm_cycle;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
use zk_evm::abstractions::*;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::*;
use zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use zk_evm::witness_trace::VmWitnessTracer;
use zk_evm::GenericNoopTracer;
use zkevm_assembly::Assembly;
use zk_evm::testing::storage::InMemoryStorage;
use crate::toolset::create_tools;
use utils::{read_test_artifact, TestArtifact};
use crate::witness::tree::{ZKSyncTestingTree, BinarySparseStorageTree};

const ACCOUNT_CODE_STORAGE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x02,
]);


#[test]
fn basic_test() {
    let test_artifact = read_test_artifact("basic_test");
    run_and_try_create_witness_inner(test_artifact, 20000);
}

use blake2::Blake2s256;
use crate::witness::tree::ZkSyncStorageLeaf;

fn save_predeployed_contracts(storage: &mut InMemoryStorage, tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>, contracts: &HashMap<Address, Vec<[u8; 32]>>) {
    let mut sorted_contracts = vec![];
    let mut keys: Vec<_> = contracts.keys().cloned().collect();
    keys.sort();
    for el in keys.into_iter() {
        let v = contracts[&el].clone();

        sorted_contracts.push((el, v));
    }

    let storage_logs: Vec<(u8, Address, U256, U256)> = sorted_contracts
        .clone()
        .into_iter()
        .map(|(address, bytecode)| {
            let hash = bytecode_to_code_hash(&bytecode).unwrap();

            println!("Have address {:?} with code hash {}", address, U256::from(hash));

            (0, ACCOUNT_CODE_STORAGE_ADDRESS, U256::from_big_endian(address.as_bytes()), U256::from(hash))
        })
        .collect();

    storage.populate(storage_logs.clone());

    for (shard_id, address, key, value) in storage_logs.into_iter() {
        assert!(shard_id == 0);
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        use crate::witness::tree::EnumeratedBinaryLeaf;
        let mut leaf = ZkSyncStorageLeaf::empty();
        let mut buffer = [0u8; 32];
        value.to_big_endian(&mut buffer);
        leaf.set_value(&buffer);

        tree.insert_leaf(&index, leaf);
    }
}

fn run_and_try_create_witness_inner(mut test_artifact: TestArtifact, cycle_limit: usize) {
    use zk_evm::precompiles::BOOTLOADER_FORMAL_ADDRESS;

    use crate::external_calls::run;

    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    use crate::toolset::GeometryConfig;

    let geometry = GeometryConfig {
        cycles_per_vm_snapshot: 1024,
        cycles_per_ram_permutation: 1024,
        cycles_per_code_decommitter: 256,
        cycles_per_storage_application: 2,
        cycles_per_keccak256_circuit: 1,
        cycles_per_sha256_circuit: 1,
        cycles_per_ecrecover_circuit: 2,

        limit_for_code_decommitter_sorter: 512,
        limit_for_log_demuxer: 512,
        limit_for_storage_sorter: 512,
        limit_for_events_or_l1_messages_sorter: 128,
        limit_for_initial_writes_pubdata_hasher: 16,
        limit_for_repeated_writes_pubdata_hasher: 16,
        limit_for_l1_messages_merklizer: 32,
    };

    let mut storage_impl = InMemoryStorage::new();
    let mut tree = ZKSyncTestingTree::empty();

    test_artifact.entry_point_address = *zk_evm::precompiles::BOOTLOADER_FORMAL_ADDRESS;
    
    let predeployed_contracts = test_artifact.predeployed_contracts.clone().into_iter().chain(Some((test_artifact.entry_point_address, test_artifact.entry_point_code.clone()))).collect::<HashMap<_,_>>();
    save_predeployed_contracts(&mut storage_impl, &mut tree, &predeployed_contracts);

    let used_bytecodes = HashMap::from_iter(test_artifact.predeployed_contracts.iter().map(|(_,bytecode)| (bytecode_to_code_hash(&bytecode).unwrap().into(), bytecode.clone())));
    for (k, _) in used_bytecodes.iter() {
        println!("Have bytecode hash {}", k);
    }
    use sha3::{Digest, Keccak256};

    const BLOCK_NUMBER: u64 = 1;
    const BLOCK_TIMESTAMP: u64 = 1;

    let previous_enumeration_index = tree.next_enumeration_index();
    let previous_root = tree.root();
    let previous_block_number = BLOCK_NUMBER - 1;
    let previous_block_number_bytes = previous_block_number.to_be_bytes();
    let previous_block_timestamp_bytes = 0u64.to_be_bytes();
    // simualate content hash

    let mut hasher = Keccak256::new();
    hasher.update(&previous_block_number_bytes);
    hasher.update(&previous_block_timestamp_bytes);
    hasher.update(&previous_enumeration_index.to_be_bytes());
    hasher.update(&previous_root);
    hasher.update(&0u64.to_be_bytes()); // porter shart
    hasher.update(&[0u8; 32]); // porter shard

    let mut previous_data_hash = [0u8; 32];
    (&mut previous_data_hash[..]).copy_from_slice(&hasher.finalize().as_slice());  

    let previous_aux_hash = [0u8; 32];
    let previous_meta_hash = [0u8; 32];

    // simulate block header

    let mut hasher = Keccak256::new();
    hasher.update(&previous_data_hash);
    hasher.update(&previous_meta_hash);
    hasher.update(&previous_aux_hash);

    let mut previous_content_hash = [0u8; 32];
    (&mut previous_content_hash[..]).copy_from_slice(&hasher.finalize().as_slice());

    // RAM verification queries
    let ram_queries = vec![
        (sync_vm::scheduler::PREVIOUS_BLOCK_HASH_HEAP_SLOT, U256::from_big_endian(&previous_content_hash))
    ];

    let (basic_block_circuits, basic_block_circuits_inputs, mut scheduler_partial_input) = run(
        previous_block_number,
        BLOCK_NUMBER,
        BLOCK_TIMESTAMP,
        Address::zero(),
        test_artifact.entry_point_address,
        test_artifact.entry_point_code,
        vec![],
        false,
        U256::zero(), // no default AA for this test
        50,
        2,
        used_bytecodes,
        vec![],
        ram_queries,
        cycle_limit,
        round_function.clone(),
        geometry,
        storage_impl,
        &mut tree
    );

    use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
    use sync_vm::recursion::transcript::GenericTranscriptGadget;

    let _num_vm_circuits = basic_block_circuits.main_vm_circuits.len();
    // dbg!(_num_vm_circuits);
    let flattened = basic_block_circuits.clone().into_flattened_set();
    let flattened_inputs = basic_block_circuits_inputs.clone().into_flattened_set();
    // dbg!(&flattened_inputs);

    let sponge_params = bn254_rescue_params();
    let rns_params = get_prefered_rns_params();
    let transcript_params = (&sponge_params, &rns_params);

    use sync_vm::recursion::get_prefered_hash_params;

    let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
        base_placeholder_point: get_base_placeholder_point_for_accumulators(),
        // hash_params: get_prefered_hash_params(),
        hash_params: sponge_params.clone(),
        transcript_params: sponge_params.clone(),
    };

    use sync_vm::recursion::RescueTranscriptForRecursion;

    let num_proofs = flattened.len();
    dbg!(num_proofs);

    for (idx, (el, input_value)) in flattened.into_iter().zip(flattened_inputs.into_iter()).enumerate() {
        let descr = el.short_description();
        println!("Doing {}: {}", idx, descr);
        if !matches!(&el, ZkSyncCircuit::ECRecover(..)) {
            continue;
        }
        // el.debug_witness();
        use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
        let (is_satisfied, public_input) = circuit_testing::check_if_satisfied::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(el).unwrap();
        assert!(is_satisfied);
        assert_eq!(public_input, input_value, "Public input diverged for circuit {} of type {}", idx, descr);
        // if public_input != input_value {
        //     println!("Public input diverged for circuit {} of type {}", idx, descr);
        // }

        // let vk_file_name = format!("vk_{}", idx);

        // if std::path::Path::new(&format!("{}.key", &vk_file_name)).exists() {
        //     continue;
        // }

        // el.debug_witness();

        // let (is_satisfied, public_input) = circuit_testing::check_if_satisfied::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(el).unwrap();
        // assert!(is_satisfied);

        // let (proof, vk) = circuit_testing::prove_and_verify_circuit_for_params::<
        //     Bn256, 
        //     _, 
        //     PlonkCsWidth4WithNextStepAndCustomGatesParams, 
        //     RescueTranscriptForRecursion<'_>
        // >(el, Some(transcript_params)).unwrap();

        // assert_eq!(proof.inputs[0], input_value, "Public input diverged for circuit {} of type {}", idx, descr);

        // let vk_file_name = format!("vk_{}", idx);
        // let proof_file_name = format!("proof_{}", idx);

        // let mut vk_file_for_bytes = std::fs::File::create(format!("{}.key", &vk_file_name)).unwrap();
        // let mut vk_file_for_json = std::fs::File::create(format!("{}.json", &vk_file_name)).unwrap();

        // let mut proof_file_for_bytes = std::fs::File::create(format!("{}.key", &proof_file_name)).unwrap();
        // let mut proof_file_for_json = std::fs::File::create(format!("{}.json", &proof_file_name)).unwrap();

        // vk.write(&mut vk_file_for_bytes).unwrap();
        // proof.write(&mut proof_file_for_bytes).unwrap();

        // serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
        // serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();
    }

    // recursion step. We decide on some arbitrary parameters
    let splitting_factor = 4; // we either split into N subqueues, or we do N leaf proofs per layer

    use crate::encodings::recursion_request::*;
    let mut recursion_requests_queue_simulator = RecursionQueueSimulator::empty();

    use crate::witness::full_block_artifact::BlockBasicCircuitsPublicInputs;
    use sync_vm::scheduler::CircuitType;
    use sync_vm::recursion::aggregation::VkInRns;
    use sync_vm::traits::ArithmeticEncodable;
    use sync_vm::glue::optimizable_queue::*;
    use crate::bellman::plonk::better_better_cs::proof::Proof;
    use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
    use sync_vm::recursion::node_aggregation::ZkSyncParametricCircuit;
    use sync_vm::recursion::leaf_aggregation::*;
    use sync_vm::scheduler::*;

    let mut vk_committments_set = vec![];
    let mut vk_encodings = vec![];

    let mut previous: Option<VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>>> = None;

    let mut g2_points = None;

    for idx in 0..num_proofs {
        let vk_file_name = format!("vk_{}", idx);

        let mut vk_file_for_json = std::fs::File::open(format!("{}.json", &vk_file_name)).unwrap();

        let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();

        if g2_points.is_none() {
            g2_points = Some(vk.g2_elements);
        }
        if let Some(p) = previous.as_ref().cloned() {
            if p.gate_selectors_commitments[0] == vk.gate_selectors_commitments[0] {
                continue
            } else {
                // add
                let vk_in_rns = VkInRns {
                    vk: Some(vk.clone()),
                    rns_params: &rns_params
                };
                let encoding = vk_in_rns.encode().unwrap();
                let committment = simulate_variable_length_hash(&encoding, &round_function);
                dbg!(idx);
                dbg!(&committment);
                vk_encodings.push(encoding);
                vk_committments_set.push(committment);

                previous = Some(vk);
            }
        } else {
            let vk_in_rns = VkInRns {
                vk: Some(vk.clone()),
                rns_params: &rns_params
            };
            let encoding = vk_in_rns.encode().unwrap();
            let committment = simulate_variable_length_hash(&encoding, &round_function);
            dbg!(idx);
            dbg!(&committment);
            vk_encodings.push(encoding);
            vk_committments_set.push(committment);

            previous = Some(vk);
        }
    }
    
    // special case of events and l1 messages sorter

    let mut all_vk_encodings = vec![];
    all_vk_encodings.extend_from_slice(&vk_encodings[..13]);
    all_vk_encodings.extend_from_slice(&vk_encodings[12..]);

    let mut all_vk_committments = vec![];
    all_vk_committments.extend_from_slice(&vk_committments_set[..13]);
    all_vk_committments.extend_from_slice(&vk_committments_set[12..]);

    dbg!(&all_vk_committments);

    drop(vk_encodings);
    drop(vk_committments_set);

    let all_circuit_types_committment_for_leaf_agg = simulate_variable_length_hash(&all_vk_committments, &round_function);

    let padding_vk_committment = all_vk_committments[0]; 
    dbg!(&all_vk_encodings[0].len());
    let padding_vk_encoding: [_; sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] = all_vk_encodings[0].to_vec().try_into().unwrap();
    let padding_proof_public_input = basic_block_circuits_inputs.clone().into_flattened_set()[0];
    let padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(std::fs::File::open("proof_0.json").unwrap()).unwrap();

    dbg!(all_vk_committments.len());

    let mut all_requests = vec![];

    for (idx, (circuit, public_input)) in basic_block_circuits.into_flattened_set().into_iter().zip(basic_block_circuits_inputs.into_flattened_set().into_iter()).enumerate() {
        let req = RecursionRequest {
            circuit_type: circuit.numeric_circuit_type(),
            public_input,
        };

        if circuit.numeric_circuit_type() == 16 {
            dbg!(&public_input);
        }

        let _ = recursion_requests_queue_simulator.push(req.clone(), &round_function);

        all_requests.push((idx, req));
    }

    dbg!(&all_requests.len());
    dbg!(&recursion_requests_queue_simulator.tail);

    // // we simulate the splitting
    // // scheduler does 1 recursive proof

    let leaf_layer: Vec<_> = all_requests.chunks(splitting_factor).map(|el| el.to_vec()).collect();

    let mut leaf_layer_subqueues = vec![];
    let mut queue = recursion_requests_queue_simulator.clone();
    for _ in 0..(leaf_layer.len() - 1) {
        let (chunk, rest) = queue.split(splitting_factor as u32);
        leaf_layer_subqueues.push(chunk);
        queue = rest;
    }
    leaf_layer_subqueues.push(queue);

    // LEAF LEVEL

    let mut level = 0;

    println!("LEVEL {}: aggregating INVIDIVUAL PROOFS by LEAFS", level);

    for (idx, subset) in leaf_layer.into_iter().enumerate() {
        // dbg!(&subset.len());
        let vk_file_name = format!("rec_vk_{}_{}", level, idx);
        let proof_file_name = format!("rec_proof_{}_{}", level, idx);
        let output_file_name = format!("rec_output_{}_{}", level, idx);
        
        // dbg!(&subset);
        let queue_wit: Vec<_> = leaf_layer_subqueues[idx].witness.iter().map(|el| {
            let (enc, prev_tail, el) = el.clone();
            let w = RecursiveProofQueryWitness {
                cicruit_type: el.circuit_type,
                closed_form_input_hash: el.public_input,
                _marker: std::marker::PhantomData
            };

            (enc, w, prev_tail)
        }).collect();
        let mut wit = LeafAggregationCircuitInstanceWitness::<Bn256> {
            closed_form_input: LeafAggregationInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                hidden_fsm_input: (),
                hidden_fsm_output: (),
                observable_input: LeafAggregationInputDataWitness {
                    initial_log_queue_state: take_queue_state_from_simulator(&leaf_layer_subqueues[idx]),
                    leaf_vk_committment: all_circuit_types_committment_for_leaf_agg,
                    _marker: std::marker::PhantomData,
                },
                observable_output: LeafAggregationOutputData::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            initial_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: queue_wit}, 
            leaf_vks_committments_set: all_vk_committments.clone(),
            proof_witnesses: vec![],
            vk_encoding_witnesses: vec![],
        };

        // dbg!(&wit.closed_form_input.observable_input.initial_log_queue_state);

        let this_aggregation_subqueue = &leaf_layer_subqueues[idx];

        for (i, (req_idx, req)) in subset.into_iter().enumerate() {
            let vk_file_name = format!("vk_{}", req_idx);
            let proof_file_name = format!("proof_{}", req_idx);

            println!("Aggregating over {}", &proof_file_name);

            let mut vk_file_for_json = std::fs::File::open(format!("{}.json", &vk_file_name)).unwrap();
            let mut proof_file_for_json = std::fs::File::open(format!("{}.json", &proof_file_name)).unwrap();

            let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
            let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut proof_file_for_json).unwrap();

            dbg!(&proof.inputs[0]);

            assert_eq!(proof.inputs[0], req.public_input, "failed for req_idx = {}, i = {}, aggregation_idx = {}", req_idx, i, idx);
            assert_eq!(proof.inputs[0], this_aggregation_subqueue.witness[i].2.public_input, "failed for req_idx = {}, i = {}, aggregation_idx = {}", req_idx, i, idx);

            let vk_in_rns = VkInRns {
                vk: Some(vk.clone()),
                rns_params: &rns_params
            };
            let encoding = vk_in_rns.encode().unwrap();
            wit.vk_encoding_witnesses.push(encoding);
            wit.proof_witnesses.push(proof);
        }

        drop(this_aggregation_subqueue);

        if std::path::Path::new(&format!("{}.key", &proof_file_name)).exists() {
            continue;
        }

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
                padding_proof_public_input,
                padding_proof.clone(),
                g2_points.clone(),
            ),
        ).unwrap();

        // dbg!(&aggregated_public_input.get_value());
        // dbg!(&output_data.create_witness());

        let public_input_value = aggregated_public_input.get_value().unwrap();
        let result_observable_output = output_data.create_witness().unwrap();

        wit.closed_form_input.observable_output = result_observable_output.clone();

        let mut output_file_for_json = std::fs::File::create(format!("{}.json", &output_file_name)).unwrap();
        serde_json::to_writer(&mut output_file_for_json, &result_observable_output).unwrap();

        use crate::abstract_zksync_circuit::concrete_circuits::LeafAggregationCircuit;

        let circuit = LeafAggregationCircuit::new(
            Some(wit),
            (
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.to_vec(),
                padding_proof_public_input,
                padding_proof.clone(),
                g2_points.clone(),
            ),
            round_function.clone()
        );

        let (proof, vk) = if std::path::Path::new(&format!("rec_vk_{}_0.json", level)).exists() {
            println!("REUSING VERIFICATION KEY");
            let mut vk_file_for_json = std::fs::File::open(&format!("rec_vk_{}_0.json", level)).unwrap();
            let vk: VerificationKey<Bn256, LeafAggregationCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
            
            circuit_testing::prove_only_circuit_for_params::<
                Bn256, 
                _, 
                PlonkCsWidth4WithNextStepAndCustomGatesParams, 
                RescueTranscriptForRecursion<'_>
            >(circuit, Some(transcript_params), vk.clone()).unwrap()
        } else {
            circuit_testing::prove_and_verify_circuit_for_params::<
                Bn256, 
                _, 
                PlonkCsWidth4WithNextStepAndCustomGatesParams, 
                RescueTranscriptForRecursion<'_>
            >(circuit, Some(transcript_params)).unwrap()
        };

        let mut vk_file_for_bytes = std::fs::File::create(format!("{}.key", &vk_file_name)).unwrap();
        let mut vk_file_for_json = std::fs::File::create(format!("{}.json", &vk_file_name)).unwrap();

        let mut proof_file_for_bytes = std::fs::File::create(format!("{}.key", &proof_file_name)).unwrap();
        let mut proof_file_for_json = std::fs::File::create(format!("{}.json", &proof_file_name)).unwrap();

        vk.write(&mut vk_file_for_bytes).unwrap();
        proof.write(&mut proof_file_for_bytes).unwrap();

        serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
        serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

        assert_eq!(proof.inputs[0], public_input_value, "Public input diverged for circuit {}", idx);
    }

    level += 1;

    // NODES THAT AGGREGATE LEAFS

    println!("LEVEL {}: aggregating LEAFS by first layer of NODES", level);

    use crate::bellman::pairing::ff::ScalarEngine;
    use crate::bellman::pairing::ff::Field;

    let leaf_vk_committment = {
        let leaf_vk_file_name = "rec_vk_0_0.json";
        let mut vk_file_for_json = std::fs::File::open(&leaf_vk_file_name).unwrap();

        let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();

        let vk_in_rns = VkInRns {
            vk: Some(vk.clone()),
            rns_params: &rns_params
        };
        let encoding = vk_in_rns.encode().unwrap();
        let committment = simulate_variable_length_hash(&encoding, &round_function);

        committment
    };

    dbg!(leaf_vk_committment);

    let padding_aggregation = {
        let mut output_file_for_json = std::fs::File::open("rec_output_0_0.json").unwrap();
        let output: LeafAggregationOutputDataWitness<Bn256> = serde_json::from_reader(&mut output_file_for_json).unwrap();

        (
            output.pair_with_generator_x,
            output.pair_with_generator_y,
            output.pair_with_x_x,
            output.pair_with_x_y,
        )
    };

    let node_vk_file_name = "rec_vk_1_0.json";
    if std::path::Path::new(&node_vk_file_name).exists() == false {
        // generate setup

        let circuit = NodeAggregationCircuit::new(
            None,
            (
                level == 1,
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.to_vec(),
                padding_proof_public_input,
                padding_proof.clone(),
                padding_aggregation,
                g2_points.clone(),
            ),
            round_function.clone()
        );

        let vk = circuit_testing::create_vk::<
            Bn256, 
            _, 
            PlonkCsWidth4WithNextStepAndCustomGatesParams, 
        >(circuit).unwrap();

        let mut vk_file_for_json = std::fs::File::create(node_vk_file_name).unwrap();
        serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
    }

    let node_vk_committment = {
        let mut vk_file_for_json = std::fs::File::open(&node_vk_file_name).unwrap();

        let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();

        let vk_in_rns = VkInRns {
            vk: Some(vk.clone()),
            rns_params: &rns_params
        };
        let encoding = vk_in_rns.encode().unwrap();
        let committment = simulate_variable_length_hash(&encoding, &round_function);

        committment
    };

    use sync_vm::recursion::node_aggregation::*;

    

    let mut previous_sequence = leaf_layer_subqueues;
    let num_previous_level_proofs = previous_sequence.len();

    let mut merged = vec![];
    for chunk in previous_sequence.chunks(splitting_factor) {
        let mut first = chunk[0].clone();
        for second in chunk[1..].iter().cloned() {
            first = QueueSimulator::merge(first, second);
        }

        merged.push(first);
    }

    let mut leafs_index = 0;

    for (idx, subset) in merged.iter().cloned().enumerate() {
        // single case of leaf circuit VK
        let vk_file_name = format!("rec_vk_{}_0", level - 1);
        let mut vk_file_for_json = std::fs::File::open(format!("{}.json", &vk_file_name)).unwrap();
        let previous_level_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();

        let queue_wit: Vec<_> = subset.witness.iter().map(|el| {
            let (enc, prev_tail, el) = el.clone();
            let w = RecursiveProofQueryWitness {
                cicruit_type: el.circuit_type,
                closed_form_input_hash: el.public_input,
                _marker: std::marker::PhantomData
            };

            (enc, w, prev_tail)
        }).collect();

        // dbg!(&subset);

        let mut wit = NodeAggregationCircuitInstanceWitness::<Bn256> {
            closed_form_input: NodeAggregationInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                hidden_fsm_input: (),
                hidden_fsm_output: (),
                observable_input: NodeAggregationInputDataWitness {
                    initial_log_queue_state: take_queue_state_from_simulator(&subset),
                    leaf_vk_committment: leaf_vk_committment,
                    node_vk_committment: node_vk_committment,
                    all_circuit_types_committment_for_leaf: all_circuit_types_committment_for_leaf_agg,
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
        };

        for _ in 0..splitting_factor {
            if leafs_index >= num_previous_level_proofs {
                break;
            }
            let proof_file_name = format!("rec_proof_{}_{}", level - 1, leafs_index);
            let output_file_name = format!("rec_output_{}_{}", level - 1, leafs_index);

            if std::path::Path::new(&format!("{}.json", &proof_file_name)).exists() == false {
                break;
            }

            println!("Aggregating over {}", &proof_file_name);

            let mut proof_file_for_json = std::fs::File::open(format!("{}.json", &proof_file_name)).unwrap();
            let mut output_file_for_json = std::fs::File::open(format!("{}.json", &output_file_name)).unwrap();
            let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut proof_file_for_json).unwrap();
            let output: LeafAggregationOutputDataWitness<Bn256> = serde_json::from_reader(&mut output_file_for_json).unwrap();

            dbg!(&proof.inputs[0]);

            let vk_in_rns = VkInRns {
                vk: Some(previous_level_vk.clone()),
                rns_params: &rns_params
            };
            let encoding = vk_in_rns.encode().unwrap();
            wit.vk_encoding_witnesses.push(encoding);
            wit.proof_witnesses.push(proof);
            wit.leaf_aggregation_results.push(output);

            leafs_index += 1;
        }

        // make a new one

        let vk_file_name = format!("rec_vk_{}_{}", level, idx);
        let proof_file_name = format!("rec_proof_{}_{}", level, idx);
        let output_file_name = format!("rec_output_{}_{}", level, idx);

        dbg!(&proof_file_name);

        if std::path::Path::new(&format!("{}.key", &proof_file_name)).exists() {
            println!("Proof exists");
            continue
        }

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let (aggregated_public_input, leaf_aggregation_output_data, node_aggregation_output_data, output_data) = aggregate_at_node_level_entry_point::<_, _, _, _, _, true>(
            &mut cs,
            Some(wit.clone()),
            &round_function,
            (
                level == 1,
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.clone(),
                padding_proof_public_input,
                padding_proof.clone(),
                padding_aggregation,
                g2_points.clone(),
            ),
        ).unwrap();

        // dbg!(&aggregated_public_input.get_value());
        dbg!(&output_data.create_witness());

        let public_input_value = aggregated_public_input.get_value().unwrap();
        let result_observable_output = output_data.create_witness().unwrap();

        wit.closed_form_input.observable_output = result_observable_output.clone();

        let mut output_file_for_json = std::fs::File::create(format!("{}.json", &output_file_name)).unwrap();
        serde_json::to_writer(&mut output_file_for_json, &result_observable_output).unwrap();

        use crate::abstract_zksync_circuit::concrete_circuits::NodeAggregationCircuit;

        let circuit = NodeAggregationCircuit::new(
            Some(wit),
            (
                level == 1,
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.to_vec(),
                padding_proof_public_input,
                padding_proof.clone(),
                padding_aggregation,
                g2_points.clone(),
            ),
            round_function.clone()
        );

        let (proof, vk) = if std::path::Path::new(&format!("rec_vk_{}_0.json", level)).exists() {
            println!("REUSING VERIFICATION KEY");
            let mut vk_file_for_json = std::fs::File::open(&format!("rec_vk_{}_0.json", level)).unwrap();
            let vk: VerificationKey<Bn256, NodeAggregationCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
            
            circuit_testing::prove_only_circuit_for_params::<
                Bn256, 
                _, 
                PlonkCsWidth4WithNextStepAndCustomGatesParams, 
                RescueTranscriptForRecursion<'_>
            >(circuit, Some(transcript_params), vk.clone()).unwrap()
        } else {
            circuit_testing::prove_and_verify_circuit_for_params::<
                Bn256, 
                _, 
                PlonkCsWidth4WithNextStepAndCustomGatesParams, 
                RescueTranscriptForRecursion<'_>
            >(circuit, Some(transcript_params)).unwrap()
        };

        dbg!(&proof.inputs[0]);

        let mut vk_file_for_bytes = std::fs::File::create(format!("{}.key", &vk_file_name)).unwrap();
        let mut vk_file_for_json = std::fs::File::create(format!("{}.json", &vk_file_name)).unwrap();

        let mut proof_file_for_bytes = std::fs::File::create(format!("{}.key", &proof_file_name)).unwrap();
        let mut proof_file_for_json = std::fs::File::create(format!("{}.json", &proof_file_name)).unwrap();

        vk.write(&mut vk_file_for_bytes).unwrap();
        proof.write(&mut proof_file_for_bytes).unwrap();

        serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
        serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

        assert_eq!(proof.inputs[0], public_input_value, "Public input diverged for circuit {}", idx);
    }

    level += 1;

    // NODES OVER NODES

    println!("LEVEL {}: aggregating NODES by NODES", level);

    previous_sequence = merged;
    let num_previous_level_proofs = previous_sequence.len();

    let mut merged = vec![];
    for chunk in previous_sequence.chunks(splitting_factor) {
        let mut first = chunk[0].clone();
        for second in chunk[1..].iter().cloned() {
            first = QueueSimulator::merge(first, second);
        }

        merged.push(first);
    }

    let mut leafs_index = 0;

    for (idx, subset) in merged.iter().cloned().enumerate() {
        // single case of leaf circuit VK
        let vk_file_name = format!("rec_vk_{}_0", level - 1);
        let mut vk_file_for_json = std::fs::File::open(format!("{}.json", &vk_file_name)).unwrap();
        let previous_level_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();

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
                    leaf_vk_committment: leaf_vk_committment,
                    node_vk_committment: node_vk_committment,
                    all_circuit_types_committment_for_leaf: all_circuit_types_committment_for_leaf_agg,
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
        };

        for _ in 0..splitting_factor {
            if leafs_index >= num_previous_level_proofs {
                break;
            }
            let proof_file_name = format!("rec_proof_{}_{}", level - 1, leafs_index);
            let output_file_name = format!("rec_output_{}_{}", level - 1, leafs_index);

            if std::path::Path::new(&format!("{}.json", &proof_file_name)).exists() == false {
                break;
            }

            println!("Aggregating over {}", &proof_file_name);

            let mut proof_file_for_json = std::fs::File::open(format!("{}.json", &proof_file_name)).unwrap();
            let mut output_file_for_json = std::fs::File::open(format!("{}.json", &output_file_name)).unwrap();
            let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut proof_file_for_json).unwrap();
            let output: NodeAggregationOutputDataWitness<Bn256> = serde_json::from_reader(&mut output_file_for_json).unwrap();

            dbg!(&proof.inputs[0]);

            let vk_in_rns = VkInRns {
                vk: Some(previous_level_vk.clone()),
                rns_params: &rns_params
            };
            let encoding = vk_in_rns.encode().unwrap();
            wit.vk_encoding_witnesses.push(encoding);
            wit.proof_witnesses.push(proof);
            wit.node_aggregation_results.push(output);

            leafs_index += 1;
        }

        // make a new one

        let vk_file_name = format!("rec_vk_{}_{}", level, idx);
        let proof_file_name = format!("rec_proof_{}_{}", level, idx);
        let output_file_name = format!("rec_output_{}_{}", level, idx);

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let (aggregated_public_input, leaf_aggregation_output_data, node_aggregation_output_data, output_data) = aggregate_at_node_level_entry_point::<_, _, _, _, _, true>(
            &mut cs,
            Some(wit.clone()),
            &round_function,
            (
                level == 1,
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.clone(),
                padding_proof_public_input,
                padding_proof.clone(),
                padding_aggregation,
                g2_points.clone(),
            ),
        ).unwrap();

        // dbg!(&aggregated_public_input.get_value());
        // dbg!(&output_data.create_witness());

        let public_input_value = aggregated_public_input.get_value().unwrap();
        let result_observable_output = output_data.create_witness().unwrap();

        wit.closed_form_input.observable_output = result_observable_output.clone();

        dbg!(&wit);
        dbg!(&public_input_value);

        dbg!(&proof_file_name);

        if std::path::Path::new(&format!("{}.key", &proof_file_name)).exists() {
            println!("Proof exists");
            continue
        }

        let mut output_file_for_json = std::fs::File::create(format!("{}.json", &output_file_name)).unwrap();
        serde_json::to_writer(&mut output_file_for_json, &result_observable_output).unwrap();

        use crate::abstract_zksync_circuit::concrete_circuits::NodeAggregationCircuit;

        let circuit = NodeAggregationCircuit::new(
            Some(wit),
            (
                level == 1,
                splitting_factor,
                rns_params.clone(),
                aggregation_params.clone(),
                padding_vk_committment,
                padding_vk_encoding.to_vec(),
                padding_proof_public_input,
                padding_proof.clone(),
                padding_aggregation,
                g2_points.clone(),
            ),
            round_function.clone()
        );

        let (proof, vk) = if std::path::Path::new(&format!("rec_vk_{}_0.json", level)).exists() {
            println!("REUSING VERIFICATION KEY");
            let mut vk_file_for_json = std::fs::File::open(&format!("rec_vk_{}_0.json", level)).unwrap();
            let vk: VerificationKey<Bn256, NodeAggregationCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
            
            circuit_testing::prove_only_circuit_for_params::<
                Bn256, 
                _, 
                PlonkCsWidth4WithNextStepAndCustomGatesParams, 
                RescueTranscriptForRecursion<'_>
            >(circuit, Some(transcript_params), vk.clone()).unwrap()
        } else {
            circuit_testing::prove_and_verify_circuit_for_params::<
                Bn256, 
                _, 
                PlonkCsWidth4WithNextStepAndCustomGatesParams, 
                RescueTranscriptForRecursion<'_>
            >(circuit, Some(transcript_params)).unwrap()
        };

        let mut vk_file_for_bytes = std::fs::File::create(format!("{}.key", &vk_file_name)).unwrap();
        let mut vk_file_for_json = std::fs::File::create(format!("{}.json", &vk_file_name)).unwrap();

        let mut proof_file_for_bytes = std::fs::File::create(format!("{}.key", &proof_file_name)).unwrap();
        let mut proof_file_for_json = std::fs::File::create(format!("{}.json", &proof_file_name)).unwrap();

        vk.write(&mut vk_file_for_bytes).unwrap();
        proof.write(&mut proof_file_for_bytes).unwrap();

        serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
        serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

        assert_eq!(proof.inputs[0], public_input_value, "Public input diverged for circuit {}", idx);
    }

    // now feed it into the scheduler

    let vk_file_name = format!("rec_vk_{}_{}", level, 0);
    let proof_file_name = format!("rec_proof_{}_{}", level, 0);
    let output_file_name = format!("rec_output_{}_{}", level, 0);

    use crate::abstract_zksync_circuit::concrete_circuits::NodeAggregationCircuit;

    let mut vk_file_for_json = std::fs::File::open(format!("{}.json", &vk_file_name)).unwrap();
    let mut proof_file_for_json = std::fs::File::open(format!("{}.json", &proof_file_name)).unwrap();
    let mut output_file_for_json = std::fs::File::open(format!("{}.json", &output_file_name)).unwrap();

    let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
    let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut proof_file_for_json).unwrap();
    let output: NodeAggregationOutputDataWitness<Bn256> = serde_json::from_reader(&mut output_file_for_json).unwrap();

    dbg!(&proof.inputs[0]);

    scheduler_partial_input.aggregation_result = output;
    scheduler_partial_input.proof_witnesses = vec![proof];
    let vk_in_rns = VkInRns {
        vk: Some(vk.clone()),
        rns_params: &rns_params
    };
    let encoding = vk_in_rns.encode().unwrap();
    scheduler_partial_input.vk_encoding_witnesses = vec![encoding];

    scheduler_partial_input.previous_block_aux_hash = Bytes32Witness::from_bytes_array(&previous_aux_hash);
    scheduler_partial_input.previous_block_meta_hash = Bytes32Witness::from_bytes_array(&previous_meta_hash);

    // now also all the key sets
    use crate::bellman::{PrimeField, PrimeFieldRepr};
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;

    dbg!(&all_circuit_types_committment_for_leaf_agg);
    dbg!(&leaf_vk_committment);
    dbg!(&node_vk_committment);

    let mut buffer = vec![];
    all_circuit_types_committment_for_leaf_agg.into_repr().write_be(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_partial_input.all_different_circuits_keys_hash = Bytes32Witness::from_bytes_array(&all_keys);

    let mut buffer = vec![];
    leaf_vk_committment.into_repr().write_be(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_partial_input.recursion_leaf_verification_key_hash = Bytes32Witness::from_bytes_array(&all_keys);

    let mut buffer = vec![];
    node_vk_committment.into_repr().write_be(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_partial_input.recursion_node_verification_key_hash = Bytes32Witness::from_bytes_array(&all_keys);

    use crate::abstract_zksync_circuit::concrete_circuits::SchedulerCircuit;

    let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
    let _ = scheduler_function(
        &mut cs, 
        Some(scheduler_partial_input.clone()), 
        &round_function, 
        (
            64,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding,
            padding_proof.clone(),
            g2_points.clone(),
        )
    );

    let circuit = SchedulerCircuit::new(
        Some(scheduler_partial_input),
        (
            64,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding.to_vec(),
            padding_proof.clone(),
            g2_points.clone(),
        ),
        round_function.clone()
    );

    let (proof, vk) = circuit_testing::prove_and_verify_circuit_for_params::<
        Bn256, 
        _, 
        PlonkCsWidth4WithNextStepAndCustomGatesParams, 
        RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>
    >(circuit, None).unwrap(); 

    let mut vk_file_for_bytes = std::fs::File::create("scheduler_vk.key").unwrap();
    let mut vk_file_for_json = std::fs::File::create("scheduler_vk.json").unwrap();

    let mut proof_file_for_bytes = std::fs::File::create("scheduler_proof.key").unwrap();
    let mut proof_file_for_json = std::fs::File::create("scheduler_proof.json").unwrap();

    vk.write(&mut vk_file_for_bytes).unwrap();
    proof.write(&mut proof_file_for_bytes).unwrap();

    serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
    serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

    println!("Done");
}
