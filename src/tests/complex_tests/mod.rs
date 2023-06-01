pub mod utils;
pub mod serialize_utils;

// pub mod invididual_debugs;

use std::collections::{HashMap, VecDeque};

use super::*;
use crate::entry_point::{create_out_of_circuit_global_context};
use crate::compute_setups::*;

use crate::ethereum_types::*;
use crate::external_calls::base_layer_proof_config;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::utils::*;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use crate::boojum::cs::implementations::pow::NoPow;
use crate::boojum::cs::implementations::prover::ProofConfig;
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::ZkSyncLeafLayerRecursiveCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::scheduler::SchedulerCircuit;
use crate::zk_evm::abstractions::*;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::*;
use crate::zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use crate::zk_evm::witness_trace::VmWitnessTracer;
use crate::zk_evm::GenericNoopTracer;
use zkevm_assembly::Assembly;
use crate::zk_evm::testing::storage::InMemoryStorage;
use crate::zkevm_circuits::scheduler::input::SchedulerCircuitInstanceWitness;
use crate::toolset::{create_tools, GeometryConfig};
use utils::{read_test_artifact, TestArtifact};
use crate::witness::tree::{ZKSyncTestingTree, BinarySparseStorageTree};
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::*;
use crate::prover_utils::*;

const ACCOUNT_CODE_STORAGE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x02,
]);

const KNOWN_CODE_HASHES_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x04,
]);


#[test]
fn basic_test() {
    let test_artifact = read_test_artifact("basic_test");
    run_and_try_create_witness_inner(test_artifact, 20000);
    // run_and_try_create_witness_inner(test_artifact, 16);
}

use blake2::Blake2s256;
use crate::witness::tree::ZkSyncStorageLeaf;

pub(crate) fn save_predeployed_contracts(storage: &mut InMemoryStorage, tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>, contracts: &HashMap<Address, Vec<[u8; 32]>>) {
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

            println!("Have address {:?} with code hash {:x}", address, U256::from(hash));

            vec![
                (0, ACCOUNT_CODE_STORAGE_ADDRESS, U256::from_big_endian(address.as_bytes()), U256::from(hash)),
                (0, KNOWN_CODE_HASHES_ADDRESS, U256::from(hash), U256::from(1u64))
            ]

        })
        .flatten()
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

use crate::witness::full_block_artifact::*;
use crate::boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;

pub(crate) fn generate_base_layer(
    mut test_artifact: TestArtifact, 
    cycle_limit: usize,
    geometry: GeometryConfig,
) -> (
    BlockBasicCircuits<GoldilocksField, ZkSyncDefaultRoundFunction>, 
    BlockBasicCircuitsPublicInputs<GoldilocksField>,
    BlockBasicCircuitsPublicCompactFormsWitnesses<GoldilocksField>,
    SchedulerCircuitInstanceWitness<GoldilocksField, CircuitGoldilocksPoseidon2Sponge, GoldilocksExt2>,
) {
    use crate::zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

    let round_function = ZkSyncDefaultRoundFunction::default();

    use crate::external_calls::run;
    use crate::toolset::GeometryConfig;

    let mut storage_impl = InMemoryStorage::new();
    let mut tree = ZKSyncTestingTree::empty();

    test_artifact.entry_point_address = *zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;
    
    let predeployed_contracts = test_artifact.predeployed_contracts.clone().into_iter().chain(Some((test_artifact.entry_point_address, test_artifact.entry_point_code.clone()))).collect::<HashMap<_,_>>();
    save_predeployed_contracts(&mut storage_impl, &mut tree, &predeployed_contracts);

    let used_bytecodes = HashMap::from_iter(
        test_artifact.predeployed_contracts.iter().map(|(_,bytecode)| (bytecode_to_code_hash(&bytecode).unwrap().into(), bytecode.clone()))
        .chain(Some(test_artifact.default_account_code.clone()).map(|bytecode|(bytecode_to_code_hash(&bytecode).unwrap().into(), bytecode.clone())))
    );
    for (k, _) in used_bytecodes.iter() {
        println!("Have bytecode hash 0x{:x}", k);
    }
    use sha3::{Digest, Keccak256};

    let previous_enumeration_index = tree.next_enumeration_index();
    let previous_root = tree.root();
    // simualate content hash

    let mut hasher = Keccak256::new();
    hasher.update(&previous_enumeration_index.to_be_bytes());
    hasher.update(&previous_root);
    hasher.update(&0u64.to_be_bytes()); // porter shard
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

    let default_account_codehash = bytecode_to_code_hash(&test_artifact.default_account_code).unwrap();
    let default_account_codehash = U256::from_big_endian(&default_account_codehash);

    println!("Default AA code hash 0x{:x}", default_account_codehash);

    // let (basic_block_circuits, basic_block_circuits_inputs, mut scheduler_partial_input) = run(
    let (
        basic_block_circuits, 
        basic_block_circuits_inputs,
        closed_form_inputs,
        scheduler_partial_input,
        aux_data,
    ) = run(
        Address::zero(),
        test_artifact.entry_point_address,
        test_artifact.entry_point_code,
        vec![],
        false,
        default_account_codehash,
        used_bytecodes,
        vec![],
        cycle_limit,
        round_function.clone(),
        geometry,
        storage_impl,
        &mut tree
    );

    (basic_block_circuits, basic_block_circuits_inputs, closed_form_inputs, scheduler_partial_input)
}

fn run_and_try_create_witness_inner(test_artifact: TestArtifact, cycle_limit: usize) {
    use crate::external_calls::run;
    use crate::toolset::GeometryConfig;

    let geometry = GeometryConfig {
        cycles_per_vm_snapshot: 1,
        // cycles_per_vm_snapshot: 1024,
        cycles_per_ram_permutation: 1024,
        cycles_per_code_decommitter: 256,
        cycles_per_storage_application: 4,
        cycles_per_keccak256_circuit: 7,
        cycles_per_sha256_circuit: 7,
        cycles_per_ecrecover_circuit: 2,
        cycles_code_decommitter_sorter: 512,
        cycles_per_log_demuxer: 16,
        cycles_per_storage_sorter: 16,
        cycles_per_events_or_l1_messages_sorter: 4,

        limit_for_initial_writes_pubdata_hasher: 16,
        limit_for_repeated_writes_pubdata_hasher: 16,
        limit_for_l1_messages_merklizer: 32,
        limit_for_l1_messages_pudata_hasher: 32,
    };

    let geometry = crate::geometry_config::get_geometry_config();

    // let (basic_block_circuits, basic_block_circuits_inputs, mut scheduler_partial_input) = run(
    let (
        basic_block_circuits, 
        basic_block_circuits_inputs,
        per_circuit_closed_form_inputs,
        scheduler_partial_input,
    ) = generate_base_layer(
        test_artifact,
        cycle_limit,
        geometry
    );

    let _num_vm_circuits = basic_block_circuits.main_vm_circuits.len();

    
    for (idx, (el, input_value)) in basic_block_circuits.clone().into_flattened_set().into_iter().zip(basic_block_circuits_inputs.clone().into_flattened_set().into_iter()).enumerate() {
        continue;

        let descr = el.short_description();
        println!("Doing {}: {}", idx, descr);


        match &el {
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
                // let witness = inner.clone_witness().unwrap();
                // dbg!(&witness.closed_form_input);
                // dbg!(witness.closed_form_input.start_flag);
                // dbg!(witness.closed_form_input.completion_flag);
            },
            _ => {
                continue;
            }
        }

        base_test_circuit(el);
    }

    let worker = Worker::new_with_num_threads(8);

    let mut previous_circuit_type = 0;

    let proof_config = base_layer_proof_config();
    let mut instance_idx = 0;

    let mut setup_data = None;

    let mut source = LocalFileDataSource;
    use crate::data_source::*;

    for (idx, el) in basic_block_circuits.clone().into_flattened_set().into_iter().enumerate() {
        let descr = el.short_description();
        println!("Doing {}: {}", idx, descr);

        if el.numeric_circuit_type() != previous_circuit_type {
            instance_idx = 0;
        }

        if let Ok(proof) = source.get_base_layer_proof(el.numeric_circuit_type(), instance_idx) {
            if instance_idx == 0 {
                source.set_base_layer_padding_proof(
                    proof,
                ).unwrap();
            }

            instance_idx += 1;
            continue;
        }

        if el.numeric_circuit_type() != previous_circuit_type || setup_data.is_none() {
            let (
                setup_base,
                setup,
                vk,
                setup_tree,
                vars_hint,
                wits_hint,
                finalization_hint
            ) = create_base_layer_setup_data(el.clone(), &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);

            source.set_base_layer_vk(
                ZkSyncBaseLayerVerificationKey::from_inner(el.numeric_circuit_type(), vk.clone())
            ).unwrap();
            source.set_base_layer_finalization_hint(
                ZkSyncBaseLayerFinalizationHint::from_inner(el.numeric_circuit_type(), finalization_hint.clone())
            ).unwrap();

            setup_data = Some((
                setup_base,
                setup,
                vk,
                setup_tree,
                vars_hint,
                wits_hint,
                finalization_hint
            ));

            previous_circuit_type = el.numeric_circuit_type();
        }

        println!("Proving!");
        let now = std::time::Instant::now();

        let (
            setup_base,
            setup,
            vk,
            setup_tree,
            vars_hint,
            wits_hint,
            finalization_hint
        ) = setup_data.as_ref().unwrap();

        let proof = prove_base_layer_circuit::<NoPow>(
            el.clone(), 
            &worker, 
            proof_config.clone(), 
            &setup_base, 
            &setup, 
            &setup_tree, 
            &vk, 
            &vars_hint, 
            &wits_hint, 
            &finalization_hint
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_base_layer_proof::<NoPow>(
            &el, 
            &proof, 
            &vk
        );

        assert!(is_valid);

        if instance_idx == 0 {
            source.set_base_layer_padding_proof(
                ZkSyncBaseLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
            ).unwrap();
        }

        source.set_base_layer_proof(
            instance_idx,
            ZkSyncBaseLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
        ).unwrap();

        instance_idx += 1;
    }

    let round_function = ZkSyncDefaultRoundFunction::default();

    println!("Preparing recursion queues");

    let recursion_queues = basic_block_circuits_inputs.into_recursion_queues(
        per_circuit_closed_form_inputs, 
        &round_function
    );

    println!("Assembling keys");

    let mut proofs = vec![];
    let mut padding_proofs = vec![];
    let mut verification_keys = vec![];

    for (circuit_id, _, inputs) in recursion_queues.iter() {
        let circuit_type = *circuit_id as u8;
        let mut proofs_for_circuit_type = vec![];
        for idx in 0..inputs.len() {
            let proof = source.get_base_layer_proof(circuit_type, idx).unwrap();
            proofs_for_circuit_type.push(proof);
        }

        let proof = source.get_base_layer_padding_proof(circuit_type).unwrap();
        padding_proofs.push(proof);

        let vk = source.get_base_layer_vk(circuit_type).unwrap();
        verification_keys.push(vk);

        proofs.push(proofs_for_circuit_type);
    }

    println!("Computing leaf vks");

    for base_circuit_type in (BaseLayerCircuitType::VM as u8)..=(BaseLayerCircuitType::L1MessagesHasher as u8) {
        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(BaseLayerCircuitType::from_numeric_value(base_circuit_type));

        if source.get_recursion_layer_vk(recursive_circuit_type as u8).is_err() {
            println!("Computing leaf layer VK for type {:?}", recursive_circuit_type);
            use crate::zkevm_circuits::recursion::leaf_layer::input::*;
            let input = RecursionLeafInput::placeholder_witness();
            let vk = source.get_base_layer_vk(base_circuit_type).unwrap();

            use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
            let witness = RecursionLeafInstanceWitness{
                input,
                vk_witness: vk.clone().into_inner(),
                queue_witness: FullStateCircuitQueueRawWitness { elements: VecDeque::new() },
                proof_witnesses: VecDeque::new(),
            };
    
            let padding_proof = source.get_base_layer_padding_proof(base_circuit_type).unwrap();
            use crate::zkevm_circuits::recursion::leaf_layer::LeafLayerRecursionConfig;
            let config = LeafLayerRecursionConfig {
                proof_config: base_layer_proof_config(),
                vk_fixed_parameters: vk.into_inner().fixed_parameters,
                capacity: RECURSION_ARITY,
                padding_proof: padding_proof.into_inner(),
            };
            let circuit = ZkSyncLeafLayerRecursiveCircuit {
                base_layer_circuit_type: BaseLayerCircuitType::from_numeric_value(base_circuit_type),
                witness: witness,
                config: config,
                transcript_params: (),
                _marker: std::marker::PhantomData,
            };

            let circuit = ZkSyncRecursiveLayerCircuit::leaf_circuit_from_base_type(
                BaseLayerCircuitType::from_numeric_value(base_circuit_type),
                circuit
            );
    
            let (
                _setup_base,
                _setup,
                vk,
                _setup_tree,
                _vars_hint,
                _wits_hint,
                finalization_hint
            ) = create_recursive_layer_setup_data(circuit, &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);
    
            let finalization_hint = ZkSyncRecursionLayerFinalizationHint::from_inner(recursive_circuit_type as u8, finalization_hint);
            source.set_recursion_layer_finalization_hint(finalization_hint).unwrap();
            let vk = ZkSyncRecursionLayerVerificationKey::from_inner(recursive_circuit_type as u8, vk);
            source.set_recursion_layer_vk(vk).unwrap();
        }
    }

    println!("Computing leaf params");
    use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
    use crate::witness::recursive_aggregation::compute_leaf_params;
    let mut leaf_vk_commits = vec![];

    for circuit_type in (BaseLayerCircuitType::VM as u8)..=(BaseLayerCircuitType::L1MessagesHasher as u8) {
        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(BaseLayerCircuitType::from_numeric_value(circuit_type));
        let base_vk = source.get_base_layer_vk(circuit_type).unwrap();
        let leaf_vk = source.get_recursion_layer_vk(recursive_circuit_type as u8).unwrap();
        let params = compute_leaf_params(
            circuit_type,
            base_vk,
            leaf_vk
        );
        leaf_vk_commits.push((circuit_type, params));
    }

    let mut all_leaf_aggregations = vec![];
    use crate::witness::recursive_aggregation::create_leaf_witnesses;

    println!("Creating leaf aggregation circuits");

    let mut all_closed_form_inputs_for_scheduler = vec![];

    for (((subset, proofs),
        padding_proof),
        vk) in recursion_queues.clone().into_iter()
            .zip(proofs.into_iter())
            .zip(padding_proofs.iter().cloned())
            .zip(verification_keys.iter().cloned()) 
        {
            let param = leaf_vk_commits.iter().find(|el| el.0 == subset.0 as u8).cloned().unwrap();
            let (aggregations, _closed_form_inputs) = create_leaf_witnesses(subset, proofs, padding_proof, vk, param);
            all_leaf_aggregations.push(aggregations);
            all_closed_form_inputs_for_scheduler.extend(_closed_form_inputs);
        }

    println!("Proving leaf aggregation circuits");

    let mut previous_circuit_type = 0;

    use circuit_definitions::circuit_definitions::recursion_layer::*;

    for aggregations_for_circuit_type in all_leaf_aggregations.iter() {
        let mut instance_idx = 0;
        let mut setup_data = None;
        for (idx, (_, _, el)) in aggregations_for_circuit_type.iter().enumerate() {
            let descr = el.short_description();
            println!("Doing {}: {}", idx, descr);

            // test_recursive_circuit(el.clone());
            // println!("Circuit is satisfied");

            if let Ok(proof) = source.get_leaf_layer_proof(el.numeric_circuit_type(), instance_idx) {
                if instance_idx == 0 {
                    source.set_recursion_layer_padding_proof(
                        proof,
                    ).unwrap();
                }

                instance_idx += 1;
                continue;
            }

            if el.numeric_circuit_type() != previous_circuit_type || setup_data.is_none() {
                let (
                    setup_base,
                    setup,
                    vk,
                    setup_tree,
                    vars_hint,
                    wits_hint,
                    finalization_hint
                ) = create_recursive_layer_setup_data(el.clone(), &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);

                source.set_recursion_layer_vk(
                    ZkSyncRecursionLayerVerificationKey::from_inner(el.numeric_circuit_type(), vk.clone())
                ).unwrap();
                source.set_recursion_layer_finalization_hint(
                    ZkSyncRecursionLayerFinalizationHint::from_inner(el.numeric_circuit_type(), finalization_hint.clone())
                ).unwrap();

                setup_data = Some((
                    setup_base,
                    setup,
                    vk,
                    setup_tree,
                    vars_hint,
                    wits_hint,
                    finalization_hint
                ));

                previous_circuit_type = el.numeric_circuit_type();
            }

            println!("Proving!");
            let now = std::time::Instant::now();

            let (
                setup_base,
                setup,
                vk,
                setup_tree,
                vars_hint,
                wits_hint,
                finalization_hint
            ) = setup_data.as_ref().unwrap();

            let proof = prove_recursion_layer_circuit::<NoPow>(
                el.clone(), 
                &worker, 
                proof_config.clone(), 
                &setup_base, 
                &setup, 
                &setup_tree, 
                &vk, 
                &vars_hint, 
                &wits_hint, 
                &finalization_hint
            );

            println!("Proving is DONE, taken {:?}", now.elapsed());

            let is_valid = verify_recursion_layer_proof::<NoPow>(
                &el, 
                &proof, 
                &vk
            );

            assert!(is_valid);

            if instance_idx == 0 {
                source.set_recursion_layer_padding_proof(
                    ZkSyncRecursionLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
                ).unwrap();

                // any circuit type would work
                if el.numeric_circuit_type() == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8 {
                    source.set_recursion_layer_leaf_padding_proof(
                        ZkSyncRecursionLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
                    ).unwrap();
                }
            }

            source.set_leaf_layer_proof(
                instance_idx,
                ZkSyncRecursionLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
            ).unwrap();

            instance_idx += 1;
        }
    }

    // do that once in setup-mode only

    if source.get_recursion_layer_node_vk().is_err() {
        use crate::zkevm_circuits::recursion::node_layer::input::*;
        let input = RecursionNodeInput::placeholder_witness();
        let vk = source.get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8).unwrap();
        let witness = RecursionNodeInstanceWitness{
            input,
            vk_witness: vk.clone().into_inner(),
            split_points: VecDeque::new(),
            proof_witnesses: VecDeque::new(),
        };

        let padding_proof = source.get_recursion_layer_leaf_padding_proof().unwrap();
        use circuit_definitions::circuit_definitions::recursion_layer::node_layer::ZkSyncNodeLayerRecursiveCircuit;
        use crate::zkevm_circuits::recursion::node_layer::NodeLayerRecursionConfig;
        let config = NodeLayerRecursionConfig {
            proof_config: base_layer_proof_config(),
            vk_fixed_parameters: vk.into_inner().fixed_parameters,
            leaf_layer_capacity: RECURSION_ARITY,
            node_layer_capacity: RECURSION_ARITY,
            padding_proof: padding_proof.into_inner(),
        };
        let circuit = ZkSyncNodeLayerRecursiveCircuit {
            witness: witness,
            config: config,
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(circuit);

        let (
            _setup_base,
            _setup,
            vk,
            _setup_tree,
            _vars_hint,
            _wits_hint,
            finalization_hint
        ) = create_recursive_layer_setup_data(circuit, &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);

        let finalization_hint = ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint);
        source.set_recursion_layer_node_finalization_hint(finalization_hint).unwrap();
        let vk = ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk);
        source.set_recursion_layer_node_vk(vk).unwrap();
    }

    let node_vk = source.get_recursion_layer_node_vk().unwrap();
    use crate::witness::recursive_aggregation::compute_node_vk_commitment;
    let node_vk_commitment = compute_node_vk_commitment(
        node_vk
    );

    let mut final_node_proofs = HashMap::new();

    println!("Continuing into nodes leaf aggregation circuits");
    for per_circuit_subtree in all_leaf_aggregations.into_iter() {
        let mut depth = 0;
        let mut next_aggregations = per_circuit_subtree;

        let base_circuit_type = next_aggregations[0].0 as u8;
        let circuit_type_enum = BaseLayerCircuitType::from_numeric_value(base_circuit_type);
        println!("Continuing into node aggregation for circuit type {:?}", circuit_type_enum);

        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(circuit_type_enum);

        use crate::witness::recursive_aggregation::create_node_witnesses;
        let vk = if depth == 0 {
            source.get_recursion_layer_vk(recursive_circuit_type as u8).unwrap()
        } else {
            source.get_recursion_layer_node_vk().unwrap()
        };

        let mut setup_data = None; 

        loop {
            println!("Working on depth {}", depth);
            let mut proofs = vec![];
            for idx in 0..next_aggregations.len() {
                let proof = if depth == 0 {
                    source.get_leaf_layer_proof(recursive_circuit_type as u8, idx).unwrap()
                } else {
                    source.get_node_layer_proof(recursive_circuit_type as u8, depth, idx).unwrap()
                };

                proofs.push(proof);
            }
            let padding_proof = if depth == 0 {
                let padding_proof_leaf = source.get_recursion_layer_leaf_padding_proof().unwrap();
                padding_proof_leaf
            } else {
                let padding_proof_node = source.get_recursion_layer_node_padding_proof().unwrap();
                padding_proof_node
            };
            next_aggregations = create_node_witnesses(
                next_aggregations,
                proofs,
                padding_proof,
                vk.clone(),
                node_vk_commitment,
                &leaf_vk_commits,
            );

            for (idx, (_, _, el)) in next_aggregations.iter().enumerate() {

                // test_recursive_circuit(el.clone());
                // println!("Circuit is satisfied");

                if let Ok(proof) = source.get_node_layer_proof(
                    recursive_circuit_type as u8,
                    depth,
                    idx,
                ) {
                    if idx == 0 {
                        source.set_recursion_layer_node_padding_proof(
                            proof,
                        ).unwrap();
                    }
                    continue;
                }

                if setup_data.is_none() {
                    let (
                        setup_base,
                        setup,
                        vk,
                        setup_tree,
                        vars_hint,
                        wits_hint,
                        finalization_hint
                    ) = create_recursive_layer_setup_data(el.clone(), &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);
    
                    // // we did it above
                    // source.set_recursion_layer_node_vk(ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk)).unwrap();
                    // source.set_recursion_layer_node_finalization_hint(ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint)).unwrap();
    
                    setup_data = Some((
                        setup_base,
                        setup,
                        vk,
                        setup_tree,
                        vars_hint,
                        wits_hint,
                        finalization_hint
                    ));
                }

                // prove
                println!("Proving!");
                let now = std::time::Instant::now();
    
                let (
                    setup_base,
                    setup,
                    vk,
                    setup_tree,
                    vars_hint,
                    wits_hint,
                    finalization_hint
                ) = setup_data.as_ref().unwrap();

                let proof = prove_recursion_layer_circuit::<NoPow>(
                    el.clone(), 
                    &worker, 
                    proof_config.clone(), 
                    &setup_base, 
                    &setup, 
                    &setup_tree, 
                    &vk, 
                    &vars_hint, 
                    &wits_hint, 
                    &finalization_hint
                );
    
                println!("Proving is DONE, taken {:?}", now.elapsed());
    
                let is_valid = verify_recursion_layer_proof::<NoPow>(
                    &el, 
                    &proof, 
                    &vk
                );
    
                assert!(is_valid);
    
                if idx == 0 {
                    source.set_recursion_layer_node_padding_proof(
                        ZkSyncRecursionLayerProof::NodeLayerCircuit(proof.clone()),
                    ).unwrap();
                }
    
                source.set_node_layer_proof(
                    recursive_circuit_type as u8,
                    depth,
                    idx,
                    ZkSyncRecursionLayerProof::NodeLayerCircuit(proof.clone()),
                ).unwrap();
            }

            if next_aggregations.len() == 1 {
                // end

                let proof = source.get_node_layer_proof(
                    recursive_circuit_type as u8,
                    depth,
                    0,
                ).unwrap();

                final_node_proofs.insert(base_circuit_type, proof);
                break;
            }


            depth += 1;
        }
    }

    let mut keys: Vec<_> = final_node_proofs.keys().into_iter().cloned().collect();
    keys.sort();

    let mut scheduler_proofs = vec![];
    for key in keys.into_iter() {
        let v = final_node_proofs.remove(&key).unwrap().into_inner();
        scheduler_proofs.push(v);
    }

    let mut scheduler_witness = scheduler_partial_input;
    // we need to reassign block specific data, and proofs

    // node VK
    let node_vk = source.get_recursion_layer_node_vk().unwrap().into_inner();
    scheduler_witness.node_layer_vk_witness = node_vk.clone();
    // leaf params
    let leaf_layer_params = leaf_vk_commits.iter().map(|el| {
        el.1.clone()
    }).collect::<Vec<_>>().try_into().unwrap();
    scheduler_witness.leaf_layer_parameters = leaf_layer_params;
    // proofs
    scheduler_witness.proof_witnesses = scheduler_proofs.into();

    // ideally we need to fill previous block meta and aux hashes, but here we are fine

    use crate::zkevm_circuits::scheduler::SchedulerConfig;

    let padding_proof = source.get_recursion_layer_node_padding_proof().unwrap().into_inner();

    let config = SchedulerConfig {
        proof_config: base_layer_proof_config(),
        vk_fixed_parameters: node_vk.fixed_parameters,
        padding_proof: padding_proof,
        capacity: SCHEDULER_CAPACITY,
    };

    let scheduler_circuit = SchedulerCircuit {
        witness: scheduler_witness,
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    let scheduler_circuit = ZkSyncRecursiveLayerCircuit::SchedulerCircuit(scheduler_circuit);

    if source.get_scheduler_proof().is_err() {
        let f = std::fs::File::create("tmp.json").unwrap();
        serde_json::to_writer(f, &scheduler_circuit).unwrap();

        // test_recursive_circuit(scheduler_circuit.clone());
        // println!("Circuit is satisfied");

        let (
            setup_base,
            setup,
            vk,
            setup_tree,
            vars_hint,
            wits_hint,
            finalization_hint
        ) = create_recursive_layer_setup_data(scheduler_circuit.clone(), &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);

        // we did it above
        source.set_recursion_layer_vk(ZkSyncRecursionLayerVerificationKey::SchedulerCircuit(vk.clone())).unwrap();
        source.set_recursion_layer_finalization_hint(ZkSyncRecursionLayerFinalizationHint::SchedulerCircuit(finalization_hint.clone())).unwrap();

        // prove
        println!("Proving!");
        let now = std::time::Instant::now();

        let proof = prove_recursion_layer_circuit::<NoPow>(
            scheduler_circuit.clone(), 
            &worker, 
            proof_config.clone(), 
            &setup_base, 
            &setup, 
            &setup_tree, 
            &vk, 
            &vars_hint, 
            &wits_hint, 
            &finalization_hint
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_recursion_layer_proof::<NoPow>(
            &scheduler_circuit, 
            &proof, 
            &vk
        );

        assert!(is_valid);

        source.set_scheduler_proof(ZkSyncRecursionLayerProof::SchedulerCircuit(proof)).unwrap();
    }

    println!("DONE");
}

#[test]
fn run_single() {
    let f = std::fs::File::open("tmp.json").unwrap();
    let circuit: ZkSyncRecursiveLayerCircuit = serde_json::from_reader(f).unwrap();
    test_recursive_circuit(circuit);
}