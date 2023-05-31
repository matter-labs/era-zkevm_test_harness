pub mod invididual_debugs;
mod serialize_utils;
mod utils;

use std::collections::{HashMap, VecDeque};

use super::*;
use crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit;
use crate::encodings::QueueSimulator;
use crate::entry_point::create_out_of_circuit_global_context;

use crate::ethereum_types::*;
use crate::pairing::bn256::Bn256;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::oracle::VmWitnessOracle;
use crate::witness::utils::*;
use num_integer::Integer;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use sync_vm::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use sync_vm::franklin_crypto::plonk::circuit::bigint::split_into_limbs;
use sync_vm::franklin_crypto::plonk::circuit::verifier_circuit::utils::verification_key_into_allocated_limb_witnesses;
use sync_vm::glue::traits::GenericHasher;
use sync_vm::recursion::leaf_aggregation::LeafAggregationCircuitInstanceWitness;
use sync_vm::recursion::recursion_tree::AggregationParameters;
use sync_vm::recursion::{get_prefered_rns_params, get_base_placeholder_point_for_accumulators, get_prefered_committer};
use sync_vm::rescue_poseidon::rescue::params::RescueParams;
use sync_vm::testing::create_test_artifacts_with_optimized_gate;
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
use zk_evm::reference_impls::memory::SimpleMemory;
use crate::toolset::create_tools;
use utils::{read_test_artifact, TestArtifact};
use crate::witness::tree::{ZKSyncTestingTree, BinarySparseStorageTree};

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

use crate::witness::tree::ZkSyncStorageLeaf;
use blake2::Blake2s256;

fn basic_circuit_vk_name(circuit_type_idx: u8) -> String {
    format!("basic_circuit_vk_{}", circuit_type_idx)
}

fn basic_circuit_proof_name(circuit_type_idx: u8, absolute_idx: usize) -> String {
    format!("basic_circuit_proof_{}_{}", circuit_type_idx, absolute_idx)
}

pub(crate) fn save_predeployed_contracts(
    storage: &mut InMemoryStorage,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    contracts: &HashMap<Address, Vec<[u8; 32]>>,
) {
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

            println!(
                "Have address {:?} with code hash {:x}",
                address,
                U256::from(hash)
            );

            vec![
                (
                    0,
                    ACCOUNT_CODE_STORAGE_ADDRESS,
                    U256::from_big_endian(address.as_bytes()),
                    U256::from(hash),
                ),
                (
                    0,
                    KNOWN_CODE_HASHES_ADDRESS,
                    U256::from(hash),
                    U256::from(1u64),
                ),
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

fn run_and_try_create_witness_inner(mut test_artifact: TestArtifact, cycle_limit: usize) {
    use zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

    use crate::external_calls::run;

    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    use crate::toolset::GeometryConfig;

    let geometry = GeometryConfig {
        // cycles_per_vm_snapshot: 16, // 24, 26
        cycles_per_vm_snapshot: 1024,
        cycles_per_ram_permutation: 1024,
        cycles_per_code_decommitter: 256,
        cycles_per_storage_application: 2,
        cycles_per_keccak256_circuit: 7,
        cycles_per_sha256_circuit: 7,
        cycles_per_ecrecover_circuit: 2,

        cycles_per_code_decommitter_sorter: 29,
        cycles_per_log_demuxer: 16,
        cycles_per_storage_sorter: 16,
        cycles_per_events_or_l1_messages_sorter: 4,
        limit_for_initial_writes_pubdata_hasher: 16,
        limit_for_repeated_writes_pubdata_hasher: 16,
        limit_for_l1_messages_merklizer: 32,
        limit_for_l1_messages_pudata_hasher: 32,
    };

    let mut storage_impl = InMemoryStorage::new();
    let mut memory_impl = SimpleMemory::new_without_preallocations();
    let mut tree = ZKSyncTestingTree::empty();

    test_artifact.entry_point_address =
        *zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

    let predeployed_contracts = test_artifact
        .predeployed_contracts
        .clone()
        .into_iter()
        .chain(Some((
            test_artifact.entry_point_address,
            test_artifact.entry_point_code.clone(),
        )))
        .collect::<HashMap<_, _>>();
    save_predeployed_contracts(&mut storage_impl, &mut tree, &predeployed_contracts);

    let used_bytecodes = HashMap::from_iter(
        test_artifact
            .predeployed_contracts
            .iter()
            .map(|(_, bytecode)| {
                (
                    bytecode_to_code_hash(&bytecode).unwrap().into(),
                    bytecode.clone(),
                )
            })
            .chain(
                Some(test_artifact.default_account_code.clone()).map(|bytecode| {
                    (
                        bytecode_to_code_hash(&bytecode).unwrap().into(),
                        bytecode.clone(),
                    )
                }),
            ),
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

    let default_account_codehash =
        bytecode_to_code_hash(&test_artifact.default_account_code).unwrap();
    let default_account_codehash = U256::from_big_endian(&default_account_codehash);

    println!("Default AA code hash 0x{:x}", default_account_codehash);

    let (basic_block_circuits, basic_block_circuits_inputs, mut scheduler_partial_input) = run(
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
        memory_impl,
        &mut tree,
    );

    use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
    use sync_vm::recursion::transcript::GenericTranscriptGadget;

    let _num_vm_circuits = basic_block_circuits.main_vm_circuits.len();

    let sponge_params = bn254_rescue_params();
    let rns_params = get_prefered_rns_params();
    let transcript_params = (&sponge_params, &rns_params);

    use sync_vm::recursion::get_prefered_hash_params;

    let aggregation_params =
        AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
            base_placeholder_point: get_base_placeholder_point_for_accumulators(),
            // hash_params: get_prefered_hash_params(),
            hash_params: sponge_params.clone(),
            transcript_params: sponge_params.clone(),
        };

    use sync_vm::recursion::RescueTranscriptForRecursion;

    // verification keys for basic circuits

    let mut unique_set = vec![];
    let mut previous_discr = -1isize;
    for el in basic_block_circuits
        .clone()
        .into_flattened_set()
        .into_iter()
    {
        let circuit_idx = el.numeric_circuit_type();
        if circuit_idx as isize != previous_discr {
            unique_set.push(el);
            previous_discr = circuit_idx as isize;
        }
    }

    // synthesize for verification

    for (idx, (el, input_value)) in basic_block_circuits
        .clone()
        .into_flattened_set()
        .into_iter()
        .zip(basic_block_circuits_inputs.clone().into_flattened_set())
        .enumerate()
    {
        let descr = el.short_description();
        println!("Checking {}: {}", idx, descr);

        // match &el {
        //     ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {
        //         let inner = inner.clone();
        //         let witness = inner.witness.take().unwrap();
        //         dbg!(&witness.closed_form_input);
        //     },
        //     _ => {
        //         continue
        //     }
        // }

        use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
        use crate::bellman::plonk::better_better_cs::cs::TrivialAssembly;

        let mut assembly = TrivialAssembly::<Bn256, PlonkCsWidth4WithNextStepAndCustomGatesParams, SelectorOptimizedWidth4MainGateWithDNext>::new();
        el.synthesize(&mut assembly).unwrap();
        assert_eq!(assembly.input_assingments.len(), 1);
        assert_eq!(assembly.num_input_gates, 1);
        let public_input = assembly.input_assingments[0];

        // let (is_satisfied, public_input) = circuit_testing::check_if_satisfied::<
        //     Bn256,
        //     _,
        //     PlonkCsWidth4WithNextStepAndCustomGatesParams,
        // >(el)
        // .unwrap();
        // assert!(is_satisfied);

        assert_eq!(
            public_input, input_value,
            "Public input diverged for circuit {} of type {}",
            idx, descr
        );
    }

    return;

    for circuit in unique_set.iter().cloned() {
        continue;

        circuit.erase_witness();

        let descr = circuit.short_description();
        println!("Creating VK for {}", descr);
        let base_name = basic_circuit_vk_name(circuit.numeric_circuit_type());

        let vk_file_name_for_bytes = format!("{}.key", &base_name);
        let vk_file_name_for_json = format!("{}.json", &base_name);

        if std::path::Path::new(&vk_file_name_for_bytes).exists() {
            continue;
        }

        let vk =
            circuit_testing::create_vk::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(
                circuit,
            )
            .unwrap();

        let mut vk_file_for_bytes = std::fs::File::create(&vk_file_name_for_bytes).unwrap();
        let mut vk_file_for_json = std::fs::File::create(&vk_file_name_for_json).unwrap();

        vk.write(&mut vk_file_for_bytes).unwrap();
        serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
    }

    // let mut skip = true;

    for (idx, (el, input_value)) in basic_block_circuits
        .clone()
        .into_flattened_set()
        .into_iter()
        .zip(
            basic_block_circuits_inputs
                .clone()
                .into_flattened_set()
                .into_iter(),
        )
        .enumerate()
    {
        continue;

        let descr = el.short_description();
        println!("Doing {}: {}", idx, descr);

        // if idx < 12 {
        //     continue;;
        // }

        // if !matches!(&el, ZkSyncCircuit::InitialWritesPubdataHasher(..))
        //     && !matches!(&el, ZkSyncCircuit::RepeatedWritesPubdataHasher(..))
        //     && !matches!(&el, ZkSyncCircuit::L1MessagesMerklier(..))
        // {
        //     continue;
        // }

        // if !matches!(&el, ZkSyncCircuit::MainVM(..))
        // {

        //     continue;
        // }

        // if matches!(&el, ZkSyncCircuit::StorageSorter(..))
        // {
        //     skip = false;
        // }

        // if skip {
        //     continue;
        // }

        // el.debug_witness();
        use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
        let (is_satisfied, public_input) = circuit_testing::check_if_satisfied::<
            Bn256,
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
        >(el)
        .unwrap();
        assert!(is_satisfied);
        assert_eq!(
            public_input, input_value,
            "Public input diverged for circuit {} of type {}",
            idx, descr
        );
    }

    for (idx, (el, input_value)) in basic_block_circuits
        .clone()
        .into_flattened_set()
        .into_iter()
        .zip(basic_block_circuits_inputs.clone().into_flattened_set())
        .enumerate()
    {
        let descr = el.short_description();
        println!("Proving {}: {}", idx, descr);

        // if matches!(&el, ZkSyncCircuit::MainVM(..)) {
        //     use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
        //     let el = el.clone();
        //     el.debug_witness();
        //     let (is_satisfied, public_input) = circuit_testing::check_if_satisfied::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(el).unwrap();
        //     assert!(is_satisfied);
        //     assert_eq!(public_input, input_value, "Public input diverged for circuit {} of type {}", idx, descr);
        //     continue;
        // } else {
        //     continue;
        // }

        // if !matches!(&el, ZkSyncCircuit::ECRecover(..)) {
        //     continue;
        // }
        // el.debug_witness();
        use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;

        let base_vk_name = basic_circuit_vk_name(el.numeric_circuit_type());
        let base_proof_name = basic_circuit_proof_name(el.numeric_circuit_type(), idx);

        // let vk_file_name_for_bytes = format!("{}.key", &base_vk_name);
        let vk_file_name_for_json = format!("{}.json", &base_vk_name);

        let proof_file_name_for_bytes = format!("{}.key", &base_proof_name);
        let proof_file_name_for_json = format!("{}.json", &base_proof_name);

        if std::path::Path::new(&proof_file_name_for_bytes).exists() {
            continue;
        }

        let mut vk_file_for_json = std::fs::File::open(&vk_file_name_for_json).unwrap();
        let vk: VerificationKey<Bn256, _> = serde_json::from_reader(&mut vk_file_for_json).unwrap(); // type deduction is a savior for us

        let (proof, _vk) = circuit_testing::prove_only_circuit_for_params::<
            Bn256,
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            RescueTranscriptForRecursion<'_>,
        >(el, Some(transcript_params), vk.clone(), None)
        .unwrap();

        assert_eq!(proof.inputs.len(), 1);
        assert_eq!(
            proof.inputs[0], input_value,
            "Public input diverged for circuit {} of type {}",
            idx, descr
        );

        let mut proof_file_for_bytes = std::fs::File::create(proof_file_name_for_bytes).unwrap();
        let mut proof_file_for_json = std::fs::File::create(proof_file_name_for_json).unwrap();

        proof.write(&mut proof_file_for_bytes).unwrap();
        serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();
    }

    // panic!("Done");

    // recursion step. We decide on some arbitrary parameters
    let splitting_factor = 4; // we either split into N subqueues, or we do N leaf proofs per layer
    let scheduler_upper_bound = 256;

    // verification keys for aggregation circuits requires some padding proof and VK, that we generated right above
    let mut all_vk_encodings = vec![];
    let mut all_vk_committments = vec![];

    let mut g2_points = None;

    use crate::encodings::recursion_request::*;
    let mut recursion_requests_queue_simulator = RecursionQueueSimulator::empty();

    use crate::bellman::plonk::better_better_cs::proof::Proof;
    use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
    use crate::witness::full_block_artifact::BlockBasicCircuitsPublicInputs;
    use sync_vm::glue::optimizable_queue::*;
    use sync_vm::recursion::aggregation::VkInRns;
    use sync_vm::recursion::leaf_aggregation::*;
    use sync_vm::recursion::node_aggregation::ZkSyncParametricCircuit;
    use sync_vm::scheduler::CircuitType;
    use sync_vm::scheduler::*;
    use sync_vm::traits::ArithmeticEncodable;

    let mut previous_type = None;
    let flattened = basic_block_circuits.clone().into_flattened_set();
    let mut padding_proof_file_names = vec![];

    for (idx, el) in flattened.iter().enumerate() {
        let descr = el.short_description();
        println!("Aggregating {}: {}", idx, descr);

        let base_vk_name = basic_circuit_vk_name(el.numeric_circuit_type());
        let base_proof_name = basic_circuit_proof_name(el.numeric_circuit_type(), idx);

        // let vk_file_name_for_bytes = format!("{}.key", &base_vk_name);
        let vk_file_name_for_json = format!("{}.json", &base_vk_name);

        // let proof_file_name_for_bytes = format!("{}.key", &base_proof_name);
        let proof_file_name_for_json = format!("{}.json", &base_proof_name);

        let mut vk_file_for_json = std::fs::File::open(&vk_file_name_for_json).unwrap();

        let vk: VerificationKey<Bn256, _> = serde_json::from_reader(&mut vk_file_for_json).unwrap();

        if g2_points.is_none() {
            g2_points = Some(vk.g2_elements);
        }
        if padding_proof_file_names.len() < splitting_factor {
            padding_proof_file_names.push(proof_file_name_for_json.clone());
        }
        if let Some(p) = previous_type.as_ref().cloned() {
            if p == el.numeric_circuit_type() {
                continue;
            } else {
                // add
                let vk_in_rns = VkInRns {
                    vk: Some(vk.clone()),
                    rns_params: &rns_params,
                };
                let encoding = vk_in_rns.encode().unwrap();
                let committment = simulate_variable_length_hash(&encoding, &round_function);
                dbg!(idx);
                dbg!(el.numeric_circuit_type());
                dbg!(&committment);
                all_vk_encodings.push(encoding);
                all_vk_committments.push(committment);

                previous_type = Some(el.numeric_circuit_type());
            }
        } else {
            let vk_in_rns = VkInRns {
                vk: Some(vk.clone()),
                rns_params: &rns_params,
            };
            let encoding = vk_in_rns.encode().unwrap();
            let committment = simulate_variable_length_hash(&encoding, &round_function);
            dbg!(idx);
            dbg!(el.numeric_circuit_type());
            dbg!(&committment);
            all_vk_encodings.push(encoding);
            all_vk_committments.push(committment);

            previous_type = Some(el.numeric_circuit_type());
        }
    }

    dbg!(&all_vk_committments);

    let all_circuit_types_committment_for_leaf_agg =
        simulate_variable_length_hash(&all_vk_committments, &round_function);

    // we pick proof number 0 as a padding element for circuit. In general it can be any valid proof
    let padding_vk_committment = all_vk_committments[0];
    dbg!(&all_vk_encodings[0].len());
    let padding_vk_encoding: [_; sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] =
        all_vk_encodings[0].to_vec().try_into().unwrap();

    let mut padding_public_inputs = vec![];
    let mut padding_proofs = vec![];

    for padding_proof_name in padding_proof_file_names.into_iter() {
        let padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> =
            serde_json::from_reader(std::fs::File::open(padding_proof_name).unwrap()).unwrap();
        let padding_proof_public_input = padding_proof.inputs[0];

        padding_public_inputs.push(padding_proof_public_input);
        padding_proofs.push(padding_proof);
    }

    dbg!(all_vk_committments.len());

    // we need any points that have e(p1, g2)*e(p2, g2^x) == 0, so we basically can use two first elements
    // of the trusted setup
    let padding_aggregations = {
        let crs_mons = circuit_testing::get_trusted_setup::<Bn256>(1 << 26);
        let mut p1 = crs_mons.g1_bases[1];
        use sync_vm::franklin_crypto::bellman::CurveAffine;
        p1.negate();
        let mut p2 = crs_mons.g1_bases[0];

        let mut all_aggregations = vec![];

        use sync_vm::franklin_crypto::bellman::PrimeField;
        let scalar = crate::bellman::bn256::Fr::from_str("1234567").unwrap(); // any factor that is > 4

        for _ in 0..splitting_factor {
            let (pair_with_generator_x, pair_with_generator_y) = p1.into_xy_unchecked();
            let (pair_with_x_x, pair_with_x_y) = p2.into_xy_unchecked();

            let pair_with_generator_x = split_into_limbs(pair_with_generator_x, &rns_params)
                .0
                .try_into()
                .unwrap();
            let pair_with_generator_y = split_into_limbs(pair_with_generator_y, &rns_params)
                .0
                .try_into()
                .unwrap();
            let pair_with_x_x = split_into_limbs(pair_with_x_x, &rns_params)
                .0
                .try_into()
                .unwrap();
            let pair_with_x_y = split_into_limbs(pair_with_x_y, &rns_params)
                .0
                .try_into()
                .unwrap();

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
    };

    // create VKs for leaf and node recursive circuits

    let leaf_vk_file_name = format!("leaf_vk");
    let node_vk_file_name = format!("node_vk");
    let scheduler_vk_file_name = format!("scheduler_vk");

    let mut leaf_vk_committment = None;
    let mut node_vk_committment = None;

    {
        let leaf_vk_file_name_for_json = format!("{}.json", &leaf_vk_file_name);
        let node_vk_file_name_for_json = format!("{}.json", &node_vk_file_name);
        let scheduler_vk_file_name_for_json = format!("{}.json", &scheduler_vk_file_name);

        // leaf
        if !std::path::Path::new(&leaf_vk_file_name_for_json).exists() {
            use crate::abstract_zksync_circuit::concrete_circuits::LeafAggregationCircuit;

            let circuit = LeafAggregationCircuit::new(
                None,
                (
                    splitting_factor,
                    rns_params.clone(),
                    aggregation_params.clone(),
                    padding_vk_committment,
                    padding_vk_encoding.to_vec(),
                    padding_public_inputs.clone(),
                    padding_proofs.clone(),
                    g2_points.clone(),
                ),
                round_function.clone(),
                None,
            );

            let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::LeafAggregation(circuit);

            let vk = circuit_testing::create_vk::<
                Bn256,
                _,
                PlonkCsWidth4WithNextStepAndCustomGatesParams,
            >(circuit)
            .unwrap();

            let vk_file_name_for_bytes = format!("{}.key", &leaf_vk_file_name);
            let vk_file_name_for_json = format!("{}.json", &leaf_vk_file_name);

            let mut vk_file_for_bytes = std::fs::File::create(&vk_file_name_for_bytes).unwrap();
            let mut vk_file_for_json = std::fs::File::create(&vk_file_name_for_json).unwrap();

            vk.write(&mut vk_file_for_bytes).unwrap();
            serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
            drop(vk_file_for_json);
        }

        // load VK
        // erase type
        let mut vk_file_for_json = std::fs::File::open(&leaf_vk_file_name_for_json).unwrap();
        let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> =
            serde_json::from_reader(&mut vk_file_for_json).unwrap();
        let vk_in_rns = VkInRns {
            vk: Some(vk.clone()),
            rns_params: &rns_params,
        };
        let encoding = vk_in_rns.encode().unwrap();
        let committment = simulate_variable_length_hash(&encoding, &round_function);
        leaf_vk_committment = Some(committment);

        // Node

        if !std::path::Path::new(&node_vk_file_name_for_json).exists() {
            use crate::abstract_zksync_circuit::concrete_circuits::NodeAggregationCircuit;

            let circuit = NodeAggregationCircuit::new(
                None,
                (
                    splitting_factor,
                    splitting_factor,
                    rns_params.clone(),
                    aggregation_params.clone(),
                    padding_vk_committment,
                    padding_vk_encoding.to_vec(),
                    padding_public_inputs.clone(),
                    padding_proofs.clone(),
                    padding_aggregations.clone(),
                    g2_points.clone(),
                ),
                round_function.clone(),
                None,
            );

            let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::NodeAggregation(circuit);

            let vk = circuit_testing::create_vk::<
                Bn256,
                _,
                PlonkCsWidth4WithNextStepAndCustomGatesParams,
            >(circuit)
            .unwrap();

            let vk_file_name_for_bytes = format!("{}.key", &node_vk_file_name);
            let vk_file_name_for_json = format!("{}.json", &node_vk_file_name);

            let mut vk_file_for_bytes = std::fs::File::create(&vk_file_name_for_bytes).unwrap();
            let mut vk_file_for_json = std::fs::File::create(&vk_file_name_for_json).unwrap();

            vk.write(&mut vk_file_for_bytes).unwrap();
            serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();

            drop(vk_file_for_json);
        }

        // load VK
        // erase type
        let mut vk_file_for_json = std::fs::File::open(&node_vk_file_name_for_json).unwrap();
        let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> =
            serde_json::from_reader(&mut vk_file_for_json).unwrap();
        let vk_in_rns = VkInRns {
            vk: Some(vk.clone()),
            rns_params: &rns_params,
        };
        let encoding = vk_in_rns.encode().unwrap();
        let committment = simulate_variable_length_hash(&encoding, &round_function);
        node_vk_committment = Some(committment);

        // scheduler

        if !std::path::Path::new(&scheduler_vk_file_name_for_json).exists() {
            use crate::abstract_zksync_circuit::concrete_circuits::SchedulerCircuit;

            let circuit = SchedulerCircuit::new(
                None,
                (
                    scheduler_upper_bound,
                    rns_params.clone(),
                    aggregation_params.clone(),
                    padding_vk_encoding.to_vec(),
                    padding_proofs[0].clone(), // not important
                    g2_points.clone(),
                ),
                round_function.clone(),
                None,
            );
            let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::Scheduler(circuit);

            let vk = circuit_testing::create_vk::<
                Bn256,
                _,
                PlonkCsWidth4WithNextStepAndCustomGatesParams,
            >(circuit)
            .unwrap();

            let vk_file_name_for_bytes = format!("{}.key", &scheduler_vk_file_name);
            let vk_file_name_for_json = format!("{}.json", &scheduler_vk_file_name);

            let mut vk_file_for_bytes = std::fs::File::create(vk_file_name_for_bytes).unwrap();
            let mut vk_file_for_json = std::fs::File::create(vk_file_name_for_json).unwrap();

            vk.write(&mut vk_file_for_bytes).unwrap();
            serde_json::to_writer(&mut vk_file_for_json, &vk).unwrap();
        }
    }

    // form a queue of recursive verification requests in the same manner as scheduler does it
    let mut all_requests = vec![];

    for (idx, (circuit, public_input)) in basic_block_circuits
        .into_flattened_set()
        .into_iter()
        .zip(basic_block_circuits_inputs.into_flattened_set().into_iter())
        .enumerate()
    {
        println!(
            "Pushing recursive request for circuit {} with input {}",
            circuit.short_description(),
            public_input
        );
        let req = RecursionRequest {
            circuit_type: circuit.numeric_circuit_type(),
            public_input,
        };

        let _ = recursion_requests_queue_simulator.push(req.clone(), &round_function);

        all_requests.push((idx, req));
    }

    dbg!(&all_requests.len());
    dbg!(&recursion_requests_queue_simulator.tail);

    // now we basically simulate recursion by chunking everything starting from the basic circuit level

    let leaf_layer_requests: Vec<_> = all_requests
        .chunks(splitting_factor)
        .map(|el| el.to_vec())
        .collect();
    let mut leaf_layer_subqueues = vec![];
    let mut queue = recursion_requests_queue_simulator.clone();
    for _ in 0..(leaf_layer_requests.len() - 1) {
        let (chunk, rest) = queue.split(splitting_factor as u32);
        leaf_layer_subqueues.push(chunk);
        queue = rest;
    }
    leaf_layer_subqueues.push(queue);

    let leaf_layer_flattened_set: Vec<_> = flattened
        .chunks(splitting_factor)
        .map(|el| el.to_vec())
        .collect();

    let mut absolute_proof_idx = 0;

    // LEAF LEVEL

    println!("Aggregating INVIDIVUAL PROOFS by LEAFS");

    for (idx, (subset, circuits)) in leaf_layer_requests
        .into_iter()
        .zip(leaf_layer_flattened_set.into_iter())
        .enumerate()
    {
        assert_eq!(subset.len(), circuits.len());
        let proof_file_name = format!("leaf_proof_{}", idx);
        let output_file_name = format!("leaf_output_{}", idx);

        let queue_wit: VecDeque<_> = leaf_layer_subqueues[idx]
            .witness
            .iter()
            .map(|el| {
                let (enc, prev_tail, el) = el.clone();
                let w = RecursiveProofQueryWitness {
                    cicruit_type: el.circuit_type,
                    closed_form_input_hash: el.public_input,
                    _marker: std::marker::PhantomData,
                };

                (enc, w, prev_tail)
            })
            .collect();
        let mut wit = LeafAggregationCircuitInstanceWitness::<Bn256> {
            closed_form_input: LeafAggregationInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                hidden_fsm_input: (),
                hidden_fsm_output: (),
                observable_input: LeafAggregationInputDataWitness {
                    initial_log_queue_state: take_queue_state_from_simulator(
                        &leaf_layer_subqueues[idx],
                    ),
                    leaf_vk_committment: all_circuit_types_committment_for_leaf_agg,
                    _marker: std::marker::PhantomData,
                },
                observable_output: LeafAggregationOutputData::placeholder_witness(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            initial_queue_witness: FixedWidthEncodingGenericQueueWitness { wit: queue_wit },
            leaf_vks_committments_set: all_vk_committments.clone(),
            proof_witnesses: vec![],
            vk_encoding_witnesses: vec![],
        };

        // dbg!(&wit.closed_form_input.observable_input.initial_log_queue_state);

        let this_aggregation_subqueue = &leaf_layer_subqueues[idx];

        for (i, ((req_idx, req), el)) in subset.into_iter().zip(circuits.into_iter()).enumerate() {
            let circuit_vk_file_name = basic_circuit_vk_name(el.numeric_circuit_type());
            let circuit_proof_file_name =
                basic_circuit_proof_name(el.numeric_circuit_type(), absolute_proof_idx);

            println!("Aggregating over {}", &circuit_proof_file_name);

            let mut vk_file_for_json =
                std::fs::File::open(format!("{}.json", &circuit_vk_file_name)).unwrap();
            let mut proof_file_for_json =
                std::fs::File::open(format!("{}.json", &circuit_proof_file_name)).unwrap();

            // type erasure for easier life
            let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> =
                serde_json::from_reader(&mut vk_file_for_json).unwrap();
            let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> =
                serde_json::from_reader(&mut proof_file_for_json).unwrap();

            assert_eq!(
                proof.inputs[0], req.public_input,
                "failed for req_idx = {}, i = {}, aggregation_idx = {}, {}",
                req_idx, i, idx, circuit_vk_file_name
            );
            assert_eq!(
                proof.inputs[0], this_aggregation_subqueue.witness[i].2.public_input,
                "failed for req_idx = {}, i = {}, aggregation_idx = {}",
                req_idx, i, idx
            );

            let vk_in_rns = VkInRns {
                vk: Some(vk.clone()),
                rns_params: &rns_params,
            };
            let encoding = vk_in_rns.encode().unwrap();
            wit.vk_encoding_witnesses.push(encoding);
            wit.proof_witnesses.push(proof);

            absolute_proof_idx += 1;
        }

        drop(this_aggregation_subqueue);

        if std::path::Path::new(&format!("{}.json", &proof_file_name)).exists() {
            continue;
        }

        // we use the circuit itself to output some witness
        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let (aggregated_public_input, output_data) =
            aggregate_at_leaf_level_entry_point::<_, _, _, _, _, true>(
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
                    g2_points.clone(),
                ),
            )
            .unwrap();

        let public_input_value = aggregated_public_input.get_value().unwrap();
        let result_observable_output = output_data.create_witness().unwrap();

        wit.closed_form_input.observable_output = result_observable_output.clone();

        let mut output_file_for_json =
            std::fs::File::create(format!("{}.json", &output_file_name)).unwrap();
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
                padding_public_inputs.clone(),
                padding_proofs.clone(),
                g2_points.clone(),
            ),
            round_function.clone(),
            None,
        );

        let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::LeafAggregation(circuit);

        let vk_file_name_for_json = format!("{}.json", &leaf_vk_file_name);
        let mut vk_file_for_json = std::fs::File::open(&vk_file_name_for_json).unwrap();
        let vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>> =
            serde_json::from_reader(&mut vk_file_for_json).unwrap();

        let (proof, _vk_) = circuit_testing::prove_only_circuit_for_params::<
            Bn256,
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            RescueTranscriptForRecursion<'_>,
        >(circuit, Some(transcript_params), vk.clone(), None)
        .unwrap();

        let mut proof_file_for_bytes =
            std::fs::File::create(format!("{}.key", &proof_file_name)).unwrap();
        let mut proof_file_for_json =
            std::fs::File::create(format!("{}.json", &proof_file_name)).unwrap();

        proof.write(&mut proof_file_for_bytes).unwrap();
        serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

        assert_eq!(
            proof.inputs[0], public_input_value,
            "Public input diverged for circuit {}",
            idx
        );
    }

    // nodes are much easier to make homogeniously generated

    let mut previous_sequence = leaf_layer_subqueues;

    let leaf_vk_committment = leaf_vk_committment.unwrap();
    let node_vk_committment = node_vk_committment.unwrap();

    let mut final_level = 0;

    for level in 0..128 {
        if level == 0 {
            println!("LEVEL {}: aggregating LEAFS by NODES", level);
        } else {
            println!("LEVEL {}: aggregating NODES by NODES", level);
        }

        let num_previous_level_proofs = previous_sequence.len();
        let mut merged = vec![];
        for chunk in previous_sequence.chunks(splitting_factor) {
            let mut first = chunk[0].clone();
            for second in chunk[1..].iter().cloned() {
                first = QueueSimulator::merge(first, second);
            }

            merged.push(first);
        }

        let previous_level_vk_file_name = if level == 0 {
            leaf_vk_file_name.clone()
        } else {
            node_vk_file_name.clone()
        };

        let previous_level_proof_base_file_name = if level == 0 {
            format!("leaf_proof")
        } else {
            format!("node_proof_{}", level - 1)
        };

        let previous_level_output_base_file_name = if level == 0 {
            format!("leaf_output")
        } else {
            format!("node_output_{}", level - 1)
        };

        let new_level_proof_base_file_name = format!("node_proof_{}", level);
        let new_level_output_base_file_name = format!("node_output_{}", level);

        let previous_level_vk_file_name_for_json = format!("{}.json", &previous_level_vk_file_name);
        let mut previous_level_vk_file_for_json =
            std::fs::File::open(previous_level_vk_file_name_for_json).unwrap();
        let previous_level_vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> =
            serde_json::from_reader(&mut previous_level_vk_file_for_json).unwrap();

        use crate::abstract_zksync_circuit::concrete_circuits::NodeAggregationCircuit;
        use sync_vm::recursion::node_aggregation::NodeAggregationCircuitInstanceWitness;
        use sync_vm::recursion::node_aggregation::NodeAggregationInputDataWitness;
        use sync_vm::recursion::node_aggregation::NodeAggregationInputOutputWitness;
        use sync_vm::recursion::node_aggregation::NodeAggregationOutputData;

        let mut circuit_to_aggregate_index = 0;

        for (idx, subset) in merged.iter().cloned().enumerate() {
            let queue_wit: VecDeque<_> = subset
                .witness
                .iter()
                .map(|el| {
                    let (enc, prev_tail, el) = el.clone();
                    let w = RecursiveProofQueryWitness {
                        cicruit_type: el.circuit_type,
                        closed_form_input_hash: el.public_input,
                        _marker: std::marker::PhantomData,
                    };

                    (enc, w, prev_tail)
                })
                .collect();

            dbg!(&subset.num_items);

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
                        all_circuit_types_committment_for_leaf:
                            all_circuit_types_committment_for_leaf_agg,
                        _marker: std::marker::PhantomData,
                    },
                    observable_output: NodeAggregationOutputData::placeholder_witness(),
                    _marker_e: (),
                    _marker: std::marker::PhantomData,
                },
                initial_queue_witness: FixedWidthEncodingGenericQueueWitness { wit: queue_wit },
                proof_witnesses: vec![],
                vk_encoding_witnesses: vec![],
                leaf_aggregation_results: vec![],
                node_aggregation_results: vec![],
                depth: level,
            };

            for _ in 0..splitting_factor {
                if circuit_to_aggregate_index >= num_previous_level_proofs {
                    break;
                }
                let proof_file_name = format!(
                    "{}_{}",
                    &previous_level_proof_base_file_name, circuit_to_aggregate_index
                );
                let output_file_name = format!(
                    "{}_{}",
                    &previous_level_output_base_file_name, circuit_to_aggregate_index
                );

                if std::path::Path::new(&format!("{}.json", &proof_file_name)).exists() == false {
                    break;
                }

                println!("Aggregating over {}", &proof_file_name);

                let mut proof_file_for_json =
                    std::fs::File::open(format!("{}.json", &proof_file_name)).unwrap();
                let mut output_file_for_json =
                    std::fs::File::open(format!("{}.json", &output_file_name)).unwrap();
                let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> =
                    serde_json::from_reader(&mut proof_file_for_json).unwrap();
                if level == 0 {
                    let output: LeafAggregationOutputDataWitness<Bn256> =
                        serde_json::from_reader(&mut output_file_for_json).unwrap();
                    wit.leaf_aggregation_results.push(output);
                } else {
                    use sync_vm::recursion::node_aggregation::NodeAggregationOutputDataWitness;
                    let output: NodeAggregationOutputDataWitness<Bn256> =
                        serde_json::from_reader(&mut output_file_for_json).unwrap();
                    wit.node_aggregation_results.push(output);
                }

                dbg!(&proof.inputs[0]);

                let vk_in_rns = VkInRns {
                    vk: Some(previous_level_vk.clone()),
                    rns_params: &rns_params,
                };
                let encoding = vk_in_rns.encode().unwrap();
                wit.vk_encoding_witnesses.push(encoding);
                wit.proof_witnesses.push(proof);
                circuit_to_aggregate_index += 1;
            }

            let new_level_proof_file_name_for_bytes =
                format!("{}_{}.key", &new_level_proof_base_file_name, idx);
            let new_level_proof_file_name_for_json =
                format!("{}_{}.json", &new_level_proof_base_file_name, idx);

            if std::path::Path::new(&new_level_proof_file_name_for_json).exists() {
                println!(
                    "Proof is already created: {}",
                    new_level_proof_file_name_for_json
                );
                continue;
            }

            use sync_vm::recursion::node_aggregation::aggregate_at_node_level_entry_point;

            let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
            println!("Simulating aggregation output");
            let (
                aggregated_public_input,
                _leaf_aggregation_output_data,
                _node_aggregation_output_data,
                output_data,
            ) = aggregate_at_node_level_entry_point::<_, _, _, _, _, true>(
                &mut cs,
                Some(wit.clone()),
                &round_function,
                (
                    splitting_factor,
                    splitting_factor,
                    rns_params.clone(),
                    aggregation_params.clone(),
                    padding_vk_committment,
                    padding_vk_encoding.clone(),
                    padding_public_inputs.clone(),
                    padding_proofs.clone(),
                    padding_aggregations.clone(),
                    g2_points.clone(),
                ),
            )
            .unwrap();

            // dbg!(&aggregated_public_input.get_value());
            // dbg!(&output_data.create_witness());

            let public_input_value = aggregated_public_input.get_value().unwrap();
            let result_observable_output = output_data.create_witness().unwrap();

            wit.closed_form_input.observable_output = result_observable_output.clone();

            let mut output_file_for_json =
                std::fs::File::create(format!("{}_{}.json", &new_level_output_base_file_name, idx))
                    .unwrap();
            serde_json::to_writer(&mut output_file_for_json, &result_observable_output).unwrap();

            println!("Creating aggregation proof");

            let circuit = NodeAggregationCircuit::new(
                Some(wit),
                (
                    splitting_factor,
                    splitting_factor,
                    rns_params.clone(),
                    aggregation_params.clone(),
                    padding_vk_committment,
                    padding_vk_encoding.to_vec(),
                    padding_public_inputs.clone(),
                    padding_proofs.clone(),
                    padding_aggregations.clone(),
                    g2_points.clone(),
                ),
                round_function.clone(),
                None,
            );

            let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::NodeAggregation(circuit);

            let vk_file_name_for_json = format!("{}.json", node_vk_file_name);
            let mut vk_file_for_json = std::fs::File::open(&vk_file_name_for_json).unwrap();
            let vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>> =
                serde_json::from_reader(&mut vk_file_for_json).unwrap();

            let (proof, _vk) = circuit_testing::prove_only_circuit_for_params::<
                Bn256,
                _,
                PlonkCsWidth4WithNextStepAndCustomGatesParams,
                RescueTranscriptForRecursion<'_>,
            >(circuit, Some(transcript_params), vk.clone(), None)
            .unwrap();

            let mut proof_file_for_bytes =
                std::fs::File::create(new_level_proof_file_name_for_bytes).unwrap();
            let mut proof_file_for_json =
                std::fs::File::create(new_level_proof_file_name_for_json).unwrap();

            proof.write(&mut proof_file_for_bytes).unwrap();
            serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

            assert_eq!(
                proof.inputs[0], public_input_value,
                "Public input diverged for circuit {}",
                idx
            );
        }

        previous_sequence = merged;
        final_level = level;

        if previous_sequence.len() == 1 {
            break;
        }
    }

    use sync_vm::recursion::node_aggregation::NodeAggregationOutputDataWitness;

    let final_proof_file_name = format!("node_proof_{}_0.json", final_level);
    let final_output_file_name = format!("node_output_{}_0.json", final_level);

    let mut vk_file_for_json = std::fs::File::open(format!("{}.json", &node_vk_file_name)).unwrap();
    let mut proof_file_for_json = std::fs::File::open(&final_proof_file_name).unwrap();
    let mut output_file_for_json = std::fs::File::open(&final_output_file_name).unwrap();
    let mut scheduler_vk_file_for_json =
        std::fs::File::open(format!("{}.json", &scheduler_vk_file_name)).unwrap();

    let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> =
        serde_json::from_reader(&mut vk_file_for_json).unwrap();
    let scheduler_vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>> =
        serde_json::from_reader(&mut scheduler_vk_file_for_json).unwrap();
    let proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> =
        serde_json::from_reader(&mut proof_file_for_json).unwrap();
    let output: NodeAggregationOutputDataWitness<Bn256> =
        serde_json::from_reader(&mut output_file_for_json).unwrap();

    dbg!(&proof.inputs[0]);

    scheduler_partial_input.aggregation_result = output;
    scheduler_partial_input.proof_witnesses = vec![proof];
    let vk_in_rns = VkInRns {
        vk: Some(vk.clone()),
        rns_params: &rns_params,
    };
    let encoding = vk_in_rns.encode().unwrap();
    scheduler_partial_input.vk_encoding_witnesses = vec![encoding];

    scheduler_partial_input.previous_block_aux_hash =
        Bytes32Witness::from_bytes_array(&previous_aux_hash);
    scheduler_partial_input.previous_block_meta_hash =
        Bytes32Witness::from_bytes_array(&previous_meta_hash);

    // now also all the key sets
    use crate::bellman::{PrimeField, PrimeFieldRepr};
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;

    dbg!(&all_circuit_types_committment_for_leaf_agg);
    dbg!(&leaf_vk_committment);
    dbg!(&node_vk_committment);

    let mut buffer = vec![];
    all_circuit_types_committment_for_leaf_agg
        .into_repr()
        .write_be(&mut buffer)
        .unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_partial_input.all_different_circuits_keys_hash =
        Bytes32Witness::from_bytes_array(&all_keys);

    let mut buffer = vec![];
    leaf_vk_committment
        .into_repr()
        .write_be(&mut buffer)
        .unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_partial_input.recursion_leaf_verification_key_hash =
        Bytes32Witness::from_bytes_array(&all_keys);

    let mut buffer = vec![];
    node_vk_committment
        .into_repr()
        .write_be(&mut buffer)
        .unwrap();
    assert_eq!(buffer.len(), 32);
    let all_keys: [u8; 32] = buffer.try_into().unwrap();
    scheduler_partial_input.recursion_node_verification_key_hash =
        Bytes32Witness::from_bytes_array(&all_keys);

    use crate::abstract_zksync_circuit::concrete_circuits::SchedulerCircuit;

    let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
    let _ = scheduler_function(
        &mut cs,
        Some(scheduler_partial_input.clone()),
        None,
        &round_function,
        (
            scheduler_upper_bound,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding,
            padding_proofs[0].clone(),
            g2_points.clone(),
        ),
    );

    let circuit = SchedulerCircuit::new(
        Some(scheduler_partial_input),
        (
            scheduler_upper_bound,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding.to_vec(),
            padding_proofs[0].clone(),
            g2_points.clone(),
        ),
        round_function.clone(),
        None,
    );

    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::Scheduler(circuit);

    use sync_vm::franklin_crypto::bellman::pairing::ff::ScalarEngine;

    // last proof uses Keccak transcript
    let (proof, _) = circuit_testing::prove_only_circuit_for_params::<
        Bn256,
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
    >(circuit, None, scheduler_vk, None)
    .unwrap();

    let mut proof_file_for_bytes = std::fs::File::create("scheduler_proof.key").unwrap();
    let mut proof_file_for_json = std::fs::File::create("scheduler_proof.json").unwrap();

    proof.write(&mut proof_file_for_bytes).unwrap();
    serde_json::to_writer(&mut proof_file_for_json, &proof).unwrap();

    println!("Done");
}

#[test]
fn get_circuit_capacity() {
    use crate::abstract_zksync_circuit::concrete_circuits::*;
    use crate::abstract_zksync_circuit::*;
    use crate::bellman::plonk::better_better_cs::cs::*;
    use crate::bellman::Engine;

    fn compute_inner<
        SF: ZkSyncUniformSynthesisFunction<
            Bn256,
            RoundFunction = GenericHasher<Bn256, RescueParams<Bn256, 2, 3>, 2, 3>,
        >,
        F: Fn(usize) -> SF::Config,
    >(
        config_fn: F,
    ) -> usize {
        let max = 1 << 26;

        let typical_sizes = vec![16, 32];
        let mut gates = vec![];

        for size in typical_sizes.iter().cloned() {
            let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

            let mut setup_assembly = SetupAssembly::<
                _,
                PlonkCsWidth4WithNextStepAndCustomGatesParams,
                SelectorOptimizedWidth4MainGateWithDNext,
            >::new();

            let config = config_fn(size);

            let circuit = ZkSyncUniformCircuitCircuitInstance::<_, SF>::new(
                None,
                config,
                round_function.clone(),
                None,
            );

            circuit.synthesize(&mut setup_assembly).unwrap();

            let n = setup_assembly.n();
            gates.push(n);
        }

        // linear approximation

        let mut per_round_gates = (gates[1] - gates[0]) / (typical_sizes[1] - typical_sizes[0]);

        if (gates[1] - gates[0]) % (typical_sizes[1] - typical_sizes[0]) != 0 {
            println!("non-linear!");
            per_round_gates += 1;
        }

        println!("Single cycle takes {} gates", per_round_gates);

        let additive = gates[1] - per_round_gates * typical_sizes[1];

        println!("O(1) costs = {}", additive);

        let cycles = (max - additive) / per_round_gates;

        println!(
            "Can fit {} cycles for circuit type {}",
            cycles,
            SF::description()
        );

        let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

        let mut setup_assembly = SetupAssembly::<
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            SelectorOptimizedWidth4MainGateWithDNext,
        >::new();

        let config = config_fn(cycles);

        let circuit = ZkSyncUniformCircuitCircuitInstance::<_, SF>::new(
            None,
            config,
            round_function.clone(),
            None,
        );

        println!("Synthesising largest size");
        circuit.synthesize(&mut setup_assembly).unwrap();
        println!("Finaizing largest size");
        setup_assembly.finalize();

        cycles
    }

    let _vm_size =
        compute_inner::<VmMainInstanceSynthesisFunction<_, VmWitnessOracle<_>>, _>(|x: usize| x);

    let _log_demux_size = compute_inner::<LogDemuxInstanceSynthesisFunction, _>(|x: usize| x);

    let _keccak256 =
        compute_inner::<Keccak256RoundFunctionInstanceSynthesisFunction, _>(|x: usize| x);

    let _sha256 = compute_inner::<Sha256RoundFunctionInstanceSynthesisFunction, _>(|x: usize| x);

    let _ecrecover = compute_inner::<ECRecoverFunctionInstanceSynthesisFunction, _>(|x: usize| x);

    let _storage_sort =
        compute_inner::<StorageSortAndDedupInstanceSynthesisFunction, _>(|x: usize| x);

    let _code_sort = compute_inner::<CodeDecommittmentsSorterSynthesisFunction, _>(|x: usize| x);

    let _code_decommit = compute_inner::<CodeDecommitterInstanceSynthesisFunction, _>(|x: usize| x);

    let _events_sort =
        compute_inner::<EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction, _>(|x: usize| x);

    let _ram_perm = compute_inner::<RAMPermutationInstanceSynthesisFunction, _>(|x: usize| x);

    let _storage_apply =
        compute_inner::<StorageApplicationInstanceSynthesisFunction, _>(|x: usize| {
            use crate::witness::postprocessing::USE_BLAKE2S_EXTRA_TABLES;

            (x, USE_BLAKE2S_EXTRA_TABLES)
        });

    let _initial_pubdata =
        compute_inner::<StorageInitialWritesRehasherInstanceSynthesisFunction, _>(|x: usize| x);

    let _repeated_pubdata =
        compute_inner::<StorageRepeatedWritesRehasherInstanceSynthesisFunction, _>(|x: usize| x);

    let _l1_messages_rehasher =
        compute_inner::<L1MessagesRehasherInstanceSynthesisFunction, _>(|x: usize| x);

    let _l1_messages_merklization =
        compute_inner::<MessagesMerklizerInstanceSynthesisFunction, _>(|x: usize| {
            use crate::witness::postprocessing::L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH;

            (x, L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH)
        });

    // // for recursive aggregation we have to unroll manually

    // let sponge_params = bn254_rescue_params();
    // let rns_params = get_prefered_rns_params();

    // use sync_vm::recursion::get_prefered_hash_params;
    // use sync_vm::recursion::transcript::GenericTranscriptGadget;
    // use sync_vm::recursion::node_aggregation::ZkSyncParametricCircuit;
    // use sync_vm::recursion::aggregation::VkInRns;
    // use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
    // use sync_vm::traits::ArithmeticEncodable;

    // let aggregation_params = AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
    //     base_placeholder_point: get_base_placeholder_point_for_accumulators(),
    //     hash_params: sponge_params.clone(),
    //     transcript_params: sponge_params.clone(),
    // };

    // let max = 1 << 26;

    // let typical_sizes = vec![8, 16];
    // let mut gates = vec![];

    // for size in typical_sizes.iter().cloned() {
    //     let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    //     let mut setup_assembly = SetupAssembly::<
    //         _,
    //         PlonkCsWidth4WithNextStepAndCustomGatesParams,
    //         SelectorOptimizedWidth4MainGateWithDNext
    //     >::new();

    //     let splitting_factor = size;

    //     let mut vk_file_for_json = std::fs::File::open(&"basic_circuit_vk_17.json").unwrap();
    //     let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
    //     let vk_in_rns = VkInRns {
    //         vk: Some(vk.clone()),
    //         rns_params: &rns_params
    //     };
    //     let padding_vk_encoding = vk_in_rns.encode().unwrap();
    //     let padding_vk_committment = simulate_variable_length_hash(&padding_vk_encoding, &round_function);

    //     let mut padding_public_inputs = vec![];
    //     let mut padding_proofs = vec![];

    //     for _ in 0..splitting_factor {
    //         use crate::bellman::plonk::better_better_cs::proof::Proof;
    //         let padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(std::fs::File::open("basic_circuit_proof_17_76.json").unwrap()).unwrap();
    //         let padding_proof_public_input = padding_proof.inputs[0];

    //         padding_public_inputs.push(padding_proof_public_input);
    //         padding_proofs.push(padding_proof);
    //     }

    //     let config = (
    //         splitting_factor,
    //         rns_params.clone(),
    //         aggregation_params.clone(),
    //         padding_vk_committment,
    //         padding_vk_encoding.clone(),
    //         padding_public_inputs.clone(),
    //         padding_proofs.clone(),
    //         None,
    //     );

    //     let circuit = ZkSyncUniformCircuitCircuitInstance::<_, LeafAggregationInstanceSynthesisFunction>::new(
    //         None,
    //         config,
    //         round_function.clone(),
    //         None,
    //     );

    //     circuit.synthesize(&mut setup_assembly).unwrap();

    //     let n = setup_assembly.n();
    //     gates.push(n);
    // }

    // // linear approximation

    // let mut per_round_gates = (gates[1] - gates[0]) / (typical_sizes[1] - typical_sizes[0]);

    // if (gates[1] - gates[0]) % (typical_sizes[1] - typical_sizes[0]) != 0 {
    //     println!("non-linear!");
    //     per_round_gates += 1;
    // }

    // println!("Single cycle takes {} gates", per_round_gates);

    // let additive = gates[1] - per_round_gates * typical_sizes[1];

    // println!("O(1) costs = {}", additive);

    // let cycles = (max - additive) / per_round_gates;

    // println!("Can fit {} cycles for circuit type {}", cycles, <LeafAggregationInstanceSynthesisFunction as ZkSyncUniformSynthesisFunction<Bn256>>::description());

    // let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    // let mut setup_assembly = SetupAssembly::<
    //     _,
    //     PlonkCsWidth4WithNextStepAndCustomGatesParams,
    //     SelectorOptimizedWidth4MainGateWithDNext
    // >::new();

    // let splitting_factor = cycles;

    // let mut vk_file_for_json = std::fs::File::open(&"basic_circuit_vk_17.json").unwrap();
    // let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
    // let vk_in_rns = VkInRns {
    //     vk: Some(vk.clone()),
    //     rns_params: &rns_params
    // };
    // let padding_vk_encoding = vk_in_rns.encode().unwrap();
    // let padding_vk_committment = simulate_variable_length_hash(&padding_vk_encoding, &round_function);

    // let mut padding_public_inputs = vec![];
    // let mut padding_proofs = vec![];

    // for _ in 0..splitting_factor {
    //     use crate::bellman::plonk::better_better_cs::proof::Proof;
    //     let padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(std::fs::File::open("basic_circuit_proof_17_76.json").unwrap()).unwrap();
    //     let padding_proof_public_input = padding_proof.inputs[0];

    //     padding_public_inputs.push(padding_proof_public_input);
    //     padding_proofs.push(padding_proof);
    // }

    // let config = (
    //     splitting_factor,
    //     rns_params.clone(),
    //     aggregation_params.clone(),
    //     padding_vk_committment,
    //     padding_vk_encoding.clone(),
    //     padding_public_inputs.clone(),
    //     padding_proofs.clone(),
    //     None,
    // );

    // let circuit = ZkSyncUniformCircuitCircuitInstance::<_, LeafAggregationInstanceSynthesisFunction>::new(
    //     None,
    //     config,
    //     round_function.clone(),
    //     None,
    // );

    // println!("Synthesising largest size");
    // circuit.synthesize(&mut setup_assembly).unwrap();
    // println!("Finaizing largest size");
    // setup_assembly.finalize();

    // // NOTE level

    // // -------------------------------------------

    // let aggregated_by_leaf = 50;

    // // we need any points that have e(p1, g2)*e(p2, g2^x) == 0, so we basically can use two first elements
    // // of the trusted setup
    // let padding_aggregations = {
    //     let crs_mons = circuit_testing::get_trusted_setup::<Bn256>(1<<26);
    //     let mut p1 = crs_mons.g1_bases[1];
    //     use sync_vm::franklin_crypto::bellman::CurveAffine;
    //     p1.negate();
    //     let mut p2 = crs_mons.g1_bases[0];

    //     let mut all_aggregations = vec![];

    //     use sync_vm::franklin_crypto::bellman::PrimeField;
    //     let scalar = crate::bellman::bn256::Fr::from_str("1234567").unwrap(); // any factor that is > 4

    //     for _ in 0..splitting_factor {
    //         let (pair_with_generator_x, pair_with_generator_y) = p1.into_xy_unchecked();
    //         let (pair_with_x_x, pair_with_x_y) = p2.into_xy_unchecked();

    //         let pair_with_generator_x = split_into_limbs(pair_with_generator_x, &rns_params).0.try_into().unwrap();
    //         let pair_with_generator_y = split_into_limbs(pair_with_generator_y, &rns_params).0.try_into().unwrap();
    //         let pair_with_x_x = split_into_limbs(pair_with_x_x, &rns_params).0.try_into().unwrap();
    //         let pair_with_x_y = split_into_limbs(pair_with_x_y, &rns_params).0.try_into().unwrap();

    //         let tuple = (
    //             pair_with_generator_x,
    //             pair_with_generator_y,
    //             pair_with_x_x,
    //             pair_with_x_y,
    //         );

    //         all_aggregations.push(tuple);

    //         use sync_vm::franklin_crypto::bellman::CurveProjective;

    //         let tmp = p1.mul(scalar);
    //         p1 = tmp.into_affine();

    //         let tmp = p2.mul(scalar);
    //         p2 = tmp.into_affine();
    //     }

    //     all_aggregations
    // };

    // let typical_sizes = vec![8, 16];
    // let mut gates = vec![];

    // for size in typical_sizes.iter().cloned() {
    //     let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    //     let mut setup_assembly = SetupAssembly::<
    //         _,
    //         PlonkCsWidth4WithNextStepAndCustomGatesParams,
    //         SelectorOptimizedWidth4MainGateWithDNext
    //     >::new();

    //     let splitting_factor = size;

    //     let mut vk_file_for_json = std::fs::File::open(&"basic_circuit_vk_17.json").unwrap();
    //     let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
    //     let vk_in_rns = VkInRns {
    //         vk: Some(vk.clone()),
    //         rns_params: &rns_params
    //     };
    //     let padding_vk_encoding = vk_in_rns.encode().unwrap();
    //     let padding_vk_committment = simulate_variable_length_hash(&padding_vk_encoding, &round_function);

    //     let mut padding_public_inputs = vec![];
    //     let mut padding_proofs = vec![];

    //     for _ in 0..splitting_factor {
    //         use crate::bellman::plonk::better_better_cs::proof::Proof;
    //         let padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(std::fs::File::open("basic_circuit_proof_17_76.json").unwrap()).unwrap();
    //         let padding_proof_public_input = padding_proof.inputs[0];

    //         padding_public_inputs.push(padding_proof_public_input);
    //         padding_proofs.push(padding_proof);
    //     }

    //     let config = (
    //         splitting_factor,
    //         aggregated_by_leaf,
    //         rns_params.clone(),
    //         aggregation_params.clone(),
    //         padding_vk_committment,
    //         padding_vk_encoding.clone(),
    //         padding_public_inputs.clone(),
    //         padding_proofs.clone(),
    //         padding_aggregations.clone(),
    //         None,
    //     );

    //     let circuit = ZkSyncUniformCircuitCircuitInstance::<_, NodeAggregationInstanceSynthesisFunction>::new(
    //         None,
    //         config,
    //         round_function.clone(),
    //         None,
    //     );

    //     circuit.synthesize(&mut setup_assembly).unwrap();

    //     let n = setup_assembly.n();
    //     gates.push(n);
    // }

    // // linear approximation

    // let mut per_round_gates = (gates[1] - gates[0]) / (typical_sizes[1] - typical_sizes[0]);

    // if (gates[1] - gates[0]) % (typical_sizes[1] - typical_sizes[0]) != 0 {
    //     println!("non-linear!");
    //     per_round_gates += 1;
    // }

    // println!("Single cycle takes {} gates", per_round_gates);

    // let additive = gates[1] - per_round_gates * typical_sizes[1];

    // println!("O(1) costs = {}", additive);

    // let cycles = (max - additive) / per_round_gates;

    // println!("Can fit {} cycles for circuit type {}", cycles, <NodeAggregationInstanceSynthesisFunction as ZkSyncUniformSynthesisFunction<Bn256>>::description());

    // let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    // let mut setup_assembly = SetupAssembly::<
    //     _,
    //     PlonkCsWidth4WithNextStepAndCustomGatesParams,
    //     SelectorOptimizedWidth4MainGateWithDNext
    // >::new();

    // let splitting_factor = cycles;

    // let mut vk_file_for_json = std::fs::File::open(&"basic_circuit_vk_17.json").unwrap();
    // let vk: VerificationKey<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(&mut vk_file_for_json).unwrap();
    // let vk_in_rns = VkInRns {
    //     vk: Some(vk.clone()),
    //     rns_params: &rns_params
    // };
    // let padding_vk_encoding = vk_in_rns.encode().unwrap();
    // let padding_vk_committment = simulate_variable_length_hash(&padding_vk_encoding, &round_function);

    // let mut padding_public_inputs = vec![];
    // let mut padding_proofs = vec![];

    // for _ in 0..splitting_factor {
    //     use crate::bellman::plonk::better_better_cs::proof::Proof;
    //     let padding_proof: Proof<Bn256, ZkSyncParametricCircuit<Bn256>> = serde_json::from_reader(std::fs::File::open("basic_circuit_proof_17_76.json").unwrap()).unwrap();
    //     let padding_proof_public_input = padding_proof.inputs[0];

    //     padding_public_inputs.push(padding_proof_public_input);
    //     padding_proofs.push(padding_proof);
    // }

    // let config = (
    //     splitting_factor,
    //     aggregated_by_leaf,
    //     rns_params.clone(),
    //     aggregation_params.clone(),
    //     padding_vk_committment,
    //     padding_vk_encoding.clone(),
    //     padding_public_inputs.clone(),
    //     padding_proofs.clone(),
    //     padding_aggregations.clone(),
    //     None,
    // );

    // let circuit = ZkSyncUniformCircuitCircuitInstance::<_, NodeAggregationInstanceSynthesisFunction>::new(
    //     None,
    //     config,
    //     round_function.clone(),
    //     None,
    // );

    // println!("Synthesising largest size");
    // circuit.synthesize(&mut setup_assembly).unwrap();
    // println!("Finaizing largest size");
    // setup_assembly.finalize();
}
