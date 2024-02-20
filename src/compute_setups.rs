use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::{
    aux_definitions::witness_oracle::VmWitnessOracle,
    circuit_definitions::{
        base_layer::{
            ZkSyncBaseLayerCircuit, ZkSyncBaseLayerFinalizationHint, ZkSyncBaseLayerProof,
            ZkSyncBaseLayerVerificationKey,
        },
        eip4844::EIP4844Circuit,
        ZkSyncUniformCircuitInstance,
    },
    eip4844_proof_config, recursion_layer_proof_config,
    zkevm_circuits::eip_4844::input::EIP4844OutputDataWitness,
    zkevm_circuits::scheduler::aux::BaseLayerCircuitType,
    EIP4844_CYCLE_LIMIT, RECURSION_LAYER_CAP_SIZE, RECURSION_LAYER_FRI_LDE_FACTOR,
};

use crossbeam::atomic::AtomicCell;

use self::toolset::GeometryConfig;

use super::*;
use crate::boojum::{
    algebraic_props::{round_function::AbsorptionModeOverwrite, sponge::GoldilocksPoseidon2Sponge},
    cs::{
        implementations::{
            hints::{DenseVariablesCopyHint, DenseWitnessCopyHint},
            polynomial_storage::{SetupBaseStorage, SetupStorage},
            pow::NoPow,
            prover::ProofConfig,
            setup::FinalizationHintsForProver,
            verifier::VerificationKey,
        },
        oracle::merkle_tree::MerkleTreeWithCap,
    },
    worker::Worker,
};

use crate::data_source::SetupDataSource;
use crate::tests::complex_tests::generate_base_layer;
use crate::zkevm_circuits::base_structures::vm_state::{
    FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH,
};
use crate::{
    data_source::local_file_data_source::LocalFileDataSource, tests::complex_tests::utils::*,
};
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::node_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::*;
use circuit_definitions::{
    base_layer_proof_config, BASE_LAYER_CAP_SIZE, BASE_LAYER_FRI_LDE_FACTOR,
};
use std::collections::VecDeque;

use crate::prover_utils::*;

/// Returns all types of basic circuits, with empty witnesses.
/// Can be used for things like verification key generation.
fn get_all_basic_circuits(
    geometry: &GeometryConfig,
) -> Vec<
    ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, Poseidon2Goldilocks>,
> {
    vec![
        ZkSyncBaseLayerCircuit::MainVM(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_code_decommitter_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::CodeDecommitter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),

            config: Arc::new(geometry.cycles_per_code_decommitter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::LogDemuxer(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_log_demuxer as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_keccak256_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_sha256_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::ECRecover(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_ecrecover_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::RAMPermutation(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_ram_permutation as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::StorageSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_storage_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::StorageApplication(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_storage_application as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::EventsSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_events_or_l1_messages_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::L1MessagesSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_events_or_l1_messages_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::L1MessagesHasher(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.limit_for_l1_messages_pudata_hasher as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
    ]
}

/// Returns all the recursive circuits (including leaves, nodes and scheduler).
/// Source must contain the verification keys for basic layer, leaf and node.
fn get_all_recursive_circuits(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<ZkSyncRecursiveLayerCircuit>> {
    let mut result = get_leaf_circuits(source)?;

    result.push(get_node_circuit(source)?);
    result.push(get_scheduler_circuit(source)?);
    return Ok(result);
}

/// Returns all the leaf circuits.
fn get_leaf_circuits(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<ZkSyncRecursiveLayerCircuit>> {
    let mut result = vec![];

    for base_circuit_type in
        (BaseLayerCircuitType::VM as u8)..=(BaseLayerCircuitType::L1MessagesHasher as u8)
    {
        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(base_circuit_type),
        );

        println!(
            "Computing leaf layer VK for type {:?}",
            recursive_circuit_type
        );
        use crate::zkevm_circuits::recursion::leaf_layer::input::*;
        let input = RecursionLeafInput::placeholder_witness();
        let vk = source.get_base_layer_vk(base_circuit_type)?;

        use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
        let witness = RecursionLeafInstanceWitness {
            input,
            vk_witness: vk.clone().into_inner(),
            queue_witness: FullStateCircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
            proof_witnesses: VecDeque::new(),
        };

        use crate::zkevm_circuits::recursion::leaf_layer::LeafLayerRecursionConfig;
        let config = LeafLayerRecursionConfig {
            proof_config: recursion_layer_proof_config(),
            vk_fixed_parameters: vk.into_inner().fixed_parameters,
            capacity: RECURSION_ARITY,
            _marker: std::marker::PhantomData,
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
            circuit,
        );
        result.push(circuit);
    }
    return Ok(result);
}

/// Returns the node circuit.
/// Source must contain the leaf verification key (for at least one).
fn get_node_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::recursion::node_layer::input::*;
    let input = RecursionNodeInput::placeholder_witness();
    let vk = source
        .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8)?;

    // the only thing to setup here is to have proper number of split points
    use crate::boojum::gadgets::queue::QueueTailState;
    let split_points = vec![
            QueueTailState::<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder_witness();
            RECURSION_ARITY - 1
        ];
    let witness = RecursionNodeInstanceWitness {
        input,
        vk_witness: vk.clone().into_inner(),
        split_points: split_points.into(),
        proof_witnesses: VecDeque::new(),
    };

    use crate::zkevm_circuits::recursion::node_layer::NodeLayerRecursionConfig;
    use circuit_definitions::circuit_definitions::recursion_layer::node_layer::ZkSyncNodeLayerRecursiveCircuit;
    let config = NodeLayerRecursionConfig {
        proof_config: recursion_layer_proof_config(),
        vk_fixed_parameters: vk.into_inner().fixed_parameters,
        leaf_layer_capacity: RECURSION_ARITY,
        node_layer_capacity: RECURSION_ARITY,
        _marker: std::marker::PhantomData,
    };
    let circuit = ZkSyncNodeLayerRecursiveCircuit {
        witness,
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    Ok(ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(circuit))
}

/// Returns the scheduler circuit.
/// Source must contain the node verification key.
fn get_scheduler_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::scheduler::SchedulerConfig;
    use circuit_definitions::circuit_definitions::recursion_layer::scheduler::SchedulerCircuit;

    let node_vk = source.get_recursion_layer_node_vk()?.into_inner();

    let config = SchedulerConfig {
        proof_config: recursion_layer_proof_config(),
        vk_fixed_parameters: node_vk.fixed_parameters.clone(),
        capacity: SCHEDULER_CAPACITY,
        _marker: std::marker::PhantomData,
    };

    use crate::zkevm_circuits::scheduler::input::SchedulerCircuitInstanceWitness;
    let mut scheduler_witness = SchedulerCircuitInstanceWitness::placeholder();
    // the only thing we need to setup here is a VK
    scheduler_witness.node_layer_vk_witness = node_vk;
    let eip_output_data_witness = EIP4844OutputDataWitness {
        linear_hash: [0u8; 32],
        output_hash: [0u8; 32],
    };
    scheduler_witness.eip4844_witnesses =
        Some([eip_output_data_witness.clone(), eip_output_data_witness]);

    let scheduler_circuit = SchedulerCircuit {
        witness: scheduler_witness,
        config,
        transcript_params: (),
        eip4844_proof_config: Some(eip4844_proof_config()),
        eip4844_vk_fixed_parameters: Some(source.get_eip4844_vk().unwrap().fixed_parameters),
        eip4844_vk: Some(source.get_eip4844_vk().unwrap()),
        _marker: std::marker::PhantomData,
    };

    Ok(ZkSyncRecursiveLayerCircuit::SchedulerCircuit(
        scheduler_circuit,
    ))
}

/// Contains all the information that prover needs to setup and verify the given circuit.
pub struct CircuitSetupData {
    pub setup_base: SetupBaseStorage<GoldilocksField, GoldilocksField>,
    pub setup: SetupStorage<GoldilocksField, GoldilocksField>,
    pub vk: VerificationKey<GoldilocksField, GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>>,
    pub setup_tree:
        MerkleTreeWithCap<GoldilocksField, GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>>,
    pub vars_hint: DenseVariablesCopyHint,
    pub wits_hint: DenseWitnessCopyHint,
    pub finalization_hint: FinalizationHintsForProver,
}

/// Generate verification, and setup keys for a given circuit type from a base layer.
/// If generating the setup data for recursion layers, the 'source' must have verification keys for basic circuits, leaf and node.
pub fn generate_circuit_setup_data(
    is_base_layer: bool,
    circuit_type: u8,
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<CircuitSetupData> {
    let geometry = crate::geometry_config::get_geometry_config();
    let worker = Worker::new();

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
        if is_base_layer {
            let circuit = get_all_basic_circuits(&geometry)
                .iter()
                .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                .expect(&format!(
                    "Could not find circuit matching {:?}",
                    circuit_type
                ))
                .clone();

            create_base_layer_setup_data(
                circuit,
                &worker,
                BASE_LAYER_FRI_LDE_FACTOR,
                BASE_LAYER_CAP_SIZE,
            )
        } else {
            let circuit = get_all_recursive_circuits(source)?
                .iter()
                .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                .expect(&format!(
                    "Could not find circuit matching {:?}",
                    circuit_type
                ))
                .clone();

            create_recursive_layer_setup_data(
                circuit,
                &worker,
                BASE_LAYER_FRI_LDE_FACTOR,
                BASE_LAYER_CAP_SIZE,
            )
        };

    Ok(CircuitSetupData {
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        wits_hint,
        finalization_hint,
    })
}

/// Generate verification, and setup keys for a 4844 circuit.
// In the current version (1.4.1), this circuit is still a special case.
// In the upcoming version (1.5.0), it will be merged into the regular 'basic' circuits.
pub fn generate_circuit_setup_data_4844() -> crate::data_source::SourceResult<CircuitSetupData> {
    let eip4844_proof_config = eip4844_proof_config();

    let worker = Worker::new();

    let circuit = EIP4844Circuit {
        witness: AtomicCell::new(None),
        config: Arc::new(EIP4844_CYCLE_LIMIT),
        round_function: Arc::new(Poseidon2Goldilocks),
        expected_public_input: None,
    };
    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
        create_eip4844_setup_data(
            circuit.clone(),
            &worker,
            eip4844_proof_config.fri_lde_factor,
            eip4844_proof_config.merkle_tree_cap_size,
        );

    Ok(CircuitSetupData {
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        wits_hint,
        finalization_hint,
    })
}

/// For backwards compatibility (as zksync-era uses this method).
/// For new cases please use generate_base_layer_vks directly.
pub fn generate_base_layer_vks_and_proofs(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    generate_base_layer_vks(source)
}

/// Generate Verification keys for all base layer circuits.
pub fn generate_base_layer_vks(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    let geometry = crate::geometry_config::get_geometry_config();
    let worker = Worker::new();

    for circuit in get_all_basic_circuits(&geometry) {
        let circuit_type = circuit.numeric_circuit_type();

        let (_, _, vk, _, _, _, finalization_hint) = create_base_layer_setup_data(
            circuit,
            &worker,
            BASE_LAYER_FRI_LDE_FACTOR,
            BASE_LAYER_CAP_SIZE,
        );

        let typed_vk = ZkSyncBaseLayerVerificationKey::from_inner(circuit_type, vk.clone());
        let typed_finalization_hint =
            ZkSyncBaseLayerFinalizationHint::from_inner(circuit_type, finalization_hint.clone());

        source.set_base_layer_finalization_hint(typed_finalization_hint)?;
        source.set_base_layer_vk(typed_vk)?;
    }

    Ok(())
}

pub fn generate_recursive_layer_vks_and_proofs(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
    use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
    use circuit_definitions::circuit_definitions::recursion_layer::base_circuit_type_into_recursive_leaf_circuit_type;

    // here we rely ONLY on VKs and proofs from the setup, so we keep the geometries and circuits
    // via padding proofs
    let worker = Worker::new();

    println!("Computing leaf vks");
    for circuit in get_leaf_circuits(source)? {
        println!(
            "Computing leaf layer VK for type {:?}",
            circuit.numeric_circuit_type()
        );

        let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit.clone(),
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        let typed_finalization_hint = ZkSyncRecursionLayerFinalizationHint::from_inner(
            circuit.numeric_circuit_type(),
            finalization_hint.clone(),
        );
        source.set_recursion_layer_finalization_hint(typed_finalization_hint)?;
        let typed_vk = ZkSyncRecursionLayerVerificationKey::from_inner(
            circuit.numeric_circuit_type(),
            vk.clone(),
        );
        source.set_recursion_layer_vk(typed_vk)?;

        println!("Proving!");
        let now = std::time::Instant::now();

        let proof = prove_recursion_layer_circuit::<NoPow>(
            circuit.clone(),
            &worker,
            recursion_layer_proof_config(),
            &setup_base,
            &setup,
            &setup_tree,
            &vk,
            &vars_hint,
            &wits_hint,
            &finalization_hint,
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_recursion_layer_proof::<NoPow>(&circuit, &proof, &vk);

        assert!(is_valid);

        let proof = ZkSyncRecursionLayerProof::from_inner(circuit.numeric_circuit_type(), proof);
        source.set_recursion_layer_leaf_padding_proof(proof)?;
    }

    println!("Computing node vk");

    {
        let circuit = get_node_circuit(source)?;

        let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit.clone(),
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        let typed_finalization_hint =
            ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint.clone());
        source.set_recursion_layer_node_finalization_hint(typed_finalization_hint)?;
        let typed_vk = ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk.clone());
        source.set_recursion_layer_node_vk(typed_vk)?;

        println!("Proving!");
        let now = std::time::Instant::now();

        let proof = prove_recursion_layer_circuit::<NoPow>(
            circuit.clone(),
            &worker,
            recursion_layer_proof_config(),
            &setup_base,
            &setup,
            &setup_tree,
            &vk,
            &vars_hint,
            &wits_hint,
            &finalization_hint,
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_recursion_layer_proof::<NoPow>(&circuit, &proof, &vk);

        assert!(is_valid);

        let proof = ZkSyncRecursionLayerProof::NodeLayerCircuit(proof);
        source.set_recursion_layer_node_padding_proof(proof)?;
    }

    println!("Computing scheduler vk");

    {
        let scheduler_circuit = get_scheduler_circuit(source)?;

        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                scheduler_circuit.clone(),
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        source.set_recursion_layer_vk(ZkSyncRecursionLayerVerificationKey::SchedulerCircuit(
            vk.clone(),
        ))?;
        source.set_recursion_layer_finalization_hint(
            ZkSyncRecursionLayerFinalizationHint::SchedulerCircuit(finalization_hint.clone()),
        )?;
    }

    Ok(())
}

pub fn generate_eip4844_vks(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    let eip4844_proof_config = eip4844_proof_config();

    let worker = Worker::new();

    let circuit = EIP4844Circuit {
        witness: AtomicCell::new(None),
        config: Arc::new(EIP4844_CYCLE_LIMIT),
        round_function: Arc::new(Poseidon2Goldilocks),
        expected_public_input: None,
    };
    let (_, _, vk, _, _, _, _) = create_eip4844_setup_data(
        circuit.clone(),
        &worker,
        eip4844_proof_config.fri_lde_factor,
        eip4844_proof_config.merkle_tree_cap_size,
    );
    source.set_eip4844_vk(vk)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_run_create_base_layer_vks_and_proofs() {
        LocalFileDataSource::create_folders_for_storing_data();
        let mut source = LocalFileDataSource;
        generate_base_layer_vks(&mut source).expect("must compute setup");
    }

    #[test]
    fn test_run_create_eip4844_vks_and_proofs() {
        LocalFileDataSource::create_folders_for_storing_data();
        let mut source = LocalFileDataSource;
        generate_eip4844_vks(&mut source).expect("must compute setup");
    }

    #[test]
    fn test_run_create_recursion_layer_vks_and_proofs() {
        LocalFileDataSource::create_folders_for_storing_data();
        let mut source = LocalFileDataSource;
        generate_recursive_layer_vks_and_proofs(&mut source).expect("must compute setup");
    }
}
