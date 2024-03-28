use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::zkevm_circuits::recursion::leaf_layer::input::RecursionLeafParametersWitness;
use crate::zkevm_circuits::recursion::NUM_BASE_LAYER_CIRCUITS;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::{
    aux_definitions::witness_oracle::VmWitnessOracle,
    circuit_definitions::{
        base_layer::{
            ZkSyncBaseLayerCircuit, ZkSyncBaseLayerFinalizationHint, ZkSyncBaseLayerProof,
            ZkSyncBaseLayerVerificationKey,
        },
        ZkSyncUniformCircuitInstance,
    },
    recursion_layer_proof_config,
    zkevm_circuits::eip_4844::input::{ELEMENTS_PER_4844_BLOCK, ENCODABLE_BYTES_PER_BLOB},
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
fn get_all_basic_circuits(geometry: &GeometryConfig) -> Vec<ZkSyncBaseLayerCircuit> {
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
        ZkSyncBaseLayerCircuit::TransientStorageSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_transient_storage_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::Secp256r1Verify(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_secp256r1_verify_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::EIP4844Repack(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(ELEMENTS_PER_4844_BLOCK as usize),
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
    result.push(get_recursion_tip_circuit(source)?);
    result.push(get_scheduler_circuit(source)?);
    return Ok(result);
}

/// Returns all the leaf circuits.
fn get_leaf_circuits(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<ZkSyncRecursiveLayerCircuit>> {
    let mut result = vec![];

    for base_circuit_type in ((BaseLayerCircuitType::VM as u8)
        ..=(BaseLayerCircuitType::Secp256r1Verify as u8))
        .chain(std::iter::once(BaseLayerCircuitType::EIP4844Repack as u8))
    {
        let _recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(base_circuit_type),
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

/// Returns the recursion tip circuit
fn get_recursion_tip_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::recursion::recursion_tip::input::*;
    let input = RecursionTipInput::placeholder_witness();
    let vk = source.get_recursion_layer_node_vk()?.into_inner();

    let witness = RecursionTipInstanceWitness {
        input,
        vk_witness: vk.clone(),
        proof_witnesses: VecDeque::new(),
    };

    use crate::zkevm_circuits::recursion::recursion_tip::*;
    use circuit_definitions::circuit_definitions::recursion_layer::recursion_tip::*;

    let config = RecursionTipConfig {
        proof_config: recursion_layer_proof_config(),
        vk_fixed_parameters: vk.fixed_parameters,
        _marker: std::marker::PhantomData,
    };

    let circuit = RecursionTipCircuit {
        witness,
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    Ok(ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(circuit))
}

/// Returns the scheduler circuit.
/// Source must contain the leafs, node and tip verification keys.
fn get_scheduler_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::eip_4844::input::EIP4844OutputDataWitness;
    use crate::zkevm_circuits::scheduler::SchedulerConfig;
    use circuit_definitions::circuit_definitions::recursion_layer::scheduler::SchedulerCircuit;

    println!("Computing leaf params");
    let leaf_layer_params = compute_leaf_params(source)?;
    println!("Obtaining node VK");
    let node_vk = source.get_recursion_layer_node_vk()?.into_inner();
    println!("Obtaining recursion tip VK");
    let recursion_tip_vk = source.get_recursion_tip_vk()?.into_inner();

    let leaf_layer_params: [RecursionLeafParametersWitness<GoldilocksField>;
        NUM_BASE_LAYER_CIRCUITS] = leaf_layer_params
        .into_iter()
        .map(|el| el.1)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let config = SchedulerConfig {
        proof_config: recursion_layer_proof_config(),
        leaf_layer_parameters: leaf_layer_params,
        node_layer_vk: node_vk,
        recursion_tip_vk: recursion_tip_vk.clone(),
        vk_fixed_parameters: recursion_tip_vk.fixed_parameters.clone(),
        capacity: SCHEDULER_CAPACITY,
        _marker: std::marker::PhantomData,
    };

    use crate::zkevm_circuits::scheduler::input::SchedulerCircuitInstanceWitness;
    let scheduler_witness = SchedulerCircuitInstanceWitness::placeholder();

    let scheduler_circuit = SchedulerCircuit {
        witness: scheduler_witness,
        config,
        transcript_params: (),
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

/// For backwards compatibility (as zksync-era uses this method).
/// For new cases please use generate_recursive_layer_vks directly.
pub fn generate_recursive_layer_vks_and_proofs(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    generate_recursive_layer_vks(source)
}

pub fn generate_recursive_layer_vks(
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

        let numeric_circuit_type = circuit.numeric_circuit_type();
        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit,
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        let typed_finalization_hint = ZkSyncRecursionLayerFinalizationHint::from_inner(
            numeric_circuit_type,
            finalization_hint.clone(),
        );
        source.set_recursion_layer_finalization_hint(typed_finalization_hint)?;
        let typed_vk =
            ZkSyncRecursionLayerVerificationKey::from_inner(numeric_circuit_type, vk.clone());
        source.set_recursion_layer_vk(typed_vk)?;
    }

    println!("Computing node vk");

    {
        let circuit = get_node_circuit(source)?;

        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit,
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        let typed_finalization_hint =
            ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint.clone());
        source.set_recursion_layer_node_finalization_hint(typed_finalization_hint)?;
        let typed_vk = ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk.clone());
        source.set_recursion_layer_node_vk(typed_vk)?;
    }

    println!("Computing recursion tip vk");
    {
        let recursion_tip_circuit = get_recursion_tip_circuit(source)?;

        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                recursion_tip_circuit,
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        source.set_recursion_tip_vk(ZkSyncRecursionLayerVerificationKey::RecursionTipCircuit(
            vk.clone(),
        ))?;
        source.set_recursion_tip_finalization_hint(
            ZkSyncRecursionLayerFinalizationHint::RecursionTipCircuit(finalization_hint.clone()),
        )?;
    }

    println!("Computing scheduler vk");

    {
        let scheduler_circuit = get_scheduler_circuit(source)?;

        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                scheduler_circuit,
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

pub fn compute_leaf_params(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<(u8, RecursionLeafParametersWitness<GoldilocksField>)>> {
    use crate::witness::recursive_aggregation::compute_leaf_params;
    use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
    let mut leaf_vk_commits = vec![];

    for circuit_type in ((BaseLayerCircuitType::VM as u8)
        ..=(BaseLayerCircuitType::Secp256r1Verify as u8))
        .chain(std::iter::once(BaseLayerCircuitType::EIP4844Repack as u8))
    {
        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(circuit_type),
        );
        let base_vk = source.get_base_layer_vk(circuit_type)?;
        let leaf_vk = source.get_recursion_layer_vk(recursive_circuit_type as u8)?;
        let params = compute_leaf_params(circuit_type, base_vk, leaf_vk);
        leaf_vk_commits.push((circuit_type, params));
    }

    Ok(leaf_vk_commits)
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
    fn test_run_create_recursion_layer_vks_and_proofs() {
        LocalFileDataSource::create_folders_for_storing_data();
        let mut source = LocalFileDataSource;
        generate_recursive_layer_vks_and_proofs(&mut source).expect("must compute setup");
    }

    #[test]
    fn generate_scheduler() {
        LocalFileDataSource::create_folders_for_storing_data();
        let mut src = LocalFileDataSource;
        let source = &mut src;

        {
            let worker = Worker::new();
            let scheduler_circuit = get_scheduler_circuit(source).unwrap();

            let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
                create_recursive_layer_setup_data(
                    scheduler_circuit,
                    &worker,
                    RECURSION_LAYER_FRI_LDE_FACTOR,
                    RECURSION_LAYER_CAP_SIZE,
                );

            source
                .set_recursion_layer_vk(ZkSyncRecursionLayerVerificationKey::SchedulerCircuit(
                    vk.clone(),
                ))
                .unwrap();
            source
                .set_recursion_layer_finalization_hint(
                    ZkSyncRecursionLayerFinalizationHint::SchedulerCircuit(
                        finalization_hint.clone(),
                    ),
                )
                .unwrap();
        }
    }
}
