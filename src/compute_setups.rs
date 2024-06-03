//! Functions to compute setup and verification keys for different circuit types.

use std::sync::Arc;

use crate::zkevm_circuits::recursion::leaf_layer::input::RecursionLeafParametersWitness;
use crate::zkevm_circuits::recursion::NUM_BASE_LAYER_CIRCUITS;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::{
    circuit_definitions::{
        base_layer::{
            ZkSyncBaseLayerCircuit, ZkSyncBaseLayerFinalizationHint, ZkSyncBaseLayerVerificationKey,
        },
        ZkSyncUniformCircuitInstance,
    },
    recursion_layer_proof_config,
    zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK,
    zkevm_circuits::scheduler::aux::BaseLayerCircuitType,
    RECURSION_LAYER_CAP_SIZE, RECURSION_LAYER_FRI_LDE_FACTOR,
};

use crossbeam::atomic::AtomicCell;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;

use self::toolset::GeometryConfig;

use super::*;
use crate::boojum::{
    algebraic_props::{round_function::AbsorptionModeOverwrite, sponge::GoldilocksPoseidon2Sponge},
    cs::{
        implementations::{
            hints::{DenseVariablesCopyHint, DenseWitnessCopyHint},
            polynomial_storage::{SetupBaseStorage, SetupStorage},
            setup::FinalizationHintsForProver,
            verifier::VerificationKey,
        },
        oracle::merkle_tree::MerkleTreeWithCap,
    },
    worker::Worker,
};

use crate::data_source::SetupDataSource;
use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;

use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::*;
use circuit_definitions::{BASE_LAYER_CAP_SIZE, BASE_LAYER_FRI_LDE_FACTOR};
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
    generate_base_layer_vks(source, None, || {})
}

/// Returns number of basic verification keys.
pub fn basic_vk_count() -> usize {
    BaseLayerCircuitType::as_iter_u8().count()
}

/// Generate Verification keys for all base layer circuits.
/// num_threads control how many VKs are generated in parallel - each one takes around 30GB of RAM.
/// if not specified, will run them sequencially.
/// CB callback will be called on each finished VK (to track progress).
pub fn generate_base_layer_vks<CB: Fn() + Send + Sync>(
    source: &mut dyn SetupDataSource,
    num_threads: Option<usize>,
    cb: CB,
) -> crate::data_source::SourceResult<()> {
    let geometry = crate::geometry_config::get_geometry_config();
    let worker = Worker::new();

    let num_threads = num_threads.unwrap_or(1);

    let pool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let r: Vec<_> = pool.install(|| {
        get_all_basic_circuits(&geometry)
            .into_par_iter()
            .map(|circuit| {
                let result = generate_vk_and_finalization_hint(circuit, &worker);
                cb();
                result
            })
            .collect()
    });

    for (vk, hint) in r.into_iter() {
        source.set_base_layer_finalization_hint(hint)?;
        source.set_base_layer_vk(vk)?;
    }

    Ok(())
}

fn generate_vk_and_finalization_hint(
    circuit: ZkSyncBaseLayerCircuit,
    worker: &Worker,
) -> (
    ZkSyncBaseLayerVerificationKey,
    ZkSyncBaseLayerFinalizationHint,
) {
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
    (typed_vk, typed_finalization_hint)
}

/// For backwards compatibility (as zksync-era uses this method).
/// For new cases please use generate_recursive_layer_vks directly.
pub fn generate_recursive_layer_vks_and_proofs(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    generate_recursive_layer_vks(source, None, || {})
}

fn generate_vk_and_finalization_hint_for_recursion(
    circuit: ZkSyncRecursiveLayerCircuit,
    worker: &Worker,
) -> (
    ZkSyncRecursionLayerVerificationKey,
    ZkSyncRecursionLayerFinalizationHint,
) {
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

    let typed_vk =
        ZkSyncRecursionLayerVerificationKey::from_inner(numeric_circuit_type, vk.clone());

    let typed_finalization_hint = ZkSyncRecursionLayerFinalizationHint::from_inner(
        numeric_circuit_type,
        finalization_hint.clone(),
    );
    (typed_vk, typed_finalization_hint)
}

/// Returns number of recursive layer verification keys.
pub fn recursive_layer_vk_count() -> usize {
    // Leafs (one per base layer) + node + recursion + scheduler
    basic_vk_count() + 3
}

/// num_threads control how many VKs are generated in parallel - each one takes around 25GB of RAM.
/// if not specified, will run them sequencially.
pub fn generate_recursive_layer_vks<CB: Fn() + Send + Sync>(
    source: &mut dyn SetupDataSource,
    num_threads: Option<usize>,
    cb: CB,
) -> crate::data_source::SourceResult<()> {
    // here we rely ONLY on VKs and proofs from the setup, so we keep the geometries and circuits
    // via padding proofs
    let worker = Worker::new();
    let num_threads = num_threads.unwrap_or(1);

    println!("Computing leaf vks");

    let pool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let leaf_circuits = get_leaf_circuits(source)?;

    let r: Vec<_> = pool.install(|| {
        leaf_circuits
            .into_par_iter()
            .map(|circuit| {
                let result = generate_vk_and_finalization_hint_for_recursion(circuit, &worker);
                cb();
                result
            })
            .collect()
    });

    for (vk, hint) in r.into_iter() {
        source.set_recursion_layer_finalization_hint(hint)?;
        source.set_recursion_layer_vk(vk)?;
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
    cb();

    println!("Computing recursion tip vk");
    generate_recursion_tip_vk(source)?;
    cb();

    println!("Computing scheduler vk");
    generate_scheduler_vk(source)?;
    cb();

    Ok(())
}

pub fn generate_recursion_tip_vk(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    let worker = Worker::new();
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
    Ok(())
}

pub fn generate_scheduler_vk(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    let worker = Worker::new();
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

    Ok(())
}

pub fn compute_leaf_params(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<(u8, RecursionLeafParametersWitness<GoldilocksField>)>> {
    use crate::witness::recursive_aggregation::compute_leaf_params;
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
    use std::sync::Mutex;

    use indicatif::{ProgressBar, ProgressStyle};

    use self::data_source::local_file_data_source::LocalFileDataSource;

    use super::*;

    #[ignore = "too slow"]
    #[test]
    fn test_run_create_base_layer_vks_and_proofs() {
        let mut source = LocalFileDataSource::default();
        source.create_folders_for_storing_data();
        let count = basic_vk_count();
        let progress_bar = ProgressBar::new(count as u64);
        progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})")
        .progress_chars("#>-"));

        let pb = Arc::new(Mutex::new(progress_bar));

        generate_base_layer_vks(&mut source, None, || {
            pb.lock().unwrap().inc(1);
        })
        .expect("must compute setup");
        pb.lock().unwrap().finish_with_message("done");
    }

    #[ignore = "too slow"]
    #[test]
    fn test_run_create_recursion_layer_vks_and_proofs() {
        let mut source = LocalFileDataSource::default();
        source.create_folders_for_storing_data();
        generate_recursive_layer_vks(&mut source, None, || {}).expect("must compute setup");
    }

    #[ignore = "too slow"]
    #[test]
    fn test_generate_recursion_tip() {
        let mut src = LocalFileDataSource::default();
        src.create_folders_for_storing_data();
        let source = &mut src;

        generate_recursion_tip_vk(source).unwrap();
    }

    #[ignore = "too slow"]
    #[test]
    fn test_generate_scheduler() {
        let mut src = LocalFileDataSource::default();
        src.create_folders_for_storing_data();
        let source = &mut src;

        generate_scheduler_vk(source).unwrap();
    }
}
