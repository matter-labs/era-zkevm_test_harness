use super::*;

use crate::witness::oracle::VmInstanceWitness;
use crate::witness::oracle::VmWitnessOracle;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::full_block_artifact::BlockBasicCircuits;
use crate::toolset::GeometryConfig;
use crate::ethereum_types::U256;

use crate::pairing::bn256::Bn256;
use crate::abstract_zksync_circuit::concrete_circuits::*;

use std::sync::Arc;
use crossbeam::atomic::AtomicCell;

pub fn create_leaf_level_circuits_and_scheduler_witness(
    block_number: u64,
    block_timestamp: u64,
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
    ergs_per_pubdata_in_block: u32,
    ergs_per_word_decommittment: u16,
    vm_instances_witness: Vec<VmInstanceWitness<Bn256, VmWitnessOracle<Bn256>>>, 
    artifacts: FullBlockArtifacts<Bn256>,
    geometry: GeometryConfig,
) -> (BlockBasicCircuits<Bn256>, ()) {
    assert!(artifacts.is_processed);

    let FullBlockArtifacts {
        ram_permutation_circuits_data,
        code_decommitter_circuits_data,
        decommittments_deduplicator_circuits_data,
        log_demuxer_circuit_data,
        storage_deduplicator_circuit_data,
        events_deduplicator_circuit_data,
        l1_messages_deduplicator_circuit_data,
        initial_writes_pubdata_hasher_circuit_data,
        repeated_writes_pubdata_hasher_circuit_data,
        rollup_storage_application_circuit_data,
        keccak256_circuits_data,
        sha256_circuits_data,
        ecrecover_circuits_data,
        l1_messages_merklizer_data,
        ..
    } = artifacts;

    use crate::entry_point::create_in_circuit_global_context;
    use sync_vm::glue::traits::GenericHasher;
    use sync_vm::rescue_poseidon::RescueParams;
    let params = sync_vm::utils::bn254_rescue_params();
    let round_function = GenericHasher::<Bn256, RescueParams<_, 2, 3>, 2, 3>::new_from_params(&params);
    let round_function = Arc::new(round_function);

    let in_circuit_global_context =
        create_in_circuit_global_context::<Bn256>(
            block_number, 
            block_timestamp, 
            zkporter_is_available, 
            default_aa_code_hash,
            ergs_per_pubdata_in_block, 
            ergs_per_word_decommittment,
        );

    use crate::witness::utils::simulate_public_input_value_from_witness;

    // VM

    let mut main_vm_circuits = vec![];
    let num_instances = vm_instances_witness.len();
    let mut observable_input = None;
    for (instance_idx, vm_instance) in vm_instances_witness.into_iter().enumerate() {
        use crate::witness::utils::vm_instance_witness_to_circuit_formal_input;
        let is_first = instance_idx == 0;
        let is_last = instance_idx == num_instances - 1;
        let mut circuit_input = vm_instance_witness_to_circuit_formal_input(
            vm_instance,
            is_first,
            is_last,
            in_circuit_global_context.clone(),
        );

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input = observable_input.as_ref().unwrap().clone();
        }

        let _proof_system_input = simulate_public_input_value_from_witness(
            circuit_input.closed_form_input.clone(),
        );

        let instance = VMMainCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: round_function.clone(),
        };

        main_vm_circuits.push(instance);
    }

    // Code decommitter sorter

    assert!(decommittments_deduplicator_circuits_data.len() == 1);        
    let circuit_input = decommittments_deduplicator_circuits_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let code_decommittments_sorter_circuit = CodeDecommittsSorterCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_code_decommitter_sorter as usize),
        round_function: round_function.clone(),
    };

    // Actual decommitter

    let mut code_decommitter_circuits = vec![];
    let num_instances = code_decommitter_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in code_decommitter_circuits_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input = observable_input.as_ref().unwrap().clone();
        }

        let _proof_system_input = simulate_public_input_value_from_witness(
            circuit_input.closed_form_input.clone(),
        );

        let instance = CodeDecommitterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_code_decommitter as usize),
            round_function: round_function.clone(),
        };

        code_decommitter_circuits.push(instance);
    }

    // log demux

    assert!(log_demuxer_circuit_data.len() == 1);        
    let circuit_input = log_demuxer_circuit_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let log_demux_circuit = LogDemuxerCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_log_demuxer as usize),
        round_function: round_function.clone(),
    };

    // keccak precompiles

    let mut keccak_precompile_circuits = vec![];

    // sha256 precompiels

    let mut sha256_precompile_circuits = vec![];
    
    // ecrecover precompiles

    let mut ecrecover_precompile_circuits = vec![];

    // RAM permutation

    let mut ram_permutation_circuits = vec![];
    let num_instances = ram_permutation_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in ram_permutation_circuits_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input = observable_input.as_ref().unwrap().clone();
        }

        let _proof_system_input = simulate_public_input_value_from_witness(
            circuit_input.closed_form_input.clone(),
        );

        let instance = RAMPermutationCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_ram_permutation as usize),
            round_function: round_function.clone(),
        };

        ram_permutation_circuits.push(instance);
    }

    // storage sorter

    assert!(storage_deduplicator_circuit_data.len() == 1);        
    let circuit_input = storage_deduplicator_circuit_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let storage_sorter_circuit = StorageSorterCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_storage_sorter as usize),
        round_function: round_function.clone(),
    };

    // storage application

    let mut storage_application_circuits = vec![];

    // initial writes rehasher

    assert!(initial_writes_pubdata_hasher_circuit_data.len() == 1);        
    let circuit_input = initial_writes_pubdata_hasher_circuit_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let initial_writes_hasher_circuit = InitialStorageWritesPubdataHasherCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_initial_writes_pubdata_hasher as usize),
        round_function: round_function.clone(),
    };

    // repetated writes

    assert!(repeated_writes_pubdata_hasher_circuit_data.len() == 1);        
    let circuit_input = repeated_writes_pubdata_hasher_circuit_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let repeated_writes_hasher_circuit = RepeatedStorageWritesPubdataHasherCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_repeated_writes_pubdata_hasher as usize),
        round_function: round_function.clone(),
    };

    // events sorter

    assert!(events_deduplicator_circuit_data.len() == 1);        
    let circuit_input = events_deduplicator_circuit_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let events_sorter_circuit = EventsSorterCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_events_or_l1_messages_sorter as usize),
        round_function: round_function.clone(),
    };

    // l1 messages sorter
    
    assert!(l1_messages_deduplicator_circuit_data.len() == 1);        
    let circuit_input = l1_messages_deduplicator_circuit_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let l1_messages_sorter_circuit = L1MessagesSorterCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_events_or_l1_messages_sorter as usize),
        round_function: round_function.clone(),
    };

    // l1 messages merklizer

    assert!(l1_messages_merklizer_data.len() == 1);        
    let circuit_input = l1_messages_merklizer_data.into_iter().next().unwrap();

    let _proof_system_input = simulate_public_input_value_from_witness(
        circuit_input.closed_form_input.clone(),
    );

    let l1_messages_merklizer_circuit = L1MessagesMerklizerCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new((geometry.limit_for_events_or_l1_messages_sorter as usize, true)), // output linear hash too
        round_function: round_function.clone(),
    };

    // done!

    let basic_circuits = BlockBasicCircuits {
        main_vm_circuits,
        code_decommittments_sorter_circuit,
        code_decommitter_circuits,
        log_demux_circuit,
        keccak_precompile_circuits,
        sha256_precompile_circuits,
        ecrecover_precompile_circuits,
        ram_permutation_circuits,
        storage_sorter_circuit,
        storage_application_circuits,
        initial_writes_hasher_circuit,
        repeated_writes_hasher_circuit,
        events_sorter_circuit,
        l1_messages_sorter_circuit,
        l1_messages_merklizer_circuit,
    };

    (basic_circuits, ())
}