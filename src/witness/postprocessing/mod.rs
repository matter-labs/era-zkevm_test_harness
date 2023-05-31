use super::full_block_artifact::BlockBasicCircuitsPublicInputs;
use super::*;

use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::witness::full_block_artifact::BlockBasicCircuits;
use crate::witness::full_block_artifact::BlockBasicCircuitsPublicCompactFormsWitnesses;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::oracle::VmInstanceWitness;
use crate::witness::oracle::VmWitnessOracle;

use crate::abstract_zksync_circuit::concrete_circuits::*;
use crate::pairing::bn256::Bn256;

use crossbeam::atomic::AtomicCell;
use std::sync::Arc;

pub const USE_BLAKE2S_EXTRA_TABLES: bool = true;
pub const L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH: bool = false;

pub fn create_leaf_level_circuits_and_scheduler_witness(
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
    vm_instances_witness: Vec<VmInstanceWitness<Bn256, VmWitnessOracle<Bn256>>>,
    artifacts: FullBlockArtifacts<Bn256>,
    geometry: GeometryConfig,
) -> (
    BlockBasicCircuits<Bn256>,
    BlockBasicCircuitsPublicInputs<Bn256>,
    BlockBasicCircuitsPublicCompactFormsWitnesses<Bn256>,
) {
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
        l1_messages_linear_hash_data,
        ..
    } = artifacts;

    use crate::entry_point::create_in_circuit_global_context;
    use sync_vm::glue::traits::GenericHasher;
    use sync_vm::rescue_poseidon::RescueParams;
    let params = sync_vm::utils::bn254_rescue_params();
    let round_function =
        GenericHasher::<Bn256, RescueParams<_, 2, 3>, 2, 3>::new_from_params(&params);
    let round_function = Arc::new(round_function);

    let in_circuit_global_context =
        create_in_circuit_global_context::<Bn256>(zkporter_is_available, default_aa_code_hash);

    use crate::witness::utils::simulate_public_input_value_from_witness;

    // VM

    let mut main_vm_circuits = vec![];
    let mut main_vm_circuits_inputs = vec![];
    let mut main_vm_circuits_compact_forms_witnesses = vec![];
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
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = VMMainCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        main_vm_circuits.push(instance);
        main_vm_circuits_inputs.push(proof_system_input);
        main_vm_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // Code decommitter sorter

    let mut code_decommittments_sorter_circuits = vec![];
    let mut code_decommittments_sorter_circuits_inputs = vec![];
    let mut code_decommittments_sorter_circuit_compact_forms_witnesses = vec![];
    let num_instances = decommittments_deduplicator_circuits_data.len();
    let mut observable_input = None;
    for (circuit_idx, mut circuit_input) in decommittments_deduplicator_circuits_data.into_iter().enumerate() {

        use crate::witness::utils::vm_instance_witness_to_circuit_formal_input;
        let is_first = circuit_idx == 0;
        let is_last = circuit_idx == num_instances - 1;
        
        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = CodeDecommittsSorterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_code_decommitter_sorter as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        code_decommittments_sorter_circuits.push(instance);
        code_decommittments_sorter_circuits_inputs.push(proof_system_input);
        code_decommittments_sorter_circuit_compact_forms_witnesses.push(compact_form_witness);
    }

    // Actual decommitter

    let mut code_decommitter_circuits = vec![];
    let mut code_decommitter_circuits_inputs = vec![];
    let mut code_decommitter_circuits_compact_forms_witnesses = vec![];
    let num_instances = code_decommitter_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in code_decommitter_circuits_data.into_iter().enumerate()
    {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = CodeDecommitterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_code_decommitter as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        code_decommitter_circuits.push(instance);
        code_decommitter_circuits_inputs.push(proof_system_input);
        code_decommitter_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // log demux

    let mut log_demux_circuits = vec![];
    let mut log_demux_circuits_inputs = vec![];
    let mut log_demux_circuits_compact_forms_witnesses = vec![];
    let num_instances = log_demuxer_circuit_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in log_demuxer_circuit_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = LogDemuxerCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_log_demuxer as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        log_demux_circuits.push(instance);
        log_demux_circuits_inputs.push(proof_system_input);
        log_demux_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // keccak precompiles

    let mut keccak_precompile_circuits = vec![];
    let mut keccak_precompile_circuits_inputs = vec![];
    let mut keccak_precompile_circuits_compact_forms_witnesses = vec![];
    let num_instances = keccak256_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in keccak256_circuits_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = Keccak256RoundFunctionCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_keccak256_circuit as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        keccak_precompile_circuits.push(instance);
        keccak_precompile_circuits_inputs.push(proof_system_input);
        keccak_precompile_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // sha256 precompiels

    let mut sha256_precompile_circuits = vec![];
    let mut sha256_precompile_circuits_inputs = vec![];
    let mut sha256_precompile_circuits_compact_forms_witnesses = vec![];
    let num_instances = sha256_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in sha256_circuits_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = Sha256RoundFunctionCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_sha256_circuit as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        sha256_precompile_circuits.push(instance);
        sha256_precompile_circuits_inputs.push(proof_system_input);
        sha256_precompile_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // ecrecover precompiles

    let mut ecrecover_precompile_circuits = vec![];
    let mut ecrecover_precompile_circuits_inputs = vec![];
    let mut ecrecover_precompile_circuits_compact_forms_witnesses = vec![];
    let num_instances = ecrecover_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in ecrecover_circuits_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = ECRecoverFunctionCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_ecrecover_circuit as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        ecrecover_precompile_circuits.push(instance);
        ecrecover_precompile_circuits_inputs.push(proof_system_input);
        ecrecover_precompile_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // RAM permutation

    let mut ram_permutation_circuits = vec![];
    let mut ram_permutation_circuits_inputs = vec![];
    let mut ram_permutation_circuits_compact_forms_witnesses = vec![];
    let num_instances = ram_permutation_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in ram_permutation_circuits_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = RAMPermutationCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_ram_permutation as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        ram_permutation_circuits.push(instance);
        ram_permutation_circuits_inputs.push(proof_system_input);
        ram_permutation_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // storage sorter

    let mut storage_sorter_circuits = vec![];
    let mut storage_sorter_circuit_inputs = vec![];
    let mut storage_sorter_circuit_compact_form_witnesses = vec![];
    let num_instances = storage_deduplicator_circuit_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in
        storage_deduplicator_circuit_data.into_iter().enumerate()
    {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = StorageSorterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_storage_sorter as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        storage_sorter_circuits.push(instance);
        storage_sorter_circuit_inputs.push(proof_system_input);
        storage_sorter_circuit_compact_form_witnesses.push(compact_form_witness);
    }

    // storage application

    let mut storage_application_circuits = vec![];
    let mut storage_application_circuits_inputs = vec![];
    let mut storage_application_circuits_compact_forms_witnesses = vec![];
    let num_instances = rollup_storage_application_circuit_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in rollup_storage_application_circuit_data
        .into_iter()
        .enumerate()
    {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = StorageApplicationCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new((
                geometry.cycles_per_storage_application as usize,
                USE_BLAKE2S_EXTRA_TABLES,
            )),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        storage_application_circuits.push(instance);
        storage_application_circuits_inputs.push(proof_system_input);
        storage_application_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // initial writes rehasher

    assert!(initial_writes_pubdata_hasher_circuit_data.len() == 1);
    let circuit_input = initial_writes_pubdata_hasher_circuit_data
        .into_iter()
        .next()
        .unwrap();

    let (proof_system_input, compact_form_witness) =
        simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

    let initial_writes_hasher_circuit = InitialStorageWritesPubdataHasherCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_initial_writes_pubdata_hasher as usize),
        round_function: round_function.clone(),
        expected_public_input: Some(proof_system_input),
    };

    let initial_writes_hasher_circuit_input = proof_system_input;
    let initial_writes_hasher_circuit_compact_form_witness = compact_form_witness;

    // repetated writes

    assert!(repeated_writes_pubdata_hasher_circuit_data.len() == 1);
    let circuit_input = repeated_writes_pubdata_hasher_circuit_data
        .into_iter()
        .next()
        .unwrap();

    let (proof_system_input, compact_form_witness) =
        simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

    let repeated_writes_hasher_circuit = RepeatedStorageWritesPubdataHasherCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_repeated_writes_pubdata_hasher as usize),
        round_function: round_function.clone(),
        expected_public_input: Some(proof_system_input),
    };

    let repeated_writes_hasher_circuit_input = proof_system_input;
    let repeated_writes_hasher_circuit_compact_form_witness = compact_form_witness;

    // events sorter

    let mut events_sorter_circuits = vec![];
    let mut events_sorter_circuits_inputs = vec![];
    let mut events_sorter_circuits_compact_forms_witnesses = vec![];
    let num_instances = events_deduplicator_circuit_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in
        events_deduplicator_circuit_data.into_iter().enumerate()
    {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = EventsSorterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_events_or_l1_messages_sorter as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        events_sorter_circuits.push(instance);
        events_sorter_circuits_inputs.push(proof_system_input);
        events_sorter_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // l1 messages sorter

    let mut l1_messages_sorter_circuits = vec![];
    let mut l1_messages_sorter_circuits_inputs = vec![];
    let mut l1_messages_sorter_circuits_compact_forms_witnesses = vec![];
    let num_instances = l1_messages_deduplicator_circuit_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in l1_messages_deduplicator_circuit_data
        .into_iter()
        .enumerate()
    {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

        let instance = L1MessagesSorterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_events_or_l1_messages_sorter as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        l1_messages_sorter_circuits.push(instance);
        l1_messages_sorter_circuits_inputs.push(proof_system_input);
        l1_messages_sorter_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // l1 messages pubdata hasher

    assert!(l1_messages_linear_hash_data.len() == 1);
    let circuit_input = l1_messages_linear_hash_data.into_iter().next().unwrap();

    let (proof_system_input, compact_form_witness) =
        simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

    let l1_messages_pubdata_hasher_circuit = L1MessagesHasherCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new(geometry.limit_for_l1_messages_pudata_hasher as usize),
        round_function: round_function.clone(),
        expected_public_input: Some(proof_system_input),
    };

    let l1_messages_pubdata_hasher_circuit_input = proof_system_input;
    let l1_messages_pubdata_hasher_circuit_compact_form_witness = compact_form_witness;

    // l1 messages merklizer

    assert!(l1_messages_merklizer_data.len() == 1);
    let circuit_input = l1_messages_merklizer_data.into_iter().next().unwrap();

    let (proof_system_input, compact_form_witness) =
        simulate_public_input_value_from_witness(circuit_input.closed_form_input.clone());

    let l1_messages_merklizer_circuit = L1MessagesMerklizerCircuit {
        witness: AtomicCell::new(Some(circuit_input)),
        config: Arc::new((
            geometry.limit_for_l1_messages_merklizer as usize,
            L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH,
        )),
        round_function: round_function.clone(),
        expected_public_input: Some(proof_system_input),
    };

    let l1_messages_merklizer_circuit_input = proof_system_input;
    let l1_messages_merklizer_circuit_compact_form_witness = compact_form_witness;

    // done!

    let basic_circuits = BlockBasicCircuits {
        main_vm_circuits,
        code_decommittments_sorter_circuits,
        code_decommitter_circuits,
        log_demux_circuits,
        keccak_precompile_circuits,
        sha256_precompile_circuits,
        ecrecover_precompile_circuits,
        ram_permutation_circuits,
        storage_sorter_circuits,
        storage_application_circuits,
        initial_writes_hasher_circuit,
        repeated_writes_hasher_circuit,
        events_sorter_circuits,
        l1_messages_sorter_circuits,
        l1_messages_pubdata_hasher_circuit,
        l1_messages_merklizer_circuit,
    };

    let basic_circuits_inputs = BlockBasicCircuitsPublicInputs {
        main_vm_circuits: main_vm_circuits_inputs,
        code_decommittments_sorter_circuits: code_decommittments_sorter_circuits_inputs,
        code_decommitter_circuits: code_decommitter_circuits_inputs,
        log_demux_circuits: log_demux_circuits_inputs,
        keccak_precompile_circuits: keccak_precompile_circuits_inputs,
        sha256_precompile_circuits: sha256_precompile_circuits_inputs,
        ecrecover_precompile_circuits: ecrecover_precompile_circuits_inputs,
        ram_permutation_circuits: ram_permutation_circuits_inputs,
        storage_sorter_circuits: storage_sorter_circuit_inputs,
        storage_application_circuits: storage_application_circuits_inputs,
        initial_writes_hasher_circuit: initial_writes_hasher_circuit_input,
        repeated_writes_hasher_circuit: repeated_writes_hasher_circuit_input,
        events_sorter_circuits: events_sorter_circuits_inputs,
        l1_messages_sorter_circuits: l1_messages_sorter_circuits_inputs,
        l1_messages_pubdata_hasher_circuit: l1_messages_pubdata_hasher_circuit_input,
        l1_messages_merklizer_circuit: l1_messages_merklizer_circuit_input,
    };

    let basic_circuits_public_inputs = BlockBasicCircuitsPublicCompactFormsWitnesses {
        main_vm_circuits: main_vm_circuits_compact_forms_witnesses,
        code_decommittments_sorter_circuits: code_decommittments_sorter_circuit_compact_forms_witnesses,
        code_decommitter_circuits: code_decommitter_circuits_compact_forms_witnesses,
        log_demux_circuits: log_demux_circuits_compact_forms_witnesses,
        keccak_precompile_circuits: keccak_precompile_circuits_compact_forms_witnesses,
        sha256_precompile_circuits: sha256_precompile_circuits_compact_forms_witnesses,
        ecrecover_precompile_circuits: ecrecover_precompile_circuits_compact_forms_witnesses,
        ram_permutation_circuits: ram_permutation_circuits_compact_forms_witnesses,
        storage_sorter_circuits: storage_sorter_circuit_compact_form_witnesses,
        storage_application_circuits: storage_application_circuits_compact_forms_witnesses,
        initial_writes_hasher_circuit: initial_writes_hasher_circuit_compact_form_witness,
        repeated_writes_hasher_circuit: repeated_writes_hasher_circuit_compact_form_witness,
        events_sorter_circuits: events_sorter_circuits_compact_forms_witnesses,
        l1_messages_sorter_circuits: l1_messages_sorter_circuits_compact_forms_witnesses,
        l1_messages_pubdata_hasher_circuit: l1_messages_pubdata_hasher_circuit_compact_form_witness,
        l1_messages_merklizer_circuit: l1_messages_merklizer_circuit_compact_form_witness,
    };

    (
        basic_circuits,
        basic_circuits_inputs,
        basic_circuits_public_inputs,
    )
}
