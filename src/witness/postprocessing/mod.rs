use super::full_block_artifact::BlockBasicCircuitsPublicInputs;
use super::*;

use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::witness::full_block_artifact::BlockBasicCircuits;
use crate::witness::full_block_artifact::BlockBasicCircuitsPublicCompactFormsWitnesses;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::oracle::VmInstanceWitness;
use crate::witness::utils::*;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::circuit_definitions::base_layer::*;

use crate::boojum::algebraic_props::round_function;
use crossbeam::atomic::AtomicCell;
use std::sync::Arc;

pub const L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH: bool = false;

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::traits::allocatable::CSAllocatableExt;
use crate::boojum::gadgets::traits::round_function::*;

pub fn create_leaf_level_circuits_and_scheduler_witness<
F: SmallField,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>(
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
    vm_instances_witness: Vec<VmInstanceWitness<F, VmWitnessOracle<F>>>,
    artifacts: FullBlockArtifacts<F>,
    geometry: GeometryConfig,
    round_function: &R,
) -> (BlockBasicCircuits<F, R>, BlockBasicCircuitsPublicInputs<F>, BlockBasicCircuitsPublicCompactFormsWitnesses<F>)
where [(); <zkevm_circuits::base_structures::log_query::LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::memory_query::MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::decommit_query::DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    assert!(artifacts.is_processed);

    let FullBlockArtifacts {
        ram_permutation_circuits_data,
        code_decommitter_circuits_data,
        decommittments_deduplicator_circuits_data,
        log_demuxer_circuit_data,
        storage_deduplicator_circuit_data,
        events_deduplicator_circuit_data,
        l1_messages_deduplicator_circuit_data,
        rollup_storage_application_circuit_data,
        keccak256_circuits_data,
        sha256_circuits_data,
        ecrecover_circuits_data,
        l1_messages_linear_hash_data,
        ..
    } = artifacts;

    let round_function = Arc::new(round_function.clone());

    use crate::zkevm_circuits::base_structures::vm_state::GlobalContextWitness;

    let in_circuit_global_context = GlobalContextWitness {
        zkporter_is_available,
        default_aa_code_hash,
    };

    use crate::witness::utils::create_cs_for_witness_generation;
    use crate::witness::utils::simulate_public_input_value_from_witness;

    let mut cs_for_witness_generation = create_cs_for_witness_generation::<F, R>(
        TRACE_LEN_LOG_2_FOR_CALCULATION,
        MAX_VARS_LOG_2_FOR_CALCULATION,
    );

    let mut cycles_used: usize = 0;

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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
    let mut code_decommittments_sorter_circuits_compact_forms_witnesses = vec![];
    let num_instances = decommittments_deduplicator_circuits_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in decommittments_deduplicator_circuits_data
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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

        let instance = CodeDecommittsSorterCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_code_decommitter_sorter as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        code_decommittments_sorter_circuits.push(instance);
        code_decommittments_sorter_circuits_inputs.push(proof_system_input);
        code_decommittments_sorter_circuits_compact_forms_witnesses.push(compact_form_witness);
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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

        let instance = StorageApplicationCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_storage_application as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        storage_application_circuits.push(instance);
        storage_application_circuits_inputs.push(proof_system_input);
        storage_application_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

    // // initial writes rehasher

    // assert!(initial_writes_pubdata_hasher_circuit_data.len() == 1);
    // let circuit_input = initial_writes_pubdata_hasher_circuit_data.into_iter().next().unwrap();

    // let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
    //     circuit_input.closed_form_input.clone(),
    // );

    // let initial_writes_hasher_circuit = InitialStorageWritesPubdataHasherCircuit {
    //     witness: AtomicCell::new(Some(circuit_input)),
    //     config: Arc::new(geometry.limit_for_initial_writes_pubdata_hasher as usize),
    //     round_function: round_function.clone(),
    //     expected_public_input: Some(proof_system_input),
    // };

    // let initial_writes_hasher_circuit_input = proof_system_input;
    // let initial_writes_hasher_circuit_compact_form_witness = compact_form_witness;

    // // repetated writes

    // assert!(repeated_writes_pubdata_hasher_circuit_data.len() == 1);
    // let circuit_input = repeated_writes_pubdata_hasher_circuit_data.into_iter().next().unwrap();

    // let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
    //     circuit_input.closed_form_input.clone(),
    // );

    // let repeated_writes_hasher_circuit = RepeatedStorageWritesPubdataHasherCircuit {
    //     witness: AtomicCell::new(Some(circuit_input)),
    //     config: Arc::new(geometry.limit_for_repeated_writes_pubdata_hasher as usize),
    //     round_function: round_function.clone(),
    //     expected_public_input: Some(proof_system_input),
    // };

    // let repeated_writes_hasher_circuit_input = proof_system_input;
    // let repeated_writes_hasher_circuit_compact_form_witness = compact_form_witness;

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

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

    let mut l1_messages_hasher_circuits = vec![];
    let mut l1_messages_hasher_circuits_inputs = vec![];
    let mut l1_messages_hasher_circuits_compact_forms_witnesses = vec![];
    let num_instances = l1_messages_linear_hash_data.len();
    let mut observable_input = None;
    for (instance_idx, mut circuit_input) in l1_messages_linear_hash_data.into_iter().enumerate() {
        let is_first = instance_idx == 0;
        let _is_last = instance_idx == num_instances - 1;

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation = create_cs_for_witness_generation(
                TRACE_LEN_LOG_2_FOR_CALCULATION,
                MAX_VARS_LOG_2_FOR_CALCULATION,
            );
            cycles_used = 0;
        }

        let instance = L1MessagesHasherCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.limit_for_l1_messages_pudata_hasher as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        l1_messages_hasher_circuits.push(instance);
        l1_messages_hasher_circuits_inputs.push(proof_system_input);
        l1_messages_hasher_circuits_compact_forms_witnesses.push(compact_form_witness);
    }

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
        events_sorter_circuits,
        l1_messages_sorter_circuits,
        l1_messages_hasher_circuits,
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
        events_sorter_circuits: events_sorter_circuits_inputs,
        l1_messages_sorter_circuits: l1_messages_sorter_circuits_inputs,
        l1_messages_hasher_circuits_inputs,
    };

    let basic_circuits_public_inputs = BlockBasicCircuitsPublicCompactFormsWitnesses {
        main_vm_circuits: main_vm_circuits_compact_forms_witnesses,
        code_decommittments_sorter_circuits:
            code_decommittments_sorter_circuits_compact_forms_witnesses,
        code_decommitter_circuits: code_decommitter_circuits_compact_forms_witnesses,
        log_demux_circuits: log_demux_circuits_compact_forms_witnesses,
        keccak_precompile_circuits: keccak_precompile_circuits_compact_forms_witnesses,
        sha256_precompile_circuits: sha256_precompile_circuits_compact_forms_witnesses,
        ecrecover_precompile_circuits: ecrecover_precompile_circuits_compact_forms_witnesses,
        ram_permutation_circuits: ram_permutation_circuits_compact_forms_witnesses,
        storage_sorter_circuits: storage_sorter_circuit_compact_form_witnesses,
        storage_application_circuits: storage_application_circuits_compact_forms_witnesses,
        events_sorter_circuits: events_sorter_circuits_compact_forms_witnesses,
        l1_messages_sorter_circuits: l1_messages_sorter_circuits_compact_forms_witnesses,
        l1_messages_hasher_circuits_compact_forms_witnesses,
    };

    (
        basic_circuits,
        basic_circuits_inputs,
        basic_circuits_public_inputs,
    )
}
