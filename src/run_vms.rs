use crate::blake2::Blake2s256;
use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::gadgets::traits::allocatable::*;
use crate::entry_point::*;
use crate::snark_wrapper::boojum::field::goldilocks::GoldilocksExt2;
use crate::snark_wrapper::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::toolset::create_tools;
use crate::toolset::GeometryConfig;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::oracle::WitnessGenerationArtifact;
use crate::witness::tracer::tracer::WitnessTracer;
use crate::witness::tree::BinarySparseStorageTree;
use crate::witness::tree::ZkSyncStorageLeaf;
use crate::witness::utils::{
    take_queue_state_from_simulator, take_sponge_like_queue_state_from_simulator,
};
use crate::zk_evm::abstractions::Storage;
use crate::zk_evm::abstractions::*;
use crate::zk_evm::aux_structures::*;
use crate::zk_evm::bytecode_to_code_hash;
use crate::zk_evm::contract_bytecode_to_words;
use crate::zk_evm::witness_trace::VmWitnessTracer;
use crate::zk_evm::GenericNoopTracer;
use crate::zkevm_circuits::linear_hasher::input::LinearHasherOutputDataWitness;
use crate::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness;
use crate::zkevm_circuits::{
    base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH,
    eip_4844::input::*,
    scheduler::{block_header::MAX_4844_BLOBS_PER_BLOCK, input::SchedulerCircuitInstanceWitness},
};
use crate::{
    ethereum_types::{Address, U256},
    utils::{calldata_to_aligned_data, u64_as_u32_le},
};
use circuit_definitions::boojum::field::Field;
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::zk_evm::reference_impls::memory::SimpleMemory;
use circuit_definitions::zk_evm::tracing::Tracer;
use circuit_definitions::zk_evm::zkevm_opcode_defs::VersionedHashLen32;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::{Field as MainField, ZkSyncDefaultRoundFunction};
use std::collections::VecDeque;

pub const SCHEDULER_TIMESTAMP: u32 = 1;

#[derive(Debug)]
pub enum RunVmError {
    InvalidInput(String),
    OutOfCircuitExecutionError(String),
}

pub type RunVMsResult = (
    SchedulerCircuitInstanceWitness<MainField, CircuitGoldilocksPoseidon2Sponge, GoldilocksExt2>,
    BlockAuxilaryOutputWitness<MainField>,
);

/// Executes a given set of instructions, and returns things necessary to do the proving:
/// - all circuits as a callback
/// - circuit recursion queues and associated inputs as a callback
/// - partial witness for the scheduler circuit (later we have to add proof witnesses for the nodes)
/// - witness with AUX data (with information that might be useful during verification to generate the public input)
///
/// This function will setup the environment and will run out-of-circuit and then in-circuit
pub fn run_vms<S: Storage, CB: FnMut(WitnessGenerationArtifact)>(
    caller: Address,                 // for real block must be zero
    entry_point_address: Address,    // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read block must be a bootloader code
    initial_heap_content: Vec<u8>,   // bootloader starts with non-deterministic heap
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    evm_simulator_code_hash: U256,
    used_bytecodes: std::collections::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    ram_verification_queries: Vec<(u32, U256)>, // we may need to check that after the bootloader's memory is filled
    cycle_limit: usize,
    geometry: GeometryConfig,
    storage: S,
    tree: impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    trusted_setup_path: &str,
    eip_4844_repack_inputs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
    artifacts_callback: CB,
    out_of_circuit_tracer: &mut impl Tracer<SupportedMemory = SimpleMemory>,
) -> Result<RunVMsResult, RunVmError> {
    let round_function = ZkSyncDefaultRoundFunction::default();

    if zk_porter_is_available {
        return Err(RunVmError::InvalidInput("zk porter not allowed".to_owned()));
    }

    if !ram_verification_queries.is_empty() {
        return Err(RunVmError::InvalidInput("ram_verification_queries isn't empty; for now it's implemented such that we do not need it".to_owned()));
    }

    let initial_rollup_root = tree.root();
    let initial_rollup_enumeration_counter = tree.next_enumeration_index();

    let bytecode_hash = bytecode_to_code_hash(&entry_point_code).unwrap();

    let mut tools = create_tools(storage, &geometry);

    // fill the tools
    let mut to_fill = vec![];
    let entry_point_code_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    if !used_bytecodes.contains_key(&entry_point_code_hash_as_u256) {
        to_fill.push((
            entry_point_code_hash_as_u256,
            contract_bytecode_to_words(&entry_point_code),
        ));
    }
    for (k, v) in used_bytecodes.into_iter() {
        to_fill.push((k, contract_bytecode_to_words(&v)));
    }
    tools.decommittment_processor.populate(to_fill);

    let heap_writes = calldata_to_aligned_data(&initial_heap_content);
    let num_non_deterministic_heap_queries = heap_writes.len();

    let (header, normalized_preimage) = crate::zk_evm::zkevm_opcode_defs::definitions::versioned_hash::ContractCodeSha256Format::normalize_for_decommitment(&bytecode_hash);

    // bootloader decommit query
    let entry_point_decommittment_query = DecommittmentQuery {
        header,
        normalized_preimage,
        timestamp: Timestamp(SCHEDULER_TIMESTAMP),
        memory_page: MemoryPage(crate::zk_evm::zkevm_opcode_defs::BOOTLOADER_CODE_PAGE),
        decommitted_length: entry_point_code.len() as u16,
        is_fresh: true,
    };

    // manually decommit entry point
    let prepared_entry_point_decommittment_query = tools
        .decommittment_processor
        .prepare_to_decommit(0, entry_point_decommittment_query)
        .expect("must prepare decommit of entry point");
    tools
        .witness_tracer
        .prepare_for_decommittment(0, entry_point_decommittment_query);
    let entry_point_decommittment_query_witness = tools
        .decommittment_processor
        .decommit_into_memory(
            0,
            prepared_entry_point_decommittment_query,
            &mut tools.memory,
        )
        .expect("must execute decommit of entry point");
    let entry_point_decommittment_query_witness = entry_point_decommittment_query_witness.unwrap();
    tools.witness_tracer.execute_decommittment(
        0,
        entry_point_decommittment_query,
        entry_point_decommittment_query_witness.clone(),
    );

    let block_properties = create_out_of_circuit_global_context(
        zk_porter_is_available,
        default_aa_code_hash,
        evm_simulator_code_hash,
    );

    use crate::toolset::create_out_of_circuit_vm;

    let mut out_of_circuit_vm =
        create_out_of_circuit_vm(tools, block_properties, caller, entry_point_address);

    // first there exists non-deterministic writes into the heap of the bootloader's heap and calldata
    // heap

    for (idx, el) in heap_writes.into_iter().enumerate() {
        let query = MemoryQuery {
            timestamp: Timestamp(0),
            location: MemoryLocation {
                memory_type: MemoryType::Heap,
                page: MemoryPage(crate::zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE),
                index: MemoryIndex(idx as u32),
            },
            rw_flag: true,
            value: el,
            value_is_pointer: false,
        };
        out_of_circuit_vm.witness_tracer.add_memory_query(0, query);
        out_of_circuit_vm.memory.execute_partial_query(0, query);
    }

    // tracing::debug!("Running out of circuit for {} cycles", cycle_limit);
    println!("Running out of circuit for {} cycles", cycle_limit);
    let mut next_snapshot_will_capture_end_of_execution = false;
    let mut snapshots_len = None;
    for _cycle in 0..cycle_limit {
        if out_of_circuit_vm.execution_has_ended() {
            // we formally have to let VM run as it resets some of the state in a process
            if next_snapshot_will_capture_end_of_execution == false {
                next_snapshot_will_capture_end_of_execution = true;
                snapshots_len = Some(out_of_circuit_vm.witness_tracer.vm_snapshots.len());
            } else {
                if snapshots_len.unwrap() != out_of_circuit_vm.witness_tracer.vm_snapshots.len() {
                    // snapshot has captured the final state
                    break;
                }
            }
        }
        out_of_circuit_vm
            .cycle(out_of_circuit_tracer)
            .expect("cycle should finish succesfully");
    }

    if !out_of_circuit_vm.execution_has_ended() {
        return Err(RunVmError::OutOfCircuitExecutionError(
            "VM execution didn't finish".to_owned(),
        ));
    }
    if out_of_circuit_vm.local_state.callstack.current.pc != 0 {
        return Err(RunVmError::OutOfCircuitExecutionError(
            "root frame ended up with panic".to_owned(),
        ));
    }

    println!("Out of circuit tracing is complete, now running witness generation");

    let vm_local_state = out_of_circuit_vm.local_state.clone();

    if !next_snapshot_will_capture_end_of_execution {
        // perform the final snapshot
        let current_cycle_counter = out_of_circuit_vm.witness_tracer.current_cycle_counter;
        use crate::witness::tracer::vm_snapshot::VmSnapshot;
        let snapshot = VmSnapshot {
            local_state: vm_local_state.clone(),
            at_cycle: current_cycle_counter,
        };
        out_of_circuit_vm.witness_tracer.vm_snapshots.push(snapshot);
    }

    let witness_tracer = out_of_circuit_vm.witness_tracer.clone();
    drop(out_of_circuit_vm);

    let (basic_circuits, compact_form_witnesses, eip4844_circuits) = create_artifacts_from_tracer(
        witness_tracer,
        &round_function,
        &geometry,
        (
            entry_point_decommittment_query,
            entry_point_decommittment_query_witness,
        ),
        tree,
        num_non_deterministic_heap_queries,
        zk_porter_is_available,
        default_aa_code_hash,
        evm_simulator_code_hash,
        eip_4844_repack_inputs.clone(),
        trusted_setup_path,
        artifacts_callback,
    );

    let (scheduler_circuit_witness, aux_data) = {
        use crate::zkevm_circuits::scheduler::block_header::*;
        use crate::zkevm_circuits::scheduler::input::*;

        let prev_rollup_state = PerShardStateWitness {
            enumeration_counter: u64_as_u32_le(initial_rollup_enumeration_counter),
            state_root: initial_rollup_root,
        };

        let prev_porter_state = PerShardStateWitness {
            enumeration_counter: [0; 2],
            state_root: [0u8; 32],
        };

        let previous_block_passthrough = BlockPassthroughDataWitness {
            per_shard_states: [prev_rollup_state, prev_porter_state],
        };

        // now we need parameters and aux
        // parameters

        let block_meta_parameters = BlockMetaParametersWitness {
            bootloader_code_hash: entry_point_code_hash_as_u256,
            default_aa_code_hash: default_aa_code_hash,
            zkporter_is_available: zk_porter_is_available,
            evm_simulator_code_hash: evm_simulator_code_hash,
        };

        use crate::zkevm_circuits::base_structures::vm_state::QUEUE_STATE_WIDTH;

        let t = basic_circuits
            .events_sorter_circuits
            .last
            .as_ref()
            .map(|wit| wit.observable_output.final_queue_state.tail.tail)
            .unwrap_or([MainField::ZERO; QUEUE_STATE_WIDTH]);

        use crate::finalize_queue_state;
        use crate::finalized_queue_state_as_bytes;

        let events_queue_state = finalize_queue_state(t, &round_function);
        let events_queue_state = finalized_queue_state_as_bytes(events_queue_state);

        let t = basic_circuits
            .main_vm_circuits
            .first
            .as_ref()
            .map(|wit| wit.observable_input.memory_queue_initial_state.tail)
            .unwrap_or([MainField::ZERO; FULL_SPONGE_QUEUE_STATE_WIDTH]);

        let bootloader_heap_initial_content = finalize_queue_state(t, &round_function);
        let bootloader_heap_initial_content =
            finalized_queue_state_as_bytes(bootloader_heap_initial_content);

        let rollup_state_diff_for_compression = basic_circuits
            .storage_application_circuits
            .last
            .as_ref()
            .map(|wit| wit.observable_output.state_diffs_keccak256_hash)
            .unwrap_or([0u8; 32]);

        let l1_messages_linear_hash = basic_circuits
            .l1_messages_hasher_circuits
            .last
            .as_ref()
            .map(|wit| wit.observable_output.keccak256_hash)
            .unwrap_or([0u8; 32]);

        // aux
        let aux_data = BlockAuxilaryOutputWitness::<MainField> {
            events_queue_state,
            bootloader_heap_initial_content,
            rollup_state_diff_for_compression,
            l1_messages_linear_hash: l1_messages_linear_hash,
            eip4844_linear_hashes: [[0u8; 32]; MAX_4844_BLOBS_PER_BLOCK],
            eip4844_output_commitment_hashes: [[0u8; 32]; MAX_4844_BLOBS_PER_BLOCK],
        };

        // here we perform a logic that is similar to what is in scheduler when we require of some circuit type is skipped, then
        // we ignore/constraint it's output

        // VM can not be skipped

        use crate::witness::artifacts::LogQueueStates;
        use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;

        let empty_log_queue_state = take_queue_state_from_simulator(
            &LogQueueStates::<GoldilocksField>::default().simulator,
        );
        let empty_sponge_like_queue_state = take_sponge_like_queue_state_from_simulator(
            &MemoryQueueSimulator::<GoldilocksField>::empty(),
        );

        // decommitter must output empty sequence (unreachable in practice, but still...)
        let decommits_sorter_observable_output = if let Some(last) =
            basic_circuits.code_decommittments_sorter_circuits.last
        {
            let observable_output = last.observable_output;

            observable_output
        } else {
            // form it manually
            use crate::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorOutputDataWitness;
            CodeDecommittmentsDeduplicatorOutputDataWitness::<GoldilocksField> {
                final_queue_state: empty_sponge_like_queue_state.clone(),
            }
        };

        // decommitter must produce the same memory sequence
        let code_decommitter_observable_output = if let Some(last) =
            basic_circuits.code_decommitter_circuits.last
        {
            let observable_output = last.observable_output;

            observable_output
        } else {
            // form it manually
            use crate::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterOutputDataWitness;
            CodeDecommitterOutputDataWitness::<GoldilocksField> {
                memory_queue_final_state: empty_sponge_like_queue_state.clone(),
            }
        };

        // demux must produce empty output
        let log_demuxer_observable_output =
            if let Some(last) = basic_circuits.log_demux_circuits.last {
                let observable_output = last.observable_output;

                observable_output
            } else {
                // form it manually
                use crate::zkevm_circuits::demux_log_queue::input::LogDemuxerOutputDataWitness;
                LogDemuxerOutputDataWitness::<GoldilocksField> {
                    output_queue_states: std::array::from_fn(|_| empty_log_queue_state.clone()),
                }
            };

        // all precompiles must output the same memory sequence
        use crate::zkevm_circuits::base_structures::precompile_input_outputs::{
            PrecompileFunctionOutputData, PrecompileFunctionOutputDataWitness,
        };
        let dummy_precompile_output =
            PrecompileFunctionOutputData::<GoldilocksField>::placeholder_witness();
        let mut outputs = std::array::from_fn(|_| dummy_precompile_output.clone());
        let mut previous_memory_state = code_decommitter_observable_output
            .memory_queue_final_state
            .clone();
        let testsing_locations = [
            basic_circuits
                .keccak_precompile_circuits
                .last
                .as_ref()
                .map(|wit| wit.observable_output.clone()),
            basic_circuits
                .sha256_precompile_circuits
                .last
                .as_ref()
                .map(|wit| wit.observable_output.clone()),
            basic_circuits
                .ecrecover_precompile_circuits
                .last
                .as_ref()
                .map(|wit| wit.observable_output.clone()),
            basic_circuits
                .secp256r1_verify_circuits
                .last
                .as_ref()
                .map(|wit| wit.observable_output.clone()),
        ];

        for (dst, src) in outputs.iter_mut().zip(testsing_locations.into_iter()) {
            if let Some(last) = src {
                *dst = last;
            } else {
                *dst = PrecompileFunctionOutputDataWitness {
                    final_memory_state: previous_memory_state.clone(),
                };
            }
            previous_memory_state = dst.final_memory_state.clone();
        }

        let [keccak256_observable_output, sha256_observable_output, ecrecover_observable_output, secp256r1_verify_observable_output] =
            outputs;

        // storage sorter must produce empty output
        let storage_sorter_observable_output = if let Some(last) =
            basic_circuits.storage_sorter_circuits.last
        {
            let observable_output = last.observable_output;

            observable_output
        } else {
            // form it manually
            use crate::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorOutputDataWitness;
            StorageDeduplicatorOutputDataWitness::<GoldilocksField> {
                final_sorted_queue_state: empty_log_queue_state.clone(),
            }
        };

        // storage application must return the same root
        let storage_application_observable_output = if let Some(last) =
            basic_circuits.storage_application_circuits.last
        {
            let observable_output = last.observable_output;

            observable_output
        } else {
            // form it manually
            use crate::zkevm_circuits::storage_application::input::StorageApplicationOutputDataWitness;
            StorageApplicationOutputDataWitness::<GoldilocksField> {
                new_root_hash: initial_rollup_root,
                new_next_enumeration_counter: u64_as_u32_le(initial_rollup_enumeration_counter),
                state_diffs_keccak256_hash: [0u8; 32],
            }
        };

        // event sorter must produce an empty queue
        let events_sorter_observable_output =
            if let Some(last) = basic_circuits.events_sorter_circuits.last {
                let observable_output = last.observable_output;

                observable_output
            } else {
                // form it manually
                use crate::zkevm_circuits::log_sorter::input::EventsDeduplicatorOutputDataWitness;
                EventsDeduplicatorOutputDataWitness::<GoldilocksField> {
                    final_queue_state: empty_log_queue_state.clone(),
                }
            };

        // same for L2 to L1 logs
        let l1messages_sorter_observable_output =
            if let Some(last) = basic_circuits.l1_messages_sorter_circuits.last {
                let observable_output = last.observable_output;

                observable_output
            } else {
                // form it manually
                use crate::zkevm_circuits::log_sorter::input::EventsDeduplicatorOutputDataWitness;
                EventsDeduplicatorOutputDataWitness::<GoldilocksField> {
                    final_queue_state: empty_log_queue_state.clone(),
                }
            };

        // also create intermediate queue states if needed
        let ram_sorted_queue_state = if let Some(state) = basic_circuits
            .ram_permutation_circuits
            .first
            .map(|wit| wit.observable_input.sorted_queue_initial_state)
        {
            state.tail
        } else {
            empty_sponge_like_queue_state.clone().tail
        };

        let decommits_sorter_intermediate_queue_state = if let Some(state) = basic_circuits
            .code_decommittments_sorter_circuits
            .first
            .map(|wit| wit.observable_input.sorted_queue_initial_state)
        {
            state.tail
        } else {
            empty_sponge_like_queue_state.clone().tail
        };

        let events_sorter_intermediate_queue_state = if let Some(state) = basic_circuits
            .events_sorter_circuits
            .first
            .map(|wit| wit.observable_input.intermediate_sorted_queue_state)
        {
            state.tail
        } else {
            empty_log_queue_state.clone().tail
        };

        let l1messages_sorter_intermediate_queue_state = if let Some(state) = basic_circuits
            .l1_messages_sorter_circuits
            .first
            .map(|wit| wit.observable_input.intermediate_sorted_queue_state)
        {
            state.tail
        } else {
            empty_log_queue_state.clone().tail
        };

        let rollup_storage_sorter_intermediate_queue_state = if let Some(state) = basic_circuits
            .storage_sorter_circuits
            .first
            .map(|wit| wit.observable_input.intermediate_sorted_queue_state)
        {
            state.tail
        } else {
            empty_log_queue_state.clone().tail
        };

        let transient_storage_sorter_intermediate_queue_state = if let Some(state) = basic_circuits
            .transient_storage_sorter_circuits
            .first
            .map(|wit| wit.observable_input.intermediate_sorted_queue_state)
        {
            state.tail
        } else {
            empty_log_queue_state.clone().tail
        };

        let l1messages_linear_hasher_observable_output =
            if let Some(last) = basic_circuits.l1_messages_hasher_circuits.last {
                last.observable_output
            } else {
                let mut empty_digest = [0u8; 32];
                use crate::zk_evm::zkevm_opcode_defs::sha3::{Digest, Keccak256};
                let mut hasher = Keccak256::new();
                hasher.update(&[]);
                let digest = hasher.finalize();
                empty_digest.copy_from_slice(digest.as_slice());
                LinearHasherOutputDataWitness {
                    keccak256_hash: empty_digest,
                }
            };

        let mut eip4844_witnesses: [Option<EIP4844OutputDataWitness<GoldilocksField>>;
            MAX_4844_BLOBS_PER_BLOCK] = std::array::from_fn(|_| None);
        for (eip4844_circuit, dst) in eip4844_circuits
            .into_iter()
            .zip(eip4844_witnesses.iter_mut())
        {
            *dst = Some(eip4844_circuit.closed_form_input.observable_output)
        }

        let scheduler_circuit_witness = SchedulerCircuitInstanceWitness {
            prev_block_data: previous_block_passthrough,
            block_meta_parameters,
            // at least one exists
            vm_end_of_execution_observable_output: basic_circuits
                .main_vm_circuits
                .last
                .unwrap()
                .observable_output,
            decommits_sorter_observable_output,
            code_decommitter_observable_output,
            log_demuxer_observable_output,
            keccak256_observable_output,
            sha256_observable_output,
            ecrecover_observable_output,
            secp256r1_verify_observable_output,
            storage_sorter_observable_output,
            storage_application_observable_output,
            events_sorter_observable_output,
            l1messages_sorter_observable_output,
            l1messages_linear_hasher_observable_output,
            // global value
            storage_log_tail: basic_circuits
                .main_vm_circuits
                .first
                .as_ref()
                .unwrap()
                .observable_input
                .rollback_queue_tail_for_block,
            per_circuit_closed_form_inputs: compact_form_witnesses.into(),

            // always exists
            bootloader_heap_memory_state: basic_circuits
                .main_vm_circuits
                .first
                .unwrap()
                .observable_input
                .memory_queue_initial_state,
            ram_sorted_queue_state,
            decommits_sorter_intermediate_queue_state,
            events_sorter_intermediate_queue_state,
            l1messages_sorter_intermediate_queue_state,
            rollup_storage_sorter_intermediate_queue_state,
            transient_storage_sorter_intermediate_queue_state,

            previous_block_meta_hash: [0u8; 32],
            previous_block_aux_hash: [0u8; 32],

            eip4844_witnesses,

            proof_witnesses: VecDeque::new(),
        };

        (scheduler_circuit_witness, aux_data)
    };

    Ok((scheduler_circuit_witness, aux_data))
}
