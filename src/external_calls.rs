use crate::{ethereum_types::{Address, U256}, witness::{full_block_artifact::FullBlockArtifacts}, utils::calldata_to_aligned_data};
use sync_vm::{circuit_structures::traits::CircuitArithmeticRoundFunction, franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns, scheduler::SchedulerCircuitInstanceWitness, glue::code_unpacker_sha256::memory_query_updated::MemoryQueriesQueue};
use crate::toolset::GeometryConfig;
use zk_evm::abstractions::Storage;
use crate::toolset::create_tools;
use crate::bellman::bn256::Bn256;
use zk_evm::contract_bytecode_to_words;
use zk_evm::bytecode_to_code_hash;
use zk_evm::aux_structures::*;
use zk_evm::abstractions::*;
use zk_evm::witness_trace::VmWitnessTracer;
use crate::entry_point::*;
use zk_evm::GenericNoopTracer;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::franklin_crypto::plonk::circuit::allocated_num::Num;
use crate::witness::tree::ZKSyncTestingTree;
use crate::witness::full_block_artifact::BlockBasicCircuits;
use blake2::Blake2s256;
use crate::witness::tree::ZkSyncStorageLeaf;
use crate::witness::tree::BinarySparseStorageTree;
use crate::witness::full_block_artifact::BlockBasicCircuitsPublicInputs;
use sync_vm::scheduler::block_header::*;

use sync_vm::circuit_structures::bytes32::Bytes32;
use sync_vm::scheduler::{NUM_MEMORY_QUERIES_TO_VERIFY, SCHEDULER_TIMESTAMP};

/// This is a testing interface that basically will
/// setup the environment and will run out-of-circuit and then in-circuit
/// and perform intermediate tests
pub fn run<R: CircuitArithmeticRoundFunction<Bn256, 2, 3, StateElement = Num<Bn256>>, S: Storage>(
    previous_block_timestamp: u64,
    block_number: u64,
    block_timestamp: u64,
    caller: Address, // for real block must be zero
    entry_point_address: Address, // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read lobkc must be a bootloader code
    initial_heap_content: Vec<u8>, // bootloader starts with non-deterministic heap
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    ergs_per_pubdata_in_block: u32,
    ergs_per_code_word_decommittment: u16,
    used_bytecodes: std::collections::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    calldata: Vec<u8>, // for real block must be empty
    ram_verification_queries: Vec<(u32, U256)>, // we may need to check that after the bootloader's memory is filled
    cycle_limit: usize,
    round_function: R, // used for all queues implementation
    geometry: GeometryConfig,
    storage: S,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
// ) -> FullBlockArtifacts<Bn256> {
) -> (BlockBasicCircuits<Bn256>, BlockBasicCircuitsPublicInputs<Bn256>, SchedulerCircuitInstanceWitness<Bn256>) {
    assert!(zk_porter_is_available == false);
    assert_eq!(ram_verification_queries.len(), 0, "for now it's implemented such that we do not need it");

    assert!(block_number >= 1);

    let initial_rollup_root = tree.root();
    let initial_rollup_enumeration_counter = tree.next_enumeration_index();

    let bytecode_hash = bytecode_to_code_hash(&entry_point_code).unwrap();

    let mut tools = create_tools(storage, &geometry);

    // fill the tools
    let mut to_fill = vec![];
    let entry_point_code_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    to_fill.push((entry_point_code_hash_as_u256, contract_bytecode_to_words(&entry_point_code)));
    for (k, v) in used_bytecodes.into_iter() {
        to_fill.push((k, contract_bytecode_to_words(&v)));
    }
    tools.decommittment_processor.populate(to_fill);

    let heap_writes = calldata_to_aligned_data(&initial_heap_content);
    let calldata_len = calldata.len();
    let calldata = calldata_to_aligned_data(&calldata);
    let num_non_deterministic_heap_queries = heap_writes.len();

    // first there exists non-deterministic writes into the heap of the bootloader's heap and calldata
    // heap

    for (idx, el) in heap_writes.into_iter().enumerate() {
        let query = MemoryQuery { 
            timestamp: Timestamp(0), 
            location: MemoryLocation { memory_type: MemoryType::Heap, page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE), index: MemoryIndex(idx as u32) }, 
            rw_flag: true, 
            is_pended: false, 
            value: el 
        };
        tools.witness_tracer.add_memory_query(0, query);
        tools.memory.execute_partial_query(0, query);
    }

    // calldata
    for (idx, el) in calldata.into_iter().enumerate() {
        let query = MemoryQuery { 
            timestamp: Timestamp(0), 
            location: MemoryLocation { memory_type: MemoryType::Calldata, page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_CALLDATA_PAGE), index: MemoryIndex(idx as u32) }, 
            rw_flag: true, 
            is_pended: false, 
            value: el 
        };
        tools.witness_tracer.add_memory_query(0, query);
        tools.memory.execute_partial_query(0, query);
    }

    let mut memory_verification_queries: Vec<sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueryWitness<Bn256>> = vec![];

    // heap content verification queries
    for (idx, el) in ram_verification_queries.into_iter() {
        let query = MemoryQuery { 
            timestamp: Timestamp(SCHEDULER_TIMESTAMP), 
            location: MemoryLocation { memory_type: MemoryType::Heap, page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE), index: MemoryIndex(idx as u32) }, 
            rw_flag: false, 
            is_pended: false, 
            value: el 
        };
        tools.witness_tracer.add_memory_query(0, query);
        tools.memory.execute_partial_query(0, query);

        use crate::encodings::initial_storage_write::CircuitEquivalentReflection;
        let as_vm_query = query.reflect();
        memory_verification_queries.push(as_vm_query);
    }

    // bootloader decommit query
    let entry_point_decommittment_query = DecommittmentQuery {
        hash: entry_point_code_hash_as_u256,
        timestamp: Timestamp(SCHEDULER_TIMESTAMP),
        memory_page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_CODE_PAGE),
        decommitted_length: entry_point_code.len() as u16,
        is_fresh: true,
    };

    let (entry_point_decommittment_query, entry_point_decommittment_query_witness) = tools.decommittment_processor.decommit_into_memory(
        0,
        entry_point_decommittment_query,
        &mut tools.memory,
    );
    let entry_point_decommittment_query_witness = entry_point_decommittment_query_witness.unwrap();
    tools.witness_tracer.add_decommittment(0, entry_point_decommittment_query, entry_point_decommittment_query_witness.clone());

    let block_properties = create_out_of_circuit_global_context(
        zk_porter_is_available, 
        default_aa_code_hash, 
        ergs_per_pubdata_in_block, 
        ergs_per_code_word_decommittment,
    );

    use crate::toolset::create_out_of_circuit_vm;

    let mut out_of_circuit_vm = create_out_of_circuit_vm(
        &mut tools, 
        &block_properties,
        caller,
        entry_point_address,
    );

    let mut early_breakpoint_after_snapshot = false;
    let mut tracer = GenericNoopTracer::<_>::new();
    println!("Running out of circuit for {} cycles", cycle_limit);
    for _cycle in 0..cycle_limit {
        if out_of_circuit_vm.execution_has_ended() && !out_of_circuit_vm.is_any_pending() {
            if out_of_circuit_vm.witness_tracer.cycle_counter_in_this_snapshot  == 1 {
                println!("Ran for {} cycles", _cycle + 1);
                early_breakpoint_after_snapshot = true;
                break;
            }
        }
        out_of_circuit_vm.cycle(&mut tracer);
    }

    assert_eq!(out_of_circuit_vm.local_state.callstack.current.pc, 0, "root frame ended up with panic");

    let vm_local_state = out_of_circuit_vm.local_state;

    if !early_breakpoint_after_snapshot {
        // perform the final snapshot
        let current_cycle_counter = tools.witness_tracer.current_cycle_counter;
        use crate::witness::vm_snapshot::VmSnapshot;
        let snapshot = VmSnapshot {
            local_state: vm_local_state.clone(),
            at_cycle: current_cycle_counter,
        };
        tools.witness_tracer.vm_snapshots.push(snapshot);
    }

    let (instance_oracles, artifacts) =
        create_artifacts_from_tracer(
            tools.witness_tracer,
            &round_function, 
            &geometry,
            (entry_point_decommittment_query, entry_point_decommittment_query_witness),
            tree,
            num_non_deterministic_heap_queries
        );

    assert!(artifacts.special_initial_decommittment_queries.len() == 1);
    use sync_vm::scheduler::queues::SpongeLikeQueueStateWitness;
    let memory_state_after_bootloader_heap_writes = if num_non_deterministic_heap_queries == 0 {
        // empty
        SpongeLikeQueueStateWitness::<Bn256, 3>::empty()
    } else {
        let full_info = &artifacts.all_memory_queue_states[num_non_deterministic_heap_queries-1];
        let sponge_state = full_info.tail;
        let length = full_info.num_items;

        SpongeLikeQueueStateWitness::<Bn256, 3> {
            length,
            sponge_state
        }
    };
    
    use crate::witness::postprocessing::create_leaf_level_circuits_and_scheduler_witness;

    let (basic_circuits, basic_circuits_inputs, compact_form_witnesses) = create_leaf_level_circuits_and_scheduler_witness(
        zk_porter_is_available,
        default_aa_code_hash,
        ergs_per_pubdata_in_block,
        ergs_per_code_word_decommittment,
        instance_oracles,
        artifacts,
        geometry
    );

    let scheduler_circuit_witness = {
        use sync_vm::circuit_structures::bytes32::Bytes32Witness;

        fn u256_to_bytes32witness_be<E: crate::bellman::Engine>(value: U256) -> Bytes32Witness<E> {
            let mut buffer = [0u8; 32];
            value.to_big_endian(&mut buffer);
            Bytes32Witness::from_bytes_array(&buffer)
        }

        let prev_rollup_state = PerShardStateWitness {
            enumeration_counter: initial_rollup_enumeration_counter,
            state_root: Bytes32Witness::from_bytes_array(&initial_rollup_root),
            _marker: std::marker::PhantomData
        };

        let prev_porter_state = PerShardStateWitness {
            enumeration_counter: 0,
            state_root: Bytes32Witness::from_bytes_array(&[0u8; 32]),
            _marker: std::marker::PhantomData
        };

        let previous_block_passthrough = BlockPassthroughDataWitness { 
            block_number: block_number - 1,
            timestamp: previous_block_timestamp,
            per_shard_states: [prev_rollup_state, prev_porter_state],
            _marker: std::marker::PhantomData
        };

        // now we need parameters and aux
        // parameters
        let block_meta_parameters = BlockMetaParametersWitness {
            bootloader_code_hash: u256_to_bytes32witness_be(entry_point_code_hash_as_u256),
            default_aa_code_hash: u256_to_bytes32witness_be(default_aa_code_hash),
            ergs_per_code_decommittment_word: ergs_per_code_word_decommittment,
            ergs_per_pubdata_byte_in_block: ergs_per_pubdata_in_block,
            zkporter_is_available: zk_porter_is_available,
            timestamp: block_timestamp,
            _marker: std::marker::PhantomData
        };

        // aux
        let _aux_data = BlockAuxilaryOutputWitness {
            l1_messages_linear_hash: basic_circuits.l1_messages_merklizer_circuit.clone_witness().unwrap().closed_form_input.observable_output.linear_hash,
            l1_messages_root: basic_circuits.l1_messages_merklizer_circuit.clone_witness().unwrap().closed_form_input.observable_output.root_hash,
            rollup_initital_writes_pubdata_hash: basic_circuits.initial_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,
            rollup_repeated_writes_pubdata_hash: basic_circuits.repeated_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,
            _marker: std::marker::PhantomData
        };

        let per_circuit_inputs = compact_form_witnesses.clone().into_flattened_set();

        let ram_permutation_full_sorted_state = basic_circuits.ram_permutation_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_input.sorted_queue_initial_state;
        let tail = ram_permutation_full_sorted_state.tail;
        let length = ram_permutation_full_sorted_state.length;

        let ram_permutation_sorted_state = SpongeLikeQueueStateWitness::<Bn256, 3> {
            length,
            sponge_state: tail
        };

        use sync_vm::traits::CSWitnessable;
        use sync_vm::recursion::node_aggregation::NodeAggregationOutputData;

        // let memory_verification_queries: [sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueryWitness<Bn256>; NUM_MEMORY_QUERIES_TO_VERIFY] = memory_verification_queries.try_into().unwrap();

        let scheduler_circuit_witness = SchedulerCircuitInstanceWitness {
            prev_block_data: previous_block_passthrough,
            block_meta_parameters,
            vm_end_of_execution_observable_output: basic_circuits.main_vm_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
            decommits_sorter_observable_output: basic_circuits.code_decommittments_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            code_decommitter_observable_output: basic_circuits.code_decommitter_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
            log_demuxer_observable_output: basic_circuits.log_demux_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            keccak256_observable_output: basic_circuits.keccak_precompile_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
            sha256_observable_output: basic_circuits.sha256_precompile_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
            ecrecover_observable_output: basic_circuits.ecrecover_precompile_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
            storage_sorter_observable_output: basic_circuits.storage_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            storage_application_observable_output: basic_circuits.storage_application_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
            initial_writes_rehasher_observable_output: basic_circuits.initial_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            repeated_writes_rehasher_observable_output: basic_circuits.repeated_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            events_sorter_observable_output: basic_circuits.events_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            l1messages_sorter_observable_output: basic_circuits.l1_messages_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            l1messages_merklizer_observable_output: basic_circuits.l1_messages_merklizer_circuit.clone_witness().unwrap().closed_form_input.observable_output,
            storage_log_tail: basic_circuits.main_vm_circuits.first().unwrap().clone_witness().unwrap().closed_form_input.observable_input.rollback_queue_tail_for_block,
            // memory_queries_to_verify: memory_verification_queries,
            per_circuit_closed_form_inputs: per_circuit_inputs,
            bootloader_heap_memory_state: memory_state_after_bootloader_heap_writes,
            ram_sorted_queue_state: ram_permutation_sorted_state,
            // storage_sorted_queue_state: basic_circuits.storage_sorter_circuit.clone_witness().unwrap().intermediate_sorted_queue_state,
            // events_sorted_queue_state: basic_circuits.events_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_input.sorted_queue_state,
            // l1messages_sorted_queue_state: basic_circuits.l1_messages_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_input.sorted_queue_state,
            rollup_initital_writes_pubdata_hash: basic_circuits.initial_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,
            rollup_repeated_writes_pubdata_hash: basic_circuits.repeated_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,

            previous_block_meta_hash: Bytes32::placeholder_witness(),
            previous_block_aux_hash: Bytes32::placeholder_witness(),
            recursion_node_verification_key_hash: Bytes32::placeholder_witness(),
            recursion_leaf_verification_key_hash: Bytes32::placeholder_witness(),
            all_different_circuits_keys_hash: Bytes32::placeholder_witness(),

            aggregation_result: NodeAggregationOutputData::placeholder_witness(),

            proof_witnesses: vec![],
            vk_encoding_witnesses: vec![],
        };

        scheduler_circuit_witness
    };

    (basic_circuits, basic_circuits_inputs, scheduler_circuit_witness)
}

