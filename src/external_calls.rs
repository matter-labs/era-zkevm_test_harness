use crate::{ethereum_types::{Address, U256}, utils::calldata_to_aligned_data};
use crate::toolset::GeometryConfig;
use boojum::{field::{SmallField, goldilocks::GoldilocksField}, cs::implementations::prover::ProofConfig};
use zk_evm::abstractions::Storage;
use crate::toolset::create_tools;
use zk_evm::contract_bytecode_to_words;
use zk_evm::bytecode_to_code_hash;
use zk_evm::aux_structures::*;
use zk_evm::abstractions::*;
use zk_evm::witness_trace::VmWitnessTracer;
use crate::entry_point::*;
use zk_evm::GenericNoopTracer;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::tree::ZKSyncTestingTree;
use crate::witness::full_block_artifact::BlockBasicCircuits;
use crate::blake2::Blake2s256;
use crate::witness::tree::ZkSyncStorageLeaf;
use crate::witness::tree::BinarySparseStorageTree;
use crate::witness::full_block_artifact::BlockBasicCircuitsPublicInputs;
use ::tracing;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::ZkSyncDefaultRoundFunction;
use boojum::gadgets::traits::round_function::BuildableCircuitRoundFunction;
use crate::witness::full_block_artifact::BlockBasicCircuitsPublicCompactFormsWitnesses;

pub const SCHEDULER_TIMESTAMP: u32 = 1;

use crate::witness::oracle::VmInstanceWitness;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use boojum::gadgets::traits::allocatable::*;

/// This is a testing interface that basically will
/// setup the environment and will run out-of-circuit and then in-circuit
/// and perform intermediate tests
pub fn run<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
    S: Storage
>(
    caller: Address, // for real block must be zero
    entry_point_address: Address, // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read lobkc must be a bootloader code
    initial_heap_content: Vec<u8>, // bootloader starts with non-deterministic heap
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    used_bytecodes: std::collections::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    ram_verification_queries: Vec<(u32, U256)>, // we may need to check that after the bootloader's memory is filled
    cycle_limit: usize,
    round_function: R, // used for all queues implementation
    geometry: GeometryConfig,
    storage: S,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
) -> (BlockBasicCircuits<F, R>, BlockBasicCircuitsPublicInputs<F>, BlockBasicCircuitsPublicCompactFormsWitnesses<F>) 
    where [(); <zkevm_circuits::base_structures::log_query::LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::memory_query::MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::decommit_query::DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
// ) -> (BlockBasicCircuits<GoldilocksField>, BlockBasicCircuitsPublicInputs<GoldilocksField>, SchedulerCircuitInstanceWitness<GoldilocksField>) {
// ) -> (Vec<VmInstanceWitness<F, VmWitnessOracle<F>>>, FullBlockArtifacts<F>) {
// ) {
    assert!(zk_porter_is_available == false);
    assert_eq!(ram_verification_queries.len(), 0, "for now it's implemented such that we do not need it");

    let initial_rollup_root = tree.root();
    let initial_rollup_enumeration_counter = tree.next_enumeration_index();

    let bytecode_hash = bytecode_to_code_hash(&entry_point_code).unwrap();

    let mut tools = create_tools(storage, &geometry);

    // fill the tools
    let mut to_fill = vec![];
    let entry_point_code_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    if !used_bytecodes.contains_key(&entry_point_code_hash_as_u256) {
        to_fill.push((entry_point_code_hash_as_u256, contract_bytecode_to_words(&entry_point_code)));
    }
    for (k, v) in used_bytecodes.into_iter() {
        to_fill.push((k, contract_bytecode_to_words(&v)));
    }
    tools.decommittment_processor.populate(to_fill);

    let heap_writes = calldata_to_aligned_data(&initial_heap_content);
    let num_non_deterministic_heap_queries = heap_writes.len();

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
    );

    use crate::toolset::create_out_of_circuit_vm;

    let mut out_of_circuit_vm = create_out_of_circuit_vm(
        &mut tools, 
        &block_properties,
        caller,
        entry_point_address,
    );


    // first there exists non-deterministic writes into the heap of the bootloader's heap and calldata
    // heap

    for (idx, el) in heap_writes.into_iter().enumerate() {
        let query = MemoryQuery { 
            timestamp: Timestamp(0), 
            location: MemoryLocation { memory_type: MemoryType::Heap, page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE), index: MemoryIndex(idx as u32) }, 
            rw_flag: true, 
            value: el,
            value_is_pointer: false,
        };
        out_of_circuit_vm.witness_tracer.add_memory_query(0, query);
        out_of_circuit_vm.memory.execute_partial_query(0, query);
    }

    // let mut memory_verification_queries: Vec<sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueryWitness<Bn256>> = vec![];

    // // heap content verification queries
    // for (idx, el) in ram_verification_queries.into_iter() {
    //     let query = MemoryQuery { 
    //         timestamp: Timestamp(SCHEDULER_TIMESTAMP), 
    //         location: MemoryLocation { memory_type: MemoryType::Heap, page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE), index: MemoryIndex(idx as u32) }, 
    //         rw_flag: false, 
    //         value: el,
    //         value_is_pointer: false,
    //     };
    //     out_of_circuit_vm.witness_tracer.add_memory_query(0, query);
    //     out_of_circuit_vm.memory.execute_partial_query(0, query);

    //     use crate::encodings::initial_storage_write::CircuitEquivalentReflection;
    //     let as_vm_query = query.reflect();
    //     memory_verification_queries.push(as_vm_query);
    // }

    let mut tracer = GenericNoopTracer::<_>::new();
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
        out_of_circuit_vm.cycle(&mut tracer);
    }

    assert!(out_of_circuit_vm.execution_has_ended(), "VM execution didn't finish");
    assert_eq!(out_of_circuit_vm.local_state.callstack.current.pc, 0, "root frame ended up with panic");

    let vm_local_state = out_of_circuit_vm.local_state;

    if !next_snapshot_will_capture_end_of_execution {
        // perform the final snapshot
        let current_cycle_counter = tools.witness_tracer.current_cycle_counter;
        use crate::witness::vm_snapshot::VmSnapshot;
        let snapshot = VmSnapshot {
            local_state: vm_local_state.clone(),
            at_cycle: current_cycle_counter,
        };
        tools.witness_tracer.vm_snapshots.push(snapshot);
    }

    // dbg!(tools.witness_tracer.vm_snapshots.len());

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

    // use sync_vm::scheduler::queues::SpongeLikeQueueStateWitness;
    // let memory_state_after_bootloader_heap_writes = if num_non_deterministic_heap_queries == 0 {
    //     // empty
    //     SpongeLikeQueueStateWitness::<Bn256, 3>::empty()
    // } else {
    //     let full_info = &artifacts.all_memory_queue_states[num_non_deterministic_heap_queries-1];
    //     let sponge_state = full_info.tail;
    //     let length = full_info.num_items;

    //     SpongeLikeQueueStateWitness::<Bn256, 3> {
    //         length,
    //         sponge_state
    //     }
    // };
    
    use crate::witness::postprocessing::create_leaf_level_circuits_and_scheduler_witness;

    let (basic_circuits, basic_circuits_inputs, compact_form_witnesses) = create_leaf_level_circuits_and_scheduler_witness(
        zk_porter_is_available,
        default_aa_code_hash,
        instance_oracles,
        artifacts,
        geometry,
        &round_function
    );

    return (basic_circuits, basic_circuits_inputs, compact_form_witnesses)

    // let scheduler_circuit_witness = {
    //     use sync_vm::circuit_structures::bytes32::Bytes32Witness;

    //     fn u256_to_bytes32witness_be<E: crate::bellman::Engine>(value: U256) -> Bytes32Witness<E> {
    //         let mut buffer = [0u8; 32];
    //         value.to_big_endian(&mut buffer);
    //         Bytes32Witness::from_bytes_array(&buffer)
    //     }

    //     let prev_rollup_state = PerShardStateWitness {
    //         enumeration_counter: initial_rollup_enumeration_counter,
    //         state_root: Bytes32Witness::from_bytes_array(&initial_rollup_root),
    //         _marker: std::marker::PhantomData
    //     };

    //     let prev_porter_state = PerShardStateWitness {
    //         enumeration_counter: 0,
    //         state_root: Bytes32Witness::from_bytes_array(&[0u8; 32]),
    //         _marker: std::marker::PhantomData
    //     };

    //     let previous_block_passthrough = BlockPassthroughDataWitness { 
    //         per_shard_states: [prev_rollup_state, prev_porter_state],
    //         _marker: std::marker::PhantomData
    //     };

    //     // now we need parameters and aux
    //     // parameters
    //     let block_meta_parameters = BlockMetaParametersWitness {
    //         bootloader_code_hash: u256_to_bytes32witness_be(entry_point_code_hash_as_u256),
    //         default_aa_code_hash: u256_to_bytes32witness_be(default_aa_code_hash),
    //         zkporter_is_available: zk_porter_is_available,
    //         _marker: std::marker::PhantomData
    //     };

    //     // aux
    //     let _aux_data = BlockAuxilaryOutputWitness {
    //         l1_messages_linear_hash: basic_circuits.l1_messages_merklizer_circuit.clone_witness().unwrap().closed_form_input.observable_output.linear_hash,
    //         l1_messages_root: basic_circuits.l1_messages_merklizer_circuit.clone_witness().unwrap().closed_form_input.observable_output.root_hash,
    //         rollup_initital_writes_pubdata_hash: basic_circuits.initial_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,
    //         rollup_repeated_writes_pubdata_hash: basic_circuits.repeated_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,
    //         _marker: std::marker::PhantomData
    //     };

    //     let per_circuit_inputs = compact_form_witnesses.clone().into_flattened_set();

    //     let ram_permutation_full_sorted_state = basic_circuits.ram_permutation_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_input.sorted_queue_initial_state;
    //     let tail = ram_permutation_full_sorted_state.tail;
    //     let length = ram_permutation_full_sorted_state.length;

    //     let ram_permutation_sorted_state = SpongeLikeQueueStateWitness::<Bn256, 3> {
    //         length,
    //         sponge_state: tail
    //     };

    //     use sync_vm::traits::CSWitnessable;
    //     use sync_vm::recursion::node_aggregation::NodeAggregationOutputData;

    //     // let memory_verification_queries: [sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueryWitness<Bn256>; NUM_MEMORY_QUERIES_TO_VERIFY] = memory_verification_queries.try_into().unwrap();

    //     let scheduler_circuit_witness = SchedulerCircuitInstanceWitness {
    //         prev_block_data: previous_block_passthrough,
    //         block_meta_parameters,
    //         vm_end_of_execution_observable_output: basic_circuits.main_vm_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         decommits_sorter_observable_output: basic_circuits.code_decommittments_sorter_circuit.clone_witness().unwrap().closed_form_input.observable_output,
    //         code_decommitter_observable_output: basic_circuits.code_decommitter_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         log_demuxer_observable_output: basic_circuits.log_demux_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         keccak256_observable_output: basic_circuits.keccak_precompile_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         sha256_observable_output: basic_circuits.sha256_precompile_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         ecrecover_observable_output: basic_circuits.ecrecover_precompile_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         storage_sorter_observable_output: basic_circuits.storage_sorter_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         storage_application_observable_output: basic_circuits.storage_application_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         initial_writes_rehasher_observable_output: basic_circuits.initial_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output,
    //         repeated_writes_rehasher_observable_output: basic_circuits.repeated_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output,
    //         events_sorter_observable_output: basic_circuits.events_sorter_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         l1messages_sorter_observable_output: basic_circuits.l1_messages_sorter_circuits.last().unwrap().clone_witness().unwrap().closed_form_input.observable_output,
    //         l1messages_linear_hasher_observable_output: basic_circuits.l1_messages_pubdata_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output,
    //         l1messages_merklizer_observable_output: basic_circuits.l1_messages_merklizer_circuit.clone_witness().unwrap().closed_form_input.observable_output,
    //         storage_log_tail: basic_circuits.main_vm_circuits.first().unwrap().clone_witness().unwrap().closed_form_input.observable_input.rollback_queue_tail_for_block,
    //         per_circuit_closed_form_inputs: per_circuit_inputs,
    //         bootloader_heap_memory_state: memory_state_after_bootloader_heap_writes,
    //         ram_sorted_queue_state: ram_permutation_sorted_state,
    //         rollup_initital_writes_pubdata_hash: basic_circuits.initial_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,
    //         rollup_repeated_writes_pubdata_hash: basic_circuits.repeated_writes_hasher_circuit.clone_witness().unwrap().closed_form_input.observable_output.pubdata_hash,

    //         events_sorter_intermediate_queue_state: basic_circuits.events_sorter_circuits.first().unwrap().clone_witness().unwrap().closed_form_input.observable_input.intermediate_sorted_queue_state,
    //         l1messages_sorter_intermediate_queue_state: basic_circuits.l1_messages_sorter_circuits.first().unwrap().clone_witness().unwrap().closed_form_input.observable_input.intermediate_sorted_queue_state,
    //         rollup_storage_sorter_intermediate_queue_state: basic_circuits.storage_sorter_circuits.first().unwrap().clone_witness().unwrap().closed_form_input.observable_input.intermediate_sorted_queue_state,

    //         previous_block_meta_hash: Bytes32::placeholder_witness(),
    //         previous_block_aux_hash: Bytes32::placeholder_witness(),
    //         recursion_node_verification_key_hash: Bytes32::placeholder_witness(),
    //         recursion_leaf_verification_key_hash: Bytes32::placeholder_witness(),
    //         all_different_circuits_keys_hash: Bytes32::placeholder_witness(),

    //         aggregation_result: NodeAggregationOutputData::placeholder_witness(),

    //         proof_witnesses: vec![],
    //         vk_encoding_witnesses: vec![],
    //     };

    //     scheduler_circuit_witness
    // };

    // (basic_circuits, basic_circuits_inputs, scheduler_circuit_witness)
}

pub fn run_with_fixed_params<S: Storage>(
    caller: Address, // for real block must be zero
    entry_point_address: Address, // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read lobkc must be a bootloader code
    initial_heap_content: Vec<u8>, // bootloader starts with non-deterministic heap
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    used_bytecodes: std::collections::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    ram_verification_queries: Vec<(u32, U256)>, // we may need to check that after the bootloader's memory is filled
    cycle_limit: usize,
    geometry: GeometryConfig,
    storage: S,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
// ) {
// ) -> (Vec<VmInstanceWitness<GoldilocksField, VmWitnessOracle<GoldilocksField>>>, FullBlockArtifacts<GoldilocksField>) {
// ) -> (BlockBasicCircuits<Bn256>, BlockBasicCircuitsPublicInputs<Bn256>, SchedulerCircuitInstanceWitness<Bn256>) {
) -> (BlockBasicCircuits<GoldilocksField, ZkSyncDefaultRoundFunction>, BlockBasicCircuitsPublicInputs<GoldilocksField>, BlockBasicCircuitsPublicCompactFormsWitnesses<GoldilocksField>) {

    let round_function = ZkSyncDefaultRoundFunction::default();

    run(
        caller,
        entry_point_address,
        entry_point_code,
        initial_heap_content,
        zk_porter_is_available,
        default_aa_code_hash,
        used_bytecodes,
        ram_verification_queries,
        cycle_limit,
        round_function,
        geometry,
        storage,
        tree,
    )
}

pub fn base_layer_proof_config() -> ProofConfig {
    use crate::*;

    ProofConfig {
        fri_lde_factor: BASE_LAYER_FRI_LDE_FACTOR,
        merkle_tree_cap_size: BASE_LAYER_CAP_SIZE,
        fri_folding_schedule: None,
        security_level: SECURITY_BITS_TARGET,
        pow_bits: 0
    }
}