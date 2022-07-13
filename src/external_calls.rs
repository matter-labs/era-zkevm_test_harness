use crate::{ethereum_types::{Address, U256}, witness::{full_block_artifact::FullBlockArtifacts}, utils::calldata_to_aligned_data};
use sync_vm::{circuit_structures::traits::CircuitArithmeticRoundFunction, franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns};
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

/// This is a testing interface that basically will
/// setup the environment and will run out-of-circuit and then in-circuit
/// and perform intermediate tests
pub fn run<R: CircuitArithmeticRoundFunction<Bn256, 2, 3, StateElement = Num<Bn256>>, S: Storage>(
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
) -> (BlockBasicCircuits<Bn256>, BlockBasicCircuitsPublicInputs<Bn256>) {
    let bytecode_hash = bytecode_to_code_hash(&entry_point_code).unwrap();

    let mut tools = create_tools(storage, &geometry);

    // fill the tools
    let mut to_fill = vec![];
    let bytecode_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    to_fill.push((bytecode_hash_as_u256, contract_bytecode_to_words(&entry_point_code)));
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

    // and do the query
    let entry_point_decommittment_query = DecommittmentQuery {
        hash: bytecode_hash_as_u256,
        timestamp: Timestamp(1u32),
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
        block_number, 
        block_timestamp, 
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

    assert_eq!(out_of_circuit_vm.local_state.callstack.current.pc, 0);

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
    
    use crate::witness::postprocessing::create_leaf_level_circuits_and_scheduler_witness;

    let (basic_circuits, basic_circuits_inputs, _) = create_leaf_level_circuits_and_scheduler_witness(
        block_number,
        block_timestamp,
        zk_porter_is_available,
        default_aa_code_hash,
        ergs_per_pubdata_in_block,
        ergs_per_code_word_decommittment,
        instance_oracles,
        artifacts,
        geometry
    );

    (basic_circuits, basic_circuits_inputs)
}