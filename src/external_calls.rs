use crate::{ethereum_types::{Address, U256}, witness::{full_block_artifact::FullBlockArtifacts}};
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
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

// TODO: needs extra definitions, like block number, ergs per pubdata in block, etc

/// This is a testing interface that basically will
/// setup the environment and will run out-of-circuit and then in-circuit
/// and perform intermediate tests
pub fn run<R: CircuitArithmeticRoundFunction<Bn256, 2, 3, StateElement = Num<Bn256>>, S: Storage>(
    caller: Address, // for real block must be zero
    entry_point_address: Address, // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read lobkc must be a bootloader code
    initial_heap_content: Vec<u8>, // bootloader starts with non-deterministic heap
    used_bytecodes: std::collections::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    calldata: Vec<u8>, // for real block must be empty
    ram_verification_queries: Vec<(u32, U256)>, // we may need to check that after the bootloader's memory is filled
    cycle_limit: usize,
    round_function: R, // used for all queues implementation
    geometry: GeometryConfig,
    storage: S
) -> FullBlockArtifacts<Bn256> {
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
        1, 
        1, 
        true, 
        U256::zero(), 
        50, 
        2);

    use crate::toolset::create_out_of_circuit_vm;

    let mut out_of_circuit_vm = create_out_of_circuit_vm(
        &mut tools, 
        &block_properties,
        caller,
        entry_point_address,
    );

    let mut tracer = GenericNoopTracer::<_>::new();
    for _ in 0..cycle_limit {
        out_of_circuit_vm.cycle(&mut tracer);
    }

    let vm_local_state = out_of_circuit_vm.local_state;

    // perform the final snapshot
    let current_cycle_counter = tools.witness_tracer.current_cycle_counter;
    use crate::witness::vm_snapshot::VmSnapshot;
    let snapshot = VmSnapshot {
        local_state: vm_local_state.clone(),
        at_cycle: current_cycle_counter,
    };
    tools.witness_tracer.vm_snapshots.push(snapshot);

    use sync_vm::testing::create_test_artifacts_with_optimized_gate;

    // use crate::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
    // inscribe_default_range_table_for_bit_width_over_first_three_columns(&mut cs, 16).unwrap();

    // let params = sync_vm::utils::bn254_rescue_params();
    // let round_function = GenericHasher::<Bn256, RescueParams<_, 2, 3>, 2, 3>::new_from_params(&params);

    let (instance_oracles, artifacts) =
        create_artifacts_from_tracer(
            tools.witness_tracer,
            &round_function, 
            &geometry,
            (entry_point_decommittment_query, entry_point_decommittment_query_witness)
        );

    assert!(artifacts.special_initial_decommittment_queries.len() == 1);

    let in_circuit_global_context =
        create_in_circuit_global_context::<Bn256>(
            1, 
            1, 
            true, 
            U256::zero(), 
            50, 
            2
        );

    // let num_instances = instance_oracles.len();

    // for (instance_idx, vm_instance) in instance_oracles.into_iter().enumerate() {
    //     println!("Running VM for range {:?}", vm_instance.cycles_range);
    //     use crate::entry_point::run_vm_instance;

    //     let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
    //     sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

    //     let vm_state = run_vm_instance(
    //         &mut cs,
    //         &round_function,
    //         &in_circuit_global_context,
    //         vm_instance
    //     );

    //     if instance_idx == num_instances - 1 {
    //         // consistency check for storage log
    //         assert_eq!(
    //             vm_state.callstack.current_context.log_queue_forward_tail.get_value().unwrap(),
    //             artifacts.original_log_queue_simulator.tail
    //         );

    //         assert_eq!(
    //             vm_state.callstack.current_context.log_queue_forward_part_length.get_value().unwrap(),
    //             artifacts.original_log_queue_simulator.num_items
    //         );
    //     }
    // }

    // test
    {
        println!("Running code decommittments sorter and deduplicator");
        assert!(artifacts.decommittments_deduplicator_circuits_data.len() == 1);        
        let subresult = &artifacts.decommittments_deduplicator_circuits_data[0];
        use sync_vm::glue::sort_decommittment_requests::sort_and_deduplicate_code_decommittments_entry_point;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

        let _ = sort_and_deduplicate_code_decommittments_entry_point(
            &mut cs,
            Some(subresult.clone()),
            &round_function,
            geometry.limit_for_code_decommitter_sorter as usize,
        ).unwrap();
    }

    // test
    {
        for (i, subresult) in artifacts.code_decommitter_circuits_data.iter().enumerate() {
            println!("Running code decommitter circuit number {}", i);
            // println!("Running RAM permutation for input {:?}", subresult);
            use sync_vm::glue::code_unpacker_sha256::unpack_code_into_memory_entry_point;

            let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
            sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

            let _ = unpack_code_into_memory_entry_point(
                &mut cs,
                Some(subresult.clone()),
                &round_function,
                geometry.cycles_per_code_decommitter as usize,
            ).unwrap();
        }
    }

    // test
    {
        println!("Running log demuxer circuit");
        assert!(artifacts.log_demuxer_circuit_data.len() == 1);        
        let subresult = &artifacts.log_demuxer_circuit_data[0];
        use sync_vm::glue::demux_log_queue::demultiplex_storage_logs_enty_point;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

        let _ = demultiplex_storage_logs_enty_point(
            &mut cs,
            Some(subresult.clone()),
            &round_function,
            geometry.limit_for_log_demuxer as usize
        ).unwrap();
    }

    // test
    {
        for (i, subresult) in artifacts.ram_permutation_circuits_data.iter().enumerate() {
            println!("Running RAM permutation circuit number {}", i);
            // println!("Running RAM permutation for input {:?}", subresult);
            use sync_vm::glue::ram_permutation::ram_permutation_entry_point;

            let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
            sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

            let _ = ram_permutation_entry_point(
                &mut cs,
                Some(subresult.clone()),
                &round_function,
                geometry.cycles_per_ram_permutation as usize
            ).unwrap();
        }
    }

    // test
    {
        println!("Running storage sorter and deduplicator");
        assert!(artifacts.storage_deduplicator_circuit_data.len() == 1);
        let subresult = &artifacts.storage_deduplicator_circuit_data[0];
        // println!("Running RAM permutation for input {:?}", subresult);
        use sync_vm::glue::storage_validity_by_grand_product::sort_and_deduplicate_storage_access_entry_point;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

        let _ = sort_and_deduplicate_storage_access_entry_point(
            &mut cs,
            Some(subresult.clone()),
            &round_function,
            geometry.limit_for_storage_sorter as usize
        ).unwrap();
    }

    // test
    {
        println!("Running events sorter and deduplicator");
        assert!(artifacts.events_deduplicator_circuit_data.len() == 1);
        let subresult = &artifacts.events_deduplicator_circuit_data[0];
        // println!("Running RAM permutation for input {:?}", subresult);
        use sync_vm::glue::log_sorter::sort_and_deduplicate_events_entry_point;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

        let _ = sort_and_deduplicate_events_entry_point(
            &mut cs,
            Some(subresult.clone()),
            &round_function,
            geometry.limit_for_events_or_l1_messages_sorter as usize
        ).unwrap();
    }

    // test
    {
        println!("Running l1 messages sorter and deduplicator");
        assert!(artifacts.l1_messages_deduplicator_circuit_data.len() == 1);
        let subresult = &artifacts.l1_messages_deduplicator_circuit_data[0];
        // println!("Running RAM permutation for input {:?}", subresult);
        use sync_vm::glue::log_sorter::sort_and_deduplicate_events_entry_point;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

        let _ = sort_and_deduplicate_events_entry_point(
            &mut cs,
            Some(subresult.clone()),
            &round_function,
            geometry.limit_for_events_or_l1_messages_sorter as usize
        ).unwrap();
    }

    artifacts
}