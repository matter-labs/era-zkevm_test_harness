use std::ops::Add;

use crate::ethereum_types::Address;
use crate::ethereum_types::U256;
use zk_evm::address_to_u256;
use zk_evm::bytecode_to_code_hash;
use crate::entry_point::create_default_testing_tools;
use zk_evm::contract_bytecode_to_words;
use zk_evm::aux_structures::Timestamp;
use zk_evm::aux_structures::MemoryPage;
use crate::entry_point::{STARTING_CODE_PAGE, STARTING_CALLDATA_PAGE};
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::abstractions::*;
use zk_evm::witness_trace::VmWitnessTracer;
use crate::entry_point::create_out_of_circuit_global_context;
use crate::entry_point::create_out_of_circuit_vm;
use zk_evm::GenericNoopTracer;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::entry_point::create_in_circuit_vm;
use sync_vm::vm::vm_cycle::cycle::vm_cycle;
use crate::tests::run_manually::assert_equal_state;

/// This is a testing interface that basically will
/// setup the environment and will run out-of-circuit and then in-circuit
/// and perform intermediate tests
pub fn run(
    caller: Address,
    entry_point_address: Address,
    entry_point_code: Vec<[u8; 32]>,
    all_known_codes: Vec<Vec<[u8; 32]>>,
    predeployed_contracts: std::collections::HashMap<Address, Vec<[u8; 32]>>,
    calldata: Vec<u8>,
    cycle_limit: usize,
) {
    todo!();

    // use sync_vm::testing::Bn256;
    // let mut tools = create_default_testing_tools();

    // let mut all_bytecodes = std::collections::HashMap::new();

    // // fill the tools

    // for bytecode in Some(entry_point_code.clone()).iter().chain(all_known_codes.iter()) {
    //     let bytecode_hash = bytecode_to_code_hash(bytecode).unwrap();
    //     let bytecode_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    //     all_bytecodes.insert(bytecode_hash_as_u256, contract_bytecode_to_words(&bytecode));
    // }

    // for (_, bytecode) in predeployed_contracts.iter() {
    //     let bytecode_hash = bytecode_to_code_hash(bytecode).unwrap();
    //     let bytecode_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    //     all_bytecodes.insert(bytecode_hash_as_u256, contract_bytecode_to_words(&bytecode));
    // }

    // let mut decommitter_data_to_fill = vec![];
    // for (bytecode_hash_as_u256, bytecode_words) in all_bytecodes.clone().into_iter() {
    //     decommitter_data_to_fill.push((bytecode_hash_as_u256, bytecode_words));
    // }

    // let (entry_point_bytecode_hash, entry_point_bytecode) = decommitter_data_to_fill[0].clone();
    // tools.decommittment_processor.populate(decommitter_data_to_fill);

    // // and do the query
    // let initial_decommittment_query = DecommittmentQuery {
    //     hash: entry_point_bytecode_hash,
    //     timestamp: Timestamp(1u32),
    //     memory_page: MemoryPage(STARTING_CODE_PAGE),
    //     decommitted_length: entry_point_bytecode.len() as u16,
    //     is_fresh: true,
    // };

    // let (query, witness) = tools.decommittment_processor.decommit_into_memory(
    //     0,
    //     initial_decommittment_query,
    //     &mut tools.memory,
    // );

    // if let Some(wit) = witness {
    //     tools.witness_tracer.add_decommittment(0, query, wit);
    // }

    // // put calldata into initial memory
    // use crate::calldata_to_aligned_data;

    // let calldata_len = calldata.len();

    // // fill the calldata
    // let aligned_calldata = calldata_to_aligned_data(&calldata);

    // tools.memory.populate(vec![
    //     (STARTING_CALLDATA_PAGE, aligned_calldata),
    //     (STARTING_CODE_PAGE, entry_point_bytecode),
    // ]);

    // // fill the formal storage of known code hashes and deployed contracts
    // let mut storage_els = vec![];

    // use zk_evm::precompiles::*;

    // for (address, bytecode) in predeployed_contracts.iter() {
    //     let bytecode_hash = bytecode_to_code_hash(bytecode).unwrap();
    //     let bytecode_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
        
    //     let address_as_u256 = address_to_u256(address);

    //     // we write into DEPLOYER that for key == address we have bytecode == bytecode hash
    //     storage_els.push((
    //         0,
    //         *DEPLOYER_SYSTEM_CONTRACT_ADDRESS,
    //         address_as_u256,
    //         bytecode_hash_as_u256,
    //     ));
    //     // we write into FACTORY that for key == bytecode hash we have marker to know it
    //     storage_els.push((
    //         0,
    //         *KNOWN_CODE_FACTORY_SYSTEM_CONTRACT_ADDRESS,
    //         bytecode_hash_as_u256,
    //         U256::from(1u64),
    //     ));
    // }

    // for (bytecode_hash_as_u256, _) in all_bytecodes.into_iter() {
    //     storage_els.push((
    //         0,
    //         *KNOWN_CODE_FACTORY_SYSTEM_CONTRACT_ADDRESS,
    //         bytecode_hash_as_u256,
    //         U256::from(1u64),
    //     ));
    // }


    // let block_properties = create_out_of_circuit_global_context(
    //     1, 
    //     1, 
    //     true, 
    //     U256::zero(), 
    //     50, 
    //     2
    // );

    // let mut out_of_circuit_vm = create_out_of_circuit_vm(
    //     &mut tools, 
    //     &block_properties,
    //     caller,
    //     entry_point_address,
    // );

    // // set initial registers
    // out_of_circuit_vm.local_state.registers[1] = U256::from(calldata_len as u64);

    // let mut tracer = GenericNoopTracer::<_>::new();
    // for _ in 0..cycle_limit {
    //     out_of_circuit_vm.cycle(&mut tracer);
    // }

    // let vm_local_state = out_of_circuit_vm.local_state;

    // use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    // let (mut cs, round_function, _) = create_test_artifacts_with_optimized_gate();
    // sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

    // // use crate::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
    // // inscribe_default_range_table_for_bit_width_over_first_three_columns(&mut cs, 16).unwrap();

    // // let params = sync_vm::utils::bn254_rescue_params();
    // // let round_function = GenericHasher::<Bn256, RescueParams<_, 2, 3>, 2, 3>::new_from_params(&params);

    // let (mut oracle, artifacts) =
    //     create_artifacts_from_tracer(tools.witness_tracer, &round_function);

    // use crate::entry_point::create_in_circuit_global_context;
    // let in_circuit_global_context =
    //     create_in_circuit_global_context::<Bn256>(1, 1, true, U256::zero(), 50, 2);

    // let initial_tail = oracle.initial_tail_for_entry_point;
    // let mut in_circuit_vm = create_in_circuit_vm(
    //     &mut cs,
    //     &round_function,
    //     initial_tail,
    //     oracle.initial_callstack_state_for_start.clone(),
    //     oracle.initial_context_for_start,
    // );

    // use sync_vm::vm::primitives::UInt128;
    // in_circuit_vm.registers[1].inner[0] = UInt128::allocate(&mut cs, Some(calldata_len as u128)).unwrap();

    // for _ in 0..cycle_limit {
    //     in_circuit_vm = vm_cycle(
    //         &mut cs,
    //         in_circuit_vm,
    //         &mut oracle,
    //         &round_function,
    //         &in_circuit_global_context,
    //     )
    //     .unwrap();
    // }

    // assert_equal_state(&vm_local_state, &in_circuit_vm);

    // TODO: run tests over artifacts
}