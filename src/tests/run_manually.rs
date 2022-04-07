use crate::entry_point::{create_default_testing_tools, create_out_of_circuit_vm, create_out_of_circuit_global_context};
use crate::ethereum_types::*;
use crate::witness::oracle::VmWitnessOracle;
use super::*;
use zk_evm::aux_structures::DecommittmentQuery;
use zkevm_assembly::Assembly;
use zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use zk_evm::aux_structures::*;
use crate::entry_point::STARTING_CODE_PAGE;
use zk_evm::abstractions::*;
use zk_evm::witness_trace::{VmWitnessTracer};
use zk_evm::GenericNoopTracer;
use crate::pairing::bn256::Bn256;
use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::rescue::params::RescueParams;

#[test]
fn run_and_try_create_witness() {
    let asm = r#"
    
    "#;

    let assembly = Assembly::try_from(asm.to_owned()).unwrap();
    let bytecode = assembly.compile_to_bytecode().unwrap();
    let bytecode_hash = bytecode_to_code_hash(&bytecode).unwrap();

    let mut tools = create_default_testing_tools();
    // fill the tools
    let mut to_fill = vec![];
    let bytecode_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    to_fill.push((bytecode_hash_as_u256, contract_bytecode_to_words(&bytecode)));
    tools.decommittment_processor.populate(to_fill);

    // and do the query
    let initial_decommittment_query = DecommittmentQuery {
        hash: bytecode_hash_as_u256,
        timestamp: Timestamp(1u32),
        memory_page: MemoryPage(STARTING_CODE_PAGE),
        decommitted_length: bytecode.len() as u16,
        is_fresh: true,
    };

    let (query, witness) = tools.decommittment_processor.decommit_into_memory(
        0, 
        initial_decommittment_query, 
        &mut tools.memory
    );
    if let Some(wit) = witness {
        tools.witness_tracer.add_decommittment(
            0,
            query,
            wit
        );
    }

    let block_properties = create_out_of_circuit_global_context(
        1, 
        1, 
        true, 
        U256::zero(),
        50, 
        2
    );
    let mut out_of_circuit_vm = create_out_of_circuit_vm(&mut tools, &block_properties);
    let mut tracer = GenericNoopTracer::<_>::new();
    for _ in 0..1000 {
        out_of_circuit_vm.cycle(&mut tracer);
    }

    drop(out_of_circuit_vm);
    let params = sync_vm::utils::bn254_rescue_params();
    let round_function = GenericHasher::<Bn256, RescueParams<_, 2, 3>, 2, 3>::new_from_params(&params);

    let oracle = VmWitnessOracle::from_witness_tracer(tools.witness_tracer, &round_function);
}