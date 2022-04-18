use crate::entry_point::{create_default_testing_tools, create_out_of_circuit_vm, create_out_of_circuit_global_context, create_in_circuit_vm};
use crate::ethereum_types::*;
use crate::witness::oracle::VmWitnessOracle;
use super::*;
use sync_vm::traits::CSWitnessable;
use sync_vm::vm::vm_cycle::cycle::vm_cycle;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
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
use crate::witness::oracle::create_artifacts_from_tracer;

#[test]
fn run_and_try_create_witness() {
    // let asm = r#"
    //     .text
    //     .file	"Test_26"
    //     .rodata.cst32
    //     .p2align	5
    //     .text
    //     .globl	__entry
    // __entry:
    // .main:
    //     add 1, r0, r1
    //     add 2, r0, r2
    //     sstore r1, r2
    //     near_call r0, @.to_revert, @.continue
    // .continue:
    //     add 5, r0, r1
    //     add 6, r0, r2
    //     sstore r1, r2
    //     ret.ok r0
    // .to_revert:
    //     add 3, r0, r1
    //     add 4, r0, r2
    //     sstore r1, r2
    //     ret.revert r0
    // "#;

    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add! 1, r0, r1
        ret.ok r0
    "#;

    let assembly = Assembly::try_from(asm.to_owned()).unwrap();
    let bytecode = assembly.compile_to_bytecode().unwrap();
    dbg!(bytecode.len());
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

    let cycle_limit = 1;

    let mut out_of_circuit_vm = create_out_of_circuit_vm(&mut tools, &block_properties);
    let mut tracer = GenericNoopTracer::<_>::new();
    for _ in 0..cycle_limit {
        out_of_circuit_vm.cycle(&mut tracer);
    }

    let vm_local_state = out_of_circuit_vm.local_state;

    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    let (mut cs, round_function, _) = create_test_artifacts_with_optimized_gate();
    sync_vm::vm::vm_cycle::add_all_tables(&mut cs).unwrap();

    // use crate::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
    // inscribe_default_range_table_for_bit_width_over_first_three_columns(&mut cs, 16).unwrap();

    // let params = sync_vm::utils::bn254_rescue_params();
    // let round_function = GenericHasher::<Bn256, RescueParams<_, 2, 3>, 2, 3>::new_from_params(&params);

    let (mut oracle, artifacts) = create_artifacts_from_tracer(tools.witness_tracer, &round_function);

    use crate::entry_point::create_in_circuit_global_context;
    let in_circuit_global_context = create_in_circuit_global_context::<Bn256>(
        1, 
        1, 
        true, 
        U256::zero(),
        50, 
        2
    );

    let initial_tail = oracle.initial_tail_for_entry_point;
    let mut in_circuit_vm = create_in_circuit_vm(
        &mut cs,
        &round_function, 
        initial_tail
    );

    for _ in 0..cycle_limit {
        in_circuit_vm = vm_cycle(&mut cs, in_circuit_vm, &mut oracle, &round_function, &in_circuit_global_context).unwrap();
    }

    assert_equal_state(
        &vm_local_state,
        &in_circuit_vm,
    );
    // compare
}

fn assert_equal_state(
    out_of_circuit: &zk_evm::vm_state::VmLocalState,
    in_circuit: &sync_vm::vm::vm_state::VmLocalState<Bn256, 3>
) {
    let wit = in_circuit.create_witness().unwrap();

    for (reg_idx, (circuit, not_circuit)) in wit.registers.iter().zip(out_of_circuit.registers.iter()).enumerate() {
        compare_reg_values(
            reg_idx + 1,
            circuit.inner,
            *not_circuit
        );
    }

    // compare flags
    let flags = wit.flags;
    assert_eq!(flags.overflow_or_less_than, out_of_circuit.flags.overflow_or_less_than_flag, "OF flag divergence");
    assert_eq!(flags.equal, out_of_circuit.flags.equality_flag, "EQ flag divergence");
    assert_eq!(flags.greater_than, out_of_circuit.flags.greater_than_flag, "GT flag divergence");
}

fn compare_reg_values(
    reg_idx: usize,
    in_circuit: [u128; 2],
    out_of_circuit: U256
) {
    let l0_a = in_circuit[0] as u64;
    let l1_a = (in_circuit[0] >> 64) as u64;
    let l2_a = in_circuit[1] as u64;
    let l3_a = (in_circuit[1] >> 64) as u64;

    let equal = out_of_circuit.0[0] == l0_a && out_of_circuit.0[1] == l1_a && out_of_circuit.0[2] == l2_a && out_of_circuit.0[3] == l3_a;
    if !equal {
        println!("Limb 0 in circuit = 0x{:016x}, out = 0x{:016x}", l0_a, out_of_circuit.0[0]);
        println!("Limb 1 in circuit = 0x{:016x}, out = 0x{:016x}", l1_a, out_of_circuit.0[1]);
        println!("Limb 2 in circuit = 0x{:016x}, out = 0x{:016x}", l2_a, out_of_circuit.0[2]);
        println!("Limb 3 in circuit = 0x{:016x}, out = 0x{:016x}", l3_a, out_of_circuit.0[3]);

        panic!("Failed as reg {}", reg_idx);
    }
}