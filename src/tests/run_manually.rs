use std::collections::HashMap;

use super::*;
use crate::entry_point::{create_out_of_circuit_global_context};

use crate::ethereum_types::*;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::oracle::VmWitnessOracle;
use boojum::implementations::poseidon_goldilocks::PoseidonGoldilocks;
use boojum::zksync::base_structures::vm_state::GlobalContextWitness;
use boojum::zksync::main_vm::main_vm_entry_point;
use zk_evm::abstractions::*;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::*;
use zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use zk_evm::witness_trace::VmWitnessTracer;
use zk_evm::GenericNoopTracer;
use zkevm_assembly::Assembly;
use zk_evm::testing::storage::InMemoryStorage;
use crate::toolset::create_tools;

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
    //     nop stack+=[4]
    //     nop stack-=[1]
    //     add 1, r0, r1
    //     add 2, r0, r2
    //     sstore r1, r2
    //     near_call r0, @.continue, @.to_revert
    //     ret.ok r0
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
        nop stack+=[4]
        nop stack-=[1]
        add 12345, r0, r1
        shl.s 7, r1, r1
        add 1, r0, r1
        sload r1, r0
        add 2, r0, r2
        sstore r1, r2
        sload r1, r0
        log.event.first r1, r2, r0
        log.to_l1.first r1, r2, r0
        add 5, r0, r1
        add 6, r0, r2
        sstore r1, r2
        sload r1, r0
        sstore r1, r0
        near_call r0, @.empty_no_rollback, @.nop
    .continue0:
        near_call r0, @.empty_with_rollback, @.continue1
    .continue1:
        near_call r0, @.to_revert, @.finish
    .finish:
        add 3, r0, r1
        sload r1, r0
        sstore r1, r0
        ret.ok r0
    .empty_no_rollback:
        ret.ok r0
    .empty_with_rollback:
        ret.revert r0
    .to_revert:
        add 3, r0, r1
        add 4, r0, r2
        sstore r1, r2
        sload r1, r0
        log.event.first r1, r2, r0
        log.to_l1.first r1, r2, r0
        ret.revert r0
    .nop:
        ret.revert r0
    "#;

    // let asm = r#"
    //     .text
    //     .file	"Test_26"
    //     .rodata.cst32
    //     .p2align	5
    //     .text
    //     .globl	__entry
    // __entry:
    // .main:
    //     add 12345, r0, r1
    //     shl.s 7, r1, r1
    //     add 1, r0, r1
    //     near_call r0, @.to_revert, @.finish
    // .finish:
    //     ret.revert r0
    // .to_revert:
    //     add 3, r0, r1
    //     add 4, r0, r2
    //     sstore r1, r2
    //     sload r1, r0
    //     ret.revert r0
    // "#;

    // let asm = r#"
    //     .text
    //     .file	"Test_26"
    //     .rodata.cst32
    //     .p2align	5
    //     .text
    //     .globl	__entry
    // __entry:
    // .main:
    //     add! 1, r0, r1
    //     ret.ok r0
    // "#;

    run_and_try_create_witness_inner(asm, 50);
}

pub(crate) fn run_and_try_create_witness_inner(asm: &str, cycle_limit: usize) {
    let mut assembly = Assembly::try_from(asm.to_owned()).unwrap();
    let bytecode = assembly.compile_to_bytecode().unwrap();

    run_and_try_create_witness_for_extended_state(
        bytecode,
        vec![],
        cycle_limit
    )
}

pub(crate) fn run_and_try_create_witness_for_extended_state(
    entry_point_bytecode: Vec<[u8; 32]>,
    other_contracts: Vec<(H160, Vec<[u8; 32]>)>,
    cycle_limit: usize
) {
    use zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;
    use crate::external_calls::run;

    use crate::toolset::GeometryConfig;

    let geometry = GeometryConfig {
        cycles_per_vm_snapshot: 10,
        limit_for_code_decommitter_sorter: 16,
        cycles_per_log_demuxer: 8,
        cycles_per_storage_sorter: 4,
        cycles_per_events_or_l1_messages_sorter: 2,
        cycles_per_ram_permutation: 4,
        cycles_per_code_decommitter: 4,
        cycles_per_storage_application: 2,
        limit_for_initial_writes_pubdata_hasher: 16,
        limit_for_repeated_writes_pubdata_hasher: 16,
        cycles_per_keccak256_circuit: 1,
        cycles_per_sha256_circuit: 1,
        cycles_per_ecrecover_circuit: 1,
        limit_for_l1_messages_merklizer: 8,
        limit_for_l1_messages_pudata_hasher: 8,
    };

    use crate::witness::tree::ZKSyncTestingTree;
    use crate::witness::tree::BinarySparseStorageTree;

    let mut used_bytecodes_and_hashes = HashMap::new();
    used_bytecodes_and_hashes.extend(other_contracts.iter().cloned().map(|(_, code)| {
        let code_hash = bytecode_to_code_hash(&code).unwrap();

        (U256::from_big_endian(&code_hash), code)
    }));

    let mut storage_impl = InMemoryStorage::new();
    let mut tree = ZKSyncTestingTree::empty();

    let mut known_contracts = HashMap::new();
    known_contracts.extend(other_contracts.iter().cloned());

    save_predeployed_contracts(
        &mut storage_impl,
        &mut tree,
        &known_contracts
    );

    let round_function = PoseidonGoldilocks;

    // let (basic_block_circuits, basic_block_circuits_inputs, scheduler_input) = run(
    let (vm_instances_witness, artifacts) = 
    // let _ = 
    run(
        Address::zero(),
        *BOOTLOADER_FORMAL_ADDRESS,
        entry_point_bytecode,
        vec![],
        false,
        U256::zero(),
        used_bytecodes_and_hashes,
        vec![],
        cycle_limit,
        round_function,
        geometry,
        storage_impl,
        &mut tree
    );

    let global_ctx = GlobalContextWitness {
        zkporter_is_available: false,
        default_aa_code_hash: U256::zero(),
    };

    let num_instances = vm_instances_witness.len();
    let mut observable_input = None;

    use boojum::zksync::main_vm::cycle::*;

    let cs_geometry = reference_vm_geometry();

    for (instance_idx, vm_instance) in vm_instances_witness.into_iter().enumerate() {
        use crate::witness::utils::vm_instance_witness_to_circuit_formal_input;
        let is_first = instance_idx == 0;
        let is_last = instance_idx == num_instances - 1;
        let mut circuit_input = vm_instance_witness_to_circuit_formal_input(
            vm_instance,
            is_first,
            is_last,
            global_ctx.clone(),
        );

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input = observable_input.as_ref().unwrap().clone();
        }

        let gates = gates_setup(&cs_geometry);
        let mut cs_owned = testing_cs(
            cs_geometry,
            1 << 18,
            gates
        );

        let _ = main_vm_entry_point(&mut cs_owned, circuit_input, &round_function, geometry.cycles_per_vm_snapshot as usize);
        cs_owned.pad_and_shrink();
        cs_owned.wait_for_witness();

        use boojum::worker::Worker;
        let worker = Worker::new();
        println!("Checking if satisfied");
        assert!(cs_owned.check_if_satisfied(&worker));
    }

    

    todo!();

    // println!("Simulation and witness creation are completed");

    // // let flattened = basic_block_circuits.into_flattened_set();
    // // for el in flattened.into_iter() {
    // //     use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
    // //     let is_satisfied = circuit_testing::check_if_satisfied::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(el).unwrap();
    // //     assert!(is_satisfied);
    // // }

    // // for el in flattened.into_iter() {
    // //     use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
    // //     circuit_testing::prove_and_verify_circuit::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(el).unwrap();
    // // }

    // let flattened = basic_block_circuits.into_flattened_set();
    // let flattened_inputs = basic_block_circuits_inputs.into_flattened_set();

    // for (idx, (el, input_value)) in flattened.into_iter().zip(flattened_inputs.into_iter()).enumerate() {
    //     let descr = el.short_description();
    //     println!("Doing {}: {}", idx, descr);
    //     use crate::abstract_zksync_circuit::concrete_circuits::ZkSyncCircuit;
    //     if !matches!(&el, ZkSyncCircuit::MainVM(..)) {
    //         continue;
    //     }
    //     // el.debug_witness();
    //     use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
    //     let (is_satisfied, public_input) = circuit_testing::check_if_satisfied::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(el).unwrap();
    //     assert!(is_satisfied);
    //     assert_eq!(public_input, input_value, "Public input diverged for circuit {} of type {}", idx, descr);
    //     // if public_input != input_value {
    //     //     println!("Public input diverged for circuit {} of type {}", idx, descr);
    //     // }
    // }
}
