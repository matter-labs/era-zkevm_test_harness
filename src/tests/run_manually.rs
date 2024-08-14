use std::collections::HashMap;

use super::*;
use crate::entry_point::create_out_of_circuit_global_context;

use crate::boojum::config::{ProvingCSConfig, SetupCSConfig};
use crate::boojum::cs::implementations::prover::ProofConfig;
use crate::boojum::cs::traits::cs::ConstraintSystem;
use crate::boojum::cs::traits::gate::GatePlacementStrategy;
use crate::boojum::field::traits::field_like::TrivialContext;
use crate::ethereum_types::*;
use crate::toolset::create_tools;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::zk_evm::abstractions::*;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::*;
use crate::zk_evm::testing::storage::InMemoryStorage;
use crate::zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use crate::zk_evm::witness_trace::VmWitnessTracer;
use crate::zk_evm::GenericNoopTracer;
use crate::zkevm_circuits::base_structures::vm_state::GlobalContextWitness;
use crate::zkevm_circuits::main_vm::main_vm_entry_point;
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::zk_evm::vm_state::cycle;
use storage::{InMemoryCustomRefundStorage, StorageRefund};
use witness::oracle::WitnessGenerationArtifact;
use zkevm_assembly::Assembly;

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

#[test]
fn run_pseudo_benchmark() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 100, r0, r1,
    .loop:
        sub.s! 1, r1, r1
        jump.ne @.loop
    .end
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 30000);
}

#[allow(dead_code)]
pub(crate) fn run_and_try_create_witness_inner(asm: &str, cycle_limit: usize) {
    let mut assembly = Assembly::try_from(asm.to_owned()).unwrap();
    let bytecode = assembly.compile_to_bytecode().unwrap();

    run_and_try_create_witness_for_extended_state(bytecode, vec![], cycle_limit)
}

const DEFAULT_CYCLE_LIMIT: usize = 50;
const DEFAULT_CYCLES_PER_VM_SNAPSHOT: u32 = 5;
#[derive(Clone)]
pub struct Options {
    // How many cycles should the main VM run for.
    // If not set - default is DEFAULT_CYCLE_LIMIT (50).
    pub cycle_limit: usize,
    // Additional contracts that should be deployed (pairs 'address, bytecode')
    pub other_contracts: Vec<(H160, Vec<[u8; 32]>)>,
    // How many cycles should a single VM handle (default is DEFAULT_CYCLES_PER_VM_SNAPSHOT = 5)
    pub cycles_per_vm_snapshot: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            cycle_limit: DEFAULT_CYCLE_LIMIT,
            other_contracts: Default::default(),
            cycles_per_vm_snapshot: DEFAULT_CYCLES_PER_VM_SNAPSHOT,
        }
    }
}

pub(crate) fn run_and_try_create_witness_for_extended_state(
    entry_point_bytecode: Vec<[u8; 32]>,
    other_contracts: Vec<(H160, Vec<[u8; 32]>)>,
    cycle_limit: usize,
) {
    run_with_options(
        entry_point_bytecode,
        Options {
            cycle_limit,
            other_contracts,
            ..Default::default()
        },
    )
}

pub(crate) fn run_with_options(entry_point_bytecode: Vec<[u8; 32]>, options: Options) {
    use crate::run_vms::{run_vms, RunVmError};
    use crate::tests::utils::testing_tracer::TestingTracer;
    use crate::toolset::GeometryConfig;
    use crate::zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

    let geometry = GeometryConfig {
        cycles_per_vm_snapshot: options.cycles_per_vm_snapshot,
        cycles_code_decommitter_sorter: 16,
        cycles_per_log_demuxer: 8,
        cycles_per_storage_sorter: 4,
        cycles_per_events_or_l1_messages_sorter: 2,
        cycles_per_ram_permutation: 4,
        cycles_per_code_decommitter: 4,
        cycles_per_storage_application: 2,
        cycles_per_keccak256_circuit: 1,
        cycles_per_sha256_circuit: 1,
        cycles_per_ecrecover_circuit: 1,
        cycles_per_secp256r1_verify_circuit: 1,
        cycles_per_transient_storage_sorter: 4,

        limit_for_l1_messages_pudata_hasher: 8,
    };

    use crate::witness::tree::BinarySparseStorageTree;
    use crate::witness::tree::ZKSyncTestingTree;

    let mut used_bytecodes_and_hashes = HashMap::new();
    used_bytecodes_and_hashes.extend(options.other_contracts.iter().cloned().map(|(_, code)| {
        let code_hash = bytecode_to_code_hash(&code).unwrap();

        (U256::from_big_endian(&code_hash), code)
    }));

    // We must pass a correct empty code hash (with proper version) into the run method.
    let empty_code_hash = U256::from_big_endian(&bytecode_to_code_hash(&[[0; 32]]).unwrap());

    let mut storage_impl = InMemoryCustomRefundStorage::new();

    let mut tree = ZKSyncTestingTree::empty();

    let mut known_contracts = HashMap::new();
    known_contracts.extend(options.other_contracts.iter().cloned());

    save_predeployed_contracts(&mut storage_impl.storage, &mut tree, &known_contracts);

    let mut basic_block_circuits = vec![];
    let mut unsorted_memory_queue_witnesses = vec![];
    let mut sorted_memory_queue_witnesses = vec![];

    // we are using TestingTracer to track prints and exceptions inside out_of_circuit_vm cycles
    let mut out_of_circuit_tracer =
        TestingTracer::new(Some(storage_impl.create_refund_controller()));

    let artifacts_callback = |artifact: WitnessGenerationArtifact| match artifact {
        WitnessGenerationArtifact::BaseLayerCircuit(circuit) => basic_block_circuits.push(circuit),
        WitnessGenerationArtifact::MemoryQueueWitness((witnesses, sorted)) => {
            if sorted {
                sorted_memory_queue_witnesses.push(witnesses)
            } else {
                unsorted_memory_queue_witnesses.push(witnesses)
            }
        }
        _ => {}
    };

    if let Err(err) = run_vms(
        Address::zero(),
        *BOOTLOADER_FORMAL_ADDRESS,
        entry_point_bytecode,
        vec![],
        false,
        empty_code_hash,
        empty_code_hash,
        used_bytecodes_and_hashes,
        vec![],
        options.cycle_limit,
        geometry,
        storage_impl,
        tree,
        "kzg/src/trusted_setup.json",
        std::array::from_fn(|_| None),
        artifacts_callback,
        &mut out_of_circuit_tracer,
    ) {
        let error_text = match err {
            RunVmError::InvalidInput(msg) => {
                format!("Invalid input error: {msg}")
            }
            RunVmError::OutOfCircuitExecutionError(msg) => {
                let msg = if let Some(exception) = out_of_circuit_tracer.exception {
                    format!("{msg} {exception}")
                } else {
                    msg
                };
                format!("Out-of-circuit execution error: {msg}")
            }
        };
        panic!("{error_text}");
    }

    println!("Simulation and witness creation are completed");

    let mut unsorted_memory_queue_witnesses_it = unsorted_memory_queue_witnesses.into_iter();
    let mut sorted_memory_queue_witnesses = sorted_memory_queue_witnesses.into_iter();
    for el in basic_block_circuits {
        println!("Doing {} circuit", el.short_description());
        match &el {
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
                let mut witness = inner.witness.take().unwrap();
                witness.sorted_queue_witness = FullStateCircuitQueueRawWitness {
                    elements: sorted_memory_queue_witnesses.next().unwrap().into(),
                };
                witness.unsorted_queue_witness = FullStateCircuitQueueRawWitness {
                    elements: unsorted_memory_queue_witnesses_it.next().unwrap().into(),
                };

                inner.witness.store(Some(witness));
            }
            _ => {}
        }
        base_test_circuit(el);
    }

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
