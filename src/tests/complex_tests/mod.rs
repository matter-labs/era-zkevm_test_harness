mod utils;
mod serialize_utils;

use std::collections::HashMap;

use super::*;
use crate::entry_point::{create_out_of_circuit_global_context};

use crate::ethereum_types::*;
use crate::pairing::bn256::Bn256;
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::oracle::VmWitnessOracle;
use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::rescue::params::RescueParams;
use sync_vm::traits::CSWitnessable;
use sync_vm::vm::vm_cycle::cycle::vm_cycle;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
use zk_evm::abstractions::*;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::*;
use zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use zk_evm::witness_trace::VmWitnessTracer;
use zk_evm::GenericNoopTracer;
use zkevm_assembly::Assembly;
use zk_evm::testing::storage::InMemoryStorage;
use crate::toolset::create_tools;
use utils::{read_test_artifact, TestArtifact};
use crate::witness::tree::{ZKSyncTestingTree, BinarySparseStorageTree};

const ACCOUNT_CODE_STORAGE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x02,
]);


#[test]
fn basic_test() {
    let test_artifact = read_test_artifact("basic_test");
    run_and_try_create_witness_inner(test_artifact, 1000);
}

fn save_predeployed_contracts(storage: &mut InMemoryStorage, contracts: &HashMap<Address, Vec<[u8;32]>>) {
    let storage_logs: Vec<(u8, Address, U256, U256)> = contracts
        .clone()
        .into_iter()
        .map(|(address, bytecode)| {
            let hash = bytecode_to_code_hash(&bytecode).unwrap();

            (0, ACCOUNT_CODE_STORAGE_ADDRESS, U256::from_big_endian(address.as_bytes()), U256::from(hash))
        })
        .collect();

    storage.populate(storage_logs);
}

fn run_and_try_create_witness_inner(test_artifact: TestArtifact, cycle_limit: usize) {
    use zk_evm::precompiles::BOOTLOADER_FORMAL_ADDRESS;

    use crate::external_calls::run;

    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    use crate::toolset::GeometryConfig;

    let geometry = GeometryConfig {
        cycles_per_vm_snapshot: 128,
        limit_for_code_decommitter_sorter: 32,
        limit_for_log_demuxer: 32,
        limit_for_storage_sorter: 32,
        limit_for_events_or_l1_messages_sorter: 32,
        cycles_per_ram_permutation: 32,
        cycles_per_code_decommitter: 32,
        cycles_per_storage_application: 32,
        limit_for_initial_writes_pubdata_hasher: 16,
        limit_for_repeated_writes_pubdata_hasher: 16,
        cycles_per_keccak256_circuit: 1,
        cycles_per_sha256_circuit: 1,
        cycles_per_ecrecover_circuit: 1,
        limit_for_l1_messages_merklizer: 8,
    };

    let mut storage_impl = InMemoryStorage::new();
    let mut tree = ZKSyncTestingTree::empty();

    save_predeployed_contracts(&mut storage_impl, &test_artifact.predeployed_contracts);

    let used_bytecodes = HashMap::from_iter(test_artifact.predeployed_contracts.iter().map(|(_,bytecode)| (bytecode_to_code_hash(&bytecode).unwrap().into(), bytecode.clone())));

    let mut basic_block_circuits = run(
        1,
        1,
        Address::zero(),
        test_artifact.entry_point_address,
        test_artifact.entry_point_code,
        vec![],
        false,
        U256::zero(),
        50,
        2,
        used_bytecodes,
        vec![],
        vec![],
        cycle_limit,
        round_function,
        geometry,
        storage_impl,
        &mut tree
    );

    let vm_circuit = basic_block_circuits.main_vm_circuits.drain(0..1).next().unwrap();
    use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;

    circuit_testing::prove_and_verify_circuit::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(vm_circuit).unwrap();
}
