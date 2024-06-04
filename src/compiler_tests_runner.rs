use std::collections::HashMap;
use crate::witness::tree::{BinarySparseStorageTree, ZKSyncTestingTree, ZkSyncStorageLeaf};
use crate::external_calls::run;
use crate::toolset::GeometryConfig;
use crate::zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::testing::storage::InMemoryStorage;
use crate::ethereum_types::{Address, U256};
use crate::tests::base_test_circuit;
use crate::tests::complex_tests::get_testing_geometry_config;

pub fn compiler_tests_run(
    entry_point_bytecode: Vec<[u8; 32]>,
    default_aa_code_hash: U256,
    evm_simulator_code_hash: U256,
    known_contracts: HashMap<U256, Vec<[u8; 32]>>,
    storage: HashMap<Address, HashMap<U256, U256>>,
    initial_heap_content: Vec<u8>,
    cycle_limit: usize,
) -> HashMap<Address, HashMap<U256, U256>> {
    let geometry = get_testing_geometry_config();

    let mut storage_impl = InMemoryStorage::new();
    let mut tree = ZKSyncTestingTree::empty();

    for(address, inner) in storage.iter() {
        for(key, value) in inner.iter() {
            let index = LogQuery::derive_final_address_for_params(&address, &key);

            use crate::witness::tree::EnumeratedBinaryLeaf;
            let mut leaf = ZkSyncStorageLeaf::empty();
            let mut buffer = [0u8; 32];
            value.to_big_endian(&mut buffer);
            leaf.set_value(&buffer);

            tree.insert_leaf(&index, leaf);
        }
    }

    storage_impl.inner[0] = storage;

    let mut basic_block_circuits = vec![];

    let (_, _, storage) = run(
        Address::zero(),
        *BOOTLOADER_FORMAL_ADDRESS,
        entry_point_bytecode,
        initial_heap_content,
        false,
        default_aa_code_hash,
        evm_simulator_code_hash,
        known_contracts,
        vec![],
        cycle_limit,
        geometry,
        storage_impl,
        &mut tree,
        "kzg/src/trusted_setup.json",
        std::array::from_fn(|_| None),
        |circuit| basic_block_circuits.push(circuit),
        |_, _, _| {},
    );

    println!("Simulation and witness creation are completed");

    for el in basic_block_circuits {
        println!("Doing {} circuit", el.short_description());
        base_test_circuit(el);
    }

    let [storage, _] = storage.inner;
    storage
}