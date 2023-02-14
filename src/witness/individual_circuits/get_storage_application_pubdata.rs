use super::*;
use crate::biguint_from_u256;
use crate::encodings::initial_storage_write::*;
use crate::encodings::repeated_storage_write::*;
use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::tree::EnumeratedBinaryLeaf;
use crate::witness::tree::ZkSyncStorageLeaf;
use crate::witness::tree::{BinarySparseStorageTree, ZKSyncTestingTree};
use blake2::Blake2s256;
use derivative::Derivative;
use num_bigint::BigUint;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::glue::keccak256_round_function_circuit::*;
use sync_vm::glue::pubdata_hasher::input::*;
use sync_vm::glue::pubdata_hasher::storage_write_data::InitialStorageWriteData;
use sync_vm::glue::pubdata_hasher::storage_write_data::RepeatedStorageWriteData;
use zk_evm::precompiles::keccak256::BUFFER_SIZE;

// We only quickly walk over the sequence of storage related logs, and separate them into either repeated application or a new one
pub fn compute_storage_application_pubdata_queues<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>,
>(
    artifacts: &mut FullBlockArtifacts<E>,
    tree: &impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    round_function: &R,
    first_writes_capacity: usize,
    repeated_writes_capacity: usize,
) -> (
    PubdataHasherInstanceWitness<E, 3, 64, InitialStorageWriteData<E>>,
    PubdataHasherInstanceWitness<E, 2, 40, RepeatedStorageWriteData<E>>,
) {
    let actual_keys: Vec<_> = artifacts
        .deduplicated_rollup_storage_queries
        .iter()
        .filter(|el| el.rw_flag)
        .map(|el| el.derive_final_address())
        .collect();

    let leafs = artifacts
        .deduplicated_rollup_storage_queries
        .iter()
        .filter(|el| el.rw_flag)
        .map(|el| {
            let mut leaf = ZkSyncStorageLeaf::empty();
            el.written_value.to_big_endian(leaf.value_ref_mut());

            leaf
        });

    let (_next_enumeration_index, first_writes, updates) =
        tree.filter_renumerate(actual_keys.iter(), leafs);

    assert!(
        first_writes.len() <= first_writes_capacity,
        "too many initial writes to hash by single circuit"
    );
    assert!(
        updates.len() <= repeated_writes_capacity,
        "too many updating writes to hash by single circuit"
    );

    let mut first_writes_simulator = InitialStorageWritesSimulator::<E>::empty();
    let mut repeated_writes_simulator = RepeatedStorageWritesSimulator::<E>::empty();

    for (idx, leaf) in first_writes.into_iter() {
        let first_write = InitialStorageWrite {
            key: idx,
            value: leaf.value,
        };
        first_writes_simulator.push(first_write, round_function);
    }

    for leaf in updates.into_iter() {
        let repeated_write = RepeatedStorageWrite {
            index: leaf.index,
            value: leaf.value,
        };
        repeated_writes_simulator.push(repeated_write, round_function);
    }

    use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_pubdata_hasher_witness;

    let first_writes_circuit_witness =
        compute_pubdata_hasher_witness(&first_writes_simulator, first_writes_capacity);

    let repeated_writes_circuit_witness =
        compute_pubdata_hasher_witness(&repeated_writes_simulator, repeated_writes_capacity);

    (
        first_writes_circuit_witness,
        repeated_writes_circuit_witness,
    )
}
