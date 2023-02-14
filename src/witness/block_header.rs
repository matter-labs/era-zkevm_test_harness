use super::*;
use crate::bellman::Engine;
use crate::encodings::initial_storage_write::CircuitEquivalentReflection;
use crate::ethereum_types::U256;
use derivative::*;
use sync_vm::franklin_crypto::bellman::SynthesisError;
use sync_vm::franklin_crypto::plonk::circuit::tables::inscribe_range_table_for_bit_width_over_first_three_columns;
use sync_vm::traits::CSAllocatable;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PerShardState {
    pub enumeration_counter: u64,
    pub state_root: [u8; 32],
}

use sha3::Keccak256;
use sync_vm::circuit_structures::bytes32::Bytes32Witness;
use sync_vm::scheduler::block_header::NUM_SHARDS;
use sync_vm::testing::create_test_artifacts_with_optimized_gate;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockPassthroughData {
    pub per_shard_states: [PerShardState; NUM_SHARDS],
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockMetaParameters {
    pub zkporter_is_available: bool,
    pub bootloader_code_hash: [u8; 32],
    pub default_aa_code_hash: [u8; 32],
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockAuxilaryOutput {
    pub l1_messages_root: [u8; 32],
    pub l1_messages_linear_hash: [u8; 32],
    pub rollup_initital_writes_pubdata_hash: [u8; 32],
    pub rollup_repeated_writes_pubdata_hash: [u8; 32],
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub previous_block_content_hash: [u8; 32],
    pub new_block_content_hash: [u8; 32],
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockContentHeader {
    pub block_data: BlockPassthroughData,
    pub block_meta: BlockMetaParameters,
    pub auxilary_output: BlockAuxilaryOutput,
}

impl<E: Engine> CircuitEquivalentReflection<E> for PerShardState {
    type Destination = sync_vm::scheduler::block_header::PerShardState<E>;

    fn reflect(&self) -> <Self::Destination as sync_vm::traits::CSWitnessable<E>>::Witness {
        sync_vm::scheduler::block_header::PerShardStateWitness::<E> {
            enumeration_counter: self.enumeration_counter,
            state_root: Bytes32Witness::from_bytes_array(&self.state_root),
            _marker: std::marker::PhantomData,
        }
    }
}

impl PerShardState {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        // everything is BE
        let mut result = vec![];
        let enumeration_index_be = self.enumeration_counter.to_be_bytes();
        result.extend(enumeration_index_be);
        result.extend_from_slice(&self.state_root);

        result
    }
}

impl<E: Engine> CircuitEquivalentReflection<E> for BlockPassthroughData {
    type Destination = sync_vm::scheduler::block_header::BlockPassthroughData<E>;

    fn reflect(&self) -> <Self::Destination as sync_vm::traits::CSWitnessable<E>>::Witness {
        let mut reflected_parts = vec![];
        for el in self.per_shard_states.iter() {
            let reflected = el.reflect();
            reflected_parts.push(reflected);
        }

        sync_vm::scheduler::block_header::BlockPassthroughDataWitness::<E> {
            per_shard_states: reflected_parts.try_into().unwrap(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl BlockPassthroughData {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        for el in self.per_shard_states.iter() {
            result.extend(el.into_flattened_bytes());
        }

        result
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(&self.into_flattened_bytes());
        let t = hasher.finalize();
        result.copy_from_slice(&t.as_slice());

        result
    }
}

impl<E: Engine> CircuitEquivalentReflection<E> for BlockMetaParameters {
    type Destination = sync_vm::scheduler::block_header::BlockMetaParameters<E>;

    fn reflect(&self) -> <Self::Destination as sync_vm::traits::CSWitnessable<E>>::Witness {
        sync_vm::scheduler::block_header::BlockMetaParametersWitness::<E> {
            bootloader_code_hash: Bytes32Witness::from_bytes_array(&self.bootloader_code_hash),
            default_aa_code_hash: Bytes32Witness::from_bytes_array(&self.default_aa_code_hash),
            zkporter_is_available: self.zkporter_is_available,
            _marker: std::marker::PhantomData,
        }
    }
}

impl BlockMetaParameters {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.zkporter_is_available as u8);
        result.extend_from_slice(&self.bootloader_code_hash);
        result.extend_from_slice(&self.default_aa_code_hash);

        result
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(&self.into_flattened_bytes());
        let t = hasher.finalize();
        result.copy_from_slice(&t.as_slice());

        result
    }
}

impl<E: Engine> CircuitEquivalentReflection<E> for BlockAuxilaryOutput {
    type Destination = sync_vm::scheduler::block_header::BlockAuxilaryOutput<E>;

    fn reflect(&self) -> <Self::Destination as sync_vm::traits::CSWitnessable<E>>::Witness {
        sync_vm::scheduler::block_header::BlockAuxilaryOutputWitness::<E> {
            l1_messages_root: Bytes32Witness::from_bytes_array(&self.l1_messages_root),
            l1_messages_linear_hash: Bytes32Witness::from_bytes_array(
                &self.l1_messages_linear_hash,
            ),
            rollup_initital_writes_pubdata_hash: Bytes32Witness::from_bytes_array(
                &self.rollup_initital_writes_pubdata_hash,
            ),
            rollup_repeated_writes_pubdata_hash: Bytes32Witness::from_bytes_array(
                &self.rollup_repeated_writes_pubdata_hash,
            ),
            _marker: std::marker::PhantomData,
        }
    }
}

impl BlockAuxilaryOutput {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&self.l1_messages_root);
        result.extend_from_slice(&self.l1_messages_linear_hash);
        result.extend_from_slice(&self.rollup_initital_writes_pubdata_hash);
        result.extend_from_slice(&self.rollup_repeated_writes_pubdata_hash);

        result
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(&self.into_flattened_bytes());
        let t = hasher.finalize();
        result.copy_from_slice(&t.as_slice());

        result
    }
}

impl BlockContentHeader {
    pub fn into_formal_block_hash(self) -> ([u8; 32], ([u8; 32], [u8; 32], [u8; 32])) {
        // everything is BE
        let block_data_hash = self.block_data.hash();
        let block_meta_hash = self.block_meta.hash();
        let auxilary_output_hash = self.auxilary_output.hash();

        let block_hash = Self::formal_block_hash_from_partial_hashes(
            block_data_hash,
            block_meta_hash,
            auxilary_output_hash,
        );

        (
            block_hash,
            (block_data_hash, block_meta_hash, auxilary_output_hash),
        )
    }

    pub fn formal_block_hash_from_partial_hashes(
        block_data_hash: [u8; 32],
        block_meta_hash: [u8; 32],
        auxilary_output_hash: [u8; 32],
    ) -> [u8; 32] {
        let mut result = [0u8; 32];
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(&block_data_hash);
        hasher.update(&block_meta_hash);
        hasher.update(&auxilary_output_hash);

        let t = hasher.finalize();
        result.copy_from_slice(&t.as_slice());

        result
    }
}

pub fn block_proof_input(
    previous_block_formal_hash: [u8; 32],
    this_block_formal_hash: [u8; 32],
    recursion_node_verification_key_hash: [u8; 32], // BE
    recursion_leaf_verification_key_hash: [u8; 32], // BE
    all_different_circuits_keys_hash: [u8; 32],     // BE
    aggregation_result: [[u8; 32]; 4],              // BE
) -> U256 {
    let mut result = [0u8; 32];
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();

    hasher.update(&previous_block_formal_hash);
    hasher.update(&this_block_formal_hash);
    hasher.update(&recursion_node_verification_key_hash);
    hasher.update(&recursion_leaf_verification_key_hash);
    hasher.update(&all_different_circuits_keys_hash);

    for el in aggregation_result.iter() {
        hasher.update(&el);
    }

    let t = hasher.finalize();
    result.copy_from_slice(&t.as_slice());

    result[0] = 0; // zero out to fit into the field

    U256::from_big_endian(&result)
}

#[test]
fn test_equality() -> Result<(), SynthesisError> {
    use crate::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
    use sync_vm::circuit_structures::byte::Byte;
    use sync_vm::scheduler::block_header::keccak_output_into_bytes;

    let (mut cs_outer, _, _) = create_test_artifacts_with_optimized_gate();
    use franklin_crypto::plonk::circuit::hashes_with_tables::keccak::gadgets::Keccak256Gadget;
    let cs = &mut cs_outer;
    inscribe_default_range_table_for_bit_width_over_first_three_columns(cs, 16)?;

    use crate::bellman::plonk::better_better_cs::cs::ConstraintSystem;
    use crate::bellman::plonk::better_better_cs::cs::LookupTableApplication;
    use crate::bellman::plonk::better_better_cs::data_structures::PolyIdentifier;
    use sync_vm::vm::tables::BitwiseLogicTable;
    use sync_vm::vm::VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
    let columns3 = vec![
        PolyIdentifier::VariablesPolynomial(0),
        PolyIdentifier::VariablesPolynomial(1),
        PolyIdentifier::VariablesPolynomial(2),
    ];

    if cs.get_table(VM_BITWISE_LOGICAL_OPS_TABLE_NAME).is_err() {
        let name = VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
        let bitwise_logic_table = LookupTableApplication::new(
            name,
            BitwiseLogicTable::new(&name, 8),
            columns3.clone(),
            None,
            true,
        );
        cs.add_table(bitwise_logic_table)?;
    };

    use crate::franklin_crypto::plonk::circuit::tables::RANGE_CHECK_SINGLE_APPLICATION_TABLE_NAME;

    let keccak_gadget = Keccak256Gadget::new(
        cs,
        None,
        None,
        None,
        None,
        true,
        RANGE_CHECK_SINGLE_APPLICATION_TABLE_NAME,
    )?;

    // we use some hardcoded values, but since we always hide under hashes it's not important
    {
        let passthrough_data = BlockPassthroughData {
            per_shard_states: [
                PerShardState {
                    enumeration_counter: 123,
                    state_root: [1u8; 32],
                },
                PerShardState {
                    enumeration_counter: 0,
                    state_root: [0; 32],
                },
            ],
        };
        let out_of_circuit_passthrough_data_hash = passthrough_data.hash();

        let in_circuit_passthrough =
            sync_vm::scheduler::block_header::BlockPassthroughData::alloc_from_witness(
                cs,
                Some(passthrough_data.reflect()),
            )?;
        let t = in_circuit_passthrough.into_flattened_bytes(cs)?;
        let in_circuit_passthrough_data_hash = keccak_gadget.digest_from_bytes(cs, &t)?;
        let in_circuit_passthrough_data_hash =
            keccak_output_into_bytes(cs, in_circuit_passthrough_data_hash)?;
        let in_circuit_passthrough_data_hash =
            Byte::get_byte_value_multiple(&in_circuit_passthrough_data_hash);

        assert_eq!(
            out_of_circuit_passthrough_data_hash,
            in_circuit_passthrough_data_hash.unwrap()
        );
    }

    {
        let out_of_circuit = BlockMetaParameters {
            zkporter_is_available: false,
            bootloader_code_hash: [2u8; 32],
            default_aa_code_hash: [3u8; 32],
        };
        let out_of_circuit_hash = out_of_circuit.hash();

        let in_circuit = sync_vm::scheduler::block_header::BlockMetaParameters::alloc_from_witness(
            cs,
            Some(out_of_circuit.reflect()),
        )?;
        let t = in_circuit.into_flattened_bytes(cs)?;
        let in_circuit_hash = keccak_gadget.digest_from_bytes(cs, &t)?;
        let in_circuit_hash = keccak_output_into_bytes(cs, in_circuit_hash)?;
        let in_circuit_hash = Byte::get_byte_value_multiple(&in_circuit_hash);

        assert_eq!(out_of_circuit_hash, in_circuit_hash.unwrap());
    }

    {
        let out_of_circuit = BlockAuxilaryOutput {
            l1_messages_root: [2u8; 32],
            l1_messages_linear_hash: [3u8; 32],
            rollup_initital_writes_pubdata_hash: [4u8; 32],
            rollup_repeated_writes_pubdata_hash: [5u8; 32],
        };
        let out_of_circuit_hash = out_of_circuit.hash();

        let in_circuit = sync_vm::scheduler::block_header::BlockAuxilaryOutput::alloc_from_witness(
            cs,
            Some(out_of_circuit.reflect()),
        )?;
        let t = in_circuit.into_flattened_bytes(cs)?;
        let in_circuit_hash = keccak_gadget.digest_from_bytes(cs, &t)?;
        let in_circuit_hash = keccak_output_into_bytes(cs, in_circuit_hash)?;
        let in_circuit_hash = Byte::get_byte_value_multiple(&in_circuit_hash);

        assert_eq!(out_of_circuit_hash, in_circuit_hash.unwrap());
    }

    Ok(())
}
