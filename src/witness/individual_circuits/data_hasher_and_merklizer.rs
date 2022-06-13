use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::circuit::input::rollup_shard_id;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::*;
use crate::ethereum_types::U256;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::utils::biguint_from_u256;
use crate::witness_structures::transform_sponge_like_queue_state;
use std::cmp::Ordering;
use crate::bellman::Engine;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use crate::ff::Field;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use crate::encodings::*;
use sync_vm::glue::log_sorter::input::*;
use crate::encodings::initial_storage_write::BytesSerializable;
pub use sha3::*;
use crate::encodings::initial_storage_write::CircuitEquivalentReflection;
use sync_vm::glue::traits::*;
use sync_vm::glue::pubdata_hasher::storage_write_data::ByteSerializable;

use sync_vm::glue::pubdata_hasher::input::PubdataHasherInstanceWitness;

pub fn compute_pubdata_hasher_witness<
    const SERIALIZATION_WIDTH: usize,
    const ENCODING_ELEMS: usize,
    const ROUNDS: usize,
    I: OutOfCircuitFixedLengthEncodable<E, ENCODING_ELEMS> + BytesSerializable<SERIALIZATION_WIDTH> + CircuitEquivalentReflection<E, Destination = D>,
    E: Engine,
    D: CircuitFixedLengthEncodableExt<E, ENCODING_ELEMS> + CircuitFixedLengthDecodableExt<E, ENCODING_ELEMS> + ByteSerializable<E, SERIALIZATION_WIDTH>,
>(
    simulator: &QueueSimulator<E, I, ENCODING_ELEMS, ROUNDS>,
    capacity: usize
) -> PubdataHasherInstanceWitness<E, ENCODING_ELEMS, SERIALIZATION_WIDTH, D> {
    assert!(capacity <= u32::MAX as usize);
    let mut full_bytestring = vec![];
    let num_elements = simulator.witness.len();
    assert!(num_elements <= u32::MAX as usize);
    full_bytestring.extend((num_elements as u32).to_be_bytes());
    full_bytestring.resize(4 + (capacity * SERIALIZATION_WIDTH), 0);
    for ((_, _, el), chunk) in simulator.witness.iter().zip(full_bytestring[4..].chunks_exact_mut(SERIALIZATION_WIDTH)) {
        chunk.copy_from_slice(&el.serialize());
    } 

    let pubdata_hash: [u8; 32] = Keccak256::digest(&full_bytestring).as_slice().try_into().unwrap();

    // in general we have everything ready, just form the witness
    use crate::witness_structures::take_queue_state_from_simulator;
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;
    use sync_vm::glue::pubdata_hasher::input::*;

    let mut input_passthrough_data = PubdataHasherInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.input_queue_state = take_queue_state_from_simulator(&simulator);

    let mut output_passthrough_data = PubdataHasherOutputData::placeholder_witness();
    output_passthrough_data.pubdata_hash = Bytes32Witness::from_bytes_array(&pubdata_hash);

    // dbg!(take_queue_state_from_simulator(&result_queue_simulator));
    // dbg!(&result_queue_simulator.witness);

    let input_queue_witness: Vec<_> = simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let circuit_witness = element.reflect();

        (*encoding, circuit_witness, *old_tail)
    }).collect();
    
    let witness = PubdataHasherInstanceWitness {
        closed_form_input: ClosedFormInputWitness { 
            start_flag: true, 
            completion_flag: true, 
            observable_input: input_passthrough_data, 
            observable_output: output_passthrough_data, 
            hidden_fsm_input: (), 
            hidden_fsm_output: (), 
            _marker_e: (), 
            _marker: std::marker::PhantomData 
        },

        input_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: input_queue_witness},
    };

    witness
}