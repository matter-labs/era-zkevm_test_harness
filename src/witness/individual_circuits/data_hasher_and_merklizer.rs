use super::*;
use crate::bellman::Engine;
use crate::encodings::initial_storage_write::BytesSerializable;
use crate::encodings::initial_storage_write::CircuitEquivalentReflection;
use crate::encodings::*;
pub use sha3::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::glue::pubdata_hasher::input::PubdataHasherInstanceWitness;
use sync_vm::glue::pubdata_hasher::storage_write_data::ByteSerializable;
use sync_vm::glue::traits::*;
use sync_vm::inputs::ClosedFormInputWitness;

pub fn compute_pubdata_hasher_witness<
    const SERIALIZATION_WIDTH: usize,
    const ENCODING_ELEMS: usize,
    const ROUNDS: usize,
    I: OutOfCircuitFixedLengthEncodable<E, ENCODING_ELEMS>
        + BytesSerializable<SERIALIZATION_WIDTH>
        + CircuitEquivalentReflection<E, Destination = D>,
    E: Engine,
    D: CircuitFixedLengthEncodableExt<E, ENCODING_ELEMS>
        + CircuitFixedLengthDecodableExt<E, ENCODING_ELEMS>
        + ByteSerializable<E, SERIALIZATION_WIDTH>,
>(
    simulator: &QueueSimulator<E, I, ENCODING_ELEMS, ROUNDS>,
    capacity: usize,
) -> PubdataHasherInstanceWitness<E, ENCODING_ELEMS, SERIALIZATION_WIDTH, D> {
    // dbg!(&simulator.num_items);
    assert!(capacity <= u32::MAX as usize);
    let mut full_bytestring = vec![];
    let num_elements = simulator.witness.len();
    assert!(num_elements <= u32::MAX as usize);
    full_bytestring.extend((num_elements as u32).to_be_bytes());

    // only append meaningful items
    for (_, _, el) in simulator.witness.iter() {
        let serialized = el.serialize();
        assert_eq!(serialized.len(), SERIALIZATION_WIDTH);
        full_bytestring.extend(serialized);
    }

    // println!("Hashing over 0x{}", hex::encode(&full_bytestring));
    let pubdata_hash: [u8; 32] = Keccak256::digest(&full_bytestring)
        .as_slice()
        .try_into()
        .unwrap();

    // in general we have everything ready, just form the witness
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;
    use sync_vm::glue::pubdata_hasher::input::*;

    let mut input_passthrough_data = PubdataHasherInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.input_queue_state = take_queue_state_from_simulator(&simulator);

    let mut output_passthrough_data = PubdataHasherOutputData::placeholder_witness();
    output_passthrough_data.pubdata_hash = Bytes32Witness::from_bytes_array(&pubdata_hash);

    // dbg!(take_queue_state_from_simulator(&result_queue_simulator));
    // dbg!(&result_queue_simulator.witness);

    let input_queue_witness: VecDeque<_> = simulator
        .witness
        .iter()
        .map(|(encoding, old_tail, element)| {
            let circuit_witness = element.reflect();

            (*encoding, circuit_witness, *old_tail)
        })
        .collect();

    let witness = PubdataHasherInstanceWitness {
        closed_form_input: ClosedFormInputWitness {
            start_flag: true,
            completion_flag: true,
            observable_input: input_passthrough_data,
            observable_output: output_passthrough_data,
            hidden_fsm_input: (),
            hidden_fsm_output: (),
            _marker_e: (),
            _marker: std::marker::PhantomData,
        },

        input_queue_witness: FixedWidthEncodingGenericQueueWitness {
            wit: input_queue_witness,
        },
    };

    witness
}

use sync_vm::glue::merkleize_l1_messages::input::MessagesMerklizerInstanceWitness;

pub fn compute_merklizer_witness<
    const SERIALIZATION_WIDTH: usize,
    const ENCODING_ELEMS: usize,
    const ROUNDS: usize,
    I: OutOfCircuitFixedLengthEncodable<E, ENCODING_ELEMS>
        + BytesSerializable<SERIALIZATION_WIDTH>
        + CircuitEquivalentReflection<E, Destination = D>,
    E: Engine,
    D: CircuitFixedLengthEncodableExt<E, ENCODING_ELEMS>
        + CircuitFixedLengthDecodableExt<E, ENCODING_ELEMS>
        + ByteSerializable<E, SERIALIZATION_WIDTH>,
>(
    simulator: &QueueSimulator<E, I, ENCODING_ELEMS, ROUNDS>,
    capacity: usize,
    output_linear_hash: bool,
) -> MessagesMerklizerInstanceWitness<E, ENCODING_ELEMS, SERIALIZATION_WIDTH, D> {
    assert!(capacity <= u32::MAX as usize);
    let num_elements = simulator.witness.len();
    assert!(num_elements <= u32::MAX as usize);
    assert!(num_elements <= capacity);
    assert!(capacity.is_power_of_two());

    // may be produce linear hash
    let linear_hash = if output_linear_hash {
        let mut full_bytestring = vec![];
        full_bytestring.extend((num_elements as u32).to_be_bytes());
        // only append meaningful items
        for (_, _, el) in simulator.witness.iter() {
            let serialized = el.serialize();
            assert_eq!(serialized.len(), SERIALIZATION_WIDTH);
            full_bytestring.extend(serialized);
        }

        let linear_hash: [u8; 32] = Keccak256::digest(&full_bytestring)
            .as_slice()
            .try_into()
            .unwrap();

        linear_hash
    } else {
        [0u8; 32]
    };

    // may be merklize
    let elements = simulator.witness.iter().map(|el| &el.2);
    use crate::binary_merklize_set;
    let root = binary_merklize_set::<SERIALIZATION_WIDTH, _, Keccak256, _>(elements, capacity);

    // in general we have everything ready, just form the witness
    use sync_vm::circuit_structures::bytes32::Bytes32Witness;
    use sync_vm::glue::merkleize_l1_messages::input::*;

    let mut input_passthrough_data = MessagesMerklizerInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.input_queue_state = take_queue_state_from_simulator(&simulator);

    let mut output_passthrough_data = MessagesMerklizerOutputData::placeholder_witness();
    output_passthrough_data.linear_hash = Bytes32Witness::from_bytes_array(&linear_hash);
    output_passthrough_data.root_hash = Bytes32Witness::from_bytes_array(&root);

    let input_queue_witness: VecDeque<_> = simulator
        .witness
        .iter()
        .map(|(encoding, old_tail, element)| {
            let circuit_witness = element.reflect();

            (*encoding, circuit_witness, *old_tail)
        })
        .collect();

    let witness = MessagesMerklizerInstanceWitness {
        closed_form_input: ClosedFormInputWitness {
            start_flag: true,
            completion_flag: true,
            observable_input: input_passthrough_data,
            observable_output: output_passthrough_data,
            hidden_fsm_input: (),
            hidden_fsm_output: (),
            _marker_e: (),
            _marker: std::marker::PhantomData,
        },

        input_queue_witness: FixedWidthEncodingGenericQueueWitness {
            wit: input_queue_witness,
        },
    };

    witness
}
