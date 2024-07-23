use super::*;
use crate::generate_eip4844_witness;
use crate::zkevm_circuits::eip_4844::input::EIP4844CircuitInstanceWitness;
use crate::zkevm_circuits::eip_4844::input::*;
use crate::zkevm_circuits::fsm_input_output::ClosedFormInputWitness;
use crate::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;
use circuit_definitions::{Field, RoundFunction};
use std::sync::Arc;

pub(crate) fn compute_eip_4844(
    eip_4844_repack_inputs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
    trusted_setup_path: &str,
) -> Vec<EIP4844CircuitInstanceWitness<Field>> {
    let mut eip_4844_circuits = Vec::new();
    for el in eip_4844_repack_inputs.into_iter() {
        let Some(input_witness) = el else {
            continue;
        };
        let (chunks, linear_hash, versioned_hash, output_hash) =
            generate_eip4844_witness::<Field>(&input_witness[..], trusted_setup_path);
        let data_chunks: VecDeque<_> = chunks
            .iter()
            .map(|el| BlobChunkWitness { inner: *el })
            .collect();

        let output_data = EIP4844OutputDataWitness {
            linear_hash,
            output_hash,
        };
        let eip_4844_circuit_input = EIP4844CircuitInstanceWitness::<Field> {
            closed_form_input: ClosedFormInputWitness {
                start_flag: true,
                completion_flag: true,
                observable_input: (),
                observable_output: output_data,
                hidden_fsm_input: (),
                hidden_fsm_output: (),
            },
            versioned_hash,
            linear_hash_output: linear_hash,
            data_chunks,
        };
        eip_4844_circuits.push(eip_4844_circuit_input);
    }

    eip_4844_circuits
}
