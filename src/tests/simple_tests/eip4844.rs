use super::*;
use circuit_definitions::circuit_definitions::base_layer::EIP4844Circuit;
use crate::zkevm_circuits::eip_4844::input::*;
use crossbeam::atomic::AtomicCell;
use rand::Rng;
use std::collections::VecDeque;
use std::sync::Arc;

const EIP4844_CYCLE_LIMIT: usize = 4096;

#[test]
fn test_eip4844() {
    let mut blob = vec![0; 4096 * 31];
    blob.iter_mut()
        .for_each(|byte| *byte = rand::thread_rng().gen());

    let (blob_arr, linear_hash, versioned_hash, output_hash) =
        generate_eip4844_witness::<GoldilocksField>(&blob);
    let blob = blob_arr
        .iter()
        .map(|el| BlobChunkWitness { inner: *el })
        .collect::<Vec<BlobChunkWitness<GoldilocksField>>>();
    let witness = EIP4844CircuitInstanceWitness {
        closed_form_input: EIP4844InputOutputWitness {
            start_flag: true,
            completion_flag: true,
            hidden_fsm_input: (),
            hidden_fsm_output: (),
            observable_input: (),
            observable_output: EIP4844OutputDataWitness {
                linear_hash,
                output_hash,
            },
        },
        data_chunks: VecDeque::from(blob),
        linear_hash_output: linear_hash,
        versioned_hash,
    };
    let circuit = EIP4844Circuit {
        witness: AtomicCell::new(Some(witness)),
        config: Arc::new(EIP4844_CYCLE_LIMIT),
        round_function: ZkSyncDefaultRoundFunction::default().into(),
        expected_public_input: None,
    };
    let circuit = ZkSyncBaseLayerCircuit::EIP4844Repack(circuit);
    base_test_circuit(circuit);
}
