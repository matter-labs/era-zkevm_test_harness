use super::*;

use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::worker::Worker as BellmanWorker;
use crate::proof_wrapper_utils::{compute_compression_circuit, compute_compression_for_wrapper_circuit, compute_wrapper_proof};

pub type TreeHasherForWrapper = 
    CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type TranscriptForWrapper = 
    CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;


pub(crate) fn test_compression_for_compression_num(compression: u8) {
    assert!(compression > 0 && compression <= 5, "compression should be between 1 and 5");

    let worker = Worker::new_with_num_threads(8);
    let bellman_worker = BellmanWorker::new();

    let mut source = LocalFileDataSource;


    for circuit_type in 1..=5 {
        if compression > circuit_type {
            compute_compression_circuit(&mut source, circuit_type, &worker);
        } else {
            compute_compression_for_wrapper_circuit(&mut source, circuit_type, &worker);
            compute_wrapper_proof(&mut source, circuit_type, &bellman_worker);
    
            return;
        }
    }
}

