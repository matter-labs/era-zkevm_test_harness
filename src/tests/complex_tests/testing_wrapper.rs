use super::*;

use crate::proof_wrapper_utils::{
    compute_compression_circuit,
    compute_compression_for_wrapper_circuit,
    compute_wrapper_proof_and_vk,
    compress_stark_pi_to_snark_pi,
};

use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::worker::Worker as BellmanWorker;

pub type TreeHasherForWrapper = CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type TranscriptForWrapper = CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;

pub(crate) fn test_compression_for_compression_num(compression: u8) {
    assert!(
        compression > 0 && compression <= 5,
        "compression should be between 1 and 5"
    );

    let worker = Worker::new();
    let bellman_worker = BellmanWorker::new();

    let mut source = LocalFileDataSource;

    for circuit_type in 1..=5 {
        if compression > circuit_type {
            compute_compression_circuit(&mut source, circuit_type, &worker);
        } else {
            compute_compression_for_wrapper_circuit(&mut source, circuit_type, &worker);
            compute_wrapper_proof_and_vk(&mut source, circuit_type, &bellman_worker);

            return;
        }
    }
}

pub(crate) fn test_wrapper_pi_inner<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    circuit_type: u8,
) {
    let scheduler_proof = source
        .get_scheduler_proof()
        .expect("scheduler proof should be present")
        .into_inner();

    let wrapper_proof = source
        .get_wrapper_proof(circuit_type)
        .expect("wrapper proof should be present")
        .into_inner();

    let scheduler_pi = scheduler_proof.public_inputs.try_into().unwrap();
    let wrapper_pi = wrapper_proof.inputs[0];
    assert!(wrapper_proof.inputs.len() == 1);

    let expected_wrapper_pi = compress_stark_pi_to_snark_pi(scheduler_pi);
    assert_eq!(expected_wrapper_pi, wrapper_pi);
}

#[test]
fn test_wrapper_pi() {
    let circuit_type = std::env::var("COMPRESSION_NUM")
        .map(|s| s.parse::<usize>().expect("should be a number"))
        .unwrap_or(1);
    assert!(
        circuit_type > 0 && circuit_type <= 5,
        "compression should be between 1 and 5"
    );

    let mut source = LocalFileDataSource;

    test_wrapper_pi_inner(&mut source, circuit_type as u8);
}

#[test]
fn test_wrapper_vk_generation() {
    let circuit_type = std::env::var("COMPRESSION_NUM")
        .map(|s| s.parse::<usize>().expect("should be a number"))
        .unwrap_or(1);
    assert!(
        circuit_type > 0 && circuit_type <= 5,
        "compression should be between 1 and 5"
    );

    let mut source = LocalFileDataSource;

    let scheduler_vk = source
        .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
        .unwrap();

    use crate::proof_wrapper_utils::get_wrapper_vk_from_scheduler_vk;
    let wrapper_vk = get_wrapper_vk_from_scheduler_vk(scheduler_vk, circuit_type as u8);

    source.set_wrapper_vk(wrapper_vk).unwrap();
}
