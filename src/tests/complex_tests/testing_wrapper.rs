use super::*;

use crate::proof_wrapper_utils::WrapperConfig;
use crate::proof_wrapper_utils::{
    compress_stark_pi_to_snark_pi, compute_compression_circuits,
    compute_compression_for_wrapper_circuit, compute_wrapper_proof_and_vk,
};

use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::worker::Worker as BellmanWorker;

pub type TreeHasherForWrapper = CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type TranscriptForWrapper = CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;

pub(crate) fn test_compression_for_compression_num(config: WrapperConfig) {
    let worker = Worker::new();
    let bellman_worker = BellmanWorker::new();

    let mut file_source = LocalFileDataSource;
    let mut source = InMemoryDataSource::new();

    // Load scheduler proof and vk
    source
        .set_scheduler_proof(file_source.get_scheduler_proof().unwrap())
        .unwrap();
    source
        .set_recursion_layer_vk(
            file_source
                .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
                .unwrap(),
        )
        .unwrap();

    compute_compression_circuits(&mut source, config, &worker);
    compute_compression_for_wrapper_circuit(&mut source, config, &worker);
    compute_wrapper_proof_and_vk(&mut source, config, &bellman_worker);

    // Write wrapper proof and vk
    let wrapper_type = config.get_wrapper_type();
    file_source
        .set_wrapper_proof(source.get_wrapper_proof(wrapper_type).unwrap())
        .unwrap();
    file_source
        .set_wrapper_vk(source.get_wrapper_vk(wrapper_type).unwrap())
        .unwrap();
}

pub(crate) fn test_wrapper_pi_inner<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    config: WrapperConfig,
) {
    let scheduler_proof = source
        .get_scheduler_proof()
        .expect("scheduler proof should be present")
        .into_inner();

    let wrapper_type = config.get_wrapper_type();
    let wrapper_proof = source
        .get_wrapper_proof(wrapper_type)
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
    let config = get_testing_wrapper_config();

    let mut source = LocalFileDataSource;

    test_wrapper_pi_inner(&mut source, config);
}

#[test]
fn test_pi_aggregation_function() {
    use crate::zkevm_circuits::scheduler::NUM_SCHEDULER_PUBLIC_INPUTS;
    use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
    use circuit_definitions::boojum::field::{Field, PrimeField, U64Representable};
    use rand::Rng;

    let input_keccak_hash = rand::thread_rng().gen::<[u8; 32]>();

    // almost code from scheduler:
    let take_by = GoldilocksField::CAPACITY_BITS / 8;

    let mut pi = vec![];
    for chunk in input_keccak_hash
        .chunks_exact(take_by)
        .take(NUM_SCHEDULER_PUBLIC_INPUTS)
    {
        let mut lc = GoldilocksField::ZERO;
        // treat as BE
        for (idx, el) in chunk.iter().rev().enumerate() {
            let mut el = GoldilocksField::from_u64(*el as u64).unwrap();
            el.mul_assign(&GoldilocksField::from_u64(1 << (idx * 8)).unwrap());
            lc.add_assign(&el);
        }
        pi.push(lc);
    }

    let wrapper_pi = compress_stark_pi_to_snark_pi(pi.try_into().unwrap());

    println!("{:x?}", input_keccak_hash);
    println!("{:?}", wrapper_pi);
}

#[test]
fn test_wrapper_vk_generation() {
    let config = get_testing_wrapper_config();

    let mut source = LocalFileDataSource;

    let scheduler_vk = source
        .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
        .unwrap();

    use crate::proof_wrapper_utils::get_wrapper_setup_and_vk_from_scheduler_vk;
    let (_, wrapper_vk) = get_wrapper_setup_and_vk_from_scheduler_vk(scheduler_vk, config);

    source.set_wrapper_vk(wrapper_vk).unwrap();
}

pub(crate) fn get_testing_wrapper_config() -> WrapperConfig {
    let compression =
        std::env::var("COMPRESSION_NUM").map(|s| s.parse::<usize>().expect("should be a number"));

    if let Ok(compression) = compression {
        WrapperConfig::new(compression as u8)
    } else {
        DEFAULT_WRAPPER_CONFIG
    }
}
