use super::*;

use crate::boojum::field::{Field, ExtensionField};
use crate::data_source::{SetupDataSource, BlockDataSource,
    local_file_data_source::LocalFileDataSource,
};
use crate::tests::complex_tests::testing_wrapper::get_testing_wrapper_config;
use crate::proof_wrapper_utils::{WrapperConfig,
    compute_compression_vks_and_write, 
    compute_compression_for_wrapper_vk_and_write,
    compute_compression_circuits,
    compute_compression_for_wrapper_circuit,
};
use crate::tests::{Worker,
    ZkSyncCompressionForWrapperProof,
    ZkSyncCompressionForWrapperVerificationKey,
};
use crate::snark_wrapper::franklin_crypto::bellman::{
    worker::Worker as BellmanWorker,
    Field as BellmanField
};

fn get_compression_for_wrapper_vk_for_testing(config: WrapperConfig) -> ZkSyncCompressionForWrapperVerificationKey {
    let mut source = LocalFileDataSource;

    let compression_for_wrapper_type = config.get_compression_for_wrapper_type();
    if source.get_compression_for_wrapper_vk(compression_for_wrapper_type).is_err() {
        // Scheduler vk should be present!
        let worker = Worker::new();
        // 1. All but one layers of compression with Goldilocks Poseidon2 hash
        compute_compression_vks_and_write(&mut source, config, &worker);
        // 2. Final compression with Bn256 Poseidon2 hash
        compute_compression_for_wrapper_vk_and_write(config, &mut source, &worker);
    }
    
    source.get_compression_for_wrapper_vk(compression_for_wrapper_type).unwrap()
}

fn get_compression_for_wrapper_proof_for_testing(config: WrapperConfig) -> ZkSyncCompressionForWrapperProof {
    let mut source = LocalFileDataSource;

    let compression_for_wrapper_type = config.get_compression_for_wrapper_type();
    if source.get_compression_for_wrapper_proof(compression_for_wrapper_type).is_err() {
        // Scheduler vk and proof should be present!
        let worker = Worker::new();
        // 1. All but one layers of compression with Goldilocks Poseidon2 hash
        compute_compression_circuits(&mut source, config, &worker);
        // 2. Final compression with Bn256 Poseidon2 hash
        compute_compression_for_wrapper_circuit(&mut source, config, &worker);
    }
    
    source.get_compression_for_wrapper_proof(compression_for_wrapper_type).unwrap()
}

use crate::proof_wrapper_utils::{L1_VERIFIER_DOMAIN_SIZE_LOG, TreeHasherForWrapper, TranscriptForWrapper};

fn try_to_synthesize_wrapper(
    proof: ZkSyncCompressionForWrapperProof,
    vk: ZkSyncCompressionForWrapperVerificationKey,
    config: WrapperConfig,
) {
    let wrapper_type = config.get_wrapper_type();

    let compression_for_wrapper_type = config.get_compression_for_wrapper_type();
    assert_eq!(compression_for_wrapper_type, proof.numeric_circuit_type());
    assert_eq!(compression_for_wrapper_type, vk.numeric_circuit_type());

    let proof = proof.into_inner();
    let vk = vk.into_inner();

    let mut assembly = ProvingAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fixed_parameters = vk.fixed_parameters.clone();

    let wrapper_function = ZkSyncCompressionWrapper::from_numeric_circuit_type(wrapper_type);
    let wrapper_circuit = WrapperCircuit::<_, _, TreeHasherForWrapper, TranscriptForWrapper, _> {
        witness: Some(proof),
        vk: vk,
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };

    wrapper_circuit.synthesize(&mut assembly).unwrap();

    dbg!(assembly.n());

    assembly.finalize_to_size_log_2(L1_VERIFIER_DOMAIN_SIZE_LOG);
    assert!(assembly.is_satisfied());
}

#[cfg(test)]
mod wrapper_tests {
    use super::*;

    #[test]
    fn synthesize() {
        let config = get_testing_wrapper_config();
        let (proof, vk) = (
            get_compression_for_wrapper_proof_for_testing(config),
            get_compression_for_wrapper_vk_for_testing(config),
        );
        try_to_synthesize_wrapper(proof, vk, config);
    }

    #[test]
    #[should_panic]
    fn synthesize_with_empty_pi() {
        let config = get_testing_wrapper_config();
        let (proof, vk) = (
            get_compression_for_wrapper_proof_for_testing(config),
            get_compression_for_wrapper_vk_for_testing(config),
        );

        let mut proof = proof.into_inner();
        proof.public_inputs.clear();

        let wrapper_type = config.get_wrapper_type();
        let proof = ZkSyncCompressionForWrapperProof::from_inner(wrapper_type, proof);
        try_to_synthesize_wrapper(proof, vk, config);
    }

    #[test]
    #[should_panic]
    fn synthesize_with_wrong_pi() {
        let config = get_testing_wrapper_config();
        let (proof, vk) = (
            get_compression_for_wrapper_proof_for_testing(config),
            get_compression_for_wrapper_vk_for_testing(config),
        );
        
        let mut proof = proof.into_inner();
        proof.public_inputs[0] = GoldilocksField::ZERO;

        let wrapper_type = config.get_wrapper_type();
        let proof = ZkSyncCompressionForWrapperProof::from_inner(wrapper_type, proof);
        try_to_synthesize_wrapper(proof, vk, config);
    }

    #[test]
    #[should_panic]
    fn synthesize_with_wrong_oracle_cap() {
        let config = get_testing_wrapper_config();
        let (proof, vk) = (
            get_compression_for_wrapper_proof_for_testing(config),
            get_compression_for_wrapper_vk_for_testing(config),
        );
        
        let mut proof = proof.into_inner();
        proof.stage_2_oracle_cap[0] = Fr::zero();

        let wrapper_type = config.get_wrapper_type();
        let proof = ZkSyncCompressionForWrapperProof::from_inner(wrapper_type, proof);
        try_to_synthesize_wrapper(proof, vk, config);
    }

    #[test]
    #[should_panic]
    fn synthesize_with_wrong_values_at_z() {
        let config = get_testing_wrapper_config();
        let (proof, vk) = (
            get_compression_for_wrapper_proof_for_testing(config),
            get_compression_for_wrapper_vk_for_testing(config),
        );
        
        let mut proof = proof.into_inner();
        proof.values_at_z[0] = ExtensionField::ZERO;

        let wrapper_type = config.get_wrapper_type();
        let proof = ZkSyncCompressionForWrapperProof::from_inner(wrapper_type, proof);
        try_to_synthesize_wrapper(proof, vk, config);
    }

    #[test]
    #[should_panic]
    fn synthesize_with_wrong_fri_queries() {
        let config = get_testing_wrapper_config();
        let (proof, vk) = (
            get_compression_for_wrapper_proof_for_testing(config),
            get_compression_for_wrapper_vk_for_testing(config),
        );
        
        let mut proof = proof.into_inner();
        proof.queries_per_fri_repetition[0].quotient_query.proof[0] = Fr::zero();

        let wrapper_type = config.get_wrapper_type();
        let proof = ZkSyncCompressionForWrapperProof::from_inner(wrapper_type, proof);
        try_to_synthesize_wrapper(proof, vk, config);
    }
}
