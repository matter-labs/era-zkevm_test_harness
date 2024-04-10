#[cfg(test)]
mod test {
    use std::alloc::Global;

    use crate::boojum::field::goldilocks::GoldilocksField;
    use circuit_definitions::boojum::cs::implementations::pow::NoPow;
    use circuit_definitions::boojum::cs::implementations::proof::Proof;
    use circuit_definitions::boojum::cs::implementations::verifier::VerificationKey;
    use circuit_definitions::circuit_definitions::aux_layer::{
        compression_modes::*, ZkSyncCompressionForWrapperProof,
        ZkSyncCompressionForWrapperVerificationKey, ZkSyncCompressionLayerProof,
        ZkSyncCompressionLayerStorage, ZkSyncCompressionLayerStorageType,
        ZkSyncCompressionLayerVerificationKey,
    };
    use circuit_definitions::{
        circuit_definitions::recursion_layer::ZkSyncRecursionLayerStorageType,
        recursion_layer_proof_config,
    };
    use serde::Serialize;

    use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
    use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
    use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
    use crate::boojum::field::goldilocks::GoldilocksExt2;

    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use crate::boojum::cs::oracle::TreeHasher;
    use crate::boojum::worker::Worker;
    use crate::data_source::{
        local_file_data_source::LocalFileDataSource, BlockDataSource, SetupDataSource,
    };
    use crate::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
    use circuit_definitions::circuit_definitions::aux_layer::compression::*;
    use circuit_definitions::circuit_definitions::recursion_layer::verifier_builder::*;

    type F = GoldilocksField;
    type P = GoldilocksField;
    type TR = GoldilocksPoisedon2Transcript;
    type EXT = GoldilocksExt2;
    type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;

    fn prove<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
    ) -> (
        Proof<GoldilocksField, <CF as ProofCompressionFunction>::ThisLayerHasher, GoldilocksExt2>,
        VerificationKey<GoldilocksField, <CF as ProofCompressionFunction>::ThisLayerHasher>,
    )
    where
        <CF::ThisLayerHasher as TreeHasher<F>>::Output:
            serde::Serialize + serde::de::DeserializeOwned,
    {
        let worker = Worker::new();

        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();
        let proof_config = CF::proof_config_for_compression_step();
        let transcript_params = CF::this_layer_transcript_parameters();

        let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, DevCSConfig>::new(
            geometry,
            max_trace_len.unwrap(),
        );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = circuit.configure_builder_proxy(builder);
        let mut cs_owned = builder.build(num_vars.unwrap());
        circuit.synthesize_into_cs(&mut cs_owned);

        cs_owned.pad_and_shrink();
        let mut assembly = cs_owned.into_assembly::<std::alloc::Global>();
        assembly.print_gate_stats();

        assert!(assembly.check_if_satisfied(&worker));

        let (proof, vk) = assembly
            .prove_one_shot::<EXT, CF::ThisLayerTranscript, CF::ThisLayerHasher, CF::ThisLayerPoW>(
                &worker,
                proof_config,
                transcript_params,
            );

        (proof, vk)
    }

    /// Saves the vk & proof (if UPDATE_TESTDATA is present in environment) - or verifies that proofs didn't change.
    fn save_or_diff_compression(
        mut source: LocalFileDataSource,
        proof: ZkSyncCompressionLayerProof,
        vk: ZkSyncCompressionLayerVerificationKey,
    ) {
        if std::env::var("UPDATE_TESTDATA").is_ok() {
            source.set_compression_proof(proof).unwrap();
            source.set_compression_vk(vk).unwrap();
        } else {
            let existing_proof = source
                .get_compression_proof(proof.numeric_circuit_type())
                .unwrap();
            let existing_vk = source
                .get_compression_vk(vk.numeric_circuit_type())
                .unwrap();

            assert!(
                bincode::serialize(&proof).unwrap() == bincode::serialize(&existing_proof).unwrap(),
                "Proofs differ. Run with UPDATE_TESTDATA env variable to see the details."
            );
            assert!(
                bincode::serialize(&vk).unwrap() == bincode::serialize(&existing_vk).unwrap(),
                "VK differ. Run with UPDATE_TESTDATA env variable to see the details."
            );
        }
    }

    fn save_or_diff_compression_wrapper(
        mut source: LocalFileDataSource,
        proof: ZkSyncCompressionForWrapperProof,
        vk: ZkSyncCompressionForWrapperVerificationKey,
    ) {
        if std::env::var("UPDATE_TESTDATA").is_ok() {
            source.set_compression_for_wrapper_proof(proof).unwrap();
            source.set_compression_for_wrapper_vk(vk).unwrap();
        } else {
            let existing_proof = source
                .get_compression_for_wrapper_proof(proof.numeric_circuit_type())
                .unwrap();
            let existing_vk = source
                .get_compression_for_wrapper_vk(vk.numeric_circuit_type())
                .unwrap();

            assert!(
                bincode::serialize(&proof).unwrap() == bincode::serialize(&existing_proof).unwrap(),
                "Proofs differ. Run with UPDATE_TESTDATA env variable to see the details."
            );
            assert!(
                bincode::serialize(&vk).unwrap() == bincode::serialize(&existing_vk).unwrap(),
                "VK differ. Run with UPDATE_TESTDATA env variable to see the details."
            );
        }
    }

    #[test]
    fn perform_step_1_compression() {
        let source = LocalFileDataSource {
            setup_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
            block_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
        };
        source.create_folders_for_storing_data();
        let proof = source.get_scheduler_proof().unwrap();
        let vk = source
            .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
            .unwrap();

        let verifier_builder = dyn_verifier_builder_for_recursive_circuit_type(
            ZkSyncRecursionLayerStorageType::SchedulerCircuit,
        );
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<H, TR, NoPow>(
            (),
            &vk.clone().into_inner(),
            &proof.clone().into_inner(),
        );
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode1Circuit {
            witness: Some(proof.clone().into_inner()),
            config: CompressionRecursionConfig {
                proof_config: recursion_layer_proof_config(),
                verification_key: vk.into_inner(),
                _marker: std::marker::PhantomData,
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let (proof, vk) = prove(circuit);
        save_or_diff_compression(
            source,
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8,
                proof,
            ),
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8,
                vk,
            ),
        );
    }

    #[test]
    fn perform_step_2_compression() {
        let source = LocalFileDataSource {
            setup_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
            block_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
        };

        let proof = source
            .get_compression_proof(ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8)
            .unwrap()
            .into_inner();

        let vk = source
            .get_compression_vk(ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8)
            .unwrap()
            .into_inner();

        let verifier_builder = CompressionMode1CircuitBuilder::dyn_verifier_builder();
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerHasher,
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerTranscript,
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerPoW,
        >((), &vk, &proof.clone());
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode2Circuit {
            witness: Some(proof.clone()),
            config: CompressionRecursionConfig {
                proof_config: CompressionMode1::proof_config_for_compression_step(),
                verification_key: vk,
                _marker: std::marker::PhantomData,
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let (proof, vk) = prove(circuit);
        save_or_diff_compression(
            source,
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8,
                proof,
            ),
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8,
                vk,
            ),
        );
    }

    #[test]
    fn perform_step_2_compression_for_wrapper() {
        let source = LocalFileDataSource {
            setup_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
            block_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
        };

        let proof = source
            .get_compression_proof(ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8)
            .unwrap()
            .into_inner();

        let vk = source
            .get_compression_vk(ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8)
            .unwrap()
            .into_inner();

        let verifier_builder = CompressionMode1CircuitBuilder::dyn_verifier_builder();
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerHasher,
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerTranscript,
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerPoW,
        >((), &vk, &proof.clone());
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode2ForWrapperCircuit {
            witness: Some(proof.clone()),
            config: CompressionRecursionConfig {
                proof_config: CompressionMode1::proof_config_for_compression_step(),
                verification_key: vk,
                _marker: std::marker::PhantomData,
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };
        let (proof, vk) = prove(circuit);
        save_or_diff_compression_wrapper(
            source,
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8,
                proof,
            ),
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8,
                vk,
            ),
        );
    }

    #[test]
    fn perform_step_3_compression() {
        let source = LocalFileDataSource {
            setup_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
            block_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
        };

        let proof = source
            .get_compression_proof(ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8)
            .unwrap()
            .into_inner();

        let vk = source
            .get_compression_vk(ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8)
            .unwrap()
            .into_inner();

        let verifier_builder = CompressionMode2CircuitBuilder::dyn_verifier_builder();
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<
            <CompressionMode2 as ProofCompressionFunction>::ThisLayerHasher,
            <CompressionMode2 as ProofCompressionFunction>::ThisLayerTranscript,
            <CompressionMode2 as ProofCompressionFunction>::ThisLayerPoW,
        >((), &vk, &proof.clone());
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode3Circuit {
            witness: Some(proof.clone()),
            config: CompressionRecursionConfig {
                proof_config: CompressionMode2::proof_config_for_compression_step(),
                verification_key: vk,
                _marker: std::marker::PhantomData,
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let (proof, vk) = prove(circuit);
        save_or_diff_compression(
            source,
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8,
                proof,
            ),
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8,
                vk,
            ),
        );
    }

    // Note - this a large test.
    #[ignore = "Test too large (too much RAM) for CI"]
    #[test]
    fn perform_step_4_compression() {
        let source = LocalFileDataSource {
            setup_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
            block_data_location: "src/proof_wrapper_utils/testdata/proof_compression".to_string(),
        };

        let proof = source
            .get_compression_proof(ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8)
            .unwrap()
            .into_inner();

        let vk = source
            .get_compression_vk(ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8)
            .unwrap()
            .into_inner();

        let verifier_builder = CompressionMode3CircuitBuilder::dyn_verifier_builder();
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<
            <CompressionMode3 as ProofCompressionFunction>::ThisLayerHasher,
            <CompressionMode3 as ProofCompressionFunction>::ThisLayerTranscript,
            <CompressionMode3 as ProofCompressionFunction>::ThisLayerPoW,
        >((), &vk, &proof.clone());
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode4Circuit {
            witness: Some(proof.clone()),
            config: CompressionRecursionConfig {
                proof_config: CompressionMode3::proof_config_for_compression_step(),
                verification_key: vk,
                _marker: std::marker::PhantomData,
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let (proof, vk) = prove(circuit);
        save_or_diff_compression(
            source,
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8,
                proof,
            ),
            ZkSyncCompressionLayerStorage::from_inner(
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8,
                vk,
            ),
        );
    }
}
