use super::*;
use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use circuit_definitions::circuit_definitions::aux_layer::compression::*;
use circuit_definitions::circuit_definitions::recursion_layer::verifier_builder::*;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

#[cfg(test)]
mod test {
    use circuit_definitions::boojum::cs::implementations::pow::NoPow;
    use circuit_definitions::boojum::cs::implementations::proof::Proof;
    use circuit_definitions::boojum::cs::implementations::verifier::VerificationKey;
    use circuit_definitions::circuit_definitions::aux_layer::compression_modes::*;
    use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
    use circuit_definitions::{
        circuit_definitions::recursion_layer::ZkSyncRecursionLayerStorageType,
        recursion_layer_proof_config,
    };

    use super::*;
    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use crate::boojum::cs::oracle::TreeHasher;
    use crate::boojum::worker::Worker;
    use crate::data_source::{
        local_file_data_source::LocalFileDataSource, BlockDataSource, SetupDataSource,
    };

    fn prove_and_save<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
        file_prefix: String,
    ) where
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
            num_vars.unwrap(),
            max_trace_len.unwrap(),
        );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = circuit.configure_builder_proxy(builder);
        let mut cs_owned = builder.build(());
        circuit.synthesize_into_cs(&mut cs_owned);

        cs_owned.pad_and_shrink();
        let mut assembly = cs_owned.into_assembly();
        assembly.print_gate_stats();

        assert!(assembly.check_if_satisfied(&worker));

        let (proof, vk) = assembly
            .prove_one_shot::<EXT, CF::ThisLayerTranscript, CF::ThisLayerHasher, CF::ThisLayerPoW>(
                &worker,
                proof_config,
                transcript_params,
            );

        let proof_file = std::fs::File::create(&format!("{}_proof.json", &file_prefix)).unwrap();
        serde_json::to_writer(proof_file, &proof).unwrap();

        let vk_file_file = std::fs::File::create(&format!("{}_vk.json", &file_prefix)).unwrap();
        serde_json::to_writer(vk_file_file, &vk).unwrap();
    }

    #[test]
    fn preform_step_1_compression() {
        let source = LocalFileDataSource;
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

        prove_and_save(circuit, "compression_1".to_string());
    }

    #[test]
    fn preform_step_2_compression() {
        let proof_file = std::fs::File::open("compression_1_proof.json").unwrap();
        let proof: Proof<F, <CompressionMode1 as ProofCompressionFunction>::ThisLayerHasher, EXT> =
            serde_json::from_reader(proof_file).unwrap();

        let vk_file_file = std::fs::File::open("compression_1_vk.json").unwrap();
        let vk: VerificationKey<
            F,
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerHasher,
        > = serde_json::from_reader(vk_file_file).unwrap();

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

        prove_and_save(circuit, "compression_2".to_string());
    }

    #[test]
    fn preform_step_2_compression_for_wrapper() {
        let proof_file = std::fs::File::open("compression_1_proof.json").unwrap();
        let proof: Proof<F, <CompressionMode1 as ProofCompressionFunction>::ThisLayerHasher, EXT> =
            serde_json::from_reader(proof_file).unwrap();

        let vk_file_file = std::fs::File::open("compression_1_vk.json").unwrap();
        let vk: VerificationKey<
            F,
            <CompressionMode1 as ProofCompressionFunction>::ThisLayerHasher,
        > = serde_json::from_reader(vk_file_file).unwrap();

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

        prove_and_save(circuit, "compression_2_for_wrapper".to_string());
    }

    #[test]
    fn preform_step_3_compression() {
        let proof_file = std::fs::File::open("compression_2_proof.json").unwrap();
        let proof: Proof<F, <CompressionMode2 as ProofCompressionFunction>::ThisLayerHasher, EXT> =
            serde_json::from_reader(proof_file).unwrap();

        let vk_file_file = std::fs::File::open("compression_2_vk.json").unwrap();
        let vk: VerificationKey<
            F,
            <CompressionMode2 as ProofCompressionFunction>::ThisLayerHasher,
        > = serde_json::from_reader(vk_file_file).unwrap();

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

        prove_and_save(circuit, "compression_3".to_string());
    }

    #[test]
    fn preform_step_4_compression() {
        let proof_file = std::fs::File::open("compression_3_proof.json").unwrap();
        let proof: Proof<F, <CompressionMode3 as ProofCompressionFunction>::ThisLayerHasher, EXT> =
            serde_json::from_reader(proof_file).unwrap();

        let vk_file_file = std::fs::File::open("compression_3_vk.json").unwrap();
        let vk: VerificationKey<
            F,
            <CompressionMode3 as ProofCompressionFunction>::ThisLayerHasher,
        > = serde_json::from_reader(vk_file_file).unwrap();

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

        prove_and_save(circuit, "compression_4".to_string());
    }

    #[test]
    fn preform_step_to_l1_compression() {
        let proof_file = std::fs::File::open("compression_4_proof.json").unwrap();
        let proof: Proof<F, <CompressionMode4 as ProofCompressionFunction>::ThisLayerHasher, EXT> =
            serde_json::from_reader(proof_file).unwrap();

        let vk_file_file = std::fs::File::open("compression_4_vk.json").unwrap();
        let vk: VerificationKey<
            F,
            <CompressionMode4 as ProofCompressionFunction>::ThisLayerHasher,
        > = serde_json::from_reader(vk_file_file).unwrap();

        let verifier_builder = CompressionMode4CircuitBuilder::dyn_verifier_builder();
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<
            <CompressionMode4 as ProofCompressionFunction>::ThisLayerHasher,
            <CompressionMode4 as ProofCompressionFunction>::ThisLayerTranscript,
            <CompressionMode4 as ProofCompressionFunction>::ThisLayerPoW,
        >((), &vk, &proof.clone());
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode5Circuit {
            witness: Some(proof.clone()),
            config: CompressionRecursionConfig {
                proof_config: CompressionMode4::proof_config_for_compression_step(),
                verification_key: vk,
                _marker: std::marker::PhantomData,
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        prove_and_save(circuit, "compression_to_l1".to_string());
    }

    #[test]
    fn compress_1() {
        let source = LocalFileDataSource;
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

        let worker = Worker::new();

        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();

        let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, DevCSConfig>::new(
            geometry,
            num_vars.unwrap(),
            max_trace_len.unwrap(),
        );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = circuit.configure_builder_proxy(builder);
        let mut cs_owned = builder.build(());
        circuit.synthesize_into_cs(&mut cs_owned);
        let _num_gates = cs_owned.pad_and_shrink();

        let mut assembly = cs_owned.into_assembly();
        assembly.print_gate_stats();

        assert!(assembly.check_if_satisfied(&worker));
    }
}
