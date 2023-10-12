#[cfg(test)]
mod test {
    use crate::boojum::cs::implementations::verifier::*;
    use crate::snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
    use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::*;
    use crate::snark_wrapper::franklin_crypto::plonk::circuit::bigint_new::BITWISE_LOGICAL_OPS_TABLE_NAME;
    use crate::snark_wrapper::franklin_crypto::plonk::circuit::goldilocks::GoldilocksField;
    use crate::snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;
    use crate::snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;

    use crate::boojum::cs::implementations::proof::Proof;
    use crate::boojum::cs::implementations::prover::ProofConfig;
    use crate::boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
    use crate::boojum::field::goldilocks::{GoldilocksExt2 as GLExt2, GoldilocksField as GL};
    use crate::boojum::field::Field;
    use crate::boojum::field::SmallField;
    use crate::boojum::field::U64Representable;

    // use crate::snark_wrapper;
    use crate::snark_wrapper::verifier_structs::allocated_proof::AllocatedProof;
    use crate::snark_wrapper::verifier_structs::allocated_vk::AllocatedVerificationKey;
    use crate::snark_wrapper::verifier_structs::WrapperVerifier;

    use circuit_definitions::circuit_definitions::aux_layer::compression::CompressionMode2ForWrapperCircuitBuilder;
    use circuit_definitions::circuit_definitions::aux_layer::compression::ProofCompressionFunction;
    use circuit_definitions::circuit_definitions::aux_layer::compression_modes::CompressionMode2ForWrapper;

    #[test]
    fn test_verify_circuit_size() {
        // Create testing constraint system

        let mut assembly = TrivialAssembly::<
            Bn256,
            PlonkCsWidth4WithNextStepParams,
            Width4MainGateWithDNext,
        >::new();
        let before = assembly.n();

        // add table for range check
        let columns3 = vec![
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
        ];

        let name = BITWISE_LOGICAL_OPS_TABLE_NAME;
        let bitwise_logic_table = LookupTableApplication::new(
            name,
            TwoKeysOneValueBinopTable::<Bn256, XorBinop>::new(8, name),
            columns3.clone(),
            None,
            true,
        );
        assembly.add_table(bitwise_logic_table).unwrap();

        // Allocate proof and vk
        use crate::snark_wrapper::traits::circuit::ErasedBuilderForWrapperVerifier;
        let verifier_builder = CompressionMode2ForWrapperCircuitBuilder::default();
        let verifier = verifier_builder.create_wrapper_verifier(&mut assembly);

        let proof_config = CompressionMode2ForWrapper::proof_config_for_compression_step();

        let proof_file = std::fs::File::open("compression_2_for_wrapper_proof.json").unwrap();
        let proof: Proof<
            GL,
            <CompressionMode2ForWrapper as ProofCompressionFunction>::ThisLayerHasher,
            GLExt2,
        > = serde_json::from_reader(proof_file).unwrap();

        let vk_file_file = std::fs::File::open("compression_2_for_wrapper_vk.json").unwrap();
        let vk: crate::boojum::cs::implementations::verifier::VerificationKey<
            GL,
            <CompressionMode2ForWrapper as ProofCompressionFunction>::ThisLayerHasher,
        > = serde_json::from_reader(vk_file_file).unwrap();

        let fixed_parameters = vk.fixed_parameters.clone();

        let proof: AllocatedProof<Bn256, CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>> =
            AllocatedProof::allocate_from_witness(
                &mut assembly,
                &Some(proof),
                &verifier,
                &fixed_parameters,
                &proof_config,
            )
            .unwrap();

        let vk: AllocatedVerificationKey<Bn256, CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>> =
            AllocatedVerificationKey::allocate_from_witness(
                &mut assembly,
                Some(vk),
                &fixed_parameters,
            )
            .unwrap();

        // Verify proof
        crate::snark_wrapper::verifier::verify::<
            _,
            _,
            _,
            CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>,
        >(
            &mut assembly,
            (),
            &proof_config,
            &proof,
            &verifier,
            &fixed_parameters,
            &vk,
        )
        .unwrap();

        let after = assembly.n();

        dbg!(after - before);

        assert!(assembly.is_satisfied());

        dbg!(assembly.gates);
    }
}
