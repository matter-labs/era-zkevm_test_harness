use super::*;

pub(crate) const L1_VERIFIER_DOMAIN_SIZE_LOG: usize = 24;

pub fn get_wrapper_setup_and_vk_from_compression_vk(
    vk: ZkSyncCompressionForWrapperVerificationKey,
    config: WrapperConfig,
) -> (ZkSyncSnarkWrapperSetup, ZkSyncSnarkWrapperVK) {
    check_trusted_setup_file_existace();

    let worker = BellmanWorker::new();

    let snark_setup = compute_wrapper_setup_inner(vk, config, &worker);

    let crs_mons = get_trusted_setup();
    let snark_vk = SnarkVK::from_setup(&snark_setup, &worker, &crs_mons).unwrap();

    let wrapper_type = config.get_wrapper_type();
    (
        ZkSyncSnarkWrapperSetup::from_inner(wrapper_type, Arc::new(snark_setup)),
        ZkSyncSnarkWrapperVK::from_inner(wrapper_type, snark_vk),
    )
}

pub(crate) fn compute_wrapper_proof_and_vk<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    config: WrapperConfig,
    worker: &BellmanWorker,
) {
    let wrapper_type = config.get_wrapper_type();

    println!("Computing wrapper setup");
    if source.get_wrapper_setup(wrapper_type).is_err() {
        let vk = source.get_compression_for_wrapper_vk(wrapper_type).unwrap();

        let snark_setup = compute_wrapper_setup_inner(vk, config, worker);

        let snark_setup =
            ZkSyncCompressionLayerStorage::from_inner(wrapper_type, Arc::new(snark_setup));
        source.set_wrapper_setup(snark_setup).unwrap();
    }

    println!("Computing wrapper vk");
    if source.get_wrapper_vk(wrapper_type).is_err() {
        let start = std::time::Instant::now();
        let snark_setup = source.get_wrapper_setup(wrapper_type).unwrap();

        let crs_mons = get_trusted_setup();
        let snark_vk = SnarkVK::from_setup(&snark_setup.into_inner(), worker, &crs_mons).unwrap();

        println!(
            "Wrapper vk {} is done, taken {:?}",
            wrapper_type,
            start.elapsed()
        );

        let snark_vk = ZkSyncCompressionLayerStorage::from_inner(wrapper_type, snark_vk);
        source.set_wrapper_vk(snark_vk).unwrap();
    }

    println!("Computing wrapper proof");
    if source.get_wrapper_proof(wrapper_type).is_err() {
        let proof = source
            .get_compression_for_wrapper_proof(wrapper_type)
            .unwrap();
        let vk = source.get_compression_for_wrapper_vk(wrapper_type).unwrap();

        let snark_setup = source.get_wrapper_setup(wrapper_type).unwrap();

        let snark_proof = compute_wrapper_proof_inner(proof, vk, snark_setup, config, worker);

        println!("Verifying");
        let snark_vk = source.get_wrapper_vk(wrapper_type).unwrap();
        use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
        let is_valid =
            verify::<_, _, RollingKeccakTranscript<Fr>>(&snark_vk.into_inner(), &snark_proof, None)
                .unwrap();
        assert!(is_valid);

        let snark_proof = ZkSyncCompressionLayerStorage::from_inner(wrapper_type, snark_proof);
        source.set_wrapper_proof(snark_proof).unwrap();
    }
}

pub(crate) fn compute_wrapper_setup_inner(
    vk: ZkSyncCompressionForWrapperVerificationKey,
    config: WrapperConfig,
    worker: &BellmanWorker,
) -> SnarkSetup<Bn256, ZkSyncSnarkWrapperCircuit> {
    let start = std::time::Instant::now();
    let wrapper_type = config.get_wrapper_type();

    let compression_for_wrapper_type = config.get_compression_for_wrapper_type();
    assert_eq!(compression_for_wrapper_type, vk.numeric_circuit_type());
    let vk = vk.into_inner();

    let mut assembly = SetupAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fixed_parameters = vk.fixed_parameters.clone();

    let wrapper_function = ZkSyncCompressionWrapper::from_numeric_circuit_type(wrapper_type);
    let wrapper_circuit = WrapperCircuit::<_, _, TreeHasherForWrapper, TranscriptForWrapper, _> {
        witness: None,
        vk: vk,
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };

    println!("Synthesizing");
    wrapper_circuit.synthesize(&mut assembly).unwrap();

    assembly.finalize_to_size_log_2(L1_VERIFIER_DOMAIN_SIZE_LOG);
    assert!(assembly.is_satisfied());

    println!("Creating setup");
    let setup =
        assembly
            .create_setup::<WrapperCircuit<
                _,
                _,
                TreeHasherForWrapper,
                TranscriptForWrapper,
                ZkSyncCompressionWrapper,
            >>(worker)
            .unwrap();

    println!(
        "Wrapper setup {} is done, taken {:?}",
        wrapper_type,
        start.elapsed()
    );

    setup
}

fn compute_wrapper_proof_inner(
    proof: ZkSyncCompressionForWrapperProof,
    vk: ZkSyncCompressionForWrapperVerificationKey,
    snark_setup: ZkSyncSnarkWrapperSetup,
    config: WrapperConfig,
    worker: &BellmanWorker,
) -> SnarkProof<Bn256, ZkSyncSnarkWrapperCircuit> {
    check_trusted_setup_file_existace();

    let start = std::time::Instant::now();
    let wrapper_type = config.get_wrapper_type();

    let compression_for_wrapper_type = config.get_compression_for_wrapper_type();
    assert_eq!(compression_for_wrapper_type, proof.numeric_circuit_type());
    assert_eq!(compression_for_wrapper_type, vk.numeric_circuit_type());
    assert_eq!(wrapper_type, snark_setup.numeric_circuit_type());

    let proof = proof.into_inner();
    let vk = vk.into_inner();
    let snark_setup = snark_setup.into_inner();

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

    println!("Synthesizing");
    wrapper_circuit.synthesize(&mut assembly).unwrap();

    assembly.finalize_to_size_log_2(L1_VERIFIER_DOMAIN_SIZE_LOG);
    assert!(assembly.is_satisfied());

    println!(
        "Wrapper benchmark: {} gates for mode {}",
        assembly.n(),
        wrapper_type
    );

    let crs_mons = get_trusted_setup();

    println!("Proving");
    let proof =
        assembly
            .create_proof::<WrapperCircuit<
                _,
                _,
                TreeHasherForWrapper,
                TranscriptForWrapper,
                ZkSyncCompressionWrapper,
            >, RollingKeccakTranscript<Fr>>(worker, &snark_setup, &crs_mons, None)
            .unwrap();

    println!(
        "Wrapper proof {} is done, taken {:?}",
        wrapper_type,
        start.elapsed()
    );

    proof
}
