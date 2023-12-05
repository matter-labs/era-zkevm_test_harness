use super::*;

pub(crate) fn compute_compression_vks_and_write<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    config: WrapperConfig,
    worker: &Worker,
) {
    for circuit_type in config.get_compression_types() {
        let vk = get_vk_for_previous_circuit(source, circuit_type).expect(&format!(
            "VK of previous circuit should be present. Current circuit type: {}",
            circuit_type
        ));

        let compression_circuit =
            ZkSyncCompressionLayerCircuit::from_witness_and_vk(None, vk, circuit_type);
        let proof_config = compression_circuit.proof_config_for_compression_step();

        let (_, _, vk, _, _, _, finalization_hint) = create_compression_layer_setup_data(
            compression_circuit,
            &worker,
            proof_config.fri_lde_factor,
            proof_config.merkle_tree_cap_size,
        );

        source
            .set_compression_vk(ZkSyncCompressionLayerStorage::from_inner(
                circuit_type,
                vk.clone(),
            ))
            .unwrap();
        source
            .set_compression_hint(ZkSyncCompressionLayerStorage::from_inner(
                circuit_type,
                finalization_hint.clone(),
            ))
            .unwrap();
    }
}

pub(crate) fn compute_compression_circuits<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    config: WrapperConfig,
    worker: &Worker,
) {
    for circuit_type in config.get_compression_types() {
        if source.get_compression_proof(circuit_type).is_err()
            || source.get_compression_vk(circuit_type).is_err()
            || source.get_compression_hint(circuit_type).is_err()
        {
            let proof = get_proof_for_previous_circuit(source, circuit_type).expect(&format!(
                "Proof of previous circuit should be present. Current circuit type: {}",
                circuit_type
            ));
            let vk = get_vk_for_previous_circuit(source, circuit_type).expect(&format!(
                "VK of previous circuit should be present. Current circuit type: {}",
                circuit_type
            ));

            let compression_circuit =
                ZkSyncCompressionLayerCircuit::from_witness_and_vk(Some(proof), vk, circuit_type);

            let (vk, finalization_hint, proof) =
                compute_compression_circuit_inner(compression_circuit, &worker);

            source
                .set_compression_vk(ZkSyncCompressionLayerStorage::from_inner(
                    circuit_type,
                    vk.clone(),
                ))
                .unwrap();
            source
                .set_compression_hint(ZkSyncCompressionLayerStorage::from_inner(
                    circuit_type,
                    finalization_hint.clone(),
                ))
                .unwrap();
            source
                .set_compression_proof(ZkSyncCompressionLayerStorage::from_inner(
                    circuit_type,
                    proof,
                ))
                .unwrap();
        }
    }
}

fn compute_compression_circuit_inner(
    circuit: ZkSyncCompressionLayerCircuit,
    worker: &Worker,
) -> (
    ZkSyncCompressionVerificationKey,
    FinalizationHintsForProver,
    ZkSyncCompressionProof,
) {
    let start = std::time::Instant::now();

    let circuit_type = circuit.numeric_circuit_type();

    test_compression_circuit(circuit.clone());
    println!("Circuit is satisfied");

    let proof_config = circuit.proof_config_for_compression_step();

    let setup_circuit = circuit.clone_without_witness();
    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
        create_compression_layer_setup_data(
            setup_circuit.clone(),
            &worker,
            proof_config.fri_lde_factor,
            proof_config.merkle_tree_cap_size,
        );

    // prove
    println!("Proving!");

    let proof = prove_compression_layer_circuit::<NoPow>(
        circuit,
        &worker,
        proof_config,
        &setup_base,
        &setup,
        &setup_tree,
        &vk,
        &vars_hint,
        &wits_hint,
        &finalization_hint,
    );

    let is_valid = verify_compression_layer_proof::<NoPow>(&setup_circuit, &proof, &vk);

    assert!(is_valid);

    println!(
        "Compression {} is done, taken {:?}",
        circuit_type,
        start.elapsed()
    );

    (vk, finalization_hint, proof)
}
