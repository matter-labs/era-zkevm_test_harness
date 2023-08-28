use circuit_definitions::base_layer_proof_config;
use circuit_definitions::boojum::cs::implementations::pow::NoPow;
use circuit_definitions::boojum::cs::implementations::setup::FinalizationHintsForProver;
use circuit_definitions::circuit_definitions::aux_layer::compression::{CompressionMode1Circuit, CompressionMode1ForWrapperCircuit, CompressionMode2Circuit, CompressionMode2ForWrapperCircuit, CompressionMode3Circuit, CompressionMode3ForWrapperCircuit, CompressionMode4Circuit, CompressionMode4ForWrapperCircuit, CompressionModeToL1Circuit, CompressionModeToL1ForWrapperCircuit, ProofCompressionFunction};
use circuit_definitions::circuit_definitions::aux_layer::compression_modes::{CompressionMode1, CompressionMode1ForWrapper, CompressionMode2, CompressionMode2ForWrapper, CompressionMode3, CompressionMode3ForWrapper, CompressionMode4, CompressionMode4ForWrapper};
use circuit_definitions::circuit_definitions::aux_layer::{ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionLayerCircuit, ZkSyncCompressionLayerStorage, ZkSyncCompressionProof, ZkSyncCompressionProofForWrapper, ZkSyncCompressionVerificationKey, ZkSyncCompressionVerificationKeyForWrapper, ZkSyncSnarkWrapperCircuit, ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperVK};
use circuit_definitions::circuit_definitions::aux_layer::wrapper::ZkSyncCompressionWrapper;
use circuit_definitions::circuit_definitions::recursion_layer::{ZkSyncRecursionLayerProof, ZkSyncRecursionLayerStorageType, ZkSyncRecursionLayerVerificationKey};
use circuit_definitions::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use snark_wrapper::franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, PlonkCsWidth4WithNextStepAndCustomGatesParams, TrivialAssembly};
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use snark_wrapper::franklin_crypto::bellman::worker::Worker as BellmanWorker;
use snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;
use snark_wrapper::verifier::WrapperCircuit;
use snark_wrapper::verifier_structs::allocated_vk::AllocatedVerificationKey;
use circuit_definitions::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use crate::boojum::worker::Worker;

pub type TreeHasherForWrapper =
CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type TranscriptForWrapper =
CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;

use crate::data_source::{BlockDataSource, SetupDataSource};
use crate::in_memory_data_source::InMemoryDataSource;
use crate::prover_utils::{create_compression_for_wrapper_setup_data, create_compression_layer_setup_data, prove_compression_for_wrapper_circuit, prove_compression_layer_circuit, verify_compression_for_wrapper_proof, verify_compression_layer_proof};
use crate::tests::{test_compression_circuit, test_compression_for_wrapper_circuit};

pub fn wrap_proof(proof: ZkSyncRecursionLayerProof, vk: ZkSyncRecursionLayerVerificationKey, compression: u8) -> (ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperVK) {
    assert!(compression > 0 && compression <= 5, "compression should be between 1 and 5");

    let worker = Worker::new_with_num_threads(8);
    let bellman_worker = BellmanWorker::new();

    let mut source = InMemoryDataSource::new();
    source.set_scheduler_proof(proof)
        .expect("Failed to set scheduler proof");
    source.set_recursion_layer_vk(vk)
        .expect("Failed to set scheduler vk");

    for circuit_type in 1..=5 {
        if compression > circuit_type {
            compute_compression_circuit(&mut source, circuit_type, &worker);
        } else {
            compute_compression_for_wrapper_circuit(&mut source, circuit_type, &worker);
            compute_wrapper_proof(&mut source, circuit_type, &bellman_worker);
            break;
        }
    }
    (source.get_wrapper_proof(compression).unwrap(), source.get_wrapper_vk(compression).unwrap())
}

pub(crate) fn compute_compression_circuit<
    DS: SetupDataSource + BlockDataSource,
> (
    source: &mut DS,
    circuit_type: u8,
    worker: &Worker,
) {
    if source.get_compression_proof(circuit_type).is_err()
        || source.get_compression_vk(circuit_type).is_err()
        || source.get_compression_hint(circuit_type).is_err() {

        let (proof, vk) = match circuit_type {
            1 => (
                source.get_scheduler_proof().expect("scheduler proof should be present").into_inner(),
                source.get_recursion_layer_vk(
                    ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
                ).expect("scheduler vk should be present").into_inner()
            ),
            circuit_type => (
                source.get_compression_proof(circuit_type - 1).expect("compression proof should be present").into_inner(),
                source.get_compression_vk(circuit_type - 1).expect("compression vk should be present").into_inner()
            )
        };

        let compression_circuit = match circuit_type {
            1 => ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(
                CompressionMode1Circuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: base_layer_proof_config(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            2 => ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(
                CompressionMode2Circuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode1::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            3 => ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(
                CompressionMode3Circuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode2::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            4 => ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(
                CompressionMode4Circuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode3::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            5 => ZkSyncCompressionLayerCircuit::CompressionModeToL1Circuit(
                CompressionModeToL1Circuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode4::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            _ => unreachable!(),
        };

        let (vk, finalization_hint, proof) = compute_compression_circuit_inner(compression_circuit, &worker);

        source.set_compression_vk(
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, vk.clone())
        ).unwrap();
        source.set_compression_hint(
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, finalization_hint.clone())
        ).unwrap();
        source.set_compression_proof(
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, proof)
        ).unwrap();
    }

}

fn compute_compression_circuit_inner(
    circuit: ZkSyncCompressionLayerCircuit,
    worker: &Worker,
) -> (
    ZkSyncCompressionVerificationKey,
    FinalizationHintsForProver,
    ZkSyncCompressionProof
) {
    let start = std::time::Instant::now();

    let circuit_type = circuit.numeric_circuit_type();
    let f = std::fs::File::create("tmp.json").unwrap();
    serde_json::to_writer(f, &circuit).unwrap();

    test_compression_circuit(circuit.clone());
    println!("Circuit is satisfied");

    let proof_config = circuit.proof_config_for_compression_step();

    let (setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        wits_hint,
        finalization_hint
    ) = create_compression_layer_setup_data(
        circuit.clone(),
        &worker,
        proof_config.fri_lde_factor,
        proof_config.merkle_tree_cap_size,
    );

    // prove
    println!("Proving!");

    let proof = prove_compression_layer_circuit::<NoPow>(
        circuit.clone(),
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

    let is_valid = verify_compression_layer_proof::<NoPow>(&circuit, &proof, &vk);

    assert!(is_valid);

    println!("Compression {} is done, taken {:?}", circuit_type, start.elapsed());

    (vk, finalization_hint, proof)
}

pub(crate) fn compute_compression_for_wrapper_circuit<
    DS: SetupDataSource + BlockDataSource,
>(
    source: &mut DS,
    circuit_type: u8,
    worker: &Worker,
){
    if source.get_compression_for_wrapper_vk(circuit_type).is_err()
        || source.get_compression_for_wrapper_hint(circuit_type).is_err()
        || source.get_compression_for_wrapper_proof(circuit_type).is_err() {

        let (proof, vk) = match circuit_type {
            1 => (
                source.get_scheduler_proof().expect("scheduler proof should be present").into_inner(),
                source.get_recursion_layer_vk(
                    ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
                ).expect("scheduler vk should be present").into_inner()
            ),
            circuit_type => (
                source.get_compression_proof(circuit_type - 1).expect("compression proof should be present").into_inner(),
                source.get_compression_vk(circuit_type - 1).expect("compression vk should be present").into_inner()
            )
        };

        let compression_circuit = match circuit_type {
            1 => ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(
                CompressionMode1ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: base_layer_proof_config(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            2 => ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(
                CompressionMode2ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode1ForWrapper::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            3 => ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(
                CompressionMode3ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode2ForWrapper::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            4 => ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(
                CompressionMode4ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode3ForWrapper::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            5 => ZkSyncCompressionForWrapperCircuit::CompressionModeToL1Circuit(
                CompressionModeToL1ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode4ForWrapper::proof_config_for_compression_step(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                }
            ),
            _ => unreachable!(),
        };

        let (vk, finalization_hint, proof) = compute_compression_for_wrapper_circuit_inner(compression_circuit, worker);


        // we did it above
        source.set_compression_for_wrapper_vk(
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, vk.clone())
        ).unwrap();
        source.set_compression_for_wrapper_hint(
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, finalization_hint.clone())
        ).unwrap();
        source.set_compression_for_wrapper_proof(
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, proof)
        ).unwrap();
    }

}

fn compute_compression_for_wrapper_circuit_inner(
    circuit: ZkSyncCompressionForWrapperCircuit,
    worker: &Worker,
) -> (
    ZkSyncCompressionVerificationKeyForWrapper,
    FinalizationHintsForProver,
    ZkSyncCompressionProofForWrapper
){
    let start = std::time::Instant::now();

    let circuit_type = circuit.numeric_circuit_type();
    let f = std::fs::File::create("tmp.json").unwrap();
    serde_json::to_writer(f, &circuit).unwrap();

    test_compression_for_wrapper_circuit(circuit.clone());
    println!("Circuit is satisfied");

    let proof_config = circuit.proof_config_for_compression_step();

    let (setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        wits_hint,
        finalization_hint
    ) = create_compression_for_wrapper_setup_data(
        circuit.clone(),
        &worker,
        proof_config.fri_lde_factor,
        proof_config.merkle_tree_cap_size,
    );

    // prove
    println!("Proving!");
    let now = std::time::Instant::now();

    let proof = prove_compression_for_wrapper_circuit::<NoPow>(
        circuit.clone(),
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

    println!("Proving is DONE, taken {:?}", now.elapsed());

    let is_valid = verify_compression_for_wrapper_proof::<NoPow>(&circuit, &proof, &vk);

    assert!(is_valid);

    println!("Compression for wrapper {} is done, taken {:?}", circuit_type, start.elapsed());

    (vk, finalization_hint, proof)
}

pub(crate) fn compute_wrapper_proof<
    DS: SetupDataSource + BlockDataSource,
> (
    source: &mut DS,
    circuit_type: u8,
    worker: &BellmanWorker,
) {
    if source.get_wrapper_vk(circuit_type).is_err()
        || source.get_wrapper_proof(circuit_type).is_err() {

        let proof = source.get_compression_for_wrapper_proof(circuit_type).unwrap();
        let vk = source.get_compression_for_wrapper_vk(circuit_type).unwrap();

        let (snark_vk, snark_proof) = compute_wrapper_proof_inner(circuit_type, proof.into_inner(), vk.into_inner(), worker);

        let snark_vk = ZkSyncCompressionLayerStorage::from_inner(circuit_type, snark_vk);
        source.set_wrapper_vk(snark_vk).unwrap();

        let snark_proof = ZkSyncCompressionLayerStorage::from_inner(circuit_type, snark_proof);
        source.set_wrapper_proof(snark_proof).unwrap();
    }
}

fn compute_wrapper_proof_inner(
    circuit_type: u8,
    proof: ZkSyncCompressionProofForWrapper,
    vk: ZkSyncCompressionVerificationKeyForWrapper,
    worker: &BellmanWorker,
) -> (
    SnarkVK<Bn256, ZkSyncSnarkWrapperCircuit>,
    SnarkProof<Bn256, ZkSyncSnarkWrapperCircuit>,
) {
    let start = std::time::Instant::now();

    let mut assembly = TrivialAssembly::<Bn256, PlonkCsWidth4WithNextStepAndCustomGatesParams, SelectorOptimizedWidth4MainGateWithDNext>::new();

    let fixed_parameters = vk.fixed_parameters.clone();

    let allocated_vk = AllocatedVerificationKey::<Bn256, TreeHasherForWrapper>::allocate_from_witness(
        &mut assembly,
        Some(vk),
        &fixed_parameters,
    ).unwrap();

    let wrapper_function = ZkSyncCompressionWrapper::from_numeric_circuit_type(circuit_type);
    let wrapper_circuit = WrapperCircuit::<_, _, _, TranscriptForWrapper, _> {
        witness: Some(proof),
        vk: allocated_vk,
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };

    wrapper_circuit.synthesize(&mut assembly).unwrap();

    assert!(assembly.is_satisfied());

    println!("Wrapper benchmark: {} gates for mode {}", assembly.n(), circuit_type);

    assembly.finalize();

    println!("Creating setup");
    let setup = assembly.create_setup::<
        WrapperCircuit::<_, _, TreeHasherForWrapper, TranscriptForWrapper, ZkSyncCompressionWrapper>
    >(worker).unwrap();

    let domain_size = assembly.n().next_power_of_two();
    let crs_mons = Crs::<Bn256, CrsForMonomialForm>::crs_42(domain_size, worker);
    let vk = SnarkVK::from_setup(&setup, worker, &crs_mons).unwrap();

    let proof = assembly.create_proof::<
        WrapperCircuit::<_, _, TreeHasherForWrapper, TranscriptForWrapper, ZkSyncCompressionWrapper>,
        RollingKeccakTranscript<Fr>
    >(
        worker,
        &setup,
        &crs_mons,
        None,
    )
        .unwrap();

    println!("Wrapper proof {} is done, taken {:?}", circuit_type, start.elapsed());

    (vk, proof)
}
