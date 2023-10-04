use circuit_definitions::recursion_layer_proof_config;
use circuit_definitions::boojum::cs::implementations::pow::NoPow;
use circuit_definitions::boojum::cs::implementations::setup::FinalizationHintsForProver;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::{PrimeField as BoojumPrimeField, U64Representable};
use circuit_definitions::circuit_definitions::aux_layer::compression::{CompressionMode1Circuit, CompressionMode1ForWrapperCircuit, CompressionMode2Circuit, CompressionMode2ForWrapperCircuit, CompressionMode3Circuit, CompressionMode3ForWrapperCircuit, CompressionMode4Circuit, CompressionMode4ForWrapperCircuit, CompressionModeToL1Circuit, CompressionModeToL1ForWrapperCircuit, ProofCompressionFunction};
use circuit_definitions::circuit_definitions::aux_layer::compression_modes::{CompressionMode1, CompressionMode1ForWrapper, CompressionMode2, CompressionMode2ForWrapper, CompressionMode3, CompressionMode3ForWrapper, CompressionMode4, CompressionMode4ForWrapper};
use circuit_definitions::circuit_definitions::aux_layer::{ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionLayerCircuit, ZkSyncCompressionLayerStorage, ZkSyncCompressionProof, ZkSyncCompressionProofForWrapper, ZkSyncCompressionVerificationKey, ZkSyncCompressionVerificationKeyForWrapper, ZkSyncSnarkWrapperCircuit, ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperVK};
use circuit_definitions::circuit_definitions::aux_layer::wrapper::ZkSyncCompressionWrapper;
use circuit_definitions::circuit_definitions::recursion_layer::{ZkSyncRecursionLayerProof, ZkSyncRecursionLayerStorageType, ZkSyncRecursionLayerVerificationKey};
use circuit_definitions::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use snark_wrapper::franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, PlonkCsWidth4WithNextStepAndCustomGatesParams, TrivialAssembly, SetupAssembly, ProvingAssembly};
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::Setup as SnarkSetup;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use snark_wrapper::franklin_crypto::bellman::worker::Worker as BellmanWorker;
use snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;
use snark_wrapper::verifier::WrapperCircuit;
use snark_wrapper::verifier_structs::allocated_vk::AllocatedVerificationKey;
use circuit_definitions::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::franklin_crypto::bellman::{Field, PrimeField, PrimeFieldRepr};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncCompressionForWrapperVerificationKey;
use crate::boojum::worker::Worker;

pub type TreeHasherForWrapper = CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type TranscriptForWrapper = CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;

pub(crate) const CRS_FILE_ENV_VAR: &str = "CRS_FILE";
pub(crate) const L1_VERIFIER_DOMAIN_SIZE_LOG: usize = 24;

use crate::data_source::{BlockDataSource, SetupDataSource};
use crate::data_source::in_memory_data_source::InMemoryDataSource;
use crate::prover_utils::{
    create_compression_for_wrapper_setup_data, create_compression_layer_setup_data,
    prove_compression_for_wrapper_circuit, prove_compression_layer_circuit,
    verify_compression_for_wrapper_proof, verify_compression_layer_proof,
};
use crate::tests::{test_compression_circuit, test_compression_for_wrapper_circuit};

pub fn wrap_proof(
    proof: ZkSyncRecursionLayerProof,
    vk: ZkSyncRecursionLayerVerificationKey,
    compression: u8,
) -> (ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperVK) {
    assert!(
        compression > 0 && compression <= 5,
        "compression should be between 1 and 5"
    );

    let worker = Worker::new();
    let bellman_worker = BellmanWorker::new();

    let mut source = InMemoryDataSource::new();
    source
        .set_scheduler_proof(proof)
        .expect("Failed to set scheduler proof");
    source
        .set_recursion_layer_vk(vk)
        .expect("Failed to set scheduler vk");

    for circuit_type in 1..=5 {
        if compression > circuit_type {
            compute_compression_circuit(&mut source, circuit_type, &worker);
        } else {
            compute_compression_for_wrapper_circuit(&mut source, circuit_type, &worker);
            compute_wrapper_proof_and_vk(&mut source, circuit_type, &bellman_worker);
            break;
        }
    }
    (
        source.get_wrapper_proof(compression).unwrap(),
        source.get_wrapper_vk(compression).unwrap(),
    )
}

pub fn get_wrapper_vk_from_scheduler_vk(
    vk: ZkSyncRecursionLayerVerificationKey, 
    circuit_type: u8
) -> ZkSyncSnarkWrapperVK {
    check_trusted_setup_file_existace();
    let worker = Worker::new();

    assert_eq!(vk.numeric_circuit_type(), ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8);
    let mut source = InMemoryDataSource::new();
    source.set_recursion_layer_vk(vk).unwrap();

    // Firstly compute VKs to compression layer
    if circuit_type > 1 {
        let vk = source.get_recursion_layer_vk(
            ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
        ).unwrap();

        let circuit = ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(
            CompressionMode1Circuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: recursion_layer_proof_config(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_vk_and_write(circuit, &mut source, &worker);
    }

    if circuit_type > 2 {
        let vk = source.get_compression_vk(1).unwrap();

        let circuit = ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(
            CompressionMode2Circuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode1::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_vk_and_write(circuit, &mut source, &worker);
    }

    if circuit_type > 3 {
        let vk = source.get_compression_vk(2).unwrap();

        let circuit = ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(
            CompressionMode3Circuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode2::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_vk_and_write(circuit, &mut source, &worker);
    }

    if circuit_type > 4 {
        let vk = source.get_compression_vk(3).unwrap();

        let circuit = ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(
            CompressionMode4Circuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode3::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_vk_and_write(circuit, &mut source, &worker);
    }
    
    // Then compute VKs to compression for wrapper
    if circuit_type == 1 {
        let vk = source.get_recursion_layer_vk(
            ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
        ).unwrap();

        let circuit = ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(
            CompressionMode1ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: recursion_layer_proof_config(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_for_wrapper_vk_and_write(circuit, &mut source, &worker);
    }
    if circuit_type == 2 {
        let vk = source.get_compression_vk(1).unwrap();

        let circuit = ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(
            CompressionMode2ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode1::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_for_wrapper_vk_and_write(circuit, &mut source, &worker);
    }
    if circuit_type == 3 {
        let vk = source.get_compression_vk(2).unwrap();

        let circuit = ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(
            CompressionMode3ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode2::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_for_wrapper_vk_and_write(circuit, &mut source, &worker);
    }
    if circuit_type == 4 {
        let vk = source.get_compression_vk(3).unwrap();

        let circuit = ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(
            CompressionMode4ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode3::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_for_wrapper_vk_and_write(circuit, &mut source, &worker);
    }
    if circuit_type == 5 {
        let vk = source.get_compression_vk(4).unwrap();

        let circuit = ZkSyncCompressionForWrapperCircuit::CompressionModeToL1Circuit(
            CompressionModeToL1ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode4::proof_config_for_compression_step(),
                    verification_key: vk.into_inner(),
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }
        );

        compute_compression_for_wrapper_vk_and_write(circuit, &mut source, &worker);
    }

    // Finally, wrapper vk
    get_wrapper_vk_from_compression_vk(
        source.get_compression_for_wrapper_vk(circuit_type).unwrap()
    )
}

fn compute_compression_vk_and_write(
    circuit: ZkSyncCompressionLayerCircuit,
    source: &mut InMemoryDataSource,
    worker: &Worker,
) {
    let circuit_type = circuit.numeric_circuit_type();
    let proof_config = circuit.proof_config_for_compression_step();

    let (_, _, vk, _, _, _, _) =
    create_compression_layer_setup_data(
        circuit,
        &worker,
        proof_config.fri_lde_factor,
        proof_config.merkle_tree_cap_size,
    );


    source
        .set_compression_vk(ZkSyncCompressionLayerStorage::from_inner(
            circuit_type,
            vk.clone(),
        )).unwrap();
}

fn compute_compression_for_wrapper_vk_and_write(
    circuit: ZkSyncCompressionForWrapperCircuit,
    source: &mut InMemoryDataSource,
    worker: &Worker,
) {
    let circuit_type = circuit.numeric_circuit_type();
    let proof_config = circuit.proof_config_for_compression_step();

    let (_, _, vk, _, _, _, _) =
    create_compression_for_wrapper_setup_data(
        circuit,
        &worker,
        proof_config.fri_lde_factor,
        proof_config.merkle_tree_cap_size,
    );
    source
        .set_compression_for_wrapper_vk(ZkSyncCompressionLayerStorage::from_inner(
            circuit_type,
            vk.clone(),
        )).unwrap();
}


pub fn get_wrapper_vk_from_compression_vk(vk: ZkSyncCompressionForWrapperVerificationKey) -> ZkSyncSnarkWrapperVK {
    check_trusted_setup_file_existace();

    let worker = BellmanWorker::new();
    let circuit_type = vk.numeric_circuit_type();
    let vk = vk.into_inner();

    let snark_setup = compute_wrapper_setup_inner(circuit_type, vk, &worker);

    let crs_mons = get_trusted_setup();
    let snark_vk = SnarkVK::from_setup(&snark_setup, &worker, &crs_mons).unwrap();

    ZkSyncSnarkWrapperVK::from_inner(circuit_type, snark_vk)
}

pub(crate) fn compute_compression_circuit<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    circuit_type: u8,
    worker: &Worker,
) {
    if source.get_compression_proof(circuit_type).is_err()
        || source.get_compression_vk(circuit_type).is_err()
        || source.get_compression_hint(circuit_type).is_err()
    {
        let (proof, vk) = match circuit_type {
            1 => (
                source
                    .get_scheduler_proof()
                    .expect("scheduler proof should be present")
                    .into_inner(),
                source
                    .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
                    .expect("scheduler vk should be present")
                    .into_inner(),
            ),
            circuit_type => (
                source
                    .get_compression_proof(circuit_type - 1)
                    .expect("compression proof should be present")
                    .into_inner(),
                source
                    .get_compression_vk(circuit_type - 1)
                    .expect("compression vk should be present")
                    .into_inner(),
            ),
        };

        let compression_circuit = match circuit_type {
            1 => ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(CompressionMode1Circuit {
                witness: Some(proof),
                config: CompressionRecursionConfig {
                    proof_config: recursion_layer_proof_config(),
                    verification_key: vk,
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }),
            2 => ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(CompressionMode2Circuit {
                witness: Some(proof),
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode1::proof_config_for_compression_step(),
                    verification_key: vk,
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }),
            3 => ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(CompressionMode3Circuit {
                witness: Some(proof),
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode2::proof_config_for_compression_step(),
                    verification_key: vk,
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }),
            4 => ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(CompressionMode4Circuit {
                witness: Some(proof),
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode3::proof_config_for_compression_step(),
                    verification_key: vk,
                    _marker: std::marker::PhantomData,
                },
                transcript_params: (),
                _marker: std::marker::PhantomData,
            }),
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
                },
            ),
            _ => unreachable!(),
        };

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

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
        create_compression_layer_setup_data(
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

    println!(
        "Compression {} is done, taken {:?}",
        circuit_type,
        start.elapsed()
    );

    (vk, finalization_hint, proof)
}

pub(crate) fn compute_compression_for_wrapper_circuit<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    circuit_type: u8,
    worker: &Worker,
) {
    if source.get_compression_for_wrapper_vk(circuit_type).is_err()
        || source
            .get_compression_for_wrapper_hint(circuit_type)
            .is_err()
        || source
            .get_compression_for_wrapper_proof(circuit_type)
            .is_err()
    {
        let (proof, vk) = match circuit_type {
            1 => (
                source
                    .get_scheduler_proof()
                    .expect("scheduler proof should be present")
                    .into_inner(),
                source
                    .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
                    .expect("scheduler vk should be present")
                    .into_inner(),
            ),
            circuit_type => (
                source
                    .get_compression_proof(circuit_type - 1)
                    .expect("compression proof should be present")
                    .into_inner(),
                source
                    .get_compression_vk(circuit_type - 1)
                    .expect("compression vk should be present")
                    .into_inner(),
            ),
        };

        let compression_circuit = match circuit_type {
            1 => ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(
                CompressionMode1ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: recursion_layer_proof_config(),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                },
            ),
            2 => ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(
                CompressionMode2ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode1ForWrapper::proof_config_for_compression_step(
                        ),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                },
            ),
            3 => ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(
                CompressionMode3ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode2ForWrapper::proof_config_for_compression_step(
                        ),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                },
            ),
            4 => ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(
                CompressionMode4ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode3ForWrapper::proof_config_for_compression_step(
                        ),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                },
            ),
            5 => ZkSyncCompressionForWrapperCircuit::CompressionModeToL1Circuit(
                CompressionModeToL1ForWrapperCircuit {
                    witness: Some(proof),
                    config: CompressionRecursionConfig {
                        proof_config: CompressionMode4ForWrapper::proof_config_for_compression_step(
                        ),
                        verification_key: vk,
                        _marker: std::marker::PhantomData,
                    },
                    transcript_params: (),
                    _marker: std::marker::PhantomData,
                },
            ),
            _ => unreachable!(),
        };

        let (vk, finalization_hint, proof) =
            compute_compression_for_wrapper_circuit_inner(compression_circuit, worker);

        // we did it above
        source
            .set_compression_for_wrapper_vk(ZkSyncCompressionLayerStorage::from_inner(
                circuit_type,
                vk.clone(),
            ))
            .unwrap();
        source
            .set_compression_for_wrapper_hint(ZkSyncCompressionLayerStorage::from_inner(
                circuit_type,
                finalization_hint.clone(),
            ))
            .unwrap();
        source
            .set_compression_for_wrapper_proof(ZkSyncCompressionLayerStorage::from_inner(
                circuit_type,
                proof,
            ))
            .unwrap();
    }
}

fn compute_compression_for_wrapper_circuit_inner(
    circuit: ZkSyncCompressionForWrapperCircuit,
    worker: &Worker,
) -> (
    ZkSyncCompressionVerificationKeyForWrapper,
    FinalizationHintsForProver,
    ZkSyncCompressionProofForWrapper,
) {
    let start = std::time::Instant::now();

    let circuit_type = circuit.numeric_circuit_type();

    test_compression_for_wrapper_circuit(circuit.clone());
    println!("Circuit is satisfied");

    let proof_config = circuit.proof_config_for_compression_step();

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
        create_compression_for_wrapper_setup_data(
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

    println!(
        "Compression for wrapper {} is done, taken {:?}",
        circuit_type,
        start.elapsed()
    );

    (vk, finalization_hint, proof)
}

pub(crate) fn compute_wrapper_proof_and_vk<DS: SetupDataSource + BlockDataSource>(
    source: &mut DS,
    circuit_type: u8,
    worker: &BellmanWorker,
) {
    println!("Computing wrapper setup");
    if source.get_wrapper_setup(circuit_type).is_err() {
        let vk = source.get_compression_for_wrapper_vk(circuit_type).unwrap();

        let snark_setup = compute_wrapper_setup_inner(circuit_type, vk.into_inner(), worker);

        let snark_setup = ZkSyncCompressionLayerStorage::from_inner(circuit_type, snark_setup);
        source.set_wrapper_setup(snark_setup).unwrap();
    }

    println!("Computing wrapper vk");
    if source.get_wrapper_vk(circuit_type).is_err() {
        let start = std::time::Instant::now();
        let snark_setup = source.get_wrapper_setup(circuit_type).unwrap();

        let crs_mons = get_trusted_setup();
        let snark_vk = SnarkVK::from_setup(&snark_setup.into_inner(), worker, &crs_mons).unwrap();

        println!(
            "Wrapper vk {} is done, taken {:?}",
            circuit_type,
            start.elapsed()
        );

        let snark_vk = ZkSyncCompressionLayerStorage::from_inner(circuit_type, snark_vk);
        source.set_wrapper_vk(snark_vk).unwrap();
    }

    println!("Computing wrapper proof");
    if source.get_wrapper_proof(circuit_type).is_err() {
        let proof = source
            .get_compression_for_wrapper_proof(circuit_type)
            .unwrap();
        let vk = source.get_compression_for_wrapper_vk(circuit_type).unwrap();

        let snark_setup = source.get_wrapper_setup(circuit_type).unwrap();

        let snark_proof = compute_wrapper_proof_inner(
            circuit_type, 
            proof.into_inner(), 
            vk.into_inner(), 
            snark_setup.into_inner(), 
            worker
        );

        println!("Verifying");
        let snark_vk = source.get_wrapper_vk(circuit_type).unwrap();
        use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
        let is_valid = verify::<_, _, RollingKeccakTranscript<Fr>>(
            &snark_vk.into_inner(), 
            &snark_proof, 
            None
        ).unwrap();
        assert!(is_valid);

        let snark_proof = ZkSyncCompressionLayerStorage::from_inner(circuit_type, snark_proof);
        source.set_wrapper_proof(snark_proof).unwrap();
    }
}

fn compute_wrapper_setup_inner(
    circuit_type: u8,
    vk: ZkSyncCompressionVerificationKeyForWrapper,
    worker: &BellmanWorker,
) -> SnarkSetup<Bn256, ZkSyncSnarkWrapperCircuit> {
    let start = std::time::Instant::now();

    let mut assembly = SetupAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fixed_parameters = vk.fixed_parameters.clone();

    let wrapper_function = ZkSyncCompressionWrapper::from_numeric_circuit_type(circuit_type);
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
        circuit_type,
        start.elapsed()
    );

    setup
}

fn compute_wrapper_proof_inner(
    circuit_type: u8,
    proof: ZkSyncCompressionProofForWrapper,
    vk: ZkSyncCompressionVerificationKeyForWrapper,
    snark_setup: SnarkSetup<Bn256, ZkSyncSnarkWrapperCircuit>,
    worker: &BellmanWorker,
) -> SnarkProof<Bn256, ZkSyncSnarkWrapperCircuit> {
    check_trusted_setup_file_existace();

    let start = std::time::Instant::now();

    let mut assembly = ProvingAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fixed_parameters = vk.fixed_parameters.clone();

    let wrapper_function = ZkSyncCompressionWrapper::from_numeric_circuit_type(circuit_type);
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
        circuit_type
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
        circuit_type,
        start.elapsed()
    );

    proof
}

/// Just to check if the file and environment variable are not forgotten
fn check_trusted_setup_file_existace() {
    let crs_file_str = std::env::var(CRS_FILE_ENV_VAR).expect("crs file env var");
    let crs_file_path = std::path::Path::new(&crs_file_str);
    let _crs_file = std::fs::File::open(&crs_file_path).expect("crs file to open");
}

fn get_trusted_setup() -> Crs<Bn256, CrsForMonomialForm> {
    let crs_file_str = std::env::var(CRS_FILE_ENV_VAR).expect("crs file env var");
    let crs_file_path = std::path::Path::new(&crs_file_str);
    let crs_file = std::fs::File::open(&crs_file_path).expect("crs file to open");
    Crs::read(&crs_file).expect("crs file for bases")
}

pub fn compress_stark_pi_to_snark_pi(stark_pi: [GoldilocksField; 4]) -> Fr {
    let chunk_bit_size = (GoldilocksField::CAPACITY_BITS / 8) * 8;
    assert!(
        stark_pi.len() * chunk_bit_size <= Fr::CAPACITY as usize,
        "scalar field capacity is not enough to fit all public inputs"
    );

    let mut coeff = Fr::one();
    let mut shift = <Fr as PrimeField>::Repr::from(1);
    shift.shl(chunk_bit_size as u32);
    let shift = Fr::from_repr(shift).unwrap();

    let mut result = Fr::zero();
    for chunk in stark_pi.iter().rev() {
        let mut chunk_fr =
            Fr::from_repr(<Fr as PrimeField>::Repr::from(chunk.as_u64_reduced())).unwrap();
        chunk_fr.mul_assign(&coeff);
        result.add_assign(&chunk_fr);
        coeff.mul_assign(&shift);
    }

    result
}
