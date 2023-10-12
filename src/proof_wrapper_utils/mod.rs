use circuit_definitions::recursion_layer_proof_config;
use circuit_definitions::boojum::cs::implementations::pow::NoPow;
use circuit_definitions::boojum::cs::implementations::setup::FinalizationHintsForProver;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::boojum::field::{PrimeField as BoojumPrimeField, U64Representable};
use circuit_definitions::circuit_definitions::aux_layer::compression::{CompressionMode1Circuit, CompressionMode1ForWrapperCircuit, CompressionMode2Circuit, CompressionMode2ForWrapperCircuit, CompressionMode3Circuit, CompressionMode3ForWrapperCircuit, CompressionMode4Circuit, CompressionMode4ForWrapperCircuit, CompressionMode5Circuit, CompressionMode5ForWrapperCircuit, ProofCompressionFunction};
use circuit_definitions::circuit_definitions::aux_layer::compression_modes::{CompressionMode1, CompressionMode1ForWrapper, CompressionMode2, CompressionMode2ForWrapper, CompressionMode3, CompressionMode3ForWrapper, CompressionMode4, CompressionMode4ForWrapper};
use circuit_definitions::circuit_definitions::aux_layer::{ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionLayerCircuit, ZkSyncCompressionLayerStorage, ZkSyncCompressionProof, ZkSyncCompressionProofForWrapper, ZkSyncCompressionVerificationKey, ZkSyncCompressionVerificationKeyForWrapper, ZkSyncSnarkWrapperCircuit, ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperVK, ZkSyncSnarkWrapperSetup};
use circuit_definitions::circuit_definitions::aux_layer::wrapper::ZkSyncCompressionWrapper;
use circuit_definitions::circuit_definitions::recursion_layer::{ZkSyncRecursionLayerProof, ZkSyncRecursionLayerStorageType, ZkSyncRecursionLayerVerificationKey};
use circuit_definitions::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use circuit_definitions::zkevm_circuits::scheduler::NUM_SCHEDULER_PUBLIC_INPUTS;
use crate::snark_wrapper::franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, PlonkCsWidth4WithNextStepAndCustomGatesParams, TrivialAssembly, SetupAssembly, ProvingAssembly};
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::Setup as SnarkSetup;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use crate::snark_wrapper::franklin_crypto::bellman::worker::Worker as BellmanWorker;
use crate::snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use crate::snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;
use crate::snark_wrapper::verifier::WrapperCircuit;
use crate::snark_wrapper::verifier_structs::allocated_vk::AllocatedVerificationKey;
use crate::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use crate::franklin_crypto::bellman::{Field, PrimeField, PrimeFieldRepr};
use circuit_definitions::circuit_definitions::aux_layer::*;
use crate::boojum::worker::Worker;

pub type TreeHasherForWrapper = CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type TranscriptForWrapper = CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;

pub const DEFAULT_WRAPPER_CONFIG: WrapperConfig = WrapperConfig {
    compression_layers: 1,
};

use crate::data_source::in_memory_data_source::InMemoryDataSource;
use crate::data_source::{BlockDataSource, SetupDataSource, SourceResult};
use crate::prover_utils::{
    create_compression_for_wrapper_setup_data, create_compression_layer_setup_data,
    prove_compression_for_wrapper_circuit, prove_compression_layer_circuit,
    verify_compression_for_wrapper_proof, verify_compression_layer_proof,
};
use crate::tests::{test_compression_circuit, test_compression_for_wrapper_circuit};

use std::sync::Arc;

mod compression;
mod compression_for_wrapper;
mod utils;
mod wrapper;

pub use compression::*;
pub use compression_for_wrapper::*;
pub use utils::*;
pub use wrapper::*;

/// Wrapper config is needed to specify how many compression layers should be done
/// So after we compute a scheduler proof we can compute a couple of compression proofs
/// The last one should be using Bn256 Poseidon2 hash for FRI
/// And then we can compute wrapper proof
///
/// Example: Scheduler -> CompressionMode1 -> CompressionMode2 ->
/// -> CompressionMode3ForWrapper -> Wrapper
#[derive(Debug, Clone, Copy)]
pub struct WrapperConfig {
    compression_layers: u8,
}

impl WrapperConfig {
    // For now we only support 1-5 compression layers
    pub const MAX_COMPRESSION_LAYERS: u8 = 5;

    pub fn new(compression_layers: u8) -> Self {
        assert!(
            compression_layers > 0 && compression_layers <= Self::MAX_COMPRESSION_LAYERS,
            "compression should be between 1 and 5"
        );

        Self { compression_layers }
    }

    pub fn get_compression_types(&self) -> Vec<u8> {
        (1..self.compression_layers).collect()
    }

    pub fn get_compression_for_wrapper_type(&self) -> u8 {
        self.compression_layers
    }

    pub fn get_wrapper_type(&self) -> u8 {
        self.compression_layers
    }
}

/// Computes wrapper proof and vk from scheduler proof and vk
/// We store all proofs and vks in the RAM
pub fn wrap_proof(
    proof: ZkSyncRecursionLayerProof,
    vk: ZkSyncRecursionLayerVerificationKey,
    config: WrapperConfig,
) -> (ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperVK) {
    // Check trusted setup file for later
    check_trusted_setup_file_existace();
    let worker = Worker::new();
    let bellman_worker = BellmanWorker::new();

    // Check circuit type correctness
    assert_eq!(
        vk.numeric_circuit_type(),
        ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
    );
    assert_eq!(
        proof.numeric_circuit_type(),
        ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
    );

    // Initialize RAM storage and upload scheduler proof and vk
    let mut source = InMemoryDataSource::new();
    source
        .set_scheduler_proof(proof)
        .expect("Failed to set scheduler proof");
    source
        .set_recursion_layer_vk(vk)
        .expect("Failed to set scheduler vk");

    // 1. All but one layers of compression with Goldilocks Poseidon2 hash
    compute_compression_circuits(&mut source, config, &worker);
    // 2. Final compression with Bn256 Poseidon2 hash
    compute_compression_for_wrapper_circuit(&mut source, config, &worker);
    // 3. Wrapper
    compute_wrapper_proof_and_vk(&mut source, config, &bellman_worker);

    // Get and return wrapper proof and vk
    let wrapper_type = config.get_wrapper_type();
    (
        source.get_wrapper_proof(wrapper_type).unwrap(),
        source.get_wrapper_vk(wrapper_type).unwrap(),
    )
}

/// Computes wrapper vk from scheduler vk
/// We store all vks in the RAM
pub fn get_wrapper_setup_and_vk_from_scheduler_vk(
    vk: ZkSyncRecursionLayerVerificationKey,
    config: WrapperConfig,
) -> (ZkSyncSnarkWrapperSetup, ZkSyncSnarkWrapperVK) {
    // Check trusted setup file for later
    check_trusted_setup_file_existace();
    let worker = Worker::new();

    // Check circuit type correctness
    assert_eq!(
        vk.numeric_circuit_type(),
        ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
    );

    // Initialize RAM storage and upload scheduler proof and vk
    let mut source = InMemoryDataSource::new();
    source.set_recursion_layer_vk(vk).unwrap();

    // 1. All but one layers of compression with Goldilocks Poseidon2 hash
    compute_compression_vks_and_write(&mut source, config, &worker);
    // 2. Final compression with Bn256 Poseidon2 hash
    compute_compression_for_wrapper_vk_and_write(config, &mut source, &worker);

    // 3. Wrapper
    let wrapper_type = config.get_wrapper_type();
    let wrapper_vk = source.get_compression_for_wrapper_vk(wrapper_type).unwrap();
    get_wrapper_setup_and_vk_from_compression_vk(wrapper_vk, config)
}
