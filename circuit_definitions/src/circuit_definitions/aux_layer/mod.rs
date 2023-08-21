use super::*;

pub mod compression;
pub mod compression_modes;
pub mod wrapper;

use crate::circuit_definitions::aux_layer::compression::*;


#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncCompressionLayerCircuit {
    CompressionMode1Circuit(CompressionMode1Circuit),
    CompressionMode2Circuit(CompressionMode2Circuit),
    CompressionMode3Circuit(CompressionMode3Circuit),
    CompressionMode4Circuit(CompressionMode4Circuit),
    CompressionModeToL1Circuit(CompressionModeToL1Circuit),
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Copy, Debug)]
#[serde(bound = "")]
#[repr(u8)]
pub enum ZkSyncCompressionLayerStorageType {
    CompressionMode1Circuit = 1,
    CompressionMode2Circuit = 2,
    CompressionMode3Circuit = 3,
    CompressionMode4Circuit = 4,
    CompressionModeToL1Circuit = 5,
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug)]
#[serde(bound = "")]
#[repr(u8)]
pub enum ZkSyncCompressionLayerStorage<
    T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
> {
    CompressionMode1Circuit(T) = 1,
    CompressionMode2Circuit(T) = 2,
    CompressionMode3Circuit(T) = 3,
    CompressionMode4Circuit(T) = 4,
    CompressionModeToL1Circuit(T) = 5,
}

impl<
    T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncCompressionLayerStorage<T> {
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncCompressionLayerStorage::CompressionMode1Circuit(..) => "Compression mode 1",
            ZkSyncCompressionLayerStorage::CompressionMode2Circuit(..) => "Compression mode 2",
            ZkSyncCompressionLayerStorage::CompressionMode3Circuit(..) => "Compression mode 3",
            ZkSyncCompressionLayerStorage::CompressionMode4Circuit(..) => "Compression mode 4",
            ZkSyncCompressionLayerStorage::CompressionModeToL1Circuit(..) => "Compression mode to L1",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            ZkSyncCompressionLayerStorage::CompressionMode1Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8
            }
            ZkSyncCompressionLayerStorage::CompressionMode2Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8
            }
            ZkSyncCompressionLayerStorage::CompressionMode3Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8
            }
            ZkSyncCompressionLayerStorage::CompressionMode4Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8
            }
            ZkSyncCompressionLayerStorage::CompressionModeToL1Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionModeToL1Circuit as u8
            }
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            Self::CompressionMode1Circuit(inner) => inner,
            Self::CompressionMode2Circuit(inner) => inner,
            Self::CompressionMode3Circuit(inner) => inner,
            Self::CompressionMode4Circuit(inner) => inner,
            Self::CompressionModeToL1Circuit(inner) => inner,
        }
    }

    pub fn from_inner(numeric_type: u8, inner: T) -> Self {
        match numeric_type {
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8 => {
                Self::CompressionMode1Circuit(inner)
            },
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8 => {
                Self::CompressionMode2Circuit(inner)
            },
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8 => {
                Self::CompressionMode3Circuit(inner)
            },
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8 => {
                Self::CompressionMode4Circuit(inner)
            },
            a if a == ZkSyncCompressionLayerStorageType::CompressionModeToL1Circuit as u8 => {
                Self::CompressionModeToL1Circuit(inner)
            },
            _ => panic!("wrong numeric_type for inner: {}", numeric_type),
        }
    }
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncCompressionForWrapperCircuit {
    CompressionMode1Circuit(CompressionMode1ForWrapperCircuit),
    CompressionMode2Circuit(CompressionMode2ForWrapperCircuit),
    CompressionMode3Circuit(CompressionMode3ForWrapperCircuit),
    CompressionMode4Circuit(CompressionMode4ForWrapperCircuit),
    CompressionModeToL1Circuit(CompressionModeToL1ForWrapperCircuit),
}

pub type ZkSyncCompressionLayerCircuitInput<F> =
    ZkSyncCompressionLayerStorage<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>;

use zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

pub type ZkSyncCompressionLayerClosedFormInput<F> =
    ZkSyncCompressionLayerStorage<ClosedFormInputCompactFormWitness<F>>;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::circuit_definitions::implementations::proof::Proof;
use crate::boojum::field::goldilocks::{GoldilocksField, GoldilocksExt2};
use crate::circuit_definitions::implementations::setup::FinalizationHintsForProver;

use rescue_poseidon::poseidon2::Poseidon2Sponge;
use snark_wrapper::implementations::poseidon2::tree_hasher::AbsorptionModeReplacement;
use snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};

pub type CompressionProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
pub type CompressionProofsTreeHasherForWrapper = 
    Poseidon2Sponge<Bn256, GoldilocksField, AbsorptionModeReplacement<Fr>, 2, 3>;
pub type ZkSyncCompressionProof = Proof<GoldilocksField, CompressionProofsTreeHasher, GoldilocksExt2>;
pub type ZkSyncCompressionProofForWrapper = Proof<GoldilocksField, CompressionProofsTreeHasherForWrapper, GoldilocksExt2>;

pub type ZkSyncCompressionLayerProof = ZkSyncCompressionLayerStorage<ZkSyncCompressionProof>;
pub type ZkSyncCompressionForWrapperProof = ZkSyncCompressionLayerStorage<ZkSyncCompressionProofForWrapper>;

pub type ZkSyncCompressionLayerFinalizationHint = ZkSyncCompressionLayerStorage<FinalizationHintsForProver>;
pub type ZkSyncCompressionForWrapperFinalizationHint = ZkSyncCompressionLayerStorage<FinalizationHintsForProver>;

use crate::boojum::cs::implementations::verifier::VerificationKey;
pub type ZkSyncCompressionVerificationKey = VerificationKey<GoldilocksField, CompressionProofsTreeHasher>;
pub type ZkSyncCompressionVerificationKeyForWrapper = VerificationKey<GoldilocksField, CompressionProofsTreeHasherForWrapper>;

pub type ZkSyncCompressionLayerVerificationKey = 
    ZkSyncCompressionLayerStorage<ZkSyncCompressionVerificationKey>;

pub type ZkSyncCompressionForWrapperVerificationKey = 
    ZkSyncCompressionLayerStorage<ZkSyncCompressionVerificationKeyForWrapper>;


use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::verifier::WrapperCircuit;
use snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;

pub type SnarkCircuit<PWF> = WrapperCircuit<
    Bn256, 
    Poseidon2Sponge<Bn256, GoldilocksField, AbsorptionModeReplacement<Fr>, 2, 3>, 
    CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>,
    CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>,
    PWF
>;

pub type ZkSyncSnarkWrapperProof<PWF> = ZkSyncCompressionLayerStorage<SnarkProof<Bn256, SnarkCircuit<PWF>>>;
pub type ZkSyncSnarkWrapperVK<PWF> = ZkSyncCompressionLayerStorage<SnarkVK<Bn256, SnarkCircuit<PWF>>>;
