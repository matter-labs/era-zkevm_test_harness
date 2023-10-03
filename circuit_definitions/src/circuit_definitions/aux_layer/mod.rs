use super::*;

pub mod compression;
pub mod compression_modes;
pub mod wrapper;

use crate::boojum::config::ProvingCSConfig;
use crate::boojum::field::traits::field_like::PrimeFieldLikeVectorized;
use crate::circuit_definitions::aux_layer::compression::*;
use crate::circuit_definitions::aux_layer::compression_modes::*;
use crate::circuit_definitions::cs_builder_reference::CsReferenceImplementationBuilder;
use crate::circuit_definitions::implementations::reference_cs::CSReferenceAssembly;
use crate::circuit_definitions::traits::circuit::CircuitBuilderProxy;
use crate::ProofConfig;

type F = GoldilocksField;
type EXT = GoldilocksExt2;

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

impl ZkSyncCompressionLayerCircuit {
    pub fn short_description(&self) -> &'static str {
        match &self {
            Self::CompressionMode1Circuit(..) => "Compression mode 1",
            Self::CompressionMode2Circuit(..) => "Compression mode 2",
            Self::CompressionMode3Circuit(..) => "Compression mode 3",
            Self::CompressionMode4Circuit(..) => "Compression mode 4",
            Self::CompressionModeToL1Circuit(..) => "Compression mode to L1",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            Self::CompressionMode1Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8
            }
            Self::CompressionMode2Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8
            }
            Self::CompressionMode3Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8
            }
            Self::CompressionMode4Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8
            }
            Self::CompressionModeToL1Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionModeToL1Circuit as u8
            }
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            Self::CompressionMode1Circuit(inner) => inner.size_hint(),
            Self::CompressionMode2Circuit(inner) => inner.size_hint(),
            Self::CompressionMode3Circuit(inner) => inner.size_hint(),
            Self::CompressionMode4Circuit(inner) => inner.size_hint(),
            Self::CompressionModeToL1Circuit(inner) => inner.size_hint(),
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        use crate::boojum::cs::traits::circuit::CircuitBuilder;
        match &self {
            Self::CompressionMode1Circuit(..) => {
                <CompressionMode1Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionMode2Circuit(..) => {
                <CompressionMode2Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionMode3Circuit(..) => {
                <CompressionMode3Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionMode4Circuit(..) => {
                <CompressionMode4Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionModeToL1Circuit(..) => {
                <CompressionModeToL1Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
        }
    }

    pub fn proof_config_for_compression_step(&self) -> ProofConfig {
        match &self {
            Self::CompressionMode1Circuit(..) => {
                CompressionMode1::proof_config_for_compression_step()
            }
            Self::CompressionMode2Circuit(..) => {
                CompressionMode2::proof_config_for_compression_step()
            }
            Self::CompressionMode3Circuit(..) => {
                CompressionMode3::proof_config_for_compression_step()
            }
            Self::CompressionMode4Circuit(..) => {
                CompressionMode4::proof_config_for_compression_step()
            }
            Self::CompressionModeToL1Circuit(..) => {
                CompressionModeToL1::proof_config_for_compression_step()
            }
        }
    }

    fn synthesis_inner<
        P: PrimeFieldLikeVectorized<Base = GoldilocksField>,
        CF: ProofCompressionFunction,
    >(
        inner: &CompressionLayerCircuit<CF>,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<GoldilocksField, P, ProvingCSConfig> {
        let geometry = inner.geometry();
        let (max_trace_len, num_vars) = inner.size_hint();
        let builder_impl =
            CsReferenceImplementationBuilder::<GoldilocksField, P, ProvingCSConfig>::new(
                geometry,
                num_vars.unwrap(),
                max_trace_len.unwrap(),
            );
        let cs_builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = inner.configure_builder_proxy(cs_builder);
        let mut cs = builder.build(());
        inner.add_tables(&mut cs);
        inner.clone().synthesize_into_cs(&mut cs);
        cs.pad_and_shrink_using_hint(hint);
        cs.into_assembly()
    }

    pub fn synthesis<P: PrimeFieldLikeVectorized<Base = F>>(
        &self,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        match &self {
            Self::CompressionMode1Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionMode2Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionMode3Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionMode4Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionModeToL1Circuit(inner) => Self::synthesis_inner(inner, hint),
        }
    }

    pub fn into_dyn_verifier_builder(
        &self,
    ) -> Box<dyn crate::boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>> {
        match &self {
            Self::CompressionMode1Circuit(..) => {
                CompressionMode1ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionMode2Circuit(..) => {
                CompressionMode2ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionMode3Circuit(..) => {
                CompressionMode3ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionMode4Circuit(..) => {
                CompressionMode4ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionModeToL1Circuit(..) => {
                CompressionModeToL1ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
        }
    }
}

use crate::circuit_definitions::recursion_layer::scheduler::ConcreteSchedulerCircuitBuilder;
use zkevm_circuits::scheduler::auxiliary::BaseLayerCircuitType;

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

impl<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned>
    ZkSyncCompressionLayerStorage<T>
{
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncCompressionLayerStorage::CompressionMode1Circuit(..) => "Compression mode 1",
            ZkSyncCompressionLayerStorage::CompressionMode2Circuit(..) => "Compression mode 2",
            ZkSyncCompressionLayerStorage::CompressionMode3Circuit(..) => "Compression mode 3",
            ZkSyncCompressionLayerStorage::CompressionMode4Circuit(..) => "Compression mode 4",
            ZkSyncCompressionLayerStorage::CompressionModeToL1Circuit(..) => {
                "Compression mode to L1"
            }
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
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8 => {
                Self::CompressionMode2Circuit(inner)
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8 => {
                Self::CompressionMode3Circuit(inner)
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8 => {
                Self::CompressionMode4Circuit(inner)
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionModeToL1Circuit as u8 => {
                Self::CompressionModeToL1Circuit(inner)
            }
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

impl ZkSyncCompressionForWrapperCircuit {
    pub fn short_description(&self) -> &'static str {
        match &self {
            Self::CompressionMode1Circuit(..) => "Compression mode 1 for wrapper",
            Self::CompressionMode2Circuit(..) => "Compression mode 2 for wrapper",
            Self::CompressionMode3Circuit(..) => "Compression mode 3 for wrapper",
            Self::CompressionMode4Circuit(..) => "Compression mode 4 for wrapper",
            Self::CompressionModeToL1Circuit(..) => "Compression mode to L1 for wrapper",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            Self::CompressionMode1Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8
            }
            Self::CompressionMode2Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8
            }
            Self::CompressionMode3Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8
            }
            Self::CompressionMode4Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8
            }
            Self::CompressionModeToL1Circuit(..) => {
                ZkSyncCompressionLayerStorageType::CompressionModeToL1Circuit as u8
            }
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            Self::CompressionMode1Circuit(inner) => inner.size_hint(),
            Self::CompressionMode2Circuit(inner) => inner.size_hint(),
            Self::CompressionMode3Circuit(inner) => inner.size_hint(),
            Self::CompressionMode4Circuit(inner) => inner.size_hint(),
            Self::CompressionModeToL1Circuit(inner) => inner.size_hint(),
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        use crate::boojum::cs::traits::circuit::CircuitBuilder;
        match &self {
            Self::CompressionMode1Circuit(..) => {
                <CompressionMode1Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionMode2Circuit(..) => {
                <CompressionMode2Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionMode3Circuit(..) => {
                <CompressionMode3Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionMode4Circuit(..) => {
                <CompressionMode4Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
            Self::CompressionModeToL1Circuit(..) => {
                <CompressionModeToL1Circuit as CircuitBuilder<GoldilocksField>>::geometry()
            }
        }
    }

    pub fn proof_config_for_compression_step(&self) -> ProofConfig {
        match &self {
            Self::CompressionMode1Circuit(..) => {
                CompressionMode1ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode2Circuit(..) => {
                CompressionMode2ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode3Circuit(..) => {
                CompressionMode3ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode4Circuit(..) => {
                CompressionMode4ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionModeToL1Circuit(..) => {
                CompressionModeToL1ForWrapper::proof_config_for_compression_step()
            }
        }
    }

    fn synthesis_inner<
        P: PrimeFieldLikeVectorized<Base = GoldilocksField>,
        CF: ProofCompressionFunction,
    >(
        inner: &CompressionLayerCircuit<CF>,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<GoldilocksField, P, ProvingCSConfig> {
        let geometry = inner.geometry();
        let (max_trace_len, num_vars) = inner.size_hint();
        let builder_impl =
            CsReferenceImplementationBuilder::<GoldilocksField, P, ProvingCSConfig>::new(
                geometry,
                num_vars.unwrap(),
                max_trace_len.unwrap(),
            );
        let cs_builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = inner.configure_builder_proxy(cs_builder);
        let mut cs = builder.build(());
        inner.add_tables(&mut cs);
        inner.clone().synthesize_into_cs(&mut cs);
        cs.pad_and_shrink_using_hint(hint);
        cs.into_assembly()
    }

    pub fn synthesis<P: PrimeFieldLikeVectorized<Base = F>>(
        &self,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        match &self {
            Self::CompressionMode1Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionMode2Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionMode3Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionMode4Circuit(inner) => Self::synthesis_inner(inner, hint),
            Self::CompressionModeToL1Circuit(inner) => Self::synthesis_inner(inner, hint),
        }
    }

    pub fn into_dyn_verifier_builder(
        &self,
    ) -> Box<dyn crate::boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>> {
        match &self {
            Self::CompressionMode1Circuit(..) => {
                CompressionMode1ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionMode2Circuit(..) => {
                CompressionMode2ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionMode3Circuit(..) => {
                CompressionMode3ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionMode4Circuit(..) => {
                CompressionMode4ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
            Self::CompressionModeToL1Circuit(..) => {
                CompressionModeToL1ForWrapperCircuitBuilder::dyn_verifier_builder()
            }
        }
    }
}

pub type ZkSyncCompressionLayerCircuitInput<F> =
    ZkSyncCompressionLayerStorage<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>;

use zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

pub type ZkSyncCompressionLayerClosedFormInput<F> =
    ZkSyncCompressionLayerStorage<ClosedFormInputCompactFormWitness<F>>;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};
use crate::circuit_definitions::implementations::proof::Proof;
use crate::circuit_definitions::implementations::setup::FinalizationHintsForProver;

use rescue_poseidon::poseidon2::Poseidon2Sponge;
use snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use snark_wrapper::implementations::poseidon2::tree_hasher::AbsorptionModeReplacement;

pub type CompressionProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
pub type CompressionProofsTreeHasherForWrapper =
    Poseidon2Sponge<Bn256, GoldilocksField, AbsorptionModeReplacement<Fr>, 2, 3>;
pub type ZkSyncCompressionProof =
    Proof<GoldilocksField, CompressionProofsTreeHasher, GoldilocksExt2>;
pub type ZkSyncCompressionProofForWrapper =
    Proof<GoldilocksField, CompressionProofsTreeHasherForWrapper, GoldilocksExt2>;

pub type ZkSyncCompressionLayerProof = ZkSyncCompressionLayerStorage<ZkSyncCompressionProof>;
pub type ZkSyncCompressionForWrapperProof =
    ZkSyncCompressionLayerStorage<ZkSyncCompressionProofForWrapper>;

pub type ZkSyncCompressionLayerFinalizationHint =
    ZkSyncCompressionLayerStorage<FinalizationHintsForProver>;
pub type ZkSyncCompressionForWrapperFinalizationHint =
    ZkSyncCompressionLayerStorage<FinalizationHintsForProver>;

use crate::boojum::cs::implementations::verifier::VerificationKey;
pub type ZkSyncCompressionVerificationKey =
    VerificationKey<GoldilocksField, CompressionProofsTreeHasher>;
pub type ZkSyncCompressionVerificationKeyForWrapper =
    VerificationKey<GoldilocksField, CompressionProofsTreeHasherForWrapper>;

pub type ZkSyncCompressionLayerVerificationKey =
    ZkSyncCompressionLayerStorage<ZkSyncCompressionVerificationKey>;

pub type ZkSyncCompressionForWrapperVerificationKey =
    ZkSyncCompressionLayerStorage<ZkSyncCompressionVerificationKeyForWrapper>;

use crate::circuit_definitions::aux_layer::wrapper::ZkSyncCompressionWrapper;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::Setup as SnarkSetup;
use snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;
use snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use snark_wrapper::verifier::WrapperCircuit;

pub type ZkSyncSnarkWrapperCircuit = WrapperCircuit<
    Bn256,
    Poseidon2Sponge<Bn256, GoldilocksField, AbsorptionModeReplacement<Fr>, 2, 3>,
    CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>,
    CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>,
    ZkSyncCompressionWrapper,
>;

pub type ZkSyncSnarkWrapperProof =
    ZkSyncCompressionLayerStorage<SnarkProof<Bn256, ZkSyncSnarkWrapperCircuit>>;
pub type ZkSyncSnarkWrapperSetup =
    ZkSyncCompressionLayerStorage<SnarkSetup<Bn256, ZkSyncSnarkWrapperCircuit>>;
pub type ZkSyncSnarkWrapperVK =
    ZkSyncCompressionLayerStorage<SnarkVK<Bn256, ZkSyncSnarkWrapperCircuit>>;
