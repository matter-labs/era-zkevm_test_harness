use super::*;
use crate::boojum::cs::implementations::proof::Proof;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};
use crate::boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use zkevm_circuits::boojum::cs::traits::circuit::CircuitBuilder;
use zkevm_circuits::recursion::leaf_layer::input::RecursionLeafParametersWitness;
use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;

pub mod circuit_def;
pub mod leaf_layer;
pub mod node_layer;
pub mod scheduler;
pub mod verifier_builder;
pub mod recursion_tip;

use self::leaf_layer::*;
use self::node_layer::*;
use self::scheduler::*;
use self::recursion_tip::*;

pub const RECURSION_ARITY: usize = 32;
pub const SCHEDULER_CAPACITY: usize = (1 << 14) + (1 << 13);

pub use zkevm_circuits::recursion::recursion_tip::input::RECURSION_TIP_ARITY;

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncRecursiveLayerCircuit {
    SchedulerCircuit(ZkSyncSchedulerCircuit),
    NodeLayerCircuit(ZkSyncNodeLayerRecursiveCircuit),
    LeafLayerCircuitForMainVM(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForCodeDecommittmentsSorter(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForCodeDecommitter(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForLogDemuxer(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForKeccakRoundFunction(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForSha256RoundFunction(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForECRecover(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForRAMPermutation(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForStorageSorter(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForStorageApplication(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForEventsSorter(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForL1MessagesSorter(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForL1MessagesHasher(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForTransientStorageSorter(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForSecp256r1Verify(ZkSyncLeafLayerRecursiveCircuit),
    LeafLayerCircuitForEIP4844Repack(ZkSyncLeafLayerRecursiveCircuit),
    RecursionTipCircuit(ZkSyncRecursionTipCircuit),
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Copy, Debug)]
#[serde(bound = "")]
#[repr(u8)]
pub enum ZkSyncRecursionLayerStorageType {
    SchedulerCircuit = 1,
    NodeLayerCircuit = 2,
    LeafLayerCircuitForMainVM = 3,
    LeafLayerCircuitForCodeDecommittmentsSorter = 4,
    LeafLayerCircuitForCodeDecommitter = 5,
    LeafLayerCircuitForLogDemuxer = 6,
    LeafLayerCircuitForKeccakRoundFunction = 7,
    LeafLayerCircuitForSha256RoundFunction = 8,
    LeafLayerCircuitForECRecover = 9,
    LeafLayerCircuitForRAMPermutation = 10,
    LeafLayerCircuitForStorageSorter = 11,
    LeafLayerCircuitForStorageApplication = 12,
    LeafLayerCircuitForEventsSorter = 13,
    LeafLayerCircuitForL1MessagesSorter = 14,
    LeafLayerCircuitForL1MessagesHasher = 15,
    LeafLayerCircuitForTransientStorageSorter = 16,
    LeafLayerCircuitForSecp256r1Verify = 17,
    LeafLayerCircuitForEIP4844Repack = 18,
    RecursionTipCircuit = 255,
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug)]
#[serde(bound = "")]
#[repr(u8)]
pub enum ZkSyncRecursionLayerStorage<
    T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
> {
    SchedulerCircuit(T) = 1,
    NodeLayerCircuit(T) = 2,
    LeafLayerCircuitForMainVM(T) = 3,
    LeafLayerCircuitForCodeDecommittmentsSorter(T) = 4,
    LeafLayerCircuitForCodeDecommitter(T) = 5,
    LeafLayerCircuitForLogDemuxer(T) = 6,
    LeafLayerCircuitForKeccakRoundFunction(T) = 7,
    LeafLayerCircuitForSha256RoundFunction(T) = 8,
    LeafLayerCircuitForECRecover(T) = 9,
    LeafLayerCircuitForRAMPermutation(T) = 10,
    LeafLayerCircuitForStorageSorter(T) = 11,
    LeafLayerCircuitForStorageApplication(T) = 12,
    LeafLayerCircuitForEventsSorter(T) = 13,
    LeafLayerCircuitForL1MessagesSorter(T) = 14,
    LeafLayerCircuitForL1MessagesHasher(T) = 15,
    LeafLayerCircuitForTransientStorageSorter(T) = 16,
    LeafLayerCircuitForSecp256r1Verify(T) = 17,
    LeafLayerCircuitForEIP4844Repack(T) = 18,
    RecursionTipCircuit(T) = 255,
}

impl<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned>
    ZkSyncRecursionLayerStorage<T>
{
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncRecursionLayerStorage::SchedulerCircuit(..) => "Scheduler",
            ZkSyncRecursionLayerStorage::NodeLayerCircuit(..) => "Node",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForMainVM(..) => "Leaf for Main VM",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommittmentsSorter(..) => {
                "Leaf for Decommitts sorter"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommitter(..) => {
                "Leaf for Code decommitter"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForLogDemuxer(..) => {
                "Leaf for Log demuxer"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForKeccakRoundFunction(..) => {
                "Leaf for Keccak"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForSha256RoundFunction(..) => {
                "Leaf for SHA256"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForECRecover(..) => "Leaf for ECRecover",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForRAMPermutation(..) => {
                "Leaf for RAM permutation"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageSorter(..) => {
                "Leaf for Storage sorter"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageApplication(..) => {
                "Leaf for Storage application"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForEventsSorter(..) => {
                "Leaf for Events sorter"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForL1MessagesSorter(..) => {
                "Leaf for L1 messages sorter"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForL1MessagesHasher(..) => {
                "Leaf for L1 messages hasher"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForTransientStorageSorter(..) => {
                "Leaf for Transient storage sorter"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForSecp256r1Verify(..) => {
                "Leaf for Secp256r1 verify"
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForEIP4844Repack(..) => {
                "Leaf for EIP4844 repack"
            }
            ZkSyncRecursionLayerStorage::RecursionTipCircuit(..) => {
                "Recursion tip"
            }
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            ZkSyncRecursionLayerStorage::SchedulerCircuit(..) => {
                ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8
            }
            ZkSyncRecursionLayerStorage::NodeLayerCircuit(..) => {
                ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForMainVM(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommittmentsSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommitter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForLogDemuxer(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForKeccakRoundFunction(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForSha256RoundFunction(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForECRecover(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForRAMPermutation(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageApplication(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForEventsSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForL1MessagesSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForL1MessagesHasher(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesHasher as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForTransientStorageSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForTransientStorageSorter as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForSecp256r1Verify(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSecp256r1Verify as u8
            }
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForEIP4844Repack(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEIP4844Repack as u8
            }
            ZkSyncRecursionLayerStorage::RecursionTipCircuit(..) => {
                ZkSyncRecursionLayerStorageType::RecursionTipCircuit as u8
            }
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            Self::SchedulerCircuit(inner) => inner,
            Self::NodeLayerCircuit(inner) => inner,
            Self::LeafLayerCircuitForMainVM(inner) => inner,
            Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner) => inner,
            Self::LeafLayerCircuitForCodeDecommitter(inner) => inner,
            Self::LeafLayerCircuitForLogDemuxer(inner) => inner,
            Self::LeafLayerCircuitForKeccakRoundFunction(inner) => inner,
            Self::LeafLayerCircuitForSha256RoundFunction(inner) => inner,
            Self::LeafLayerCircuitForECRecover(inner) => inner,
            Self::LeafLayerCircuitForRAMPermutation(inner) => inner,
            Self::LeafLayerCircuitForStorageSorter(inner) => inner,
            Self::LeafLayerCircuitForStorageApplication(inner) => inner,
            Self::LeafLayerCircuitForEventsSorter(inner) => inner,
            Self::LeafLayerCircuitForL1MessagesSorter(inner) => inner,
            Self::LeafLayerCircuitForL1MessagesHasher(inner) => inner,
            Self::LeafLayerCircuitForTransientStorageSorter(inner) => inner,
            Self::LeafLayerCircuitForSecp256r1Verify(inner) => inner,
            Self::LeafLayerCircuitForEIP4844Repack(inner) => inner,
            Self::RecursionTipCircuit(inner) => inner,
        }
    }

    pub fn from_inner(numeric_type: u8, inner: T) -> Self {
        match numeric_type {
            a if a == ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8 => {
                Self::SchedulerCircuit(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8 => {
                Self::NodeLayerCircuit(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8 => {
                Self::LeafLayerCircuitForMainVM(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter
                    as u8 =>
            {
                Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter as u8 => {
                Self::LeafLayerCircuitForCodeDecommitter(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer as u8 => {
                Self::LeafLayerCircuitForLogDemuxer(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction
                    as u8 =>
            {
                Self::LeafLayerCircuitForKeccakRoundFunction(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction
                    as u8 =>
            {
                Self::LeafLayerCircuitForSha256RoundFunction(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover as u8 => {
                Self::LeafLayerCircuitForECRecover(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation as u8 => {
                Self::LeafLayerCircuitForRAMPermutation(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter as u8 => {
                Self::LeafLayerCircuitForStorageSorter(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication as u8 =>
            {
                Self::LeafLayerCircuitForStorageApplication(inner)
            }
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter as u8 => {
                Self::LeafLayerCircuitForEventsSorter(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter as u8 =>
            {
                Self::LeafLayerCircuitForL1MessagesSorter(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesHasher as u8 =>
            {
                Self::LeafLayerCircuitForL1MessagesHasher(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForTransientStorageSorter as u8 =>
            {
                Self::LeafLayerCircuitForTransientStorageSorter(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSecp256r1Verify as u8 =>
            {
                Self::LeafLayerCircuitForSecp256r1Verify(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEIP4844Repack as u8 =>
            {
                Self::LeafLayerCircuitForEIP4844Repack(inner)
            }
            a if a
                == ZkSyncRecursionLayerStorageType::RecursionTipCircuit as u8 =>
            {
                Self::RecursionTipCircuit(inner)
            }
            a @ _ => panic!("unknown numeric type {}", a),
        }
    }

    pub fn leaf_circuit_from_base_type(base_type: BaseLayerCircuitType, inner: T) -> Self {
        match base_type {
            BaseLayerCircuitType::VM => Self::LeafLayerCircuitForMainVM(inner),
            BaseLayerCircuitType::DecommitmentsFilter => {
                Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner)
            }
            BaseLayerCircuitType::Decommiter => Self::LeafLayerCircuitForCodeDecommitter(inner),
            BaseLayerCircuitType::LogDemultiplexer => Self::LeafLayerCircuitForLogDemuxer(inner),
            BaseLayerCircuitType::KeccakPrecompile => {
                Self::LeafLayerCircuitForKeccakRoundFunction(inner)
            }
            BaseLayerCircuitType::Sha256Precompile => {
                Self::LeafLayerCircuitForSha256RoundFunction(inner)
            }
            BaseLayerCircuitType::EcrecoverPrecompile => Self::LeafLayerCircuitForECRecover(inner),
            BaseLayerCircuitType::RamValidation => Self::LeafLayerCircuitForRAMPermutation(inner),
            BaseLayerCircuitType::StorageFilter => Self::LeafLayerCircuitForStorageSorter(inner),
            BaseLayerCircuitType::StorageApplicator => {
                Self::LeafLayerCircuitForStorageApplication(inner)
            }
            BaseLayerCircuitType::EventsRevertsFilter => {
                Self::LeafLayerCircuitForEventsSorter(inner)
            }
            BaseLayerCircuitType::L1MessagesRevertsFilter => {
                Self::LeafLayerCircuitForL1MessagesSorter(inner)
            }
            BaseLayerCircuitType::L1MessagesHasher => {
                Self::LeafLayerCircuitForL1MessagesHasher(inner)
            }
            BaseLayerCircuitType::TransientStorageChecker => {
                Self::LeafLayerCircuitForTransientStorageSorter(inner)
            }
            BaseLayerCircuitType::Secp256r1Verify => {
                Self::LeafLayerCircuitForSecp256r1Verify(inner)
            }
            BaseLayerCircuitType::EIP4844Repack => {
                Self::LeafLayerCircuitForEIP4844Repack(inner)
            }
            circuit_type => {
                panic!("unknown base circuit type for leaf: {:?}", circuit_type);
            }
        }
    }
}

use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;

pub type ZkSyncRecursionLayerFinalizationHint =
    ZkSyncRecursionLayerStorage<FinalizationHintsForProver>;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::config::ProvingCSConfig;
use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;

pub type RecursiveProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;

pub type ZkSyncRecursionProof = Proof<GoldilocksField, RecursiveProofsTreeHasher, GoldilocksExt2>;

pub type ZkSyncRecursionLayerProof = ZkSyncRecursionLayerStorage<ZkSyncRecursionProof>;

use crate::boojum::cs::implementations::verifier::VerificationKey;
use crate::boojum::field::traits::field_like::PrimeFieldLikeVectorized;
use crate::ZkSyncDefaultRoundFunction;

pub type ZkSyncRecursionVerificationKey =
    VerificationKey<GoldilocksField, RecursiveProofsTreeHasher>;

pub type ZkSyncRecursionLayerVerificationKey =
    ZkSyncRecursionLayerStorage<ZkSyncRecursionVerificationKey>;

pub type ZkSyncRecursionLayerLeafParameters =
    ZkSyncRecursionLayerStorage<RecursionLeafParametersWitness<GoldilocksField>>;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

impl ZkSyncRecursiveLayerCircuit {
    pub fn short_description(&self) -> &'static str {
        match &self {
            Self::SchedulerCircuit(..) => "Scheduler",
            Self::NodeLayerCircuit(..) => "Node",
            Self::LeafLayerCircuitForMainVM(..) => "Leaf for Main VM",
            Self::LeafLayerCircuitForCodeDecommittmentsSorter(..) => "Leaf for Decommitts sorter",
            Self::LeafLayerCircuitForCodeDecommitter(..) => "Leaf for Code decommitter",
            Self::LeafLayerCircuitForLogDemuxer(..) => "Leaf for Log demuxer",
            Self::LeafLayerCircuitForKeccakRoundFunction(..) => "Leaf for Keccak",
            Self::LeafLayerCircuitForSha256RoundFunction(..) => "Leaf for SHA256",
            Self::LeafLayerCircuitForECRecover(..) => "Leaf for ECRecover",
            Self::LeafLayerCircuitForRAMPermutation(..) => "Leaf for RAM permutation",
            Self::LeafLayerCircuitForStorageSorter(..) => "Leaf for Storage sorter",
            Self::LeafLayerCircuitForStorageApplication(..) => "Leaf for Storage application",
            Self::LeafLayerCircuitForEventsSorter(..) => "Leaf for Events sorter",
            Self::LeafLayerCircuitForL1MessagesSorter(..) => "Leaf for L1 messages sorter",
            Self::LeafLayerCircuitForL1MessagesHasher(..) => "Leaf for L1 messages hasher",
            Self::LeafLayerCircuitForTransientStorageSorter(..) => "Leaf for transient storage sorter",
            Self::LeafLayerCircuitForSecp256r1Verify(..) => "Leaf for Secp256r1 verify",
            Self::LeafLayerCircuitForEIP4844Repack(..) => "Leaf for EIP4844 repack",
            Self::RecursionTipCircuit(..) => "Recursion tip",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            Self::SchedulerCircuit(..) => ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8,
            Self::NodeLayerCircuit(..) => ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8,
            Self::LeafLayerCircuitForMainVM(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8
            }
            Self::LeafLayerCircuitForCodeDecommittmentsSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter as u8
            }
            Self::LeafLayerCircuitForCodeDecommitter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter as u8
            }
            Self::LeafLayerCircuitForLogDemuxer(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer as u8
            }
            Self::LeafLayerCircuitForKeccakRoundFunction(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction as u8
            }
            Self::LeafLayerCircuitForSha256RoundFunction(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction as u8
            }
            Self::LeafLayerCircuitForECRecover(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover as u8
            }
            Self::LeafLayerCircuitForRAMPermutation(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation as u8
            }
            Self::LeafLayerCircuitForStorageSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter as u8
            }
            Self::LeafLayerCircuitForStorageApplication(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication as u8
            }
            Self::LeafLayerCircuitForEventsSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter as u8
            }
            Self::LeafLayerCircuitForL1MessagesSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter as u8
            }
            Self::LeafLayerCircuitForL1MessagesHasher(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesHasher as u8
            }
            Self::LeafLayerCircuitForTransientStorageSorter(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForTransientStorageSorter as u8
            }
            Self::LeafLayerCircuitForSecp256r1Verify(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSecp256r1Verify as u8
            }
            Self::LeafLayerCircuitForEIP4844Repack(..) => {
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEIP4844Repack as u8
            }
            Self::RecursionTipCircuit(..) => {
                ZkSyncRecursionLayerStorageType::RecursionTipCircuit as u8
            }
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            Self::SchedulerCircuit(inner) => inner.size_hint(),
            Self::NodeLayerCircuit(inner) => inner.size_hint(),
            Self::LeafLayerCircuitForMainVM(inner)
            | Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner)
            | Self::LeafLayerCircuitForCodeDecommitter(inner)
            | Self::LeafLayerCircuitForLogDemuxer(inner)
            | Self::LeafLayerCircuitForKeccakRoundFunction(inner)
            | Self::LeafLayerCircuitForSha256RoundFunction(inner)
            | Self::LeafLayerCircuitForECRecover(inner)
            | Self::LeafLayerCircuitForRAMPermutation(inner)
            | Self::LeafLayerCircuitForStorageSorter(inner)
            | Self::LeafLayerCircuitForStorageApplication(inner)
            | Self::LeafLayerCircuitForEventsSorter(inner)
            | Self::LeafLayerCircuitForL1MessagesSorter(inner)
            | Self::LeafLayerCircuitForL1MessagesHasher(inner) 
            | Self::LeafLayerCircuitForTransientStorageSorter(inner)
            | Self::LeafLayerCircuitForSecp256r1Verify(inner)
            | Self::LeafLayerCircuitForEIP4844Repack(inner) => inner.size_hint(),
            Self::RecursionTipCircuit(inner) => inner.size_hint(),
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        match &self {
            Self::SchedulerCircuit(..) => ZkSyncSchedulerCircuit::geometry(),
            Self::NodeLayerCircuit(..) => ZkSyncNodeLayerRecursiveCircuit::geometry(),
            Self::LeafLayerCircuitForMainVM(..)
            | Self::LeafLayerCircuitForCodeDecommittmentsSorter(..)
            | Self::LeafLayerCircuitForCodeDecommitter(..)
            | Self::LeafLayerCircuitForLogDemuxer(..)
            | Self::LeafLayerCircuitForKeccakRoundFunction(..)
            | Self::LeafLayerCircuitForSha256RoundFunction(..)
            | Self::LeafLayerCircuitForECRecover(..)
            | Self::LeafLayerCircuitForRAMPermutation(..)
            | Self::LeafLayerCircuitForStorageSorter(..)
            | Self::LeafLayerCircuitForStorageApplication(..)
            | Self::LeafLayerCircuitForEventsSorter(..)
            | Self::LeafLayerCircuitForL1MessagesSorter(..)
            | Self::LeafLayerCircuitForL1MessagesHasher(..) 
            | Self::LeafLayerCircuitForTransientStorageSorter(..)
            | Self::LeafLayerCircuitForSecp256r1Verify(..)
            | Self::LeafLayerCircuitForEIP4844Repack(..)=> {
                ZkSyncLeafLayerRecursiveCircuit::geometry()
            },
            Self::RecursionTipCircuit(..) => {
                ZkSyncRecursionTipCircuit::geometry()
            }
        }
    }

    fn synthesis_inner<P: PrimeFieldLikeVectorized<Base = F>>(
        inner: &ZkSyncLeafLayerRecursiveCircuit,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        let geometry = ZkSyncLeafLayerRecursiveCircuit::geometry();
        let (max_trace_len, num_vars) = inner.size_hint();
        let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig>::new(
            geometry,
            max_trace_len.unwrap(),
        );
        let cs_builder = new_builder::<_, F>(builder_impl);
        let builder = inner.configure_builder_proxy(cs_builder);
        let mut cs = builder.build(num_vars.unwrap());
        let round_function = ZkSyncDefaultRoundFunction::default();
        inner.add_tables(&mut cs);
        inner.clone().synthesize_into_cs(&mut cs, &round_function);
        cs.pad_and_shrink_using_hint(hint);
        cs.into_assembly()
    }

    pub fn synthesis<P: PrimeFieldLikeVectorized<Base = F>>(
        &self,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        match &self {
            Self::SchedulerCircuit(inner) => {
                let geometry = ZkSyncSchedulerCircuit::geometry();
                let (max_trace_len, num_vars) = inner.size_hint();
                let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig>::new(
                    geometry,
                    max_trace_len.unwrap(),
                );
                let cs_builder = new_builder::<_, F>(builder_impl);
                let builder = inner.configure_builder_proxy(cs_builder);
                let mut cs = builder.build(num_vars.unwrap());
                let round_function = ZkSyncDefaultRoundFunction::default();
                inner.add_tables(&mut cs);
                inner.clone().synthesize_into_cs(&mut cs, &round_function);
                cs.pad_and_shrink_using_hint(hint);
                cs.into_assembly()
            }
            Self::NodeLayerCircuit(inner) => {
                let geometry = ZkSyncNodeLayerRecursiveCircuit::geometry();
                let (max_trace_len, num_vars) = inner.size_hint();
                let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig>::new(
                    geometry,
                    max_trace_len.unwrap(),
                );
                let cs_builder = new_builder::<_, F>(builder_impl);
                let builder = inner.configure_builder_proxy(cs_builder);
                let mut cs = builder.build(num_vars.unwrap());
                let round_function = ZkSyncDefaultRoundFunction::default();
                inner.add_tables(&mut cs);
                inner.clone().synthesize_into_cs(&mut cs, &round_function);
                cs.pad_and_shrink_using_hint(hint);
                cs.into_assembly()
            }
            Self::LeafLayerCircuitForMainVM(inner)
            | Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner)
            | Self::LeafLayerCircuitForCodeDecommitter(inner)
            | Self::LeafLayerCircuitForLogDemuxer(inner)
            | Self::LeafLayerCircuitForKeccakRoundFunction(inner)
            | Self::LeafLayerCircuitForSha256RoundFunction(inner)
            | Self::LeafLayerCircuitForECRecover(inner)
            | Self::LeafLayerCircuitForRAMPermutation(inner)
            | Self::LeafLayerCircuitForStorageSorter(inner)
            | Self::LeafLayerCircuitForStorageApplication(inner)
            | Self::LeafLayerCircuitForEventsSorter(inner)
            | Self::LeafLayerCircuitForL1MessagesSorter(inner)
            | Self::LeafLayerCircuitForL1MessagesHasher(inner)
            | Self::LeafLayerCircuitForTransientStorageSorter(inner)
            | Self::LeafLayerCircuitForSecp256r1Verify(inner) 
            | Self::LeafLayerCircuitForEIP4844Repack(inner) => {
                Self::synthesis_inner(inner, hint)
            }
            Self::RecursionTipCircuit(inner) => {
                let geometry = ZkSyncRecursionTipCircuit::geometry();
                let (max_trace_len, num_vars) = inner.size_hint();
                let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig>::new(
                    geometry,
                    max_trace_len.unwrap(),
                );
                let cs_builder = new_builder::<_, F>(builder_impl);
                let builder = inner.configure_builder_proxy(cs_builder);
                let mut cs = builder.build(num_vars.unwrap());
                let round_function = ZkSyncDefaultRoundFunction::default();
                inner.add_tables(&mut cs);
                inner.clone().synthesize_into_cs(&mut cs, &round_function);
                cs.pad_and_shrink_using_hint(hint);
                cs.into_assembly()
            }
        }
    }

    pub fn into_dyn_verifier_builder(
        &self,
    ) -> Box<dyn crate::boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>> {
        match &self {
            Self::SchedulerCircuit(..) => {
                ConcreteSchedulerCircuitBuilder::dyn_verifier_builder::<EXT>()
            }
            Self::NodeLayerCircuit(..) => {
                ConcreteLeafLayerCircuitBuilder::dyn_verifier_builder::<EXT>()
            }
            Self::LeafLayerCircuitForMainVM(..)
            | Self::LeafLayerCircuitForCodeDecommittmentsSorter(..)
            | Self::LeafLayerCircuitForCodeDecommitter(..)
            | Self::LeafLayerCircuitForLogDemuxer(..)
            | Self::LeafLayerCircuitForKeccakRoundFunction(..)
            | Self::LeafLayerCircuitForSha256RoundFunction(..)
            | Self::LeafLayerCircuitForECRecover(..)
            | Self::LeafLayerCircuitForRAMPermutation(..)
            | Self::LeafLayerCircuitForStorageSorter(..)
            | Self::LeafLayerCircuitForStorageApplication(..)
            | Self::LeafLayerCircuitForEventsSorter(..)
            | Self::LeafLayerCircuitForL1MessagesSorter(..)
            | Self::LeafLayerCircuitForL1MessagesHasher(..) 
            | Self::LeafLayerCircuitForTransientStorageSorter(..)
            | Self::LeafLayerCircuitForSecp256r1Verify(..) 
            | Self::LeafLayerCircuitForEIP4844Repack(..) => {
                ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<EXT>()
            },
            Self::RecursionTipCircuit(..) => {
                ConcreteRecursionTipCircuitBuilder::dyn_verifier_builder::<EXT>()
            }
        }
    }

    pub fn into_dyn_recursive_verifier_builder<CS: ConstraintSystem<F> + 'static>(
        &self,
    ) -> Box<dyn crate::boojum::cs::traits::circuit::ErasedBuilderForRecursiveVerifier<F, EXT, CS>>
    {
        match &self {
            Self::SchedulerCircuit(..) => {
                ConcreteSchedulerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
            }
            Self::NodeLayerCircuit(..) => {
                ConcreteLeafLayerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
            }
            Self::LeafLayerCircuitForMainVM(..)
            | Self::LeafLayerCircuitForCodeDecommittmentsSorter(..)
            | Self::LeafLayerCircuitForCodeDecommitter(..)
            | Self::LeafLayerCircuitForLogDemuxer(..)
            | Self::LeafLayerCircuitForKeccakRoundFunction(..)
            | Self::LeafLayerCircuitForSha256RoundFunction(..)
            | Self::LeafLayerCircuitForECRecover(..)
            | Self::LeafLayerCircuitForRAMPermutation(..)
            | Self::LeafLayerCircuitForStorageSorter(..)
            | Self::LeafLayerCircuitForStorageApplication(..)
            | Self::LeafLayerCircuitForEventsSorter(..)
            | Self::LeafLayerCircuitForL1MessagesSorter(..)
            | Self::LeafLayerCircuitForL1MessagesHasher(..) 
            | Self::LeafLayerCircuitForTransientStorageSorter(..)
            | Self::LeafLayerCircuitForSecp256r1Verify(..) 
            | Self::LeafLayerCircuitForEIP4844Repack(..) => {
                ConcreteNodeLayerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
            },
            Self::RecursionTipCircuit(..) => {
                ConcreteRecursionTipCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
            }
        }
    }

    pub fn leaf_circuit_from_base_type(
        base_type: BaseLayerCircuitType,
        inner: ZkSyncLeafLayerRecursiveCircuit,
    ) -> Self {
        match base_type {
            BaseLayerCircuitType::VM => Self::LeafLayerCircuitForMainVM(inner),
            BaseLayerCircuitType::DecommitmentsFilter => {
                Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner)
            }
            BaseLayerCircuitType::Decommiter => Self::LeafLayerCircuitForCodeDecommitter(inner),
            BaseLayerCircuitType::LogDemultiplexer => Self::LeafLayerCircuitForLogDemuxer(inner),
            BaseLayerCircuitType::KeccakPrecompile => {
                Self::LeafLayerCircuitForKeccakRoundFunction(inner)
            }
            BaseLayerCircuitType::Sha256Precompile => {
                Self::LeafLayerCircuitForSha256RoundFunction(inner)
            }
            BaseLayerCircuitType::EcrecoverPrecompile => Self::LeafLayerCircuitForECRecover(inner),
            BaseLayerCircuitType::RamValidation => Self::LeafLayerCircuitForRAMPermutation(inner),
            BaseLayerCircuitType::StorageFilter => Self::LeafLayerCircuitForStorageSorter(inner),
            BaseLayerCircuitType::StorageApplicator => {
                Self::LeafLayerCircuitForStorageApplication(inner)
            }
            BaseLayerCircuitType::EventsRevertsFilter => {
                Self::LeafLayerCircuitForEventsSorter(inner)
            }
            BaseLayerCircuitType::L1MessagesRevertsFilter => {
                Self::LeafLayerCircuitForL1MessagesSorter(inner)
            }
            BaseLayerCircuitType::L1MessagesHasher => {
                Self::LeafLayerCircuitForL1MessagesHasher(inner)
            }
            BaseLayerCircuitType::TransientStorageChecker => {
                Self::LeafLayerCircuitForTransientStorageSorter(inner)
            }
            BaseLayerCircuitType::Secp256r1Verify => {
                Self::LeafLayerCircuitForSecp256r1Verify(inner)
            }
            BaseLayerCircuitType::EIP4844Repack => {
                Self::LeafLayerCircuitForEIP4844Repack(inner)
            }
            circuit_type => {
                panic!("unknown base circuit type for leaf: {:?}", circuit_type);
            }
        }
    }
}

pub fn base_circuit_type_into_recursive_leaf_circuit_type(
    value: BaseLayerCircuitType,
) -> ZkSyncRecursionLayerStorageType {
    match value {
        BaseLayerCircuitType::None => {
            panic!("None is not a proper type")
        }
        BaseLayerCircuitType::VM => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM,
        BaseLayerCircuitType::DecommitmentsFilter => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter
        }
        BaseLayerCircuitType::Decommiter => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter
        }
        BaseLayerCircuitType::LogDemultiplexer => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer
        }
        BaseLayerCircuitType::KeccakPrecompile => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction
        }
        BaseLayerCircuitType::Sha256Precompile => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction
        }
        BaseLayerCircuitType::EcrecoverPrecompile => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover
        }
        BaseLayerCircuitType::RamValidation => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation
        }
        BaseLayerCircuitType::StorageFilter => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter
        }
        BaseLayerCircuitType::StorageApplicator => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication
        }
        BaseLayerCircuitType::EventsRevertsFilter => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter
        }
        BaseLayerCircuitType::L1MessagesRevertsFilter => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter
        }
        BaseLayerCircuitType::L1MessagesHasher => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesHasher
        }
        BaseLayerCircuitType::TransientStorageChecker => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForTransientStorageSorter
        }
        BaseLayerCircuitType::Secp256r1Verify => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSecp256r1Verify
        }
        BaseLayerCircuitType::TransientStorageChecker => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForTransientStorageSorter
        }
        BaseLayerCircuitType::Secp256r1Verify => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSecp256r1Verify
        }
        BaseLayerCircuitType::EIP4844Repack => {
            ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEIP4844Repack
        }
    }
}
