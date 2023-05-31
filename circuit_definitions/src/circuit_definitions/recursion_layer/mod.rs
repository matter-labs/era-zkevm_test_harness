use super::*;
use boojum::cs::implementations::proof::Proof;
use boojum::field::goldilocks::{GoldilocksField, GoldilocksExt2};
use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;
use boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;

pub mod leaf_layer;
pub mod node_layer;
pub mod circuit_def;
pub mod scheduler;

use self::leaf_layer::*;
use self::node_layer::*;
use self::scheduler::*;

pub const RECURSION_ARITY: usize = 16;
pub const SCHEDULER_CAPACITY: usize = 4096;

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
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug)]
#[serde(bound = "")]
#[repr(u8)]
pub enum ZkSyncRecursionLayerStorage<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned> {
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
}

impl<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned> ZkSyncRecursionLayerStorage<T> {
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncRecursionLayerStorage::SchedulerCircuit(..) => "Scheduler",
            ZkSyncRecursionLayerStorage::NodeLayerCircuit(..) => "Node",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForMainVM(..) => "Leaf for Main VM",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommittmentsSorter(..) => "Leaf for Decommitts sorter",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommitter(..) => "Leaf for Code decommitter",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForLogDemuxer(..) => "Leaf for Log demuxer",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForKeccakRoundFunction(..) => "Leaf for Keccak",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForSha256RoundFunction(..) => "Leaf for SHA256",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForECRecover(..) => "Leaf for ECRecover",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForRAMPermutation(..) => "Leaf for RAM permutation",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageSorter(..) => "Leaf for Storage sorter",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageApplication(..) => "Leaf for Storage application",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForEventsSorter(..) => "Leaf for Events sorter",
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForL1MessagesSorter(..) => "Leaf for L1 messages sorter",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            ZkSyncRecursionLayerStorage::SchedulerCircuit(..) => ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8,
            ZkSyncRecursionLayerStorage::NodeLayerCircuit(..) => ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForMainVM(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommittmentsSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForCodeDecommitter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForLogDemuxer(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForKeccakRoundFunction(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForSha256RoundFunction(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForECRecover(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForRAMPermutation(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForStorageApplication(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForEventsSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter as u8,
            ZkSyncRecursionLayerStorage::LeafLayerCircuitForL1MessagesSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter as u8,
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
        }
    }

    pub fn from_inner(numeric_type: u8, inner: T) -> Self {
        match numeric_type {
            a if a == ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8 => Self::SchedulerCircuit(inner),
            a if a == ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8 => Self::NodeLayerCircuit(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8 => Self::LeafLayerCircuitForMainVM(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter as u8 => Self::LeafLayerCircuitForCodeDecommittmentsSorter(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter as u8 => Self::LeafLayerCircuitForCodeDecommitter(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer as u8 => Self::LeafLayerCircuitForLogDemuxer(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction as u8 => Self::LeafLayerCircuitForKeccakRoundFunction(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction as u8 => Self::LeafLayerCircuitForSha256RoundFunction(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover as u8 => Self::LeafLayerCircuitForECRecover(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation as u8 => Self::LeafLayerCircuitForRAMPermutation(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter as u8 => Self::LeafLayerCircuitForStorageSorter(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication as u8 => Self::LeafLayerCircuitForStorageApplication(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter as u8 => Self::LeafLayerCircuitForEventsSorter(inner),
            a if a == ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter as u8 => Self::LeafLayerCircuitForL1MessagesSorter(inner),
            a @ _ => panic!("unknown numeric type {}", a)
        }
    }
}

use boojum::cs::implementations::setup::FinalizationHintsForProver;

pub type ZkSyncRecursionLayerFinalizationHint = ZkSyncRecursionLayerStorage<FinalizationHintsForProver>;

use boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;

pub type RecursiveProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;

pub type ZkSyncRecursionProof = Proof<GoldilocksField, RecursiveProofsTreeHasher, GoldilocksExt2>;

pub type ZkSyncRecursionLayerProof = ZkSyncRecursionLayerStorage<ZkSyncRecursionProof>;

use boojum::cs::implementations::verifier::VerificationKey;
pub type ZkSyncRecursionVerificationKey = VerificationKey<GoldilocksField, RecursiveProofsTreeHasher>;

pub type ZkSyncRecursionLayerVerificationKey = ZkSyncRecursionLayerStorage<ZkSyncRecursionVerificationKey>;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;
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
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            Self::SchedulerCircuit(..) => ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8,
            Self::NodeLayerCircuit(..) => ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8,
            Self::LeafLayerCircuitForMainVM(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8,
            Self::LeafLayerCircuitForCodeDecommittmentsSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter as u8,
            Self::LeafLayerCircuitForCodeDecommitter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter as u8,
            Self::LeafLayerCircuitForLogDemuxer(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer as u8,
            Self::LeafLayerCircuitForKeccakRoundFunction(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction as u8,
            Self::LeafLayerCircuitForSha256RoundFunction(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction as u8,
            Self::LeafLayerCircuitForECRecover(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover as u8,
            Self::LeafLayerCircuitForRAMPermutation(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation as u8,
            Self::LeafLayerCircuitForStorageSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter as u8,
            Self::LeafLayerCircuitForStorageApplication(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication as u8,
            Self::LeafLayerCircuitForEventsSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter as u8,
            Self::LeafLayerCircuitForL1MessagesSorter(..) => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter as u8,
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            Self::SchedulerCircuit(inner) => {inner.size_hint()},
            Self::NodeLayerCircuit(inner) => {inner.size_hint()},
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
            | Self::LeafLayerCircuitForL1MessagesSorter(inner) => {
                inner.size_hint()
            },
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        use boojum::cs::traits::circuit::CircuitBuilder;

        match &self {
            Self::SchedulerCircuit(..) => {ZkSyncSchedulerCircuit::geometry()},
            Self::NodeLayerCircuit(..) => {ZkSyncNodeLayerRecursiveCircuit::geometry()},
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
            | Self::LeafLayerCircuitForL1MessagesSorter(..) => {
                ZkSyncLeafLayerRecursiveCircuit::geometry()
            },
        }
    }

    pub fn into_dyn_verifier_builder(&self) -> Box<dyn boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>> {
        match &self {
            Self::SchedulerCircuit(..) => {ConcreteSchedulerCircuitBuilder::dyn_verifier_builder::<EXT>()},
            Self::NodeLayerCircuit(..) => {ConcreteLeafLayerCircuitBuilder::dyn_verifier_builder::<EXT>()},
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
            | Self::LeafLayerCircuitForL1MessagesSorter(..) => {
                ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<EXT>()
            }
        }
    }

    pub fn into_dyn_recursive_verifier_builder<CS: ConstraintSystem<F> + 'static>(&self) -> Box<dyn boojum::cs::traits::circuit::ErasedBuilderForRecursiveVerifier<F, EXT, CS>> {
        match &self {
            Self::SchedulerCircuit(..) => {ConcreteSchedulerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()},
            Self::NodeLayerCircuit(..) => {ConcreteLeafLayerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()},
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
            | Self::LeafLayerCircuitForL1MessagesSorter(..) => {
                ConcreteNodeLayerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
            }
        }
    }
}