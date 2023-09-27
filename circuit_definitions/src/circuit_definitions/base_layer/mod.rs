use crate::boojum::cs::gates::*;
use crate::boojum::cs::implementations::proof::Proof;
use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;
use crate::boojum::cs::traits::gate::GatePlacementStrategy;
use crate::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};
use crate::boojum::gadgets::tables::*;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;
use zkevm_circuits::tables::*;

use super::*;

pub const TARGET_CIRCUIT_TRACE_LENGTH: usize = 1 << 20;

// should follow in the same sequence as we will logically process sequences
pub mod code_decommitter;
pub mod ecrecover;
pub mod events_sort_dedup;
pub mod keccak256_round_function;
pub mod log_demux;
pub mod ram_permutation;
pub mod sha256_round_function;
pub mod sort_code_decommits;
pub mod storage_apply;
pub mod storage_sort_dedup;
pub mod vm_main;
// pub mod l1_messages_sort_dedup; // equal to one above
pub mod linear_hasher;

pub use self::code_decommitter::CodeDecommitterInstanceSynthesisFunction;
pub use self::ecrecover::ECRecoverFunctionInstanceSynthesisFunction;
pub use self::events_sort_dedup::EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction;
pub use self::keccak256_round_function::Keccak256RoundFunctionInstanceSynthesisFunction;
pub use self::linear_hasher::LinearHasherInstanceSynthesisFunction;
pub use self::log_demux::LogDemuxInstanceSynthesisFunction;
pub use self::ram_permutation::RAMPermutationInstanceSynthesisFunction;
pub use self::sha256_round_function::Sha256RoundFunctionInstanceSynthesisFunction;
pub use self::sort_code_decommits::CodeDecommittmentsSorterSynthesisFunction;
pub use self::storage_apply::StorageApplicationInstanceSynthesisFunction;
pub use self::storage_sort_dedup::StorageSortAndDedupInstanceSynthesisFunction;
pub use self::vm_main::VmMainInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<F> for ZkSyncUniformCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<F, W, R> =
    ZkSyncUniformCircuitInstance<F, VmMainInstanceSynthesisFunction<F, W, R>>;
pub type CodeDecommittsSorterCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, LogDemuxInstanceSynthesisFunction<F, R>>;
pub type Keccak256RoundFunctionCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, Keccak256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type Sha256RoundFunctionCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, Sha256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type ECRecoverFunctionCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, ECRecoverFunctionInstanceSynthesisFunction<F, R>>;
pub type RAMPermutationCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, RAMPermutationInstanceSynthesisFunction<F, R>>;
pub type StorageSorterCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, StorageSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type StorageApplicationCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, StorageApplicationInstanceSynthesisFunction<F, R>>;
pub type EventsSorterCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesSorterCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesHasherCircuit<F, R> =
    ZkSyncUniformCircuitInstance<F, LinearHasherInstanceSynthesisFunction<F, R>>;

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug)]
#[serde(bound = "")]
pub enum ZkSyncBaseLayerStorage<
    T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
> {
    MainVM(T),
    CodeDecommittmentsSorter(T),
    CodeDecommitter(T),
    LogDemuxer(T),
    KeccakRoundFunction(T),
    Sha256RoundFunction(T),
    ECRecover(T),
    RAMPermutation(T),
    StorageSorter(T),
    StorageApplication(T),
    EventsSorter(T),
    L1MessagesSorter(T),
    L1MessagesHasher(T),
}

impl<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned>
    ZkSyncBaseLayerStorage<T>
{
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncBaseLayerStorage::MainVM(..) => "Main VM",
            ZkSyncBaseLayerStorage::CodeDecommittmentsSorter(..) => "Decommitts sorter",
            ZkSyncBaseLayerStorage::CodeDecommitter(..) => "Code decommitter",
            ZkSyncBaseLayerStorage::LogDemuxer(..) => "Log demuxer",
            ZkSyncBaseLayerStorage::KeccakRoundFunction(..) => "Keccak",
            ZkSyncBaseLayerStorage::Sha256RoundFunction(..) => "SHA256",
            ZkSyncBaseLayerStorage::ECRecover(..) => "ECRecover",
            ZkSyncBaseLayerStorage::RAMPermutation(..) => "RAM permutation",
            ZkSyncBaseLayerStorage::StorageSorter(..) => "Storage sorter",
            ZkSyncBaseLayerStorage::StorageApplication(..) => "Storage application",
            ZkSyncBaseLayerStorage::EventsSorter(..) => "Events sorter",
            ZkSyncBaseLayerStorage::L1MessagesSorter(..) => "L1 messages sorter",
            ZkSyncBaseLayerStorage::L1MessagesHasher(..) => "L1 messages rehasher",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match &self {
            ZkSyncBaseLayerStorage::MainVM(..) => BaseLayerCircuitType::VM as u8,
            ZkSyncBaseLayerStorage::CodeDecommittmentsSorter(..) => {
                BaseLayerCircuitType::DecommitmentsFilter as u8
            }
            ZkSyncBaseLayerStorage::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
            ZkSyncBaseLayerStorage::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
            ZkSyncBaseLayerStorage::KeccakRoundFunction(..) => {
                BaseLayerCircuitType::KeccakPrecompile as u8
            }
            ZkSyncBaseLayerStorage::Sha256RoundFunction(..) => {
                BaseLayerCircuitType::Sha256Precompile as u8
            }
            ZkSyncBaseLayerStorage::ECRecover(..) => {
                BaseLayerCircuitType::EcrecoverPrecompile as u8
            }
            ZkSyncBaseLayerStorage::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
            ZkSyncBaseLayerStorage::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
            ZkSyncBaseLayerStorage::StorageApplication(..) => {
                BaseLayerCircuitType::StorageApplicator as u8
            }
            ZkSyncBaseLayerStorage::EventsSorter(..) => {
                BaseLayerCircuitType::EventsRevertsFilter as u8
            }
            ZkSyncBaseLayerStorage::L1MessagesSorter(..) => {
                BaseLayerCircuitType::L1MessagesRevertsFilter as u8
            }
            ZkSyncBaseLayerStorage::L1MessagesHasher(..) => {
                BaseLayerCircuitType::L1MessagesHasher as u8
            }
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            ZkSyncBaseLayerStorage::MainVM(inner) => inner,
            ZkSyncBaseLayerStorage::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncBaseLayerStorage::CodeDecommitter(inner) => inner,
            ZkSyncBaseLayerStorage::LogDemuxer(inner) => inner,
            ZkSyncBaseLayerStorage::KeccakRoundFunction(inner) => inner,
            ZkSyncBaseLayerStorage::Sha256RoundFunction(inner) => inner,
            ZkSyncBaseLayerStorage::ECRecover(inner) => inner,
            ZkSyncBaseLayerStorage::RAMPermutation(inner) => inner,
            ZkSyncBaseLayerStorage::StorageSorter(inner) => inner,
            ZkSyncBaseLayerStorage::StorageApplication(inner) => inner,
            ZkSyncBaseLayerStorage::EventsSorter(inner) => inner,
            ZkSyncBaseLayerStorage::L1MessagesSorter(inner) => inner,
            ZkSyncBaseLayerStorage::L1MessagesHasher(inner) => inner,
        }
    }

    pub fn from_inner(numeric_type: u8, inner: T) -> Self {
        use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match numeric_type {
            a if a == BaseLayerCircuitType::VM as u8 => Self::MainVM(inner),
            a if a == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
                Self::CodeDecommittmentsSorter(inner)
            }
            a if a == BaseLayerCircuitType::Decommiter as u8 => Self::CodeDecommitter(inner),
            a if a == BaseLayerCircuitType::LogDemultiplexer as u8 => Self::LogDemuxer(inner),
            a if a == BaseLayerCircuitType::KeccakPrecompile as u8 => {
                Self::KeccakRoundFunction(inner)
            }
            a if a == BaseLayerCircuitType::Sha256Precompile as u8 => {
                Self::Sha256RoundFunction(inner)
            }
            a if a == BaseLayerCircuitType::EcrecoverPrecompile as u8 => Self::ECRecover(inner),
            a if a == BaseLayerCircuitType::RamValidation as u8 => Self::RAMPermutation(inner),
            a if a == BaseLayerCircuitType::StorageFilter as u8 => Self::StorageSorter(inner),
            a if a == BaseLayerCircuitType::StorageApplicator as u8 => {
                Self::StorageApplication(inner)
            }
            a if a == BaseLayerCircuitType::EventsRevertsFilter as u8 => Self::EventsSorter(inner),
            a if a == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
                Self::L1MessagesSorter(inner)
            }
            a if a == BaseLayerCircuitType::L1MessagesHasher as u8 => Self::L1MessagesHasher(inner),
            a @ _ => panic!("unknown numeric type {}", a),
        }
    }
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncBaseLayerCircuit<
    F: SmallField,
    W: WitnessOracle<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
> where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    MainVM(VMMainCircuit<F, W, R>),
    CodeDecommittmentsSorter(CodeDecommittsSorterCircuit<F, R>),
    CodeDecommitter(CodeDecommitterCircuit<F, R>),
    LogDemuxer(LogDemuxerCircuit<F, R>),
    KeccakRoundFunction(Keccak256RoundFunctionCircuit<F, R>),
    Sha256RoundFunction(Sha256RoundFunctionCircuit<F, R>),
    ECRecover(ECRecoverFunctionCircuit<F, R>),
    RAMPermutation(RAMPermutationCircuit<F, R>),
    StorageSorter(StorageSorterCircuit<F, R>),
    StorageApplication(StorageApplicationCircuit<F, R>),
    EventsSorter(EventsSorterCircuit<F, R>),
    L1MessagesSorter(L1MessagesSorterCircuit<F, R>),
    L1MessagesHasher(L1MessagesHasherCircuit<F, R>),
}

impl<
        F: SmallField,
        W: WitnessOracle<F>,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > ZkSyncBaseLayerCircuit<F, W, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(..) => "Main VM",
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(..) => "Decommitts sorter",
            ZkSyncBaseLayerCircuit::CodeDecommitter(..) => "Code decommitter",
            ZkSyncBaseLayerCircuit::LogDemuxer(..) => "Log demuxer",
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(..) => "Keccak",
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(..) => "SHA256",
            ZkSyncBaseLayerCircuit::ECRecover(..) => "ECRecover",
            ZkSyncBaseLayerCircuit::RAMPermutation(..) => "RAM permutation",
            ZkSyncBaseLayerCircuit::StorageSorter(..) => "Storage sorter",
            ZkSyncBaseLayerCircuit::StorageApplication(..) => "Storage application",
            ZkSyncBaseLayerCircuit::EventsSorter(..) => "Events sorter",
            ZkSyncBaseLayerCircuit::L1MessagesSorter(..) => "L1 messages sorter",
            ZkSyncBaseLayerCircuit::L1MessagesHasher(..) => "L1 messages rehasher",
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::ECRecover(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => inner.size_hint(),
        }
    }

    fn synthesis_inner<P: PrimeFieldLikeVectorized<Base = F>>(
        inner: &ZkSyncUniformCircuitInstance<F, impl ZkSyncUniformSynthesisFunction<F>>,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        let geometry = inner.geometry_proxy();
        let (max_trace_len, num_vars) = inner.size_hint();
        let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig>::new(
            geometry,
            num_vars.unwrap(),
            max_trace_len.unwrap(),
        );
        let cs_builder = new_builder::<_, F>(builder_impl);
        let builder = inner.configure_builder_proxy(cs_builder);
        let mut cs = builder.build(());
        inner.add_tables_proxy(&mut cs);
        inner.clone().synthesize_proxy(&mut cs);
        cs.pad_and_shrink_using_hint(hint);
        cs.into_assembly()
    }

    pub fn synthesis<P: PrimeFieldLikeVectorized<Base = F>>(
        &self,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
                Self::synthesis_inner(inner, hint)
            }
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
                Self::synthesis_inner(inner, hint)
            }
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
                Self::synthesis_inner(inner, hint)
            }
            ZkSyncBaseLayerCircuit::ECRecover(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => Self::synthesis_inner(inner, hint),
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => Self::synthesis_inner(inner, hint),
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::ECRecover(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => inner.geometry_proxy(),
        }
    }

    pub fn debug_witness(&self) {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::ECRecover(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => {
                inner.debug_witness();
            }
        };

        ()
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match &self {
            ZkSyncBaseLayerCircuit::MainVM(..) => BaseLayerCircuitType::VM as u8,
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(..) => {
                BaseLayerCircuitType::DecommitmentsFilter as u8
            }
            ZkSyncBaseLayerCircuit::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
            ZkSyncBaseLayerCircuit::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(..) => {
                BaseLayerCircuitType::KeccakPrecompile as u8
            }
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(..) => {
                BaseLayerCircuitType::Sha256Precompile as u8
            }
            ZkSyncBaseLayerCircuit::ECRecover(..) => {
                BaseLayerCircuitType::EcrecoverPrecompile as u8
            }
            ZkSyncBaseLayerCircuit::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
            ZkSyncBaseLayerCircuit::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
            ZkSyncBaseLayerCircuit::StorageApplication(..) => {
                BaseLayerCircuitType::StorageApplicator as u8
            }
            ZkSyncBaseLayerCircuit::EventsSorter(..) => {
                BaseLayerCircuitType::EventsRevertsFilter as u8
            }
            ZkSyncBaseLayerCircuit::L1MessagesSorter(..) => {
                BaseLayerCircuitType::L1MessagesRevertsFilter as u8
            }
            ZkSyncBaseLayerCircuit::L1MessagesHasher(..) => {
                BaseLayerCircuitType::L1MessagesHasher as u8
            }
        }
    }

    // pub fn erase_witness(&self) {
    //     match &self {
    //         ZkSyncCircuit::Scheduler(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::LeafAggregation(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::NodeAggregation(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::MainVM(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::CodeDecommitter(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::LogDemuxer(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::KeccakRoundFunction(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::Sha256RoundFunction(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::ECRecover(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::RAMPermutation(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::StorageSorter(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::StorageApplication(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::EventsSorter(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::L1MessagesSorter(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::L1MessagesMerklier(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::InitialWritesPubdataHasher(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => {inner.erase_witness();},
    //         ZkSyncCircuit::L1MessagesPubdataHasher(inner) => {inner.erase_witness();},
    //     };
    // }
}

pub type ZkSyncBaseLayerCircuitInput<F> =
    ZkSyncBaseLayerStorage<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>;

use zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

pub type ZkSyncBaseLayerClosedFormInput<F> =
    ZkSyncBaseLayerStorage<ClosedFormInputCompactFormWitness<F>>;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::config::ProvingCSConfig;
use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;

pub type BaseProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
pub type ZkSyncBaseProof = Proof<GoldilocksField, BaseProofsTreeHasher, GoldilocksExt2>;

pub type ZkSyncBaseLayerProof = ZkSyncBaseLayerStorage<ZkSyncBaseProof>;

pub type ZkSyncBaseLayerFinalizationHint = ZkSyncBaseLayerStorage<FinalizationHintsForProver>;

use crate::boojum::cs::implementations::verifier::VerificationKey;
use crate::boojum::field::traits::field_like::PrimeFieldLikeVectorized;

pub type ZkSyncBaseVerificationKey = VerificationKey<GoldilocksField, BaseProofsTreeHasher>;

pub type ZkSyncBaseLayerVerificationKey = ZkSyncBaseLayerStorage<ZkSyncBaseVerificationKey>;
