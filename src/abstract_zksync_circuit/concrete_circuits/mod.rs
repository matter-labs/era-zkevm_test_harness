use crate::witness::oracle::VmWitnessOracle;
use boojum::cs::implementations::proof::Proof;
use boojum::field::FieldExtension;
use boojum::field::goldilocks::{GoldilocksField, GoldilocksExt2};
use zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use crate::Poseidon2Goldilocks;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use zkevm_circuits::tables::*;
use boojum::gadgets::tables::*;
use boojum::cs::gates::*;
use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;

use super::*;

pub const TARGET_CIRCUIT_TRACE_LENGTH: usize = 1 << 20;

// should follow in the same sequence as we will logically process sequences
pub mod vm_main;
pub mod sort_code_decommits;
pub mod code_decommitter;
pub mod log_demux;
pub mod keccak256_round_function;
pub mod sha256_round_function;
pub mod ecrecover;
pub mod ram_permutation;
pub mod storage_sort_dedup;
pub mod storage_apply;
pub mod events_sort_dedup;
// pub mod l1_messages_sort_dedup; // equal to one above
// pub mod l1_messages_merklize;
// pub mod l1_messages_hasher;

pub use self::vm_main::VmMainInstanceSynthesisFunction;
pub use self::sort_code_decommits::CodeDecommittmentsSorterSynthesisFunction;
pub use self::code_decommitter::CodeDecommitterInstanceSynthesisFunction;
pub use self::log_demux::LogDemuxInstanceSynthesisFunction;
pub use self::keccak256_round_function::Keccak256RoundFunctionInstanceSynthesisFunction;
pub use self::sha256_round_function::Sha256RoundFunctionInstanceSynthesisFunction;
pub use self::ecrecover::ECRecoverFunctionInstanceSynthesisFunction;
pub use self::ram_permutation::RAMPermutationInstanceSynthesisFunction;
pub use self::storage_sort_dedup::StorageSortAndDedupInstanceSynthesisFunction;
pub use self::storage_apply::StorageApplicationInstanceSynthesisFunction;
pub use self::events_sort_dedup::EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction;
// pub use self::l1_messages_merklize::MessagesMerklizerInstanceSynthesisFunction;
// pub use self::l1_messages_hasher::L1MessagesRehasherInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<F> for ZkSyncUniformCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<F, W, R> = ZkSyncUniformCircuitInstance<F, VmMainInstanceSynthesisFunction<F, W, R>>; 
pub type CodeDecommittsSorterCircuit<F, R> = ZkSyncUniformCircuitInstance<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterCircuit<F, R> = ZkSyncUniformCircuitInstance<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerCircuit<F, R> = ZkSyncUniformCircuitInstance<F, LogDemuxInstanceSynthesisFunction<F, R>>;
pub type Keccak256RoundFunctionCircuit<F, R> = ZkSyncUniformCircuitInstance<F, Keccak256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type Sha256RoundFunctionCircuit<F, R> = ZkSyncUniformCircuitInstance<F, Sha256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type ECRecoverFunctionCircuit<F, R> = ZkSyncUniformCircuitInstance<F, ECRecoverFunctionInstanceSynthesisFunction<F, R>>;
pub type RAMPermutationCircuit<F, R> = ZkSyncUniformCircuitInstance<F, RAMPermutationInstanceSynthesisFunction<F, R>>;
pub type StorageSorterCircuit<F, R> = ZkSyncUniformCircuitInstance<F, StorageSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type StorageApplicationCircuit<F, R> = ZkSyncUniformCircuitInstance<F, StorageApplicationInstanceSynthesisFunction<F, R>>;
pub type EventsSorterCircuit<F, R> = ZkSyncUniformCircuitInstance<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesSorterCircuit<F, R> = ZkSyncUniformCircuitInstance<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;

// pub type L1MessagesMerklizerCircuit<F> = ZkSyncUniformCircuitInstance<F, MessagesMerklizerInstanceSynthesisFunction>;
// pub type L1MessagesHasherCircuit<F> = ZkSyncUniformCircuitInstance<F, L1MessagesRehasherInstanceSynthesisFunction>;

pub type VMMainCircuitVerifierBuilder<F, W, R> = ZkSyncUniformCircuitVerifierBuilder<F, VmMainInstanceSynthesisFunction<F, W, R>>; 
pub type CodeDecommittsSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, LogDemuxInstanceSynthesisFunction<F, R>>;
pub type Keccak256RoundFunctionVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, Keccak256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type Sha256RoundFunctionVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, Sha256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type ECRecoverFunctionVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, ECRecoverFunctionInstanceSynthesisFunction<F, R>>;
pub type RAMPermutationVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, RAMPermutationInstanceSynthesisFunction<F, R>>;
pub type StorageSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, StorageSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type StorageApplicationVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, StorageApplicationInstanceSynthesisFunction<F, R>>;
pub type EventsSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug)]
#[serde(bound = "")]
pub enum ZkSyncProofBaseLayerStorage<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned> {
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
}

impl<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned> ZkSyncProofBaseLayerStorage<T> {
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncProofBaseLayerStorage::MainVM(..) => "Main VM",
            ZkSyncProofBaseLayerStorage::CodeDecommittmentsSorter(..) => "Decommitts sorter",
            ZkSyncProofBaseLayerStorage::CodeDecommitter(..) => "Code decommitter",
            ZkSyncProofBaseLayerStorage::LogDemuxer(..) => "Log demuxer",
            ZkSyncProofBaseLayerStorage::KeccakRoundFunction(..) => "Keccak",
            ZkSyncProofBaseLayerStorage::Sha256RoundFunction(..) => "SHA256",
            ZkSyncProofBaseLayerStorage::ECRecover(..) => "ECRecover",
            ZkSyncProofBaseLayerStorage::RAMPermutation(..) => "RAM permutation",
            ZkSyncProofBaseLayerStorage::StorageSorter(..) => "Storage sorter",
            ZkSyncProofBaseLayerStorage::StorageApplication(..) => "Storage application",
            ZkSyncProofBaseLayerStorage::EventsSorter(..) => "Events sorter",
            ZkSyncProofBaseLayerStorage::L1MessagesSorter(..) => "L1 messages sorter",
            // ZkSyncProofBaseLayerStorage::L1MessagesMerklier(..) => "L1 messages merklizer",
            // ZkSyncProofBaseLayerStorage::L1MessagesPubdataHasher(..) => "L1 messages rehasher",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match &self {
            ZkSyncProofBaseLayerStorage::MainVM(..) => BaseLayerCircuitType::VM as u8,
            ZkSyncProofBaseLayerStorage::CodeDecommittmentsSorter(..) => BaseLayerCircuitType::DecommitmentsFilter as u8,
            ZkSyncProofBaseLayerStorage::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
            ZkSyncProofBaseLayerStorage::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
            ZkSyncProofBaseLayerStorage::KeccakRoundFunction(..) => BaseLayerCircuitType::KeccakPrecompile as u8,
            ZkSyncProofBaseLayerStorage::Sha256RoundFunction(..) => BaseLayerCircuitType::Sha256Precompile as u8,
            ZkSyncProofBaseLayerStorage::ECRecover(..) => BaseLayerCircuitType::EcrecoverPrecompile as u8,
            ZkSyncProofBaseLayerStorage::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
            ZkSyncProofBaseLayerStorage::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
            ZkSyncProofBaseLayerStorage::StorageApplication(..) => BaseLayerCircuitType::StorageApplicator as u8,
            ZkSyncProofBaseLayerStorage::EventsSorter(..) => BaseLayerCircuitType::EventsRevertsFilter as u8,
            ZkSyncProofBaseLayerStorage::L1MessagesSorter(..) => BaseLayerCircuitType::L1MessagesRevertsFilter as u8,
            // ZkSyncProofBaseLayerStorage::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
            // ZkSyncProofBaseLayerStorage::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            ZkSyncProofBaseLayerStorage::MainVM(inner) => inner,
            ZkSyncProofBaseLayerStorage::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncProofBaseLayerStorage::CodeDecommitter(inner) => inner,
            ZkSyncProofBaseLayerStorage::LogDemuxer(inner) => inner,
            ZkSyncProofBaseLayerStorage::KeccakRoundFunction(inner) => inner,
            ZkSyncProofBaseLayerStorage::Sha256RoundFunction(inner) => inner,
            ZkSyncProofBaseLayerStorage::ECRecover(inner) => inner,
            ZkSyncProofBaseLayerStorage::RAMPermutation(inner) => inner,
            ZkSyncProofBaseLayerStorage::StorageSorter(inner) => inner,
            ZkSyncProofBaseLayerStorage::StorageApplication(inner) => inner,
            ZkSyncProofBaseLayerStorage::EventsSorter(inner) => inner,
            ZkSyncProofBaseLayerStorage::L1MessagesSorter(inner) => inner,
            // ZkSyncProofBaseLayerStorage::L1MessagesMerklier(inner) => inner,
            // ZkSyncProofBaseLayerStorage::L1MessagesPubdataHasher(inner) => inner,
        }
    }
}

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncBaseLayerCircuit<
    F: SmallField, 
    W: WitnessOracle<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>  
    where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
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

    // L1MessagesMerklier(L1MessagesMerklizerCircuit<F>),
    // L1MessagesPubdataHasher(L1MessagesHasherCircuit<F>),
}

impl<
    F: SmallField, 
    W: WitnessOracle<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncBaseLayerCircuit<F, W, R>  
    where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
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
            // ZkSyncBaseLayerCircuit::L1MessagesMerklier(..) => "L1 messages merklizer",
            // ZkSyncBaseLayerCircuit::L1MessagesPubdataHasher(..) => "L1 messages rehasher",
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::ECRecover(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {inner.size_hint()},
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {inner.size_hint()},
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::ECRecover(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {inner.geometry()},
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {inner.geometry()},
        }
    }

    // pub fn debug_witness(&self) {
    //     match &self {
    //         ZkSyncCircuit::Scheduler(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::LeafAggregation(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::NodeAggregation(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::MainVM(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::CodeDecommitter(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::LogDemuxer(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::KeccakRoundFunction(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::Sha256RoundFunction(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::ECRecover(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::RAMPermutation(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::StorageSorter(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::StorageApplication(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::EventsSorter(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::L1MessagesSorter(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::L1MessagesMerklier(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::InitialWritesPubdataHasher(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => {inner.debug_witness();},
    //         ZkSyncCircuit::L1MessagesPubdataHasher(inner) => {inner.debug_witness();},
    //     };

    //     ()
    // }

    pub fn numeric_circuit_type(&self) -> u8 {
        use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match &self {
            ZkSyncBaseLayerCircuit::MainVM(..) => BaseLayerCircuitType::VM as u8,
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(..) => BaseLayerCircuitType::DecommitmentsFilter as u8,
            ZkSyncBaseLayerCircuit::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
            ZkSyncBaseLayerCircuit::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(..) => BaseLayerCircuitType::KeccakPrecompile as u8,
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(..) => BaseLayerCircuitType::Sha256Precompile as u8,
            ZkSyncBaseLayerCircuit::ECRecover(..) => BaseLayerCircuitType::EcrecoverPrecompile as u8,
            ZkSyncBaseLayerCircuit::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
            ZkSyncBaseLayerCircuit::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
            ZkSyncBaseLayerCircuit::StorageApplication(..) => BaseLayerCircuitType::StorageApplicator as u8,
            ZkSyncBaseLayerCircuit::EventsSorter(..) => BaseLayerCircuitType::EventsRevertsFilter as u8,
            ZkSyncBaseLayerCircuit::L1MessagesSorter(..) => BaseLayerCircuitType::L1MessagesRevertsFilter as u8,
            // ZkSyncBaseLayerCircuit::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
            // ZkSyncBaseLayerCircuit::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8
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

pub type ZkSyncBaseLayerCircuitInput<F> = ZkSyncProofBaseLayerStorage<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>;

// #[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
// #[derivative(Clone(bound = ""), Copy, Debug)]
// #[serde(bound = "")]
// pub enum ZkSyncBaseLayerCircuitInput<
//     F: SmallField, 
// >  {
//     MainVM([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     CodeDecommittmentsSorter([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     CodeDecommitter([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     LogDemuxer([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     KeccakRoundFunction([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     Sha256RoundFunction([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     ECRecover([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     RAMPermutation([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     StorageSorter([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     StorageApplication([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     EventsSorter([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     L1MessagesSorter([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),

//     // L1MessagesMerklier([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
//     // L1MessagesPubdataHasher([F; INPUT_OUTPUT_COMMITMENT_LENGTH]),
// }

// impl<
//     F: SmallField, 
// > ZkSyncBaseLayerCircuitInput<F>
// {
//     pub fn short_description(&self) -> &'static str {
//         match &self {
//             ZkSyncBaseLayerCircuitInput::MainVM(..) => "Main VM",
//             ZkSyncBaseLayerCircuitInput::CodeDecommittmentsSorter(..) => "Decommitts sorter",
//             ZkSyncBaseLayerCircuitInput::CodeDecommitter(..) => "Code decommitter",
//             ZkSyncBaseLayerCircuitInput::LogDemuxer(..) => "Log demuxer",
//             ZkSyncBaseLayerCircuitInput::KeccakRoundFunction(..) => "Keccak",
//             ZkSyncBaseLayerCircuitInput::Sha256RoundFunction(..) => "SHA256",
//             ZkSyncBaseLayerCircuitInput::ECRecover(..) => "ECRecover",
//             ZkSyncBaseLayerCircuitInput::RAMPermutation(..) => "RAM permutation",
//             ZkSyncBaseLayerCircuitInput::StorageSorter(..) => "Storage sorter",
//             ZkSyncBaseLayerCircuitInput::StorageApplication(..) => "Storage application",
//             ZkSyncBaseLayerCircuitInput::EventsSorter(..) => "Events sorter",
//             ZkSyncBaseLayerCircuitInput::L1MessagesSorter(..) => "L1 messages sorter",
//             // ZkSyncBaseLayerCircuitInput::L1MessagesMerklier(..) => "L1 messages merklizer",
//             // ZkSyncBaseLayerCircuitInput::L1MessagesPubdataHasher(..) => "L1 messages rehasher",
//         }
//     }

//     pub fn numeric_circuit_type(&self) -> u8 {
//         use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

//         match &self {
//             ZkSyncBaseLayerCircuitInput::MainVM(..) => BaseLayerCircuitType::VM as u8,
//             ZkSyncBaseLayerCircuitInput::CodeDecommittmentsSorter(..) => BaseLayerCircuitType::DecommitmentsFilter as u8,
//             ZkSyncBaseLayerCircuitInput::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
//             ZkSyncBaseLayerCircuitInput::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
//             ZkSyncBaseLayerCircuitInput::KeccakRoundFunction(..) => BaseLayerCircuitType::KeccakPrecompile as u8,
//             ZkSyncBaseLayerCircuitInput::Sha256RoundFunction(..) => BaseLayerCircuitType::Sha256Precompile as u8,
//             ZkSyncBaseLayerCircuitInput::ECRecover(..) => BaseLayerCircuitType::EcrecoverPrecompile as u8,
//             ZkSyncBaseLayerCircuitInput::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
//             ZkSyncBaseLayerCircuitInput::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
//             ZkSyncBaseLayerCircuitInput::StorageApplication(..) => BaseLayerCircuitType::StorageApplicator as u8,
//             ZkSyncBaseLayerCircuitInput::EventsSorter(..) => BaseLayerCircuitType::EventsRevertsFilter as u8,
//             ZkSyncBaseLayerCircuitInput::L1MessagesSorter(..) => BaseLayerCircuitType::L1MessagesRevertsFilter as u8,
//             // ZkSyncBaseLayerCircuitInput::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
//             // ZkSyncBaseLayerCircuitInput::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8
//         }
//     }

//     pub fn into_inner(self) -> [F; INPUT_OUTPUT_COMMITMENT_LENGTH] {
//         match self {
//             ZkSyncBaseLayerCircuitInput::MainVM(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::CodeDecommittmentsSorter(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::CodeDecommitter(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::LogDemuxer(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::KeccakRoundFunction(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::Sha256RoundFunction(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::ECRecover(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::RAMPermutation(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::StorageSorter(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::StorageApplication(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::EventsSorter(inner) => inner,
//             ZkSyncBaseLayerCircuitInput::L1MessagesSorter(inner) => inner,
//             // ZkSyncBaseLayerCircuitInput::L1MessagesMerklier(inner) => inner,
//             // ZkSyncBaseLayerCircuitInput::L1MessagesPubdataHasher(inner) => inner,
//         }
//     }
// }

use zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

pub type ZkSyncBaseLayerClosedFormInput<F> = ZkSyncProofBaseLayerStorage<ClosedFormInputCompactFormWitness<F>>;

// #[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
// #[derivative(Clone(bound = ""), Debug)]
// #[serde(bound = "")]
// pub enum ZkSyncBaseLayerClosedFormInput<
//     F: SmallField, 
// >  {
//     MainVM(ClosedFormInputCompactFormWitness<F>),
//     CodeDecommittmentsSorter(ClosedFormInputCompactFormWitness<F>),
//     CodeDecommitter(ClosedFormInputCompactFormWitness<F>),
//     LogDemuxer(ClosedFormInputCompactFormWitness<F>),
//     KeccakRoundFunction(ClosedFormInputCompactFormWitness<F>),
//     Sha256RoundFunction(ClosedFormInputCompactFormWitness<F>),
//     ECRecover(ClosedFormInputCompactFormWitness<F>),
//     RAMPermutation(ClosedFormInputCompactFormWitness<F>),
//     StorageSorter(ClosedFormInputCompactFormWitness<F>),
//     StorageApplication(ClosedFormInputCompactFormWitness<F>),
//     EventsSorter(ClosedFormInputCompactFormWitness<F>),
//     L1MessagesSorter(ClosedFormInputCompactFormWitness<F>),

//     // L1MessagesMerklier(ClosedFormInputCompactFormWitness<F>),
//     // L1MessagesPubdataHasher(ClosedFormInputCompactFormWitness<F>),
// }

// impl<
//     F: SmallField, 
// > ZkSyncBaseLayerClosedFormInput<F>
// {
//     pub fn short_description(&self) -> &'static str {
//         match &self {
//             ZkSyncBaseLayerClosedFormInput::MainVM(..) => "Main VM",
//             ZkSyncBaseLayerClosedFormInput::CodeDecommittmentsSorter(..) => "Decommitts sorter",
//             ZkSyncBaseLayerClosedFormInput::CodeDecommitter(..) => "Code decommitter",
//             ZkSyncBaseLayerClosedFormInput::LogDemuxer(..) => "Log demuxer",
//             ZkSyncBaseLayerClosedFormInput::KeccakRoundFunction(..) => "Keccak",
//             ZkSyncBaseLayerClosedFormInput::Sha256RoundFunction(..) => "SHA256",
//             ZkSyncBaseLayerClosedFormInput::ECRecover(..) => "ECRecover",
//             ZkSyncBaseLayerClosedFormInput::RAMPermutation(..) => "RAM permutation",
//             ZkSyncBaseLayerClosedFormInput::StorageSorter(..) => "Storage sorter",
//             ZkSyncBaseLayerClosedFormInput::StorageApplication(..) => "Storage application",
//             ZkSyncBaseLayerClosedFormInput::EventsSorter(..) => "Events sorter",
//             ZkSyncBaseLayerClosedFormInput::L1MessagesSorter(..) => "L1 messages sorter",
//             // ZkSyncBaseLayerClosedFormInput::L1MessagesMerklier(..) => "L1 messages merklizer",
//             // ZkSyncBaseLayerClosedFormInput::L1MessagesPubdataHasher(..) => "L1 messages rehasher",
//         }
//     }

//     pub fn numeric_circuit_type(&self) -> u8 {
//         use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

//         match &self {
//             ZkSyncBaseLayerClosedFormInput::MainVM(..) => BaseLayerCircuitType::VM as u8,
//             ZkSyncBaseLayerClosedFormInput::CodeDecommittmentsSorter(..) => BaseLayerCircuitType::DecommitmentsFilter as u8,
//             ZkSyncBaseLayerClosedFormInput::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
//             ZkSyncBaseLayerClosedFormInput::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
//             ZkSyncBaseLayerClosedFormInput::KeccakRoundFunction(..) => BaseLayerCircuitType::KeccakPrecompile as u8,
//             ZkSyncBaseLayerClosedFormInput::Sha256RoundFunction(..) => BaseLayerCircuitType::Sha256Precompile as u8,
//             ZkSyncBaseLayerClosedFormInput::ECRecover(..) => BaseLayerCircuitType::EcrecoverPrecompile as u8,
//             ZkSyncBaseLayerClosedFormInput::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
//             ZkSyncBaseLayerClosedFormInput::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
//             ZkSyncBaseLayerClosedFormInput::StorageApplication(..) => BaseLayerCircuitType::StorageApplicator as u8,
//             ZkSyncBaseLayerClosedFormInput::EventsSorter(..) => BaseLayerCircuitType::EventsRevertsFilter as u8,
//             ZkSyncBaseLayerClosedFormInput::L1MessagesSorter(..) => BaseLayerCircuitType::L1MessagesRevertsFilter as u8,
//             // ZkSyncBaseLayerClosedFormInput::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
//             // ZkSyncBaseLayerClosedFormInput::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8
//         }
//     }

//     pub fn into_inner(self) -> ClosedFormInputCompactFormWitness<F> {
//         match self {
//             ZkSyncBaseLayerClosedFormInput::MainVM(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::CodeDecommittmentsSorter(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::CodeDecommitter(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::LogDemuxer(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::KeccakRoundFunction(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::Sha256RoundFunction(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::ECRecover(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::RAMPermutation(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::StorageSorter(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::StorageApplication(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::EventsSorter(inner) => inner,
//             ZkSyncBaseLayerClosedFormInput::L1MessagesSorter(inner) => inner,
//             // ZkSyncBaseLayerClosedFormInput::L1MessagesMerklier(inner) => inner,
//             // ZkSyncBaseLayerClosedFormInput::L1MessagesPubdataHasher(inner) => inner,
//         }
//     }
// }

use boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;

pub type BaseProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;
pub type ZkSyncBaseProof = Proof<GoldilocksField, BaseProofsTreeHasher, GoldilocksExt2>;
use crate::ZkSyncDefaultRoundFunction;

pub type ZkSyncBaseLayerProof = ZkSyncProofBaseLayerStorage<ZkSyncBaseProof>;

// /// Wrapper around proof for easier indexing
// #[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
// #[derivative(Clone(bound = ""))]
// #[serde(bound = "")]
// pub enum ZkSyncProofBaseLayerProof {
//     MainVM(ZkSyncBaseProof),
//     CodeDecommittmentsSorter(ZkSyncBaseProof),
//     CodeDecommitter(ZkSyncBaseProof),
//     LogDemuxer(ZkSyncBaseProof),
//     KeccakRoundFunction(ZkSyncBaseProof),
//     Sha256RoundFunction(ZkSyncBaseProof),
//     ECRecover(ZkSyncBaseProof),
//     RAMPermutation(ZkSyncBaseProof),
//     StorageSorter(ZkSyncBaseProof),
//     StorageApplication(ZkSyncBaseProof),
//     EventsSorter(ZkSyncBaseProof),
//     L1MessagesSorter(ZkSyncBaseProof),
// }

// impl ZkSyncProofBaseLayerProof {
//     pub fn short_description(&self) -> &'static str {
//         match &self {
//             ZkSyncProofBaseLayerProof::MainVM(..) => "Main VM",
//             ZkSyncProofBaseLayerProof::CodeDecommittmentsSorter(..) => "Decommitts sorter",
//             ZkSyncProofBaseLayerProof::CodeDecommitter(..) => "Code decommitter",
//             ZkSyncProofBaseLayerProof::LogDemuxer(..) => "Log demuxer",
//             ZkSyncProofBaseLayerProof::KeccakRoundFunction(..) => "Keccak",
//             ZkSyncProofBaseLayerProof::Sha256RoundFunction(..) => "SHA256",
//             ZkSyncProofBaseLayerProof::ECRecover(..) => "ECRecover",
//             ZkSyncProofBaseLayerProof::RAMPermutation(..) => "RAM permutation",
//             ZkSyncProofBaseLayerProof::StorageSorter(..) => "Storage sorter",
//             ZkSyncProofBaseLayerProof::StorageApplication(..) => "Storage application",
//             ZkSyncProofBaseLayerProof::EventsSorter(..) => "Events sorter",
//             ZkSyncProofBaseLayerProof::L1MessagesSorter(..) => "L1 messages sorter",
//             // ZkSyncProofBaseLayerProof::L1MessagesMerklier(..) => "L1 messages merklizer",
//             // ZkSyncProofBaseLayerProof::L1MessagesPubdataHasher(..) => "L1 messages rehasher",
//         }
//     }

//     pub fn numeric_circuit_type(&self) -> u8 {
//         use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

//         match &self {
//             ZkSyncProofBaseLayerProof::MainVM(..) => BaseLayerCircuitType::VM as u8,
//             ZkSyncProofBaseLayerProof::CodeDecommittmentsSorter(..) => BaseLayerCircuitType::DecommitmentsFilter as u8,
//             ZkSyncProofBaseLayerProof::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
//             ZkSyncProofBaseLayerProof::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
//             ZkSyncProofBaseLayerProof::KeccakRoundFunction(..) => BaseLayerCircuitType::KeccakPrecompile as u8,
//             ZkSyncProofBaseLayerProof::Sha256RoundFunction(..) => BaseLayerCircuitType::Sha256Precompile as u8,
//             ZkSyncProofBaseLayerProof::ECRecover(..) => BaseLayerCircuitType::EcrecoverPrecompile as u8,
//             ZkSyncProofBaseLayerProof::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
//             ZkSyncProofBaseLayerProof::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
//             ZkSyncProofBaseLayerProof::StorageApplication(..) => BaseLayerCircuitType::StorageApplicator as u8,
//             ZkSyncProofBaseLayerProof::EventsSorter(..) => BaseLayerCircuitType::EventsRevertsFilter as u8,
//             ZkSyncProofBaseLayerProof::L1MessagesSorter(..) => BaseLayerCircuitType::L1MessagesRevertsFilter as u8,
//             // ZkSyncProofBaseLayerProof::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
//             // ZkSyncProofBaseLayerProof::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8
//         }
//     }

//     pub fn into_inner(self) -> ZkSyncBaseProof {
//         match self {
//             ZkSyncProofBaseLayerProof::MainVM(inner) => inner,
//             ZkSyncProofBaseLayerProof::CodeDecommittmentsSorter(inner) => inner,
//             ZkSyncProofBaseLayerProof::CodeDecommitter(inner) => inner,
//             ZkSyncProofBaseLayerProof::LogDemuxer(inner) => inner,
//             ZkSyncProofBaseLayerProof::KeccakRoundFunction(inner) => inner,
//             ZkSyncProofBaseLayerProof::Sha256RoundFunction(inner) => inner,
//             ZkSyncProofBaseLayerProof::ECRecover(inner) => inner,
//             ZkSyncProofBaseLayerProof::RAMPermutation(inner) => inner,
//             ZkSyncProofBaseLayerProof::StorageSorter(inner) => inner,
//             ZkSyncProofBaseLayerProof::StorageApplication(inner) => inner,
//             ZkSyncProofBaseLayerProof::EventsSorter(inner) => inner,
//             ZkSyncProofBaseLayerProof::L1MessagesSorter(inner) => inner,
//             // ZkSyncProofBaseLayerProof::L1MessagesMerklier(inner) => inner,
//             // ZkSyncProofBaseLayerProof::L1MessagesPubdataHasher(inner) => inner,
//         }
//     }
    
//     // pub fn from_proof_and_numeric_type(numeric_type: u8, proof: Proof<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>) -> Self {
//     //     use sync_vm::scheduler::CircuitType;

//     //     match numeric_type {
//     //         a if a == CircuitType::Scheduler as u8 => ZkSyncProof::Scheduler(proof),
//     //         a if a == CircuitType::Leaf as u8 => ZkSyncProof::LeafAggregation(proof),
//     //         a if a == CircuitType::IntermidiateNode as u8 => ZkSyncProof::NodeAggregation(proof),
//     //         a if a == CircuitType::VM as u8 => ZkSyncProof::MainVM(proof),
//     //         a if a == CircuitType::DecommitmentsFilter as u8 => ZkSyncProof::CodeDecommittmentsSorter(proof),
//     //         a if a == CircuitType::Decommiter as u8 => ZkSyncProof::CodeDecommitter(proof),
//     //         a if a == CircuitType::LogDemultiplexer as u8 => ZkSyncProof::LogDemuxer(proof),
//     //         a if a == CircuitType::KeccakPrecompile as u8 => ZkSyncProof::KeccakRoundFunction(proof),
//     //         a if a == CircuitType::Sha256Precompile as u8 => ZkSyncProof::Sha256RoundFunction(proof),
//     //         a if a == CircuitType::EcrecoverPrecompile as u8 => ZkSyncProof::ECRecover(proof),
//     //         a if a == CircuitType::RamValidation as u8 => ZkSyncProof::RAMPermutation(proof),
//     //         a if a == CircuitType::StorageFilter as u8 => ZkSyncProof::StorageSorter(proof),
//     //         a if a == CircuitType::StorageApplicator as u8 => ZkSyncProof::StorageApplication(proof),
//     //         a if a == CircuitType::EventsRevertsFilter as u8 => ZkSyncProof::EventsSorter(proof),
//     //         a if a == CircuitType::L1MessagesRevertsFilter as u8 => ZkSyncProof::L1MessagesSorter(proof),
//     //         a if a == CircuitType::L1MessagesMerkelization as u8 => ZkSyncProof::L1MessagesMerklier(proof),
//     //         a if a == CircuitType::L1MessagesHasher as u8 => ZkSyncProof::L1MessagesPubdataHasher(proof),
//     //         a if a == CircuitType::StorageFreshWritesHasher as u8 => ZkSyncProof::InitialWritesPubdataHasher(proof),
//     //         a if a == CircuitType::StorageRepeatedWritesHasher as u8 => ZkSyncProof::RepeatedWritesPubdataHasher(proof),
//     //         a @ _ => panic!("unknown numeric type {}", a)
//     //     }
//     // }
// }

use boojum::cs::implementations::verifier::VerificationKey;
pub type ZkSyncBaseVerificationKey = VerificationKey<GoldilocksField, BaseProofsTreeHasher>;

pub type ZkSyncBaseLayerVerificationKey = ZkSyncProofBaseLayerStorage<ZkSyncBaseVerificationKey>;

// impl ZkSyncVerificationKey<Bn256> {
//     pub fn verify_proof(&self, proof: &ZkSyncProof<Bn256>) -> bool {
//         assert_eq!(self.numeric_circuit_type(), proof.numeric_circuit_type(), "mismatching IDs, VK is for {}, proof is for {}", self.numeric_circuit_type(), proof.numeric_circuit_type());
//         match &self {
//             a @ ZkSyncVerificationKey::Scheduler(..) => {
//                 // use Keccak transcript
//                 use crate::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;

//                 let vk = a.as_verification_key();
//                 let proof = proof.as_proof();
//                 let is_valid = crate::bellman::plonk::better_better_cs::verifier::verify::<
//                     Bn256, 
//                     _, 
//                     RollingKeccakTranscript<sync_vm::testing::Fr>
//                 >(
//                     vk, 
//                     proof, 
//                     None,
//                 ).expect("must try to verify a proof");

//                 is_valid
//             },
//             a @ ZkSyncVerificationKey::LeafAggregation(..) | 
//             a @ ZkSyncVerificationKey::NodeAggregation(..) |
//             a @ ZkSyncVerificationKey::MainVM(..) |
//             a @ ZkSyncVerificationKey::CodeDecommittmentsSorter(..) |
//             a @ ZkSyncVerificationKey::CodeDecommitter(..) |
//             a @ ZkSyncVerificationKey::LogDemuxer(..) |
//             a @ ZkSyncVerificationKey::KeccakRoundFunction(..) |
//             a @ ZkSyncVerificationKey::Sha256RoundFunction(..) |
//             a @ ZkSyncVerificationKey::ECRecover(..) |
//             a @ ZkSyncVerificationKey::RAMPermutation(..) |
//             a @ ZkSyncVerificationKey::StorageSorter(..) |
//             a @ ZkSyncVerificationKey::StorageApplication(..) |
//             a @ ZkSyncVerificationKey::EventsSorter(..) |
//             a @ ZkSyncVerificationKey::L1MessagesSorter(..) |
//             a @ ZkSyncVerificationKey::L1MessagesPubdataHasher(..) |
//             a @ ZkSyncVerificationKey::L1MessagesMerklier(..) |
//             a @ ZkSyncVerificationKey::InitialWritesPubdataHasher(..) |
//             a @ ZkSyncVerificationKey::RepeatedWritesPubdataHasher(..) => {
//                 // Use algebraic transcript
//                 use sync_vm::recursion::RescueTranscriptForRecursion;
//                 use sync_vm::circuit_structures::utils::bn254_rescue_params;
//                 use sync_vm::recursion::get_prefered_rns_params;

//                 let sponge_params = bn254_rescue_params();
//                 let rns_params = get_prefered_rns_params();
//                 let transcript_params = (&sponge_params, &rns_params);

//                 let vk = a.as_verification_key();
//                 let proof = proof.as_proof();
//                 let is_valid = crate::bellman::plonk::better_better_cs::verifier::verify::<
//                     Bn256, 
//                     _, 
//                     RescueTranscriptForRecursion<'_>
//                 >(
//                     vk, 
//                     proof, 
//                     Some(transcript_params)
//                 ).expect("must try to verify a proof");

//                 is_valid
//             }
//         }
//     }
// }

pub fn dyn_verifier_builder_for_circuit_type<
F: SmallField, 
EXT: FieldExtension<2, BaseField = F>,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>(circuit_type: u8) -> Box<dyn boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>> 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

    match circuit_type {
        i if i == BaseLayerCircuitType::VM as u8 => {
            VMMainCircuitVerifierBuilder::<F, VmWitnessOracle<F>, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_verifier_builder()
        // },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_verifier_builder()
        // },
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}

pub fn dyn_recursive_verifier_builder_for_circuit_type<
F: SmallField, 
EXT: FieldExtension<2, BaseField = F>,
CS: ConstraintSystem<F> + 'static,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>(circuit_type: u8) -> Box<dyn boojum::cs::traits::circuit::ErasedBuilderForRecursiveVerifier<F, EXT, CS>> 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

    match circuit_type {
        i if i == BaseLayerCircuitType::VM as u8 => {
            VMMainCircuitVerifierBuilder::<F, VmWitnessOracle<F>, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_recursive_verifier_builder()
        // },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_recursive_verifier_builder()
        // },
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}