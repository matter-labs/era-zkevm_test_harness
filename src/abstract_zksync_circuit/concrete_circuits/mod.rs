use crate::witness::oracle::VmWitnessOracle;
use boojum::cs::implementations::proof::Proof;
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
// pub mod storage_initial_writes_pubdata_hasher;
// pub mod storage_repeated_writes_pubdata_hasher;
// pub mod l1_messages_hasher;

// pub mod leaf_aggregation;
// pub mod node_aggregation;

// pub mod scheduler;



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
// pub use self::storage_initial_writes_pubdata_hasher::StorageInitialWritesRehasherInstanceSynthesisFunction;
// pub use self::storage_repeated_writes_pubdata_hasher::StorageRepeatedWritesRehasherInstanceSynthesisFunction;
// pub use self::l1_messages_hasher::L1MessagesRehasherInstanceSynthesisFunction;

// pub use self::leaf_aggregation::LeafAggregationInstanceSynthesisFunction;
// pub use self::node_aggregation::NodeAggregationInstanceSynthesisFunction;

// pub use self::scheduler::SchedulerInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<F> for ZkSyncUniformCircuitCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<F, W, R> = ZkSyncUniformCircuitCircuitInstance<F, VmMainInstanceSynthesisFunction<F, W, R>>; 
pub type CodeDecommittsSorterCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, LogDemuxInstanceSynthesisFunction<F, R>>;
pub type Keccak256RoundFunctionCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, Keccak256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type Sha256RoundFunctionCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, Sha256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type ECRecoverFunctionCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, ECRecoverFunctionInstanceSynthesisFunction<F, R>>;
pub type RAMPermutationCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, RAMPermutationInstanceSynthesisFunction<F, R>>;
pub type StorageSorterCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, StorageSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type StorageApplicationCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, StorageApplicationInstanceSynthesisFunction<F, R>>;
pub type EventsSorterCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesSorterCircuit<F, R> = ZkSyncUniformCircuitCircuitInstance<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;

// pub type L1MessagesMerklizerCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, MessagesMerklizerInstanceSynthesisFunction>;
// pub type InitialStorageWritesPubdataHasherCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, StorageInitialWritesRehasherInstanceSynthesisFunction>;
// pub type RepeatedStorageWritesPubdataHasherCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, StorageRepeatedWritesRehasherInstanceSynthesisFunction>;
// pub type L1MessagesHasherCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, L1MessagesRehasherInstanceSynthesisFunction>;

// pub type LeafAggregationCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, LeafAggregationInstanceSynthesisFunction>;
// pub type NodeAggregationCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, NodeAggregationInstanceSynthesisFunction>;

// pub type SchedulerCircuit<F> = ZkSyncUniformCircuitCircuitInstance<F, SchedulerInstanceSynthesisFunction>;

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
    // Scheduler(SchedulerCircuit<F>),
    // NodeAggregation(NodeAggregationCircuit<F>),
    // LeafAggregation(LeafAggregationCircuit<F>),
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
    // InitialWritesPubdataHasher(InitialStorageWritesPubdataHasherCircuit<F>),
    // RepeatedWritesPubdataHasher(RepeatedStorageWritesPubdataHasherCircuit<F>),
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
            // ZkSyncBaseLayerCircuit::Scheduler(..) => "Scheduler",
            // ZkSyncBaseLayerCircuit::LeafAggregation(..) => "Leaf aggregation",
            // ZkSyncBaseLayerCircuit::NodeAggregation(..) => "Node aggregation",
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
            // ZkSyncBaseLayerCircuit::InitialWritesPubdataHasher(..) => "Initial writes pubdata rehasher",
            // ZkSyncBaseLayerCircuit::RepeatedWritesPubdataHasher(..) => "Repeated writes pubdata rehasher",
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

    // pub fn numeric_circuit_type(&self) -> u8 {
    //     use sync_vm::scheduler::CircuitType;

    //     match &self {
    //         ZkSyncCircuit::Scheduler(..) => CircuitType::Scheduler as u8,
    //         ZkSyncCircuit::LeafAggregation(..) => CircuitType::Leaf as u8,
    //         ZkSyncCircuit::NodeAggregation(..) => CircuitType::IntermidiateNode as u8,
    //         ZkSyncCircuit::MainVM(..) => CircuitType::VM as u8,
    //         ZkSyncCircuit::CodeDecommittmentsSorter(..) => CircuitType::DecommitmentsFilter as u8,
    //         ZkSyncCircuit::CodeDecommitter(..) => CircuitType::Decommiter as u8,
    //         ZkSyncCircuit::LogDemuxer(..) => CircuitType::LogDemultiplexer as u8,
    //         ZkSyncCircuit::KeccakRoundFunction(..) => CircuitType::KeccakPrecompile as u8,
    //         ZkSyncCircuit::Sha256RoundFunction(..) => CircuitType::Sha256Precompile as u8,
    //         ZkSyncCircuit::ECRecover(..) => CircuitType::EcrecoverPrecompile as u8,
    //         ZkSyncCircuit::RAMPermutation(..) => CircuitType::RamValidation as u8,
    //         ZkSyncCircuit::StorageSorter(..) => CircuitType::StorageFilter as u8,
    //         ZkSyncCircuit::StorageApplication(..) => CircuitType::StorageApplicator as u8,
    //         ZkSyncCircuit::EventsSorter(..) => CircuitType::EventsRevertsFilter as u8,
    //         ZkSyncCircuit::L1MessagesSorter(..) => CircuitType::L1MessagesRevertsFilter as u8,
    //         ZkSyncCircuit::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
    //         ZkSyncCircuit::InitialWritesPubdataHasher(..) => CircuitType::StorageFreshWritesHasher as u8,
    //         ZkSyncCircuit::RepeatedWritesPubdataHasher(..) => CircuitType::StorageRepeatedWritesHasher as u8,
    //         ZkSyncCircuit::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8
    //     }
    // }

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

use boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;

pub type BaseProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;
pub type ZkSyncBaseProof = Proof<GoldilocksField, BaseProofsTreeHasher, GoldilocksExt2>;
use crate::ZkSyncDefaultRoundFunction;

/// Wrapper around proof for easier indexing
#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub struct ZkSyncProofBaseLayerProof {
    pub proof: ZkSyncBaseProof,
    pub over_circuit: ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, ZkSyncDefaultRoundFunction>,
}

impl ZkSyncProofBaseLayerProof {

    // pub fn numeric_circuit_type(&self) -> u8 {
    //     use sync_vm::scheduler::CircuitType;

    //     match &self {
    //         ZkSyncProof::Scheduler(..) => CircuitType::Scheduler as u8,
    //         ZkSyncProof::LeafAggregation(..) => CircuitType::Leaf as u8,
    //         ZkSyncProof::NodeAggregation(..) => CircuitType::IntermidiateNode as u8,
    //         ZkSyncProof::MainVM(..) => CircuitType::VM as u8,
    //         ZkSyncProof::CodeDecommittmentsSorter(..) => CircuitType::DecommitmentsFilter as u8,
    //         ZkSyncProof::CodeDecommitter(..) => CircuitType::Decommiter as u8,
    //         ZkSyncProof::LogDemuxer(..) => CircuitType::LogDemultiplexer as u8,
    //         ZkSyncProof::KeccakRoundFunction(..) => CircuitType::KeccakPrecompile as u8,
    //         ZkSyncProof::Sha256RoundFunction(..) => CircuitType::Sha256Precompile as u8,
    //         ZkSyncProof::ECRecover(..) => CircuitType::EcrecoverPrecompile as u8,
    //         ZkSyncProof::RAMPermutation(..) => CircuitType::RamValidation as u8,
    //         ZkSyncProof::StorageSorter(..) => CircuitType::StorageFilter as u8,
    //         ZkSyncProof::StorageApplication(..) => CircuitType::StorageApplicator as u8,
    //         ZkSyncProof::EventsSorter(..) => CircuitType::EventsRevertsFilter as u8,
    //         ZkSyncProof::L1MessagesSorter(..) => CircuitType::L1MessagesRevertsFilter as u8,
    //         ZkSyncProof::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8,
    //         ZkSyncProof::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
    //         ZkSyncProof::InitialWritesPubdataHasher(..) => CircuitType::StorageFreshWritesHasher as u8,
    //         ZkSyncProof::RepeatedWritesPubdataHasher(..) => CircuitType::StorageRepeatedWritesHasher as u8,
    //     }
    // }

    // pub fn from_proof_and_numeric_type(numeric_type: u8, proof: Proof<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>) -> Self {
    //     use sync_vm::scheduler::CircuitType;

    //     match numeric_type {
    //         a if a == CircuitType::Scheduler as u8 => ZkSyncProof::Scheduler(proof),
    //         a if a == CircuitType::Leaf as u8 => ZkSyncProof::LeafAggregation(proof),
    //         a if a == CircuitType::IntermidiateNode as u8 => ZkSyncProof::NodeAggregation(proof),
    //         a if a == CircuitType::VM as u8 => ZkSyncProof::MainVM(proof),
    //         a if a == CircuitType::DecommitmentsFilter as u8 => ZkSyncProof::CodeDecommittmentsSorter(proof),
    //         a if a == CircuitType::Decommiter as u8 => ZkSyncProof::CodeDecommitter(proof),
    //         a if a == CircuitType::LogDemultiplexer as u8 => ZkSyncProof::LogDemuxer(proof),
    //         a if a == CircuitType::KeccakPrecompile as u8 => ZkSyncProof::KeccakRoundFunction(proof),
    //         a if a == CircuitType::Sha256Precompile as u8 => ZkSyncProof::Sha256RoundFunction(proof),
    //         a if a == CircuitType::EcrecoverPrecompile as u8 => ZkSyncProof::ECRecover(proof),
    //         a if a == CircuitType::RamValidation as u8 => ZkSyncProof::RAMPermutation(proof),
    //         a if a == CircuitType::StorageFilter as u8 => ZkSyncProof::StorageSorter(proof),
    //         a if a == CircuitType::StorageApplicator as u8 => ZkSyncProof::StorageApplication(proof),
    //         a if a == CircuitType::EventsRevertsFilter as u8 => ZkSyncProof::EventsSorter(proof),
    //         a if a == CircuitType::L1MessagesRevertsFilter as u8 => ZkSyncProof::L1MessagesSorter(proof),
    //         a if a == CircuitType::L1MessagesMerkelization as u8 => ZkSyncProof::L1MessagesMerklier(proof),
    //         a if a == CircuitType::L1MessagesHasher as u8 => ZkSyncProof::L1MessagesPubdataHasher(proof),
    //         a if a == CircuitType::StorageFreshWritesHasher as u8 => ZkSyncProof::InitialWritesPubdataHasher(proof),
    //         a if a == CircuitType::StorageRepeatedWritesHasher as u8 => ZkSyncProof::RepeatedWritesPubdataHasher(proof),
    //         a @ _ => panic!("unknown numeric type {}", a)
    //     }
    // }

    // pub fn into_proof(self) -> Proof<F, ZkSyncCircuit<F, VmWitnessOracle<F>>> {
    //     match self {
    //         ZkSyncProof::Scheduler(inner) => inner,
    //         ZkSyncProof::LeafAggregation(inner) => inner,
    //         ZkSyncProof::NodeAggregation(inner) => inner,
    //         ZkSyncProof::MainVM(inner) => inner,
    //         ZkSyncProof::CodeDecommittmentsSorter(inner) => inner,
    //         ZkSyncProof::CodeDecommitter(inner) => inner,
    //         ZkSyncProof::LogDemuxer(inner) => inner,
    //         ZkSyncProof::KeccakRoundFunction(inner) => inner,
    //         ZkSyncProof::Sha256RoundFunction(inner) => inner,
    //         ZkSyncProof::ECRecover(inner) => inner,
    //         ZkSyncProof::RAMPermutation(inner) => inner,
    //         ZkSyncProof::StorageSorter(inner) => inner,
    //         ZkSyncProof::StorageApplication(inner) => inner,
    //         ZkSyncProof::EventsSorter(inner) => inner,
    //         ZkSyncProof::L1MessagesSorter(inner) => inner,
    //         ZkSyncProof::L1MessagesMerklier(inner) => inner,
    //         ZkSyncProof::L1MessagesPubdataHasher(inner) => inner,
    //         ZkSyncProof::InitialWritesPubdataHasher(inner) => inner,
    //         ZkSyncProof::RepeatedWritesPubdataHasher(inner) => inner,
    //     }
    // }

    // pub fn as_proof(&self) -> &Proof<F, ZkSyncCircuit<F, VmWitnessOracle<F>>> {
    //     match self {
    //         ZkSyncProof::Scheduler(inner) => inner,
    //         ZkSyncProof::LeafAggregation(inner) => inner,
    //         ZkSyncProof::NodeAggregation(inner) => inner,
    //         ZkSyncProof::MainVM(inner) => inner,
    //         ZkSyncProof::CodeDecommittmentsSorter(inner) => inner,
    //         ZkSyncProof::CodeDecommitter(inner) => inner,
    //         ZkSyncProof::LogDemuxer(inner) => inner,
    //         ZkSyncProof::KeccakRoundFunction(inner) => inner,
    //         ZkSyncProof::Sha256RoundFunction(inner) => inner,
    //         ZkSyncProof::ECRecover(inner) => inner,
    //         ZkSyncProof::RAMPermutation(inner) => inner,
    //         ZkSyncProof::StorageSorter(inner) => inner,
    //         ZkSyncProof::StorageApplication(inner) => inner,
    //         ZkSyncProof::EventsSorter(inner) => inner,
    //         ZkSyncProof::L1MessagesSorter(inner) => inner,
    //         ZkSyncProof::L1MessagesPubdataHasher(inner) => inner,
    //         ZkSyncProof::L1MessagesMerklier(inner) => inner,
    //         ZkSyncProof::InitialWritesPubdataHasher(inner) => inner,
    //         ZkSyncProof::RepeatedWritesPubdataHasher(inner) => inner,
    //     }
    // }
}

use boojum::cs::implementations::verifier::VerificationKey;
pub type ZkSyncBaseVerificationKey = VerificationKey<GoldilocksField, BaseProofsTreeHasher>;

// /// Wrapper around verification key for easier indexing
// #[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
// #[derivative(Debug, Clone(bound = ""))]
// #[serde(bound = "")]
// pub enum ZkSyncVerificationKey<F: SmallField> {
//     Scheduler(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     LeafAggregation(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     NodeAggregation(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     MainVM(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     CodeDecommittmentsSorter(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     CodeDecommitter(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     LogDemuxer(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     KeccakRoundFunction(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     Sha256RoundFunction(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     ECRecover(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     RAMPermutation(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     StorageSorter(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     StorageApplication(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     EventsSorter(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     L1MessagesSorter(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     L1MessagesPubdataHasher(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     L1MessagesMerklier(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     InitialWritesPubdataHasher(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
//     RepeatedWritesPubdataHasher(VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>),
// }

// impl<F: SmallField> ZkSyncVerificationKey<F> {
//     pub fn numeric_circuit_type(&self) -> u8 {
//         use sync_vm::scheduler::CircuitType;

//         match &self {
//             ZkSyncVerificationKey::Scheduler(..) => CircuitType::Scheduler as u8,
//             ZkSyncVerificationKey::LeafAggregation(..) => CircuitType::Leaf as u8,
//             ZkSyncVerificationKey::NodeAggregation(..) => CircuitType::IntermidiateNode as u8,
//             ZkSyncVerificationKey::MainVM(..) => CircuitType::VM as u8,
//             ZkSyncVerificationKey::CodeDecommittmentsSorter(..) => CircuitType::DecommitmentsFilter as u8,
//             ZkSyncVerificationKey::CodeDecommitter(..) => CircuitType::Decommiter as u8,
//             ZkSyncVerificationKey::LogDemuxer(..) => CircuitType::LogDemultiplexer as u8,
//             ZkSyncVerificationKey::KeccakRoundFunction(..) => CircuitType::KeccakPrecompile as u8,
//             ZkSyncVerificationKey::Sha256RoundFunction(..) => CircuitType::Sha256Precompile as u8,
//             ZkSyncVerificationKey::ECRecover(..) => CircuitType::EcrecoverPrecompile as u8,
//             ZkSyncVerificationKey::RAMPermutation(..) => CircuitType::RamValidation as u8,
//             ZkSyncVerificationKey::StorageSorter(..) => CircuitType::StorageFilter as u8,
//             ZkSyncVerificationKey::StorageApplication(..) => CircuitType::StorageApplicator as u8,
//             ZkSyncVerificationKey::EventsSorter(..) => CircuitType::EventsRevertsFilter as u8,
//             ZkSyncVerificationKey::L1MessagesSorter(..) => CircuitType::L1MessagesRevertsFilter as u8,
//             ZkSyncVerificationKey::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8,
//             ZkSyncVerificationKey::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
//             ZkSyncVerificationKey::InitialWritesPubdataHasher(..) => CircuitType::StorageFreshWritesHasher as u8,
//             ZkSyncVerificationKey::RepeatedWritesPubdataHasher(..) => CircuitType::StorageRepeatedWritesHasher as u8,
//         }
//     }

//     pub fn from_verification_key_and_numeric_type(numeric_type: u8, vk: VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>>) -> Self {
//         use sync_vm::scheduler::CircuitType;

//         match numeric_type {
//             a if a == CircuitType::Scheduler as u8 => ZkSyncVerificationKey::Scheduler(vk),
//             a if a == CircuitType::Leaf as u8 => ZkSyncVerificationKey::LeafAggregation(vk),
//             a if a == CircuitType::IntermidiateNode as u8 => ZkSyncVerificationKey::NodeAggregation(vk),
//             a if a == CircuitType::VM as u8 => ZkSyncVerificationKey::MainVM(vk),
//             a if a == CircuitType::DecommitmentsFilter as u8 => ZkSyncVerificationKey::CodeDecommittmentsSorter(vk),
//             a if a == CircuitType::Decommiter as u8 => ZkSyncVerificationKey::CodeDecommitter(vk),
//             a if a == CircuitType::LogDemultiplexer as u8 => ZkSyncVerificationKey::LogDemuxer(vk),
//             a if a == CircuitType::KeccakPrecompile as u8 => ZkSyncVerificationKey::KeccakRoundFunction(vk),
//             a if a == CircuitType::Sha256Precompile as u8 => ZkSyncVerificationKey::Sha256RoundFunction(vk),
//             a if a == CircuitType::EcrecoverPrecompile as u8 => ZkSyncVerificationKey::ECRecover(vk),
//             a if a == CircuitType::RamValidation as u8 => ZkSyncVerificationKey::RAMPermutation(vk),
//             a if a == CircuitType::StorageFilter as u8 => ZkSyncVerificationKey::StorageSorter(vk),
//             a if a == CircuitType::StorageApplicator as u8 => ZkSyncVerificationKey::StorageApplication(vk),
//             a if a == CircuitType::EventsRevertsFilter as u8 => ZkSyncVerificationKey::EventsSorter(vk),
//             a if a == CircuitType::L1MessagesRevertsFilter as u8 => ZkSyncVerificationKey::L1MessagesSorter(vk),
//             a if a == CircuitType::L1MessagesHasher as u8 => ZkSyncVerificationKey::L1MessagesPubdataHasher(vk),
//             a if a == CircuitType::L1MessagesMerkelization as u8 => ZkSyncVerificationKey::L1MessagesMerklier(vk),
//             a if a == CircuitType::StorageFreshWritesHasher as u8 => ZkSyncVerificationKey::InitialWritesPubdataHasher(vk),
//             a if a == CircuitType::StorageRepeatedWritesHasher as u8 => ZkSyncVerificationKey::RepeatedWritesPubdataHasher(vk),
//             a @ _ => panic!("unknown numeric type {}", a)
//         }
//     }

//     pub fn into_verification_key(self) -> VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>> {
//         match self {
//             ZkSyncVerificationKey::Scheduler(inner) => inner,
//             ZkSyncVerificationKey::LeafAggregation(inner) => inner,
//             ZkSyncVerificationKey::NodeAggregation(inner) => inner,
//             ZkSyncVerificationKey::MainVM(inner) => inner,
//             ZkSyncVerificationKey::CodeDecommittmentsSorter(inner) => inner,
//             ZkSyncVerificationKey::CodeDecommitter(inner) => inner,
//             ZkSyncVerificationKey::LogDemuxer(inner) => inner,
//             ZkSyncVerificationKey::KeccakRoundFunction(inner) => inner,
//             ZkSyncVerificationKey::Sha256RoundFunction(inner) => inner,
//             ZkSyncVerificationKey::ECRecover(inner) => inner,
//             ZkSyncVerificationKey::RAMPermutation(inner) => inner,
//             ZkSyncVerificationKey::StorageSorter(inner) => inner,
//             ZkSyncVerificationKey::StorageApplication(inner) => inner,
//             ZkSyncVerificationKey::EventsSorter(inner) => inner,
//             ZkSyncVerificationKey::L1MessagesSorter(inner) => inner,
//             ZkSyncVerificationKey::L1MessagesPubdataHasher(inner) => inner,
//             ZkSyncVerificationKey::L1MessagesMerklier(inner) => inner,
//             ZkSyncVerificationKey::InitialWritesPubdataHasher(inner) => inner,
//             ZkSyncVerificationKey::RepeatedWritesPubdataHasher(inner) => inner,
//         }
//     }

//     pub fn as_verification_key(&self) -> &VerificationKey<F, ZkSyncCircuit<F, VmWitnessOracle<F>>> {
//         match self {
//             ZkSyncVerificationKey::Scheduler(inner) => inner,
//             ZkSyncVerificationKey::LeafAggregation(inner) => inner,
//             ZkSyncVerificationKey::NodeAggregation(inner) => inner,
//             ZkSyncVerificationKey::MainVM(inner) => inner,
//             ZkSyncVerificationKey::CodeDecommittmentsSorter(inner) => inner,
//             ZkSyncVerificationKey::CodeDecommitter(inner) => inner,
//             ZkSyncVerificationKey::LogDemuxer(inner) => inner,
//             ZkSyncVerificationKey::KeccakRoundFunction(inner) => inner,
//             ZkSyncVerificationKey::Sha256RoundFunction(inner) => inner,
//             ZkSyncVerificationKey::ECRecover(inner) => inner,
//             ZkSyncVerificationKey::RAMPermutation(inner) => inner,
//             ZkSyncVerificationKey::StorageSorter(inner) => inner,
//             ZkSyncVerificationKey::StorageApplication(inner) => inner,
//             ZkSyncVerificationKey::EventsSorter(inner) => inner,
//             ZkSyncVerificationKey::L1MessagesSorter(inner) => inner,
//             ZkSyncVerificationKey::L1MessagesPubdataHasher(inner) => inner,
//             ZkSyncVerificationKey::L1MessagesMerklier(inner) => inner,
//             ZkSyncVerificationKey::InitialWritesPubdataHasher(inner) => inner,
//             ZkSyncVerificationKey::RepeatedWritesPubdataHasher(inner) => inner,
//         }
//     }
// }

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
