use super::*;

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
// pub mod l1_messages_sort_dedup; // equal to one 
pub mod l1_messages_merklize;
pub mod storage_initial_writes_pubdata_hasher;
pub mod storage_repeated_writes_pubdata_hasher;

pub mod leaf_aggregation;
pub mod node_aggregation;

pub mod scheduler;

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
pub use self::l1_messages_merklize::MessagesMerklizerInstanceSynthesisFunction;
pub use self::storage_initial_writes_pubdata_hasher::StorageInitialWritesRehasherInstanceSynthesisFunction;
pub use self::storage_repeated_writes_pubdata_hasher::StorageRepeatedWritesRehasherInstanceSynthesisFunction;

pub use self::leaf_aggregation::LeafAggregationInstanceSynthesisFunction;
pub use self::node_aggregation::NodeAggregationInstanceSynthesisFunction;

pub use self::scheduler::SchedulerInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<E> for ZkSyncUniformCircuitCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<E, W> = ZkSyncUniformCircuitCircuitInstance<E, VmMainInstanceSynthesisFunction<E, W>>; 
pub type CodeDecommittsSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, CodeDecommittmentsSorterSynthesisFunction>;
pub type CodeDecommitterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, CodeDecommitterInstanceSynthesisFunction>;
pub type LogDemuxerCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, LogDemuxInstanceSynthesisFunction>;
pub type Keccak256RoundFunctionCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, Keccak256RoundFunctionInstanceSynthesisFunction>;
pub type Sha256RoundFunctionCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, Sha256RoundFunctionInstanceSynthesisFunction>;
pub type ECRecoverFunctionCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, ECRecoverFunctionInstanceSynthesisFunction>;
pub type RAMPermutationCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, RAMPermutationInstanceSynthesisFunction>;
pub type StorageSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageSortAndDedupInstanceSynthesisFunction>;
pub type StorageApplicationCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageApplicationInstanceSynthesisFunction>;
pub type EventsSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction>;
pub type L1MessagesSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction>;
pub type L1MessagesMerklizerCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, MessagesMerklizerInstanceSynthesisFunction>;
pub type InitialStorageWritesPubdataHasherCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageInitialWritesRehasherInstanceSynthesisFunction>;
pub type RepeatedStorageWritesPubdataHasherCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageRepeatedWritesRehasherInstanceSynthesisFunction>;

pub type LeafAggregationCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, LeafAggregationInstanceSynthesisFunction>;
pub type NodeAggregationCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, NodeAggregationInstanceSynthesisFunction>;

pub type SchedulerCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, SchedulerInstanceSynthesisFunction>;

/// NOTE: It DOES implement Circuit<E>, but one would need to load the
/// setup for it's INNER contents somehow, so do NOT synthesise it directly
/// unless you know what you are doing!
#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncCircuit<E: Engine, W: WitnessOracle<E>> {
    Scheduler(SchedulerCircuit<E>),
    LeafAggregation(LeafAggregationCircuit<E>),
    NodeAggregation(NodeAggregationCircuit<E>),
    MainVM(VMMainCircuit<E, W>),
    CodeDecommittmentsSorter(CodeDecommittsSorterCircuit<E>),
    CodeDecommitter(CodeDecommitterCircuit<E>),
    LogDemuxer(LogDemuxerCircuit<E>),
    KeccakRoundFunction(Keccak256RoundFunctionCircuit<E>),
    Sha256RoundFunction(Sha256RoundFunctionCircuit<E>),
    ECRecover(ECRecoverFunctionCircuit<E>),
    RAMPermutation(RAMPermutationCircuit<E>),
    StorageSorter(StorageSorterCircuit<E>),
    StorageApplication(StorageApplicationCircuit<E>),
    EventsSorter(EventsSorterCircuit<E>),
    L1MessagesSorter(L1MessagesSorterCircuit<E>),
    L1MessagesMerklier(L1MessagesMerklizerCircuit<E>),
    InitialWritesPubdataHasher(InitialStorageWritesPubdataHasherCircuit<E>),
    RepeatedWritesPubdataHasher(RepeatedStorageWritesPubdataHasherCircuit<E>),
}

impl<E: Engine,  W: WitnessOracle<E>> Circuit<E> for ZkSyncCircuit<E, W> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;
    // always two gates
    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(
            vec![
                Self::MainGate::default().into_internal(),
                Rescue5CustomGate::default().into_internal()
            ]
        )
    }
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        match &self {
            ZkSyncCircuit::Scheduler(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::LeafAggregation(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::NodeAggregation(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::MainVM(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::CodeDecommitter(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::LogDemuxer(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::KeccakRoundFunction(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::Sha256RoundFunction(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::ECRecover(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::RAMPermutation(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::StorageSorter(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::StorageApplication(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::EventsSorter(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::L1MessagesSorter(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::L1MessagesMerklier(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::InitialWritesPubdataHasher(inner) => {inner.synthesize(cs)},
            ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => {inner.synthesize(cs)},
        }
    }
}

// use sync_vm::*;

impl<E: Engine, W: WitnessOracle<E>> ZkSyncCircuit<E, W> {
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncCircuit::Scheduler(..) => "Scheduler",
            ZkSyncCircuit::LeafAggregation(..) => "Leaf aggregation",
            ZkSyncCircuit::NodeAggregation(..) => "Node aggregation",
            ZkSyncCircuit::MainVM(..) => "Main VM",
            ZkSyncCircuit::CodeDecommittmentsSorter(..) => "Decommitts sorter",
            ZkSyncCircuit::CodeDecommitter(..) => "Code decommitter",
            ZkSyncCircuit::LogDemuxer(..) => "Log demuxer",
            ZkSyncCircuit::KeccakRoundFunction(..) => "Keccak",
            ZkSyncCircuit::Sha256RoundFunction(..) => "SHA256",
            ZkSyncCircuit::ECRecover(..) => "ECRecover",
            ZkSyncCircuit::RAMPermutation(..) => "RAM permutation",
            ZkSyncCircuit::StorageSorter(..) => "Storage sorter",
            ZkSyncCircuit::StorageApplication(..) => "Storage application",
            ZkSyncCircuit::EventsSorter(..) => "Events sorter",
            ZkSyncCircuit::L1MessagesSorter(..) => "L1 messages sorter",
            ZkSyncCircuit::L1MessagesMerklier(..) => "L1 messages merklizer",
            ZkSyncCircuit::InitialWritesPubdataHasher(..) => "Initial writes pubdata rehasher",
            ZkSyncCircuit::RepeatedWritesPubdataHasher(..) => "Repeated writes pubdata rehasher",
        }
    }

    pub fn debug_witness(&self) {
        match &self {
            ZkSyncCircuit::Scheduler(inner) => {inner.debug_witness();},
            ZkSyncCircuit::LeafAggregation(inner) => {inner.debug_witness();},
            ZkSyncCircuit::NodeAggregation(inner) => {inner.debug_witness();},
            ZkSyncCircuit::MainVM(inner) => {inner.debug_witness();},
            ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {inner.debug_witness();},
            ZkSyncCircuit::CodeDecommitter(inner) => {inner.debug_witness();},
            ZkSyncCircuit::LogDemuxer(inner) => {inner.debug_witness();},
            ZkSyncCircuit::KeccakRoundFunction(inner) => {inner.debug_witness();},
            ZkSyncCircuit::Sha256RoundFunction(inner) => {inner.debug_witness();},
            ZkSyncCircuit::ECRecover(inner) => {inner.debug_witness();},
            ZkSyncCircuit::RAMPermutation(inner) => {inner.debug_witness();},
            ZkSyncCircuit::StorageSorter(inner) => {inner.debug_witness();},
            ZkSyncCircuit::StorageApplication(inner) => {inner.debug_witness();},
            ZkSyncCircuit::EventsSorter(inner) => {inner.debug_witness();},
            ZkSyncCircuit::L1MessagesSorter(inner) => {inner.debug_witness();},
            ZkSyncCircuit::L1MessagesMerklier(inner) => {inner.debug_witness();},
            ZkSyncCircuit::InitialWritesPubdataHasher(inner) => {inner.debug_witness();},
            ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => {inner.debug_witness();},
        };

        ()
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use sync_vm::scheduler::CircuitType;

        match &self {
            ZkSyncCircuit::Scheduler(..) => unreachable!(),
            ZkSyncCircuit::LeafAggregation(..) => unreachable!(),
            ZkSyncCircuit::NodeAggregation(..) => unreachable!(),
            ZkSyncCircuit::MainVM(..) => CircuitType::VM as u8,
            ZkSyncCircuit::CodeDecommittmentsSorter(..) => CircuitType::DecommitmentsFilter as u8,
            ZkSyncCircuit::CodeDecommitter(..) => CircuitType::Decommiter as u8,
            ZkSyncCircuit::LogDemuxer(..) => CircuitType::LogDemultiplexer as u8,
            ZkSyncCircuit::KeccakRoundFunction(..) => CircuitType::KeccakPrecompile as u8,
            ZkSyncCircuit::Sha256RoundFunction(..) => CircuitType::Sha256Precompile as u8,
            ZkSyncCircuit::ECRecover(..) => CircuitType::EcrecoverPrecompile as u8,
            ZkSyncCircuit::RAMPermutation(..) => CircuitType::RamValidation as u8,
            ZkSyncCircuit::StorageSorter(..) => CircuitType::StorageFilter as u8,
            ZkSyncCircuit::StorageApplication(..) => CircuitType::StorageApplicator as u8,
            ZkSyncCircuit::EventsSorter(..) => CircuitType::EventsRevertsFilter as u8,
            ZkSyncCircuit::L1MessagesSorter(..) => CircuitType::L1MessagesRevertsFilter as u8,
            ZkSyncCircuit::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
            ZkSyncCircuit::InitialWritesPubdataHasher(..) => CircuitType::StorageFreshWritesHasher as u8,
            ZkSyncCircuit::RepeatedWritesPubdataHasher(..) => CircuitType::StorageRepeatedWritesHasher as u8,
        }
    }
}
