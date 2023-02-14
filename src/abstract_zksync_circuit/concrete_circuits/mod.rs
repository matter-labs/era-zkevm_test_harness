use sync_vm::testing::Bn256;

use crate::witness::oracle::VmWitnessOracle;

use super::*;

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
// pub mod l1_messages_sort_dedup; // equal to one
pub mod l1_messages_hasher;
pub mod l1_messages_merklize;
pub mod storage_initial_writes_pubdata_hasher;
pub mod storage_repeated_writes_pubdata_hasher;

pub mod leaf_aggregation;
pub mod node_aggregation;

pub mod scheduler;

pub use self::code_decommitter::CodeDecommitterInstanceSynthesisFunction;
pub use self::ecrecover::ECRecoverFunctionInstanceSynthesisFunction;
pub use self::events_sort_dedup::EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction;
pub use self::keccak256_round_function::Keccak256RoundFunctionInstanceSynthesisFunction;
pub use self::l1_messages_hasher::L1MessagesRehasherInstanceSynthesisFunction;
pub use self::l1_messages_merklize::MessagesMerklizerInstanceSynthesisFunction;
pub use self::log_demux::LogDemuxInstanceSynthesisFunction;
pub use self::ram_permutation::RAMPermutationInstanceSynthesisFunction;
pub use self::sha256_round_function::Sha256RoundFunctionInstanceSynthesisFunction;
pub use self::sort_code_decommits::CodeDecommittmentsSorterSynthesisFunction;
pub use self::storage_apply::StorageApplicationInstanceSynthesisFunction;
pub use self::storage_initial_writes_pubdata_hasher::StorageInitialWritesRehasherInstanceSynthesisFunction;
pub use self::storage_repeated_writes_pubdata_hasher::StorageRepeatedWritesRehasherInstanceSynthesisFunction;
pub use self::storage_sort_dedup::StorageSortAndDedupInstanceSynthesisFunction;
pub use self::vm_main::VmMainInstanceSynthesisFunction;

pub use self::leaf_aggregation::LeafAggregationInstanceSynthesisFunction;
pub use self::node_aggregation::NodeAggregationInstanceSynthesisFunction;

pub use self::scheduler::SchedulerInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<E> for ZkSyncUniformCircuitCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<E, W> =
    ZkSyncUniformCircuitCircuitInstance<E, VmMainInstanceSynthesisFunction<E, W>>;
pub type CodeDecommittsSorterCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, CodeDecommittmentsSorterSynthesisFunction>;
pub type CodeDecommitterCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, CodeDecommitterInstanceSynthesisFunction>;
pub type LogDemuxerCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, LogDemuxInstanceSynthesisFunction>;
pub type Keccak256RoundFunctionCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, Keccak256RoundFunctionInstanceSynthesisFunction>;
pub type Sha256RoundFunctionCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, Sha256RoundFunctionInstanceSynthesisFunction>;
pub type ECRecoverFunctionCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, ECRecoverFunctionInstanceSynthesisFunction>;
pub type RAMPermutationCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, RAMPermutationInstanceSynthesisFunction>;
pub type StorageSorterCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, StorageSortAndDedupInstanceSynthesisFunction>;
pub type StorageApplicationCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, StorageApplicationInstanceSynthesisFunction>;
pub type EventsSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<
    E,
    EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction,
>;
pub type L1MessagesSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<
    E,
    EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction,
>;
pub type L1MessagesMerklizerCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, MessagesMerklizerInstanceSynthesisFunction>;
pub type InitialStorageWritesPubdataHasherCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, StorageInitialWritesRehasherInstanceSynthesisFunction>;
pub type RepeatedStorageWritesPubdataHasherCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, StorageRepeatedWritesRehasherInstanceSynthesisFunction>;
pub type L1MessagesHasherCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, L1MessagesRehasherInstanceSynthesisFunction>;

pub type LeafAggregationCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, LeafAggregationInstanceSynthesisFunction>;
pub type NodeAggregationCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, NodeAggregationInstanceSynthesisFunction>;

pub type SchedulerCircuit<E> =
    ZkSyncUniformCircuitCircuitInstance<E, SchedulerInstanceSynthesisFunction>;

/// NOTE: It DOES implement Circuit<E>, but one would need to load the
/// setup for it's INNER contents somehow, so do NOT synthesise it directly
/// unless you know what you are doing!
#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncCircuit<E: Engine, W: WitnessOracle<E>> {
    Scheduler(SchedulerCircuit<E>),
    NodeAggregation(NodeAggregationCircuit<E>),
    LeafAggregation(LeafAggregationCircuit<E>),
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
    L1MessagesPubdataHasher(L1MessagesHasherCircuit<E>),
}

impl<E: Engine, W: WitnessOracle<E>> Circuit<E> for ZkSyncCircuit<E, W> {
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;
    // always two gates
    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate::default().into_internal(),
        ])
    }
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        match &self {
            ZkSyncCircuit::Scheduler(inner) => inner.synthesize(cs),
            ZkSyncCircuit::LeafAggregation(inner) => inner.synthesize(cs),
            ZkSyncCircuit::NodeAggregation(inner) => inner.synthesize(cs),
            ZkSyncCircuit::MainVM(inner) => inner.synthesize(cs),
            ZkSyncCircuit::CodeDecommittmentsSorter(inner) => inner.synthesize(cs),
            ZkSyncCircuit::CodeDecommitter(inner) => inner.synthesize(cs),
            ZkSyncCircuit::LogDemuxer(inner) => inner.synthesize(cs),
            ZkSyncCircuit::KeccakRoundFunction(inner) => inner.synthesize(cs),
            ZkSyncCircuit::Sha256RoundFunction(inner) => inner.synthesize(cs),
            ZkSyncCircuit::ECRecover(inner) => inner.synthesize(cs),
            ZkSyncCircuit::RAMPermutation(inner) => inner.synthesize(cs),
            ZkSyncCircuit::StorageSorter(inner) => inner.synthesize(cs),
            ZkSyncCircuit::StorageApplication(inner) => inner.synthesize(cs),
            ZkSyncCircuit::EventsSorter(inner) => inner.synthesize(cs),
            ZkSyncCircuit::L1MessagesSorter(inner) => inner.synthesize(cs),
            ZkSyncCircuit::L1MessagesMerklier(inner) => inner.synthesize(cs),
            ZkSyncCircuit::InitialWritesPubdataHasher(inner) => inner.synthesize(cs),
            ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => inner.synthesize(cs),
            ZkSyncCircuit::L1MessagesPubdataHasher(inner) => inner.synthesize(cs),
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
            ZkSyncCircuit::L1MessagesPubdataHasher(..) => "L1 messages rehasher",
        }
    }

    pub fn debug_witness(&self) {
        match &self {
            ZkSyncCircuit::Scheduler(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::LeafAggregation(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::NodeAggregation(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::MainVM(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::CodeDecommitter(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::LogDemuxer(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::KeccakRoundFunction(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::Sha256RoundFunction(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::ECRecover(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::RAMPermutation(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::StorageSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::StorageApplication(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::EventsSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::L1MessagesSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::L1MessagesMerklier(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::InitialWritesPubdataHasher(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => {
                inner.debug_witness();
            }
            ZkSyncCircuit::L1MessagesPubdataHasher(inner) => {
                inner.debug_witness();
            }
        };

        ()
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use sync_vm::scheduler::CircuitType;

        match &self {
            ZkSyncCircuit::Scheduler(..) => CircuitType::Scheduler as u8,
            ZkSyncCircuit::LeafAggregation(..) => CircuitType::Leaf as u8,
            ZkSyncCircuit::NodeAggregation(..) => CircuitType::IntermidiateNode as u8,
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
            ZkSyncCircuit::InitialWritesPubdataHasher(..) => {
                CircuitType::StorageFreshWritesHasher as u8
            }
            ZkSyncCircuit::RepeatedWritesPubdataHasher(..) => {
                CircuitType::StorageRepeatedWritesHasher as u8
            }
            ZkSyncCircuit::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8,
        }
    }

    pub fn erase_witness(&self) {
        match &self {
            ZkSyncCircuit::Scheduler(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::LeafAggregation(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::NodeAggregation(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::MainVM(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::CodeDecommittmentsSorter(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::CodeDecommitter(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::LogDemuxer(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::KeccakRoundFunction(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::Sha256RoundFunction(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::ECRecover(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::RAMPermutation(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::StorageSorter(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::StorageApplication(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::EventsSorter(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::L1MessagesSorter(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::L1MessagesMerklier(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::InitialWritesPubdataHasher(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::RepeatedWritesPubdataHasher(inner) => {
                inner.erase_witness();
            }
            ZkSyncCircuit::L1MessagesPubdataHasher(inner) => {
                inner.erase_witness();
            }
        };
    }
}

use crate::bellman::plonk::better_better_cs::proof::Proof;

/// Wrapper around proof for easier indexing
#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncProof<E: Engine> {
    Scheduler(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    LeafAggregation(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    NodeAggregation(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    MainVM(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    CodeDecommittmentsSorter(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    CodeDecommitter(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    LogDemuxer(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    KeccakRoundFunction(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    Sha256RoundFunction(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    ECRecover(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    RAMPermutation(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    StorageSorter(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    StorageApplication(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    EventsSorter(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    L1MessagesSorter(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    L1MessagesPubdataHasher(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    L1MessagesMerklier(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    InitialWritesPubdataHasher(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    RepeatedWritesPubdataHasher(Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
}

impl<E: Engine> ZkSyncProof<E> {
    pub fn numeric_circuit_type(&self) -> u8 {
        use sync_vm::scheduler::CircuitType;

        match &self {
            ZkSyncProof::Scheduler(..) => CircuitType::Scheduler as u8,
            ZkSyncProof::LeafAggregation(..) => CircuitType::Leaf as u8,
            ZkSyncProof::NodeAggregation(..) => CircuitType::IntermidiateNode as u8,
            ZkSyncProof::MainVM(..) => CircuitType::VM as u8,
            ZkSyncProof::CodeDecommittmentsSorter(..) => CircuitType::DecommitmentsFilter as u8,
            ZkSyncProof::CodeDecommitter(..) => CircuitType::Decommiter as u8,
            ZkSyncProof::LogDemuxer(..) => CircuitType::LogDemultiplexer as u8,
            ZkSyncProof::KeccakRoundFunction(..) => CircuitType::KeccakPrecompile as u8,
            ZkSyncProof::Sha256RoundFunction(..) => CircuitType::Sha256Precompile as u8,
            ZkSyncProof::ECRecover(..) => CircuitType::EcrecoverPrecompile as u8,
            ZkSyncProof::RAMPermutation(..) => CircuitType::RamValidation as u8,
            ZkSyncProof::StorageSorter(..) => CircuitType::StorageFilter as u8,
            ZkSyncProof::StorageApplication(..) => CircuitType::StorageApplicator as u8,
            ZkSyncProof::EventsSorter(..) => CircuitType::EventsRevertsFilter as u8,
            ZkSyncProof::L1MessagesSorter(..) => CircuitType::L1MessagesRevertsFilter as u8,
            ZkSyncProof::L1MessagesPubdataHasher(..) => CircuitType::L1MessagesHasher as u8,
            ZkSyncProof::L1MessagesMerklier(..) => CircuitType::L1MessagesMerkelization as u8,
            ZkSyncProof::InitialWritesPubdataHasher(..) => {
                CircuitType::StorageFreshWritesHasher as u8
            }
            ZkSyncProof::RepeatedWritesPubdataHasher(..) => {
                CircuitType::StorageRepeatedWritesHasher as u8
            }
        }
    }

    pub fn from_proof_and_numeric_type(
        numeric_type: u8,
        proof: Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>,
    ) -> Self {
        use sync_vm::scheduler::CircuitType;

        match numeric_type {
            a if a == CircuitType::Scheduler as u8 => ZkSyncProof::Scheduler(proof),
            a if a == CircuitType::Leaf as u8 => ZkSyncProof::LeafAggregation(proof),
            a if a == CircuitType::IntermidiateNode as u8 => ZkSyncProof::NodeAggregation(proof),
            a if a == CircuitType::VM as u8 => ZkSyncProof::MainVM(proof),
            a if a == CircuitType::DecommitmentsFilter as u8 => {
                ZkSyncProof::CodeDecommittmentsSorter(proof)
            }
            a if a == CircuitType::Decommiter as u8 => ZkSyncProof::CodeDecommitter(proof),
            a if a == CircuitType::LogDemultiplexer as u8 => ZkSyncProof::LogDemuxer(proof),
            a if a == CircuitType::KeccakPrecompile as u8 => {
                ZkSyncProof::KeccakRoundFunction(proof)
            }
            a if a == CircuitType::Sha256Precompile as u8 => {
                ZkSyncProof::Sha256RoundFunction(proof)
            }
            a if a == CircuitType::EcrecoverPrecompile as u8 => ZkSyncProof::ECRecover(proof),
            a if a == CircuitType::RamValidation as u8 => ZkSyncProof::RAMPermutation(proof),
            a if a == CircuitType::StorageFilter as u8 => ZkSyncProof::StorageSorter(proof),
            a if a == CircuitType::StorageApplicator as u8 => {
                ZkSyncProof::StorageApplication(proof)
            }
            a if a == CircuitType::EventsRevertsFilter as u8 => ZkSyncProof::EventsSorter(proof),
            a if a == CircuitType::L1MessagesRevertsFilter as u8 => {
                ZkSyncProof::L1MessagesSorter(proof)
            }
            a if a == CircuitType::L1MessagesMerkelization as u8 => {
                ZkSyncProof::L1MessagesMerklier(proof)
            }
            a if a == CircuitType::L1MessagesHasher as u8 => {
                ZkSyncProof::L1MessagesPubdataHasher(proof)
            }
            a if a == CircuitType::StorageFreshWritesHasher as u8 => {
                ZkSyncProof::InitialWritesPubdataHasher(proof)
            }
            a if a == CircuitType::StorageRepeatedWritesHasher as u8 => {
                ZkSyncProof::RepeatedWritesPubdataHasher(proof)
            }
            a @ _ => panic!("unknown numeric type {}", a),
        }
    }

    pub fn into_proof(self) -> Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>> {
        match self {
            ZkSyncProof::Scheduler(inner) => inner,
            ZkSyncProof::LeafAggregation(inner) => inner,
            ZkSyncProof::NodeAggregation(inner) => inner,
            ZkSyncProof::MainVM(inner) => inner,
            ZkSyncProof::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncProof::CodeDecommitter(inner) => inner,
            ZkSyncProof::LogDemuxer(inner) => inner,
            ZkSyncProof::KeccakRoundFunction(inner) => inner,
            ZkSyncProof::Sha256RoundFunction(inner) => inner,
            ZkSyncProof::ECRecover(inner) => inner,
            ZkSyncProof::RAMPermutation(inner) => inner,
            ZkSyncProof::StorageSorter(inner) => inner,
            ZkSyncProof::StorageApplication(inner) => inner,
            ZkSyncProof::EventsSorter(inner) => inner,
            ZkSyncProof::L1MessagesSorter(inner) => inner,
            ZkSyncProof::L1MessagesMerklier(inner) => inner,
            ZkSyncProof::L1MessagesPubdataHasher(inner) => inner,
            ZkSyncProof::InitialWritesPubdataHasher(inner) => inner,
            ZkSyncProof::RepeatedWritesPubdataHasher(inner) => inner,
        }
    }

    pub fn as_proof(&self) -> &Proof<E, ZkSyncCircuit<E, VmWitnessOracle<E>>> {
        match self {
            ZkSyncProof::Scheduler(inner) => inner,
            ZkSyncProof::LeafAggregation(inner) => inner,
            ZkSyncProof::NodeAggregation(inner) => inner,
            ZkSyncProof::MainVM(inner) => inner,
            ZkSyncProof::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncProof::CodeDecommitter(inner) => inner,
            ZkSyncProof::LogDemuxer(inner) => inner,
            ZkSyncProof::KeccakRoundFunction(inner) => inner,
            ZkSyncProof::Sha256RoundFunction(inner) => inner,
            ZkSyncProof::ECRecover(inner) => inner,
            ZkSyncProof::RAMPermutation(inner) => inner,
            ZkSyncProof::StorageSorter(inner) => inner,
            ZkSyncProof::StorageApplication(inner) => inner,
            ZkSyncProof::EventsSorter(inner) => inner,
            ZkSyncProof::L1MessagesSorter(inner) => inner,
            ZkSyncProof::L1MessagesPubdataHasher(inner) => inner,
            ZkSyncProof::L1MessagesMerklier(inner) => inner,
            ZkSyncProof::InitialWritesPubdataHasher(inner) => inner,
            ZkSyncProof::RepeatedWritesPubdataHasher(inner) => inner,
        }
    }
}

use crate::bellman::plonk::better_better_cs::setup::VerificationKey;

/// Wrapper around verification key for easier indexing
#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Debug, Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncVerificationKey<E: Engine> {
    Scheduler(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    LeafAggregation(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    NodeAggregation(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    MainVM(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    CodeDecommittmentsSorter(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    CodeDecommitter(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    LogDemuxer(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    KeccakRoundFunction(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    Sha256RoundFunction(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    ECRecover(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    RAMPermutation(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    StorageSorter(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    StorageApplication(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    EventsSorter(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    L1MessagesSorter(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    L1MessagesPubdataHasher(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    L1MessagesMerklier(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    InitialWritesPubdataHasher(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
    RepeatedWritesPubdataHasher(VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>),
}

impl<E: Engine> ZkSyncVerificationKey<E> {
    pub fn numeric_circuit_type(&self) -> u8 {
        use sync_vm::scheduler::CircuitType;

        match &self {
            ZkSyncVerificationKey::Scheduler(..) => CircuitType::Scheduler as u8,
            ZkSyncVerificationKey::LeafAggregation(..) => CircuitType::Leaf as u8,
            ZkSyncVerificationKey::NodeAggregation(..) => CircuitType::IntermidiateNode as u8,
            ZkSyncVerificationKey::MainVM(..) => CircuitType::VM as u8,
            ZkSyncVerificationKey::CodeDecommittmentsSorter(..) => {
                CircuitType::DecommitmentsFilter as u8
            }
            ZkSyncVerificationKey::CodeDecommitter(..) => CircuitType::Decommiter as u8,
            ZkSyncVerificationKey::LogDemuxer(..) => CircuitType::LogDemultiplexer as u8,
            ZkSyncVerificationKey::KeccakRoundFunction(..) => CircuitType::KeccakPrecompile as u8,
            ZkSyncVerificationKey::Sha256RoundFunction(..) => CircuitType::Sha256Precompile as u8,
            ZkSyncVerificationKey::ECRecover(..) => CircuitType::EcrecoverPrecompile as u8,
            ZkSyncVerificationKey::RAMPermutation(..) => CircuitType::RamValidation as u8,
            ZkSyncVerificationKey::StorageSorter(..) => CircuitType::StorageFilter as u8,
            ZkSyncVerificationKey::StorageApplication(..) => CircuitType::StorageApplicator as u8,
            ZkSyncVerificationKey::EventsSorter(..) => CircuitType::EventsRevertsFilter as u8,
            ZkSyncVerificationKey::L1MessagesSorter(..) => {
                CircuitType::L1MessagesRevertsFilter as u8
            }
            ZkSyncVerificationKey::L1MessagesPubdataHasher(..) => {
                CircuitType::L1MessagesHasher as u8
            }
            ZkSyncVerificationKey::L1MessagesMerklier(..) => {
                CircuitType::L1MessagesMerkelization as u8
            }
            ZkSyncVerificationKey::InitialWritesPubdataHasher(..) => {
                CircuitType::StorageFreshWritesHasher as u8
            }
            ZkSyncVerificationKey::RepeatedWritesPubdataHasher(..) => {
                CircuitType::StorageRepeatedWritesHasher as u8
            }
        }
    }

    pub fn from_verification_key_and_numeric_type(
        numeric_type: u8,
        vk: VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>>,
    ) -> Self {
        use sync_vm::scheduler::CircuitType;

        match numeric_type {
            a if a == CircuitType::Scheduler as u8 => ZkSyncVerificationKey::Scheduler(vk),
            a if a == CircuitType::Leaf as u8 => ZkSyncVerificationKey::LeafAggregation(vk),
            a if a == CircuitType::IntermidiateNode as u8 => {
                ZkSyncVerificationKey::NodeAggregation(vk)
            }
            a if a == CircuitType::VM as u8 => ZkSyncVerificationKey::MainVM(vk),
            a if a == CircuitType::DecommitmentsFilter as u8 => {
                ZkSyncVerificationKey::CodeDecommittmentsSorter(vk)
            }
            a if a == CircuitType::Decommiter as u8 => ZkSyncVerificationKey::CodeDecommitter(vk),
            a if a == CircuitType::LogDemultiplexer as u8 => ZkSyncVerificationKey::LogDemuxer(vk),
            a if a == CircuitType::KeccakPrecompile as u8 => {
                ZkSyncVerificationKey::KeccakRoundFunction(vk)
            }
            a if a == CircuitType::Sha256Precompile as u8 => {
                ZkSyncVerificationKey::Sha256RoundFunction(vk)
            }
            a if a == CircuitType::EcrecoverPrecompile as u8 => {
                ZkSyncVerificationKey::ECRecover(vk)
            }
            a if a == CircuitType::RamValidation as u8 => ZkSyncVerificationKey::RAMPermutation(vk),
            a if a == CircuitType::StorageFilter as u8 => ZkSyncVerificationKey::StorageSorter(vk),
            a if a == CircuitType::StorageApplicator as u8 => {
                ZkSyncVerificationKey::StorageApplication(vk)
            }
            a if a == CircuitType::EventsRevertsFilter as u8 => {
                ZkSyncVerificationKey::EventsSorter(vk)
            }
            a if a == CircuitType::L1MessagesRevertsFilter as u8 => {
                ZkSyncVerificationKey::L1MessagesSorter(vk)
            }
            a if a == CircuitType::L1MessagesHasher as u8 => {
                ZkSyncVerificationKey::L1MessagesPubdataHasher(vk)
            }
            a if a == CircuitType::L1MessagesMerkelization as u8 => {
                ZkSyncVerificationKey::L1MessagesMerklier(vk)
            }
            a if a == CircuitType::StorageFreshWritesHasher as u8 => {
                ZkSyncVerificationKey::InitialWritesPubdataHasher(vk)
            }
            a if a == CircuitType::StorageRepeatedWritesHasher as u8 => {
                ZkSyncVerificationKey::RepeatedWritesPubdataHasher(vk)
            }
            a @ _ => panic!("unknown numeric type {}", a),
        }
    }

    pub fn into_verification_key(self) -> VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>> {
        match self {
            ZkSyncVerificationKey::Scheduler(inner) => inner,
            ZkSyncVerificationKey::LeafAggregation(inner) => inner,
            ZkSyncVerificationKey::NodeAggregation(inner) => inner,
            ZkSyncVerificationKey::MainVM(inner) => inner,
            ZkSyncVerificationKey::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncVerificationKey::CodeDecommitter(inner) => inner,
            ZkSyncVerificationKey::LogDemuxer(inner) => inner,
            ZkSyncVerificationKey::KeccakRoundFunction(inner) => inner,
            ZkSyncVerificationKey::Sha256RoundFunction(inner) => inner,
            ZkSyncVerificationKey::ECRecover(inner) => inner,
            ZkSyncVerificationKey::RAMPermutation(inner) => inner,
            ZkSyncVerificationKey::StorageSorter(inner) => inner,
            ZkSyncVerificationKey::StorageApplication(inner) => inner,
            ZkSyncVerificationKey::EventsSorter(inner) => inner,
            ZkSyncVerificationKey::L1MessagesSorter(inner) => inner,
            ZkSyncVerificationKey::L1MessagesPubdataHasher(inner) => inner,
            ZkSyncVerificationKey::L1MessagesMerklier(inner) => inner,
            ZkSyncVerificationKey::InitialWritesPubdataHasher(inner) => inner,
            ZkSyncVerificationKey::RepeatedWritesPubdataHasher(inner) => inner,
        }
    }

    pub fn as_verification_key(&self) -> &VerificationKey<E, ZkSyncCircuit<E, VmWitnessOracle<E>>> {
        match self {
            ZkSyncVerificationKey::Scheduler(inner) => inner,
            ZkSyncVerificationKey::LeafAggregation(inner) => inner,
            ZkSyncVerificationKey::NodeAggregation(inner) => inner,
            ZkSyncVerificationKey::MainVM(inner) => inner,
            ZkSyncVerificationKey::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncVerificationKey::CodeDecommitter(inner) => inner,
            ZkSyncVerificationKey::LogDemuxer(inner) => inner,
            ZkSyncVerificationKey::KeccakRoundFunction(inner) => inner,
            ZkSyncVerificationKey::Sha256RoundFunction(inner) => inner,
            ZkSyncVerificationKey::ECRecover(inner) => inner,
            ZkSyncVerificationKey::RAMPermutation(inner) => inner,
            ZkSyncVerificationKey::StorageSorter(inner) => inner,
            ZkSyncVerificationKey::StorageApplication(inner) => inner,
            ZkSyncVerificationKey::EventsSorter(inner) => inner,
            ZkSyncVerificationKey::L1MessagesSorter(inner) => inner,
            ZkSyncVerificationKey::L1MessagesPubdataHasher(inner) => inner,
            ZkSyncVerificationKey::L1MessagesMerklier(inner) => inner,
            ZkSyncVerificationKey::InitialWritesPubdataHasher(inner) => inner,
            ZkSyncVerificationKey::RepeatedWritesPubdataHasher(inner) => inner,
        }
    }
}

impl ZkSyncVerificationKey<Bn256> {
    pub fn verify_proof(&self, proof: &ZkSyncProof<Bn256>) -> bool {
        assert_eq!(
            self.numeric_circuit_type(),
            proof.numeric_circuit_type(),
            "mismatching IDs, VK is for {}, proof is for {}",
            self.numeric_circuit_type(),
            proof.numeric_circuit_type()
        );
        match &self {
            a @ ZkSyncVerificationKey::Scheduler(..) => {
                // use Keccak transcript
                use crate::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;

                let vk = a.as_verification_key();
                let proof = proof.as_proof();
                let is_valid = crate::bellman::plonk::better_better_cs::verifier::verify::<
                    Bn256,
                    _,
                    RollingKeccakTranscript<sync_vm::testing::Fr>,
                >(vk, proof, None)
                .expect("must try to verify a proof");

                is_valid
            }
            a @ ZkSyncVerificationKey::LeafAggregation(..)
            | a @ ZkSyncVerificationKey::NodeAggregation(..)
            | a @ ZkSyncVerificationKey::MainVM(..)
            | a @ ZkSyncVerificationKey::CodeDecommittmentsSorter(..)
            | a @ ZkSyncVerificationKey::CodeDecommitter(..)
            | a @ ZkSyncVerificationKey::LogDemuxer(..)
            | a @ ZkSyncVerificationKey::KeccakRoundFunction(..)
            | a @ ZkSyncVerificationKey::Sha256RoundFunction(..)
            | a @ ZkSyncVerificationKey::ECRecover(..)
            | a @ ZkSyncVerificationKey::RAMPermutation(..)
            | a @ ZkSyncVerificationKey::StorageSorter(..)
            | a @ ZkSyncVerificationKey::StorageApplication(..)
            | a @ ZkSyncVerificationKey::EventsSorter(..)
            | a @ ZkSyncVerificationKey::L1MessagesSorter(..)
            | a @ ZkSyncVerificationKey::L1MessagesPubdataHasher(..)
            | a @ ZkSyncVerificationKey::L1MessagesMerklier(..)
            | a @ ZkSyncVerificationKey::InitialWritesPubdataHasher(..)
            | a @ ZkSyncVerificationKey::RepeatedWritesPubdataHasher(..) => {
                // Use algebraic transcript
                use sync_vm::circuit_structures::utils::bn254_rescue_params;
                use sync_vm::recursion::get_prefered_rns_params;
                use sync_vm::recursion::RescueTranscriptForRecursion;

                let sponge_params = bn254_rescue_params();
                let rns_params = get_prefered_rns_params();
                let transcript_params = (&sponge_params, &rns_params);

                let vk = a.as_verification_key();
                let proof = proof.as_proof();
                let is_valid = crate::bellman::plonk::better_better_cs::verifier::verify::<
                    Bn256,
                    _,
                    RescueTranscriptForRecursion<'_>,
                >(vk, proof, Some(transcript_params))
                .expect("must try to verify a proof");

                is_valid
            }
        }
    }
}
