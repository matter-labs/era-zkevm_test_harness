use super::*;

// should follow in the same sequence as we will logically process sequences
pub mod vm_main;
pub mod sort_code_decommits;
pub mod code_decommitter;
pub mod log_demux;
// pub mod keccak_round_function;
// pub mod sha256_round_function;
// pub mod ecrecover;
pub mod ram_permutation;
pub mod storage_sort_dedup;
// pub mod storage_apply;
pub mod events_sort_dedup;
// pub mod l1_messages_sort_dedup; // equal to one 
pub mod l1_messages_merklize;
pub mod storage_initial_writes_pubdata_hasher;
pub mod storage_repeated_writes_pubdata_hasher;

pub use self::vm_main::VmMainInstanceSynthesisFunction;
pub use self::sort_code_decommits::CodeDecommittmentsSorterSynthesisFunction;
pub use self::code_decommitter::CodeDecommitterInstanceSynthesisFunction;
pub use self::log_demux::LogDemuxInstanceSynthesisFunction;
pub use self::ram_permutation::RAMPermutationInstanceSynthesisFunction;
pub use self::storage_sort_dedup::StorageSortAndDedupInstanceSynthesisFunction;
pub use self::events_sort_dedup::EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction;
pub use self::l1_messages_merklize::MessagesMerklizerInstanceSynthesisFunction;
pub use self::storage_initial_writes_pubdata_hasher::StorageInitialWritesRehasherInstanceSynthesisFunction;
pub use self::storage_repeated_writes_pubdata_hasher::StorageRepeatedWritesRehasherInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<E> for ZkSyncUniformCircuitCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<E, W> = ZkSyncUniformCircuitCircuitInstance<E, VmMainInstanceSynthesisFunction<E, W>>; 
pub type CodeDecommittsSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, CodeDecommittmentsSorterSynthesisFunction>;
pub type CodeDecommitterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, CodeDecommitterInstanceSynthesisFunction>;
pub type LogDemuxerCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, LogDemuxInstanceSynthesisFunction>;
pub type RAMPermutationCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, RAMPermutationInstanceSynthesisFunction>;
pub type StorageSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageSortAndDedupInstanceSynthesisFunction>;
pub type EventsSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction>;
pub type L1MessagesSorterCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction>;
pub type L1MessagesMerklizerCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, MessagesMerklizerInstanceSynthesisFunction>;
pub type InitialStorageWritesPubdataHasherCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageInitialWritesRehasherInstanceSynthesisFunction>;
pub type RepeatedStorageWritesPubdataHasherCircuit<E> = ZkSyncUniformCircuitCircuitInstance<E, StorageRepeatedWritesRehasherInstanceSynthesisFunction>;