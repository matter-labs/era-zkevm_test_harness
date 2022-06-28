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

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<E> for ZkSyncUniformCircuitCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit<E, W> = ZkSyncUniformCircuitCircuitInstance<E, VmMainInstanceSynthesisFunction<E, W>>; 