use crate::zk_evm::abstractions::Storage;
use crate::zk_evm::reference_impls::decommitter::SimpleDecommitter;
use crate::zk_evm::reference_impls::event_sink::InMemoryEventSink;
use crate::zk_evm::zk_evm_abstractions::precompiles::DefaultPrecompilesProcessor;
use crate::zk_evm::zkevm_opcode_defs::system_params::VM_INITIAL_FRAME_ERGS;
use std::hash::Hash;

use derivative::Derivative;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default, Hash, PartialEq)]
pub struct GeometryConfig {
    pub cycles_per_vm_snapshot: u32,
    pub cycles_per_log_demuxer: u32,
    pub cycles_per_storage_sorter: u32,
    pub cycles_per_events_or_l1_messages_sorter: u32,
    pub cycles_per_ram_permutation: u32,
    pub cycles_code_decommitter_sorter: u32,
    pub cycles_per_code_decommitter: u32,
    pub cycles_per_storage_application: u32,
    pub cycles_per_keccak256_circuit: u32,
    pub cycles_per_sha256_circuit: u32,
    pub cycles_per_ecrecover_circuit: u32,

    pub limit_for_l1_messages_pudata_hasher: u32,
}

//use crate::entry_point::initial_out_of_circuit_context;
use crate::ethereum_types::Address;
use crate::zk_evm::block_properties::BlockProperties;
use crate::zk_evm::reference_impls::memory::SimpleMemory;
use crate::zk_evm::vm_state::{PrimitiveValue, VmState};
use crate::zk_evm::zkevm_opcode_defs::*;
