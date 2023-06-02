use crate::zk_evm::aux_structures::*;
use crate::zk_evm::ethereum_types::*;
use crate::zk_evm::vm_state::CallStackEntry;
use crate::zk_evm::vm_state::VmState;
use crate::zk_evm::zkevm_opcode_defs::system_params::INITIAL_FRAME_FORMAL_EH_LOCATION;
use crate::zk_evm::zkevm_opcode_defs::*;

use super::*;

// Define initial contexts to work with

pub fn initial_out_of_circuit_context(
    initial_pc: u16,
    initial_ergs: u32,
    this_address: Address,
    msg_sender: Address,
    code_address: Address,
) -> CallStackEntry {
    CallStackEntry {
        this_address,
        msg_sender,
        code_address,
        base_memory_page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_BASE_PAGE),
        code_page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_CODE_PAGE),
        sp: INITIAL_SP_ON_FAR_CALL as u16,
        pc: initial_pc,
        exception_handler_location: INITIAL_FRAME_FORMAL_EH_LOCATION,
        ergs_remaining: initial_ergs,
        this_shard_id: 0,
        caller_shard_id: 0,
        code_shard_id: 0,
        is_static: false,
        is_local_frame: false,
        context_u128_value: 0,
        heap_bound: u32::MAX,     // so bootloader doesn't pay for resizes
        aux_heap_bound: u32::MAX, // so bootloader doesn't pay for resizes
    }
}

use crate::zk_evm::block_properties::BlockProperties;

pub fn create_out_of_circuit_global_context(
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
) -> BlockProperties {
    BlockProperties {
        default_aa_code_hash,
        zkporter_is_available,
    }
}
