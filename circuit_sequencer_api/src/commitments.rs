use crate::{
    boojum::{
        algebraic_props::round_function::AlgebraicRoundFunction, field::SmallField,
        gadgets::traits::round_function::*,
    },
    utils::{calldata_to_aligned_data, finalize_queue_state, finalized_queue_state_as_bytes},
};
use circuit_encodings::{boojum::field::goldilocks::GoldilocksField, *};
use zk_evm::aux_structures::LogQuery;

pub fn initial_heap_content_commitment<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    bootloader_heap_data: &Vec<u8>,
    round_function: &R,
) -> [u8; 32] {
    let heap_writes = calldata_to_aligned_data(bootloader_heap_data);

    use circuit_encodings::memory_query::MemoryQueueSimulator;
    use zk_evm::abstractions::*;
    use zk_evm::aux_structures::*;

    let mut memory_queue = MemoryQueueSimulator::empty();

    for (idx, el) in heap_writes.into_iter().enumerate() {
        let query = MemoryQuery {
            timestamp: Timestamp(0),
            location: MemoryLocation {
                memory_type: MemoryType::Heap,
                page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE),
                index: MemoryIndex(idx as u32),
            },
            rw_flag: true,
            value: el,
            value_is_pointer: false,
        };
        memory_queue.push(query, round_function);
    }

    let finalized_state = finalize_queue_state(memory_queue.tail, round_function);
    finalized_queue_state_as_bytes(finalized_state)
}

pub fn initial_heap_content_commitment_fixed(bootloader_heap_data: &Vec<u8>) -> [u8; 32] {
    initial_heap_content_commitment::<GoldilocksField, ZkSyncDefaultRoundFunction>(
        bootloader_heap_data,
        &ZkSyncDefaultRoundFunction::default(),
    )
}

pub fn events_queue_commitment<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    sorted_and_deduplicated_events: &Vec<LogQuery>,
    round_function: &R,
) -> [u8; 32] {
    let mut queue = LogQueueSimulator::empty();

    for el in sorted_and_deduplicated_events.iter() {
        queue.push(*el, round_function);
    }

    let finalized_state = finalize_queue_state(queue.tail, round_function);
    finalized_queue_state_as_bytes(finalized_state)
}

pub fn events_queue_commitment_fixed(sorted_and_deduplicated_events: &Vec<LogQuery>) -> [u8; 32] {
    events_queue_commitment::<GoldilocksField, ZkSyncDefaultRoundFunction>(
        sorted_and_deduplicated_events,
        &ZkSyncDefaultRoundFunction::default(),
    )
}
