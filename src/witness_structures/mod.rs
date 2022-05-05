use super::*;

pub mod keccak_circuit;
pub mod log_circuit_splitter;

use crate::bellman::Engine;
use crate::encodings::{QueueIntermediateStates, SpongeLikeQueueIntermediateStates};
use sync_vm::scheduler::queues::{
    FixedWidthEncodingGenericQueueStateWitness, FullSpongeLikeQueueStateWitness,
};

pub fn transform_queue_state<E: Engine, const N: usize, const M: usize>(
    witness_state: QueueIntermediateStates<E, N, M>,
) -> FixedWidthEncodingGenericQueueStateWitness<E> {
    let result = FixedWidthEncodingGenericQueueStateWitness::<E> {
        num_items: witness_state.num_items,
        head_state: witness_state.head,
        tail_state: witness_state.tail,
        _marker: std::marker::PhantomData,
    };

    result
}

pub fn transform_sponge_like_queue_state<E: Engine, const M: usize>(
    witness_state: SpongeLikeQueueIntermediateStates<E, 3, M>,
) -> FullSpongeLikeQueueStateWitness<E> {
    let result = FullSpongeLikeQueueStateWitness::<E> {
        length: witness_state.num_items,
        head: witness_state.head,
        tail: witness_state.tail,
        _marker: std::marker::PhantomData,
    };

    result
}
