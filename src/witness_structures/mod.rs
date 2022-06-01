use super::*;

pub mod keccak_circuit;
pub mod log_circuit_splitter;
pub mod ram_circuit;

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

use crate::encodings::*;

pub fn take_queue_state_from_simulator<
    E: Engine, 
    I: OutOfCircuitFixedLengthEncodable<E, N>,
    const N: usize,
    const ROUNDS: usize
>(
    simulator: &QueueSimulator<E, I, N, ROUNDS>
) -> FixedWidthEncodingGenericQueueStateWitness<E> {
    let result = FixedWidthEncodingGenericQueueStateWitness::<E> {
        num_items: simulator.num_items,
        head_state: simulator.head,
        tail_state: simulator.tail,
        _marker: std::marker::PhantomData,
    };

    result
}

pub fn take_sponge_like_queue_state_from_simulator<
    E: Engine, 
    I: OutOfCircuitFixedLengthEncodable<E, N>,
    const N: usize,
    const ROUNDS: usize
>(
    simulator: &SpongeLikeQueueSimulator<E, I, N, 3, ROUNDS>
) -> FullSpongeLikeQueueStateWitness<E> {
    let result = FullSpongeLikeQueueStateWitness::<E> {
        length: simulator.num_items,
        head: simulator.head,
        tail: simulator.tail,
        _marker: std::marker::PhantomData,
    };

    result
}
