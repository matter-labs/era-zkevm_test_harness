pub trait TupleFirst {
    fn first(&self) -> u32;
}

impl TupleFirst for u32 {
    fn first(&self) -> u32 {
        *self
    }
}

impl<T> TupleFirst for (u32, T) {
    fn first(&self) -> u32 {
        self.0
    }
}
impl<T, U> TupleFirst for (u32, T, U) {
    fn first(&self) -> u32 {
        self.0
    }
}

use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulator;
use circuit_definitions::encodings::memory_query::QueueWitness;
use circuit_definitions::encodings::memory_query::{CustomMemoryQueueSimulator, MemoryQueueState};

pub type MemoryQueuePerCircuitSimulator<F> =
    CustomMemoryQueueSimulator<F, PerCircuitAccumulator<QueueWitness<F>>>;

pub(crate) mod one_per_circuit_accumulator;
pub(crate) mod per_circuit_accumulator;
