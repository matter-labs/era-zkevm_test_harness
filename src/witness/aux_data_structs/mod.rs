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

// TODO cleanup
use circuit_definitions::encodings::memory_query::QueueWitness;
use circuit_definitions::encodings::memory_query::{CustomMemoryQueueSimulator, MemoryQueueState};
use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulator;

pub type MemoryQueuePerCircuitSimulator<F> = CustomMemoryQueueSimulator<F, PerCircuitAccumulator::<QueueWitness<F>>>;

pub(crate) mod per_circuit_accumulator;
pub(crate) mod last_per_circuit_accumulator;
pub(crate) mod memory_queue_witnesses_per_ciruit_builder;