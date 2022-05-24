use super::*;

use sync_vm::glue::memory_queries_validity::ram_permutation_inout::RamPermutationCycleInputOutputWitness;
use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;
use sync_vm::scheduler::queues::RawMemoryQuery;

pub struct RamPermutationCircuitInstanceWitness<E: Engine> {
    pub closed_form_input: RamPermutationCycleInputOutputWitness<E>,
    pub unsorted_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness<E, RawMemoryQuery<E>, 2, 3>,
    pub sorted_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness<E, RawMemoryQuery<E>, 2, 3>,
}