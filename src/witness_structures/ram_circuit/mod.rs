use super::*;

use sync_vm::franklin_crypto::plonk::circuit::bigint::biguint_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQueryWitness;
use sync_vm::glue::memory_queries_validity::ram_permutation_inout::RamPermutationCycleInputOutputWitness;
use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;

// pub struct RamPermutationCircuitInstanceWitness<E: Engine> {
//     pub closed_form_input: RamPermutationCycleInputOutputWitness<E>,
//     pub unsorted_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness<E, RawMemoryQuery<E>, 2, 3>,
//     pub sorted_queue_witness: FixedWidthEncodingSpongeLikeQueueWitness<E, RawMemoryQuery<E>, 2, 3>,
// }

use zk_evm::aux_structures::MemoryQuery;
use num_bigint::BigUint;

pub fn transform_raw_memory_query_witness<E: Engine>(
    witness: &MemoryQuery
) -> RawMemoryQueryWitness<E> {
    let value_residual = witness.value.0[3];
    let value = biguint_from_u256(witness.value);
    let value_low = value.clone() % (BigUint::from(1u64) << 192);
    let value_low = biguint_to_fe::<E::Fr>(value_low);

    RawMemoryQueryWitness { 
        timestamp: witness.timestamp.0, 
        memory_page: witness.location.page.0, 
        memory_index: witness.location.index.0, 
        rw_flag: witness.rw_flag, 
        value_residual,
        value: value_low,
        _marker: std::marker::PhantomData
    }
}