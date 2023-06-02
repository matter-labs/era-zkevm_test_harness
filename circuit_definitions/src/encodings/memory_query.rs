use super::*;
use zk_evm::aux_structures::MemoryQuery;

use zkevm_circuits::ram_permutation::input::{RAM_FULL_KEY_LENGTH, RAM_SORTING_KEY_LENGTH};

pub fn sorting_key(query: &MemoryQuery) -> Key<RAM_SORTING_KEY_LENGTH> {
    let le_words = [
        query.timestamp.0,
        query.location.index.0,
        query.location.page.0,
    ];

    Key(le_words)
}

pub fn comparison_key(query: &MemoryQuery) -> Key<RAM_FULL_KEY_LENGTH> {
    let le_words = [query.location.index.0, query.location.page.0];

    Key(le_words)
}

use zkevm_circuits::base_structures::memory_query::MEMORY_QUERY_PACKED_WIDTH;

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<F, MEMORY_QUERY_PACKED_WIDTH> for MemoryQuery {
    fn encoding_witness(&self) -> [F; MEMORY_QUERY_PACKED_WIDTH] {
        // we assume the fact that capacity of F is quite close to 64 bits
        debug_assert!(F::CAPACITY_BITS >= 56);

        let value = decompose_u256_as_u32x8(self.value);

        // strategy: we use 3 field elements to pack timestamp, decomposition of page, index and r/w flag,
        // and 5 more elements to tightly pack 8xu32 of values

        let v0 = self.timestamp.0.into_field();
        let v1 = self.location.page.0.into_field();
        let v2 = linear_combination(&[
            (self.location.index.0.into_field(), F::ONE),
            (self.rw_flag.into_field(), F::from_u64_unchecked(1u64 << 32)),
            (
                self.value_is_pointer.into_field(),
                F::from_u64_unchecked(1u64 << 33),
            ),
        ]);

        // value. Those in most of the cases will be nops
        let decomposition_5 = value[5].to_le_bytes();
        let decomposition_6 = value[6].to_le_bytes();
        let decomposition_7 = value[7].to_le_bytes();

        let v3 = linear_combination(&[
            (value[0].into_field(), F::ONE),
            (
                decomposition_5[0].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                decomposition_5[1].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                decomposition_5[2].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v4 = linear_combination(&[
            (value[1].into_field(), F::ONE),
            (
                decomposition_5[3].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                decomposition_6[0].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                decomposition_6[1].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v5 = linear_combination(&[
            (value[2].into_field(), F::ONE),
            (
                decomposition_6[2].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                decomposition_6[3].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                decomposition_7[0].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v6 = linear_combination(&[
            (value[3].into_field(), F::ONE),
            (
                decomposition_7[1].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                decomposition_7[2].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                decomposition_7[3].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v7 = value[4].into_field();

        [v0, v1, v2, v3, v4, v5, v6, v7]
    }
}

pub type MemoryQueueSimulator<F> = FullWidthQueueSimulator<
    F,
    MemoryQuery,
    MEMORY_QUERY_PACKED_WIDTH,
    FULL_SPONGE_QUEUE_STATE_WIDTH,
    1,
>;
pub type MemoryQueueState<F> =
    FullWidthQueueIntermediateStates<F, FULL_SPONGE_QUEUE_STATE_WIDTH, 1>;

impl<F: SmallField> CircuitEquivalentReflection<F> for MemoryQuery {
    type Destination = zkevm_circuits::base_structures::memory_query::MemoryQuery<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness {
        use zkevm_circuits::base_structures::memory_query::MemoryQueryWitness;

        MemoryQueryWitness {
            timestamp: self.timestamp.0,
            memory_page: self.location.page.0,
            index: self.location.index.0,
            rw_flag: self.rw_flag,
            value: self.value,
            is_ptr: self.value_is_pointer,
        }
    }
}
