use super::*;
use zk_evm::aux_structures::DecommittmentQuery;

use zkevm_circuits::base_structures::decommit_query::DECOMMIT_QUERY_PACKED_WIDTH;

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<F, DECOMMIT_QUERY_PACKED_WIDTH>
    for DecommittmentQuery
{
    fn encoding_witness(&self) -> [F; DECOMMIT_QUERY_PACKED_WIDTH] {
        debug_assert!(F::CAPACITY_BITS >= 56);

        let code_hash = decompose_u256_as_u32x8(self.hash);

        // we assume that page bytes are known, so it'll be nop anyway
        let page_bytes = self.memory_page.0.to_le_bytes();
        let timestamp_bytes = self.timestamp.0.to_le_bytes();

        let v0 = linear_combination(&[
            (code_hash[0].into_field(), F::ONE),
            (
                page_bytes[0].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                page_bytes[1].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                page_bytes[2].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v1 = linear_combination(&[
            (code_hash[1].into_field(), F::ONE),
            (
                page_bytes[3].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                timestamp_bytes[0].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                timestamp_bytes[1].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v2 = linear_combination(&[
            (code_hash[2].into_field(), F::ONE),
            (
                timestamp_bytes[2].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                timestamp_bytes[3].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                self.is_fresh.into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v3 = code_hash[3].into_field();
        let v4 = code_hash[4].into_field();
        let v5 = code_hash[5].into_field();
        let v6 = code_hash[6].into_field();
        let v7 = code_hash[7].into_field();

        [v0, v1, v2, v3, v4, v5, v6, v7]
    }
}

pub type DecommittmentQueueSimulator<F> = FullWidthQueueSimulator<
    F,
    DecommittmentQuery,
    DECOMMIT_QUERY_PACKED_WIDTH,
    FULL_SPONGE_QUEUE_STATE_WIDTH,
    1,
>;
pub type DecommittmentQueueState<F> =
    FullWidthQueueIntermediateStates<F, FULL_SPONGE_QUEUE_STATE_WIDTH, 1>;

impl<F: SmallField> CircuitEquivalentReflection<F> for DecommittmentQuery {
    type Destination = zkevm_circuits::base_structures::decommit_query::DecommitQuery<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness {
        use zkevm_circuits::base_structures::decommit_query::DecommitQueryWitness;

        DecommitQueryWitness {
            timestamp: self.timestamp.0,
            code_hash: self.hash,
            is_first: self.is_fresh,
            page: self.memory_page.0,
        }
    }
}
