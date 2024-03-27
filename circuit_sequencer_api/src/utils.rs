use crate::boojum::{
    algebraic_props::round_function::AlgebraicRoundFunction,
    gadgets::traits::round_function::BuildableCircuitRoundFunction,
};
use circuit_encodings::{
    boojum::{algebraic_props::round_function::AbsorptionModeOverwrite, field::SmallField},
    zkevm_circuits::scheduler::QUEUE_FINAL_STATE_COMMITMENT_LENGTH,
};
use zk_evm::ethereum_types::U256;

pub fn calldata_to_aligned_data(calldata: &Vec<u8>) -> Vec<U256> {
    if calldata.len() == 0 {
        return vec![];
    }
    let mut capacity = calldata.len() / 32;
    if calldata.len() % 32 != 0 {
        capacity += 1;
    }
    let mut result = Vec::with_capacity(capacity);
    let mut it = calldata.chunks_exact(32);
    for el in &mut it {
        let el = U256::from_big_endian(el);
        result.push(el);
    }
    let remainder = it.remainder();
    if remainder.len() != 0 {
        let mut buffer = [0u8; 32];
        buffer[0..remainder.len()].copy_from_slice(remainder);
        let el = U256::from_big_endian(&buffer);
        result.push(el);
    }

    result
}

pub fn finalize_queue_state<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    const N: usize,
>(
    tail: [F; N],
    _round_function: &R,
) -> [F; QUEUE_FINAL_STATE_COMMITMENT_LENGTH] {
    // rescue prime paddings
    let mut to_absorb = vec![];
    to_absorb.extend(tail);
    to_absorb.push(F::ONE);

    let mut state = R::initial_state();
    use crate::boojum::algebraic_props::round_function::absorb_into_state_vararg;
    absorb_into_state_vararg::<F, R, AbsorptionModeOverwrite, 8, 12, 4>(&mut state, &to_absorb);
    let commitment = <R as AlgebraicRoundFunction<F, 8, 12, 4>>::state_into_commitment::<
        QUEUE_FINAL_STATE_COMMITMENT_LENGTH,
    >(&state);

    commitment
}

pub fn finalized_queue_state_as_bytes<F: SmallField>(
    input: [F; QUEUE_FINAL_STATE_COMMITMENT_LENGTH],
) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (dst, src) in result.array_chunks_mut::<8>().zip(input.into_iter()) {
        *dst = src.as_u64_reduced().to_be_bytes();
    }

    result
}
