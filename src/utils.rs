use std::ops::Add;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::config::*;
use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::{algebraic_props::round_function, field::SmallField};
use crate::witness::tree::BinaryHasher;
use crate::zk_evm::{address_to_u256, ethereum_types::*};
use circuit_definitions::encodings::{BytesSerializable, QueueSimulator};

pub fn u64_as_u32_le(value: u64) -> [u32; 2] {
    [value as u32, (value >> 32) as u32]
}

pub fn u128_as_u32_le(value: u128) -> [u32; 4] {
    [
        value as u32,
        (value >> 32) as u32,
        (value >> 64) as u32,
        (value >> 96) as u32,
    ]
}

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

pub fn bytes_to_u32_le<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u32; M] {
    assert!(M > 0);
    assert!(M * 4 == N);

    let mut result = [0u32; M];

    for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        result[idx] = word;
    }

    result
}

pub fn bytes_to_u128_le<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u128; M] {
    assert!(M > 0);
    assert!(M * 16 == N);

    let mut result = [0u128; M];

    for (idx, chunk) in bytes.chunks_exact(16).enumerate() {
        let word = u128::from_le_bytes(chunk.try_into().unwrap());
        result[idx] = word;
    }

    result
}

pub fn binary_merklize_set<
    'a,
    const N: usize,
    T: BytesSerializable<N> + 'a,
    H: BinaryHasher<32>,
    I: Iterator<Item = &'a T> + ExactSizeIterator,
>(
    input: I,
    tree_size: usize,
) -> [u8; 32] {
    let input_len = input.len();
    assert!(tree_size >= input_len);
    assert!(tree_size.is_power_of_two());
    let mut leaf_hashes = Vec::with_capacity(tree_size);

    for el in input {
        let encoding = el.serialize();
        let leaf_hash = H::leaf_hash(&encoding);
        leaf_hashes.push(leaf_hash);
    }

    let trivial_leaf_hash = H::leaf_hash(&[0u8; N]);
    leaf_hashes.resize(tree_size, trivial_leaf_hash);

    let mut previous_layer_hashes = leaf_hashes;
    let mut node_hashes = vec![];

    let num_layers = tree_size.trailing_zeros();

    for level in 0..num_layers {
        for pair in previous_layer_hashes.chunks(2) {
            let new_node_hash = H::node_hash(level as usize, &pair[0], &pair[1]);
            node_hashes.push(new_node_hash);
        }

        let p = std::mem::replace(&mut node_hashes, vec![]);
        previous_layer_hashes = p;
    }

    assert_eq!(previous_layer_hashes.len(), 1);
    let root = previous_layer_hashes[0];

    root
}

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::gadgets::traits::round_function::BuildableCircuitRoundFunction;
use crate::zkevm_circuits::scheduler::QUEUE_FINAL_STATE_COMMITMENT_LENGTH;
use circuit_definitions::encodings::OutOfCircuitFixedLengthEncodable;

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
