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

use crate::boojum::pairing::bls12_381::fr::{Fr, FrRepr};
use crate::sha3::{Digest, Keccak256};
use crate::zkevm_circuits::eip_4844::input::EIP4844OutputDataWitness;
use crate::zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK;
use crate::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;
use circuit_definitions::franklin_crypto::bellman::Field;
use circuit_definitions::franklin_crypto::bellman::PrimeField;

pub fn generate_eip4844_witness<F: SmallField>(
    blob: Vec<u8>,
) -> (
    [[u8; 31]; ELEMENTS_PER_4844_BLOCK],
    [u8; 32],
    [u8; 32],
    [u8; 32],
) {
    // create blob array from vec
    assert!(blob.len() <= 31 * 4096);
    let mut blob_arr = [[0u8; 31]; ELEMENTS_PER_4844_BLOCK];
    blob.chunks(31).enumerate().for_each(|(i, chunk)| {
        if chunk.len() == 31 {
            blob_arr[i].copy_from_slice(chunk);
        } else {
            blob_arr[i][..chunk.len()].copy_from_slice(chunk);
        }
    });

    // compute versioned hash
    let blob_fr = blob_arr
        .iter()
        .map(|chunk| {
            let repr = chunk
                .chunks(8)
                .map(|bytes| {
                    let mut arr = [0u8; 8];
                    for (i, b) in bytes.iter().enumerate() {
                        arr[i] = *b;
                    }
                    u64::from_le_bytes(arr)
                })
                .collect::<Vec<u64>>();
            Fr::from_repr(FrRepr([repr[0], repr[1], repr[2], repr[3]]))
                .expect("31 bytes should create valid field element")
        })
        .collect::<Vec<Fr>>();

    use crate::kzg::compute_commitment;
    use circuit_definitions::boojum::pairing::CurveAffine;
    let commitment = compute_commitment(&blob_fr);
    let mut versioned_hash: [u8; 32] = Keccak256::digest(&commitment.into_compressed())
        .try_into()
        .expect("should be able to create an array from a keccak digest");
    versioned_hash[0] = 1;

    // compute linear hash
    let linear_hash: [u8; 32] =
        Keccak256::digest(&blob_arr.clone().into_iter().flatten().collect::<Vec<u8>>())
            .try_into()
            .expect("should be able to create an array from a keccak digest");

    // compute output commitment
    let evaluation_point = &Keccak256::digest(
        &linear_hash
            .iter()
            .chain(&versioned_hash)
            .map(|x| *x)
            .collect::<Vec<u8>>(),
    )[16..];
    let evaluation_repr =
        u128::from_be_bytes(evaluation_point.try_into().expect("should have 16 bytes"));
    let evaluation_point_fe = Fr::from_repr(FrRepr([
        evaluation_repr as u64,
        (evaluation_repr >> 64) as u64,
        0u64,
        0u64,
    ]))
    .expect("should have a valid field element from 16 bytes");
    let opening_value = blob_arr
        .iter()
        .enumerate()
        .fold(Fr::zero(), |mut acc, (i, x)| {
            let repr = x
                .chunks(8)
                .map(|bytes| {
                    let mut arr = [0u8; 8];
                    for (i, b) in bytes.iter().enumerate() {
                        arr[i] = *b;
                    }
                    u64::from_le_bytes(arr)
                })
                .collect::<Vec<u64>>();
            let el = Fr::from_repr(FrRepr([repr[0], repr[1], repr[2], repr[3]]))
                .expect("31 bytes should create valid field element");
            acc.add_assign(&el);
            if i != ELEMENTS_PER_4844_BLOCK - 1 {
                acc.mul_assign(&evaluation_point_fe);
            }
            acc
        });
    let opening_value_bytes = opening_value
        .into_repr()
        .0
        .iter()
        .rev()
        .flat_map(|el| el.to_be_bytes())
        .collect::<Vec<u8>>();

    let output_hash: [u8; 32] = Keccak256::digest(
        versioned_hash
            .iter()
            .chain(evaluation_point.iter())
            .chain(opening_value_bytes.iter())
            .map(|x| *x)
            .collect::<Vec<u8>>(),
    )
    .try_into()
    .expect("should be able to convert genericarray to array");

    (blob_arr, linear_hash, versioned_hash, output_hash)
}
