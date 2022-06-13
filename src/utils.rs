use std::ops::Add;

use crate::ff::PrimeField;
use num_bigint::BigUint;
use sync_vm::vm::primitives::u160;
use zk_evm::{address_to_u256, ethereum_types::*};

pub fn u160_from_address(address: Address) -> u160 {
    // transform to limbs

    let lowest = u64::from_be_bytes(address.0[12..20].try_into().unwrap());
    let mid = u64::from_be_bytes(address.0[4..12].try_into().unwrap());
    let high = u32::from_be_bytes(address.0[0..4].try_into().unwrap());

    u160 {
        limb0: lowest,
        limb1: mid,
        limb2: high,
    }
}

pub fn address_from_u160(value: u160) -> Address {
    // transform to limbs

    let lowest = value.limb0.to_be_bytes();
    let mid = value.limb1.to_be_bytes();
    let highest = value.limb2.to_be_bytes();

    let mut result = Address::zero();
    result[0..4].copy_from_slice(&highest);
    result[4..12].copy_from_slice(&mid);
    result[12..].copy_from_slice(&lowest);

    result
}

pub fn biguint_from_u256(value: U256) -> BigUint {
    let mut result = BigUint::from(value.0[3]);
    result <<= 64u32;
    result += BigUint::from(value.0[2]);
    result <<= 64u32;
    result += BigUint::from(value.0[1]);
    result <<= 64u32;
    result += BigUint::from(value.0[0]);

    result
}

pub fn address_to_fe<F: PrimeField>(value: Address) -> F {
    let value = address_to_u256(&value);
    u256_to_fe::<F>(value)
}

pub fn u256_to_fe<F: PrimeField>(value: U256) -> F {
    let num_bits = value.bits();
    assert!(num_bits <= F::CAPACITY as usize);

    let mut repr = F::zero().into_repr();
    repr.as_mut()[0] = value.0[0];
    repr.as_mut()[1] = value.0[1];
    repr.as_mut()[2] = value.0[2];
    repr.as_mut()[3] = value.0[3];

    F::from_repr(repr).unwrap()
}

pub fn calldata_to_aligned_data(calldata: &Vec<u8>) -> Vec<U256> {
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
    let mut buffer = [0u8; 32];
    buffer[0..it.remainder().len()].copy_from_slice(it.remainder());
    let el = U256::from_big_endian(&buffer);
    result.push(el);

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