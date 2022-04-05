use sync_vm::vm::primitives::u160;
use zk_evm::ethereum_types::*;
use num_bigint::BigUint;

pub fn u160_from_address(address: Address) -> u160 {
    // transform to limbs

    let lowest = u64::from_be_bytes(address.0[12..20].try_into().unwrap());
    let mid = u64::from_be_bytes(address.0[4..12].try_into().unwrap());
    let high = u32::from_be_bytes(address.0[0..4].try_into().unwrap());

    u160 {
        limb0: lowest,
        limb1: mid,
        limb2: high
    }
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