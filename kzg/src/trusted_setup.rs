use crate::{KzgSettings, TrustedSetup};

use once_cell::sync::Lazy;

pub(super) static KZG_SETTINGS: Lazy<KzgSettings> = Lazy::new(|| {
    // Taken from the C KZG library: https://github.com/ethereum/c-kzg-4844/blob/main/src/trusted_setup.txt
    const TRUSTED_SETUP: &[u8] = include_bytes!("trusted_setup.json");
    let setup: TrustedSetup = serde_json::from_slice(TRUSTED_SETUP).unwrap();
    KzgSettings::new_from_trusted_setup(setup)
});

#[cfg(test)]
mod tests {
    use zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK;

    use zkevm_circuits::boojum::pairing::{
        bls12_381::{Fr, FrRepr},
        ff::{Field as _, PrimeField as _},
    };

    const FIRST_ROOT_OF_UNITY: FrRepr = FrRepr([
        0xe206da11a5d36306,
        0x0ad1347b378fbf96,
        0xfc3e8acfe0f8245f,
        0x564c0a11a0f704f4,
    ]);

    #[test]
    fn kzg_roots_of_unity_are_correct() {
        let mut value = Fr::from_repr(FIRST_ROOT_OF_UNITY).unwrap();
        for _ in 0..ELEMENTS_PER_4844_BLOCK.ilog2() {
            assert_ne!(value, Fr::one());
            value.mul_assign(&value.clone());
        }
        assert_eq!(value, Fr::one());
    }
}
