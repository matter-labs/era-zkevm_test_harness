use super::*;
use crate::tests::simple_tests::asm_tests::run_asm_based_test;

#[test_log::test]
fn test_fat_pointer_erasure() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/ptr/fat_pointer_erasure",
        &[65536, 65537],
        Default::default(),
    )
}
