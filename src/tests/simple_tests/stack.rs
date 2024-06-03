use super::*;
use crate::tests::simple_tests::asm_tests::run_asm_based_test;

#[test_log::test]
fn test_stack_addressing_modes() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/stack/addressing",
        &[],
        Default::default(),
    )
}

#[test_log::test]
fn test_stack_overflow() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/stack/overflow",
        &[],
        Default::default(),
    )
}
