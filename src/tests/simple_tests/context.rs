use super::*;
use crate::tests::simple_tests::asm_tests::run_asm_based_test;

// TODO return value of "meta" opcode isn't checked
#[test_log::test]
fn test_meta_opcode() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/meta_opcode",
        &[],
        Default::default(),
    )
}
