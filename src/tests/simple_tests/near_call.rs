use super::*;
use crate::tests::simple_tests::asm_tests::run_asm_based_test;

#[test_log::test]
fn test_near_call_memory_growth_ret_ok() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/near_call/memory_growth_ret_ok",
        &[65536],
        Options {
            cycle_limit: 100,
            ..Default::default()
        },
    )
}

#[test_log::test]
fn test_near_call_resets_sp() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/near_call/resets_sp",
        &[],
        Default::default(),
    )
}

#[test_log::test]
fn test_near_call_resets_flags() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/near_call/resets_flags",
        &[],
        Default::default(),
    )
}

#[test_log::test]
fn test_near_call_not_rollback_memory() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/near_call/not_rollback_memory",
        &[65536],
        Default::default(),
    )
}

#[test_log::test]
fn test_near_call_limited_ergs() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/near_call/limited_ergs",
        &[65536],
        Default::default(),
    )
}
