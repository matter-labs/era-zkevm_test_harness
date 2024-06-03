use asm_tests::TemplateDictionary;

use super::*;
use crate::tests::simple_tests::asm_tests::{run_asm_based_test, run_asm_based_test_template};

// For far_call, the first register is holding the 'FarCallABI', which consists of:
// 64 bytes of 'extra data' - [forwarding_byte, shard_id, constructor_call, system_byte, 32 bytes ergs]
// 64 bytes empty.
// 128 bytes of 'fat pointer' - [length, start] [memory_page, offset]

#[test_log::test]
fn test_far_call_read_fat_pointer() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/far_call/read_fat_pointer",
        &[65535],
        Default::default(),
    );
}

#[test_log::test]
fn test_far_call_return_large_data() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/far_call/return_large_data",
        &[65536],
        Default::default(),
    );
}

#[test_log::test]
fn test_far_call_panic_on_return_large_data() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/far_call/panic_on_return_large_data",
        &[65536],
        Default::default(),
    );
}

#[test_log::test]
fn test_far_call_pay_for_memory_growth() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/far_call/pay_for_memory_growth",
        &[65536, 65537],
        Default::default(),
    );
}

#[test_log::test]
fn test_far_call_with_decommit() {
    // In this test, we have a very large bytecode that we try to call.
    // But we don't have enough gas to actually decommit it.

    let garbage = r#"
        nop
    "#
    .repeat(10000);

    let dummy_address = 65536;
    let contracts = Vec::from([(dummy_address.to_string(), dummy_address)]);
    let dictionary: TemplateDictionary = TemplateDictionary::from([("garbage", garbage)]);

    run_asm_based_test_template(
        "src/tests/simple_tests/testdata/far_call/fail_on_decommit",
        &contracts,
        Default::default(),
        Some(&dictionary),
    );
}
