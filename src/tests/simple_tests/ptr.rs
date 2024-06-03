use super::*;
use crate::tests::simple_tests::asm_tests::run_asm_based_test;
use crate::tests::utils::preprocess_asm::asm_with_default_config;

#[test_log::test]
fn test_ptr_add_valid_input() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/ptr/ptr_add_valid_input",
        &[],
        Default::default(),
    );
}

#[test_log::test]
fn test_ptr_add_invalid_1_pointer() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/ptr/ptr_add_invalid_1_pointer",
        &[],
        Default::default(),
    );
}

#[test_log::test]
fn test_ptr_add_max_offset() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 1, r0, r2
        shl.s 32, r2, r2
        near_call r0, @should_panic, @handler
        ret.panic r0
    should_panic:
        ; trying to use MAX_OFFSET as second input for ptr.add
        ptr.add r1, r2, r3
    handler:
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_add_max_offset_minus_one() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 1, r0, r2
        shl.s 32, r2, r2
        sub.s 1, r2, r2
        ; trying to use MAX_OFFSET - 1 as second input for ptr.add
        ptr.add r1, r2, r3
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_add_overflow_offset() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 1, r0, r2
        shl.s 31, r2, r2
        ptr.add r1, r2, r1
        near_call r0, @should_panic, @handler
        ret.panic r0
    should_panic:
        ; trying to overflow offset in pointer
        ptr.add r1, r2, r1
    handler:
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_add_invalid_0_number() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        near_call r0, @should_panic, @handler
        ret.panic r0
    should_panic:
        ; trying to use number as first input for ptr.add
        ptr.add r3, r2, r3
        ret.ok r0
    handler:
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_sub_valid_input() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        ptr.add r1, r2, r1
        ptr.sub r1, r2, r1
        ptr.pack r1, r3, r4
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_sub_invalid_1_pointer() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        near_call r0, @should_panic, @handler
        ret.panic r0
    should_panic:
        ; trying to sub pointer from pointer
        ptr.sub r1, r1, r1
    handler:
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_sub_invalid_0_number() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        near_call r0, @should_panic, @handler
        ret.panic r0
    should_panic:
        ; trying to use number as first input for ptr.sub
        ptr.sub r3, r2, r3
    handler:
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_sub_overflow_offset() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 1, r0, r2
        shl.s 31, r2, r2
        near_call r0, @should_panic, @handler
        ret.panic r0
    should_panic:
        ; trying to overflow offset in pointer
        ptr.sub r1, r2, r1
    handler:
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_to_global() {
    let asm = asm_with_default_config(
        r#"
        .data
        .globl    val                             ; @val
    val:
        .cell 0
        .text
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        ptr.add r1, r0, stack[@val]
        ptr.add r1, r0, r1
        ptr.sub r1, r0, stack[@val]
        ptr.sub r1, r0, r1
        ptr.pack r1, r3, r4
        ret.ok r0
    "#,
    );

    run_and_try_create_witness_inner(&asm, 50);
}

#[test_log::test]
fn test_ptr_erasure_not_kernel() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/ptr/ptr_erasure_not_kernel",
        &[65536, 65534],
        Default::default(),
    )
}

#[test_log::test]
fn test_ptr_erasure_kernel() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/ptr/ptr_erasure_kernel",
        &[65533, 65534],
        Default::default(),
    )
}

#[test_log::test]
fn test_ptr_add_src0_erasure() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/ptr/ptr_add_src0_erasure",
        &[65537],
        Default::default(),
    )
}
