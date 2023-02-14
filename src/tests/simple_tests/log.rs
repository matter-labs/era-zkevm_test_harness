use super::*;

#[test_log::test]
fn test_out_of_ergs_l1_message() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        context.set_ergs_per_pubdata r10
        near_call r1, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        to_l1 r0, r1
        ret.ok r0
    handler:
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_write_same_value() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r0, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        sstore r1, r0
        ret.ok r0
    handler:
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_rollback_to_same_value_no_reads() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r0, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        ret.panic r0
    handler:
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_rollback_to_same_value_with_reads() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r1, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        ret.panic r0
    handler:
    add 10000, r0, r1
        sload r1, r2
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
