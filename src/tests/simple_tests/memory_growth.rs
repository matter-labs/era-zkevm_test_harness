use super::*;

// todo: move calls to another contract, so upper bound is not max value

#[test_log::test]
fn test_memory_growth() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 64, r0, r2
        add 8, r0, r3
        st.1 r2, r3
        add 128, r0, r2
        ld.1 r2, r3
        ld.1.inc r2, r4, r2
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_ret_memory_growth() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 128, r0, r1
        shl.s 96, r1, r1
        ret r1
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_ret_memory_growth_out_of_ergs() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 1, r0, r1
        shl.s 32, r1, r1
        sub.s 1, r1, r1
        shl.s 96, r1, r1
        ret r1
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_new_uma_store() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 32, r0, r7
        add 1, r0, r1
        st.1 32, r1
        ld.1 r7, r2
        sub.s! 1, r2, r0
        jump.ne @.panic
        ret r0
    .panic:
        ret.panic r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
