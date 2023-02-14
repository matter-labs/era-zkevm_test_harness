use super::*;

#[test_log::test]
fn test_ptr_on_valid_input() {
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
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        ptr.add r1, r2, r1
        ptr.pack r1, r3, r4
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_ptr_add_invalid_0() {
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
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        ptr.add r1, r1, r1
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_ptr_to_global() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .data
        .globl    val                             ; @val
        .p2align    5
    val:
        .cell 0
        .text
        .globl	__entry
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
        ptr.pack r1, r3, r4
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
