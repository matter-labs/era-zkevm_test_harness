use super::*;

#[test_log::test]
fn test_stack_push_pop_addressing() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 1, r0, stack[0]
        add stack[0], r0, r2
        sub.s! 1, r2, r0
        jump.ne @.panic
        ret.ok r0
    .panic:
        ret.panic r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
