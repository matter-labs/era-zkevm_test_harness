use super::*;

#[test_log::test]
fn test_kernel_opcodes() {
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
        context.set_ergs_per_pubdata r2
        context.set_context_u128 r3
        context.inc_tx_num
        add 16, r0, r4
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
