use super::*;

#[test_log::test]
fn test_meta_opcode() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 32, r0, r2
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
