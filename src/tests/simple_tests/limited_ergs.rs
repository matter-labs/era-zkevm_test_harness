use super::*;

#[test_log::test]
fn test_limited_ergs_0() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 32, r0, r1
        near_call r1, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        sstore r0, r0
        event.first r0, r0
        add 64, r0, r3
        st.1.inc r2, r3, r2
        ret.ok r0
    handler:
        ret.panic r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
