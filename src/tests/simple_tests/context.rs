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
        add 64, r0, r3
        st.1.inc r2, r3, r2
        st.2.inc r2, r3, r2
        context.set_ergs_per_pubdata r2
        context.set_context_u128 r3
        context.inc_tx_num
        context.meta r5
        context.sp r6
        context.ergs_left r7
        context.this r8
        context.caller r9
        context.code_source r10
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}
