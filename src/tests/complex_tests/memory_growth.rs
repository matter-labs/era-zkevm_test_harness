use super::*;

#[test]
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

    run_and_try_create_witness(asm, 50);
}
