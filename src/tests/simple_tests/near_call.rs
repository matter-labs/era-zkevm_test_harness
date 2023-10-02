use super::*;

#[test_log::test]
fn test_near_call_memory_growth_ret_ok() {
    // far call with 0 bytes of heap memory allocated and 10000 ergs
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
	    .cell 65536
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r1
        shl.s 192, r1, r1
        context.ergs_left r9
        add r9, r0, stack[0]
        add @CPI0_0[0], r0, r2
        far_call r1, r2, @catch_all
        add stack[0], r0, r10
        context.ergs_left r9
        add r9, r0, stack[0]
        ret.ok r0
    catch_all:
        ret.panic r0
    "#;

    // open a near call frame, grow heap and return, then grow heap again in parent frame
    let other_asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r0, @inner, @handler
        sstore r0, r0
        add 64, r0, r2
        add 8, r0, r3
        st.1 r2, r3
        add 128, r0, r2
        ld.1 r2, r3
        ld.1.inc r2, r4, r2
        ret.ok r0
    inner:
        sstore r1, r1
        add 2, r0, r1
        shl.s 136, r1, r1
        add 2000, r1, r1
        shl.s 32, r1, r1
        add 2048, r0, r2
        st.1 r2, r1
        add 128, r1, r1
        shl.s 64, r1, r1
        ld.1 r2, r1
        ret.ok r0
    handler:
        ret.ok r0
    "#;

    let entry_bytecode = Assembly::try_from(asm.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .unwrap();
    use crate::ethereum_types::Address;
    let other_address = Address::from_low_u64_be(1u64 << 16);
    let other_bytecode = Assembly::try_from(other_asm.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .unwrap();
    run_and_try_create_witness_for_extended_state(
        entry_bytecode,
        vec![(other_address, other_bytecode)],
        50,
    );
}
