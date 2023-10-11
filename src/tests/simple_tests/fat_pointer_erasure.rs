use super::*;

#[test_log::test]
fn test_fat_pointer_erasure() {
    // perform far call with limited ergs. create a fat pointer and clone it before VM designates
    // it as one. then perform a sub and if fat pointer == fat pointer clone then we panic
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
	    .cell 30272441630670900764332283662402067049651745785153368133042924362431065855
        .cell 30272434434303437454318367229716471635614919446304865000139367529706422272
    CPI0_1:
	    .cell 65536
        .text
        .globl	__entry
    __entry:
    .main:
        add 1000, r0, r1
        shl.s 192, r1, r1
        add @CPI0_1[0], r0, r2
        context.ergs_left r9
        add r9, r0, stack[0]
        add r0, r1, r4
        far_call r1, r2, @catch_all
        add stack[0], r0, r10
        context.ergs_left r9
        add r9, r0, stack[0]
        sub! r1, r4, r5
        jump.eq @catch_all
        ret.ok r0
    catch_all:
        ret.panic r0
    "#;

    // far call using 256 bytes of data and pass 100 ergs
    let other_asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
	    .cell 65537
        .text
        .globl	__entry
    __entry:
    .main:
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
