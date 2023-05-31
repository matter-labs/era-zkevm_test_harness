use super::*;

#[test_log::test]
fn test_far_call_and_read_fat_pointer() {
    // makes 36 bytes of calldata in aux heap and calls with it, and then returns with fat ptr forward
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
        add 64, r0, r2
        add @CPI0_0[0], r0, r3
        st.2.inc r2, r3, r2
        add @CPI0_0[1], r0, r3
        st.2 r2, r3
        add 2, r0, r1
        shl.s 136, r1, r1
        add 36, r1, r1
        shl.s 32, r1, r1
        add 64, r1, r1
        shl.s 64, r1, r1
        add @CPI0_1[0], r0, r2
        far_call r1, r2, @catch_all
        ret.ok r0
    catch_all:
        ret.panic r0
    "#;

    // this one reads some calldata, including partially beyond the bound,
    // and completely beyond the bound, and returns
    let other_asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r1, r1
        event.first r1, r0
        to_l1.first r0, r1
        ld.inc r1, r2, r1
        ld.inc r1, r3, r1
        ld r1, r4
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

#[test_log::test]
fn test_far_call_and_return_large_data() {
    // makes 36 bytes of calldata in aux heap and calls with it
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
        add 64, r0, r2
        add @CPI0_0[0], r0, r3
        st.2.inc r2, r3, r2
        add @CPI0_0[1], r0, r3
        st.2 r2, r3
        add 2, r0, r1
        shl.s 136, r1, r1
        add 36, r1, r1
        shl.s 32, r1, r1
        add 64, r1, r1
        shl.s 64, r1, r1
        add @CPI0_1[0], r0, r2
        far_call r1, r2, @catch_all
        add 1, r0, r2
        shl.s 224, r2, r2
        ptr.pack r1, r2, r1
        ret.ok r1
    catch_all:
        ret.panic r0
    "#;

    // tries to return 2kb of data from the heap
    let other_asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r1, r1
        event.first r1, r0
        to_l1.first r0, r1
        add 2, r0, r1
        shl.s 136, r1, r1
        add 2048, r1, r1
        shl.s 32, r1, r1
        add 128, r1, r1
        shl.s 64, r1, r1
        ret.ok r1
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

#[test_log::test]
fn test_far_call_and_panic_on_return_large_data() {
    // makes 36 bytes of calldata in aux heap and calls with it
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
        add 64, r0, r2
        add @CPI0_0[0], r0, r3
        st.2.inc r2, r3, r2
        add @CPI0_0[1], r0, r3
        st.2 r2, r3
        add 2, r0, r1
        shl.s 232, r1, r1
        add 2000, r0, r15
        shl.s 192, r15, r15
        add r1, r15, r15
        add 36, r0, r1
        shl.s 32, r1, r1
        add 64, r1, r1
        shl.s 64, r1, r1
        add r1, r15, r1
        add @CPI0_1[0], r0, r2
        far_call r1, r2, @catch_all
        add 1, r0, r2
        shl.s 224, r2, r2
        ptr.pack r1, r2, r1
        ret.ok r1
    catch_all:
        ret.panic r0
    "#;

    // tries to return 16kb of data from the heap
    let other_asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        sstore r1, r1
        event.first r1, r0
        to_l1.first r0, r1
        add 0, r0, r1
        shl.s 136, r1, r1
        add 16000, r1, r1
        shl.s 32, r1, r1
        add 128, r1, r1
        shl.s 64, r1, r1
        ret.ok r1
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

#[test_log::test]
fn test_far_call_pay_for_memory_growth() {
    // perform far call with limited ergs
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
        far_call r1, r2, @catch_all
        add stack[0], r0, r10
        context.ergs_left r9
        add r9, r0, stack[0]
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
        add 100, r0, r1
        shl.s 96, r1, r1
        add 256, r1, r1
        shl.s 32, r1, r1
        add 128, r1, r1
        shl.s 64, r1, r1
        context.ergs_left r9
        add r9, r0, stack[0]
        add @CPI0_0[0], r0, r2
        far_call r1, r2, @catch_all
        add stack[0], r0, r10
        context.ergs_left r9
        add r9, r0, stack[0]
        shl.s 96, r1, r1
        ret.ok r1
    catch_all:
        ret.panic r0
    "#;

    // just return
    let other_asm_1 = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        context.ergs_left r9
        add r9, r0, stack[0]
        add stack[0], r0, r10
        add 64, r0, r1
        shl.s 96, r1, r1
        ret.ok r1
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

    let other_address_1 = Address::from_low_u64_be((1u64 << 16) + 1);
    // let other_address_1 = Address::from_low_u64_be(1u64 << 16 + 1);
    let other_bytecode_1 = Assembly::try_from(other_asm_1.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .unwrap();

    run_and_try_create_witness_for_extended_state(
        entry_bytecode,
        vec![
            (other_address, other_bytecode),
            (other_address_1, other_bytecode_1),
        ],
        50,
    );
}

#[test_log::test]
fn test_far_call_not_enough_ergs() {
    // try to pass 0xffffffff bytes

    // first we limit ergs
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
	    .cell 340282366841710300949110269838224261120
    CPI0_1:
	    .cell 65536
        .text
        .globl	__entry
    __entry:
    .main:
        add @CPI0_0[0], r0, r1
        add 1234, r0, r1,
        shl.s 192, r1, r1
        add 1, r0, r2
        shl.s 16, r2, r2
        far_call r1, r2, @catch_all
        ret.ok r0
    catch_all:
        sstore r1, r1
        event.first r1, r0
        to_l1.first r0, r1
        ret.ok r0
        ret.panic r0
    "#;

    // this one reads some calldata, including partially beyond the bound,
    // and completely beyond the bound, and returns
    let other_asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
	    .cell 340282366841710300949110269838224261120
        .text
        .globl	__entry
    __entry:
    .main:
        add @CPI0_0[0], r0, r1
        add 1, r0, r2
        shl.s 16, r2, r2
        far_call r1, r2, @catch_all
        ret.ok r0
        sstore r1, r1
        event.first r1, r0
        to_l1.first r0, r1
        ld.inc r1, r2, r1
        ld.inc r1, r3, r1
        ld r1, r4
        ret.ok r0
    catch_all:
        sstore r1, r1
        event.first r1, r0
        to_l1.first r0, r1
        ret.ok r0
        ret.panic r0
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