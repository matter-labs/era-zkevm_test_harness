        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 32, r0, r1
        ; should revert with out of ergs inside
        near_call r1, @inner, @expected_out_of_ergs
        revert("Near call not reverted")

    inner:
        sstore r0, r0
        add 64, r0, r3
        st.1.inc r2, r3, r2
        ret.ok r0

    expected_out_of_ergs:
        context.ergs_left r15
        jump @check_limited_ok

    check_limited_ok:
        add 15000, r0, r1
        ; should not revert with out of ergs inside
        near_call r1, @inner, @panic
        context.ergs_left r15
        ret.ok r0

    panic:
        ret.panic r0