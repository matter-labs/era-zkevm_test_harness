        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; set LT flag
        sub.s! 1, r0, r0
        jump.lt @check_lt

        revert("LT flag not set")

    check_lt:
        near_call r0, @check_flags, @panic

        ; set GT flag
        sub! 1, r0, r0
        jump.gt @check_gt
        revert("GT flag not set")

    check_gt:
        near_call r0, @check_flags, @panic

        ; set EQ flag
        sub! 0, r0, r0
        jump.eq @check_eq
        revert("EQ flag not set")

    check_eq:
        near_call r0, @check_flags, @panic

        ret.ok r0


    check_flags:
        ; check LT flag
        jump.lt @lt_not_reset

        ; check GT flag
        jump.gt @lt_not_reset

        ; check EQ flag
        jump.eq @eq_not_reset

        ret.ok r0


    lt_not_reset:
        revert("LT flag not reset")

    gt_not_reset:
        revert("GT flag not reset")
    
    eq_not_reset:
        revert("EQ flag not reset")

    panic:
        ret.panic r0
