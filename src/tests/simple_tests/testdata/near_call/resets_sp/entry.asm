        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; SP is 0
        ; change it to 1000

        nop stack+=[1000]
        context.sp r6
        add r6, r0, stack[0]

        ; SP will be changed inside of near call
        ; but all changes should be discarded after return
        near_call r0, @inner, @panic

        ; SP should revert to value before near_call
        context.sp r6
        sub! stack[0], r6, r0
        jump.ne @stack_pointer_not_reverted

    inner:
        ; change SP again
        nop stack+=[1000]
        context.sp r6
        add r6, r0, stack[1]

        ; check that SP changed as expected
        add stack[0], r0, r2
        add 1000, r2, r2
        sub! r2, r6, r0
        jump.ne @inner_stack_pointer_invalid

        sstore r0, r6
        ret.ok r0


    inner_stack_pointer_invalid:
        revert("Stack pointer incorrect")

    stack_pointer_not_reverted:
        revert("Stack pointer changed")

    panic:
        ret.panic r0
