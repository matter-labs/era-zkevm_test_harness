        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; Stack is empty, SP is 0

        ; try absolute address on stack
        add 1, r0, stack[0]
        add stack[0], r0, r2
        sub.s! 1, r2, r0
        jump.ne @absolute_panic

        add 100, r0, stack[1000]
        add stack[1000], r0, r2
        sub.s! 100, r2, r0
        jump.ne @absolute_panic

        ; try addressing with offset on stack
        ; checking value at SP - 0
        add 2, r0, stack-[0]
        add stack-[0], r0, r2
        sub.s! 2, r2, r0
        jump.ne @offset_panic

        ; checking value at SP - 100
        add 200, r0, stack-[100]
        add stack-[100], r0, r2
        sub.s! 200, r2, r0
        jump.ne @offset_panic

        ; try push addressing on stack
        ; Write 3 to stack at SP - 0 and increase SP
        add 3, r0, stack+=[1]
        add stack-[1], r0, r2
        sub.s! 3, r2, r0
        jump.ne @push_panic

        ; try pop addressing on stack
        add 4, r0, stack-[0]
        ; increase stack
        nop stack+=[1]
        ; pop should return value at SP - offset and move SP to SP - offset
        ; ! "pop" addressing can be used only as src0
        add stack-=[1], r0, r5
        sub.s! 4, r5, r0
        jump.ne @pop_panic

        ; try overflowing push addressing on stack
        sub.s 2, r0, r3
        context.sp r6
        ; push should change value at SP and move SP to SP + offset
        ; ! "push" addressing can be used only as dst0
        add 999, r0, stack+=[r3]
        add stack[r6], r0, r2
        sub.s! 999, r2, r0
        jump.ne @push_panic

        ; try do push and pop addressing on stack simultaneously
        add 4, r0, stack-[0]
        ; increase stack
        nop stack+=[2]
        ; pop should return value at SP - offset and move SP to SP - offset
        ; push should change value at SP and move SP to SP + offset
        add stack-=[2], r0, stack+=[2]
        add stack-[2], r0, r3
        sub.s! 4, r3, r0
        jump.ne @push_pop_panic

        ret.ok r0

    absolute_panic:
        revert("Absolute addressing failed")

    offset_panic:
        revert("Offset addressing failed")

    push_panic:
        revert("Push addressing failed")

    pop_panic:
        revert("Pop addressing failed")

    push_pop_panic:
        revert("Push+pop addressing failed")