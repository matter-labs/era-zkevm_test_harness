        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; Stack is empty, SP is 0

        ; try overflowing absolute address on stack
        sub.s 2, r0, r5
        add 1, r0, stack[r5]
        add stack[r5], r0, r2
        sub.s! 1, r2, r0
        jump.ne @absolute_panic

        ; try overflow stack with pop
        context.sp r6
        add 1, r6, r6
        ; pop stack
        nop stack-=[r6]
        add 1, r0, stack-[0]
        add stack-[0], r0, r3
        sub.s! 1, r3, r0
        jump.ne @pop_panic
        
        ; try overflowing stack with push
        sub.s 2, r0, r3
        ; push stack
        nop stack+=[r3]
        add 2, r0, stack-[0]
        add stack-[0], r0, r3
        sub.s! 2, r3, r0
        jump.ne @push_panic

        ret.ok r0

    absolute_panic:
        revert("Overflowing addressing failed")

    push_panic:
        revert("Push overflow failed")

    pop_panic:
        revert("Pop overflow failed")