        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ptr.add r1, r0, r12
        add 999, r0, r11
        context.ergs_left r9

        add 1, r0, r6

        log.twrite r6, r6, r0

        add 1, r0, r3
        shl.s 224, r3, r3

        ptr.pack r12, r3, r12

        add 12, r0, r7
        ;context.set_context_u128 r7
        

        ret.ok r12
        