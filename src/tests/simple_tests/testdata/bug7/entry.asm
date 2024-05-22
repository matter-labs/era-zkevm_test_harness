        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
CPI0_0:
        .cell 180000

        .text
        .globl	__entry
    __entry:
    .main:        
        ; use 2 for forwarding mode
        add 2, r1, r1
        shl.s 32, r1, r1
        
        ; give lots of gas
        add 1, r0, r5
        shl.s 32, r5, r5
        sub.s 1, r5, r5
        add r5, r1, r1

        shl.s 96, r1, r1
        ; fat ptr length
        add 36, r1, r1
        shl.s 32, r1, r1
        ; fat ptr offset
        add 64, r1, r1
        shl.s 64, r1, r1

        add @CPI0_0[0], r0, r2
        far_call r1, r2, @do_panic


        ret.ok r0
    do_panic:
        ret.panic r0

        