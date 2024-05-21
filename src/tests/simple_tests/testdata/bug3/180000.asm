        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
CPI0_1:
	    .cell 200000
        .text
        .globl	__entry
    __entry:
    .main:
        add 28, r0, r1
        context.ergs_left r9
        log.event.first r1, r9, r1

        ; use 2 for forwarding mode
        add 2, r1, r1
        shl.s 32, r1, r1
        
        ; give a lot of gas
        add 1, r0, r5
        shl.s 12, r5, r5
        sub.s 1, r5, r5

        add r5, r1, r1
        shl.s 192, r1, r1
        
        add @CPI0_1[0], r0, r2

        far_call r1, r2, @do_ok

        ret.ok r0

    do_ok:
        ret.panic r0