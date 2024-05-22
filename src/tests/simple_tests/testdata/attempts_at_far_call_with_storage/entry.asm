        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
CPI0_1:
	    .cell 180000
        .text
        .globl	__entry
    __entry:
    .main:
        ;add 15, r0, r11
        ;add 16, r0, r12
        ;context.ergs_left r9

        ; use 2 for forwarding mode
        add 2, r1, r1
        shl.s 32, r1, r1
        
        ; give lots of gas
        add 1, r0, r5
        shl.s 20, r5, r5
        sub.s 1, r5, r5


        add r5, r1, r1
        shl.s 192, r1, r1

        
        add @CPI0_1[0], r0, r2

        far_call r1, r2, @do_panic

    
        add 120, r0, r2
        log.sread r2, r0, r5
        add 25, r0, r10
        log.event.first r10, r5, r10

        ret.ok r0
    do_panic:
        ret.panic r0

        