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
        add 2001, r0, r11
        add 2001, r0, r12
        context.ergs_left r9

        add 120, r0, r11
        log.sread r11, r0, r12
        context.ergs_left r9


        ; use 2 for forwarding mode
        add 2, r0, r1
        shl.s 32, r1, r1
        
        ; give a lot of gas
        add 1, r0, r5
        shl.s 15, r5, r5
        sub.s 1, r5, r5

        add r5, r1, r1
        shl.s 192, r1, r1
        
        add @CPI0_1[0], r0, r2


        add 2005, r0, r11
        add 2005, r0, r12
        context.ergs_left r9

        far_call r1, r2, @handle_panic

        add 2002, r0, r11
        add 2002, r0, r12
        context.ergs_left r9


        ret.ok r0


    do_fail:
        ret.panic r0

    handle_panic:
        ret.ok r0