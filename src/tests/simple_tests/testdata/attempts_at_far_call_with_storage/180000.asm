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

        add 1000, r0, r11
        add 1000, r0, r12
        context.ergs_left r9

        add 120, r0, r2
        log.tread r2, r0, r3
        sub! 0, r3, r0
        jump.ne @second_round

        add 1001, r0, r11
        add 1001, r0, r12
        context.ergs_left r9

        jump @first_round
        
    

        ret.ok r0


    second_round:

        add 1002, r0, r11
        add 1002, r0, r12
        context.ergs_left r9

        add 185, r0, r4
        log.twrite r2, r4, r0

        ret.panic r0


        ;ret.ok r0


    first_round:

        ; write something in 120 slot.
        add 155, r0, r4
        log.twrite r2, r4, r0
        add 1003, r0, r11
        add r4, r0, r12
        context.ergs_left r9

        log.tread r2, r0, r5
        add 1004, r0, r11
        add r5, r0, r12
        context.ergs_left r9

        add 1005, r0, r11
        add r2, r0, r12
        context.ergs_left r9

    

        ; use 2 for forwarding mode
        add 2, r1, r1
        shl.s 32, r1, r1
        
        ; give a lot of gas
        add 1, r0, r5
        shl.s 18, r5, r5
        sub.s 1, r5, r5

        add r5, r1, r1
        shl.s 192, r1, r1
        
        add @CPI0_1[0], r0, r2

        far_call r1, r2, @do_ok


        add 120, r0, r2
        log.tread r2, r0, r12
        add 1007, r0, r11
        context.ergs_left r9



        ret.ok r0

    do_ok:
        ret.panic r0