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
        ;aux heap
        add 2, r0, r3
        shl.s 224, r3, r3

        ; start
        add 32, r0, r4
        shl.s 64, r4, r4
        add r4, r3, r3

        ; length
        add 300, r0, r4
        shl.s 96, r4, r4
        add r4, r3, r3

        
        ; memory page
        add 150, r0, r4
        shl.s 32, r4, r4
        add r4, r3, r3

        ; offset
        add 0, r3, r3

        

        ret.ok r3


    do_fail:
        ret.panic r0

    handle_panic:
        ret.ok r0