        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
CPI0_0:
        ; this is the hash of the contract in 80000.asm
	    .cell 452312938437537823148903869859771978505772238111866864847149311043017845250


        .text
        .globl	__entry
    __entry:
    .main:
        
        add @CPI0_0[0], r0, r1
        add @CPI0_0[0], r0, r2
        ; r1 has some messy data now.

        far_call r1, r2, @do_panic

        ret.ok r0
    do_panic:
        ret.ok r0

        