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

        add 10000, r0, r4

        near_call r4, @inner, @handler
        ; We should never get here - as the near_call should panic due to out of gas.
        ret.panic r0
        
    inner:
        add @CPI0_0[0], r0, r1
        context.ergs_left r9
        ; extra cost - too large, will panic
        add 20000, r0, r2
        log.decommit r1, r2, r3
        
        ret.ok r0

    handler:
        ; we expect the near_call to panic
        ret.ok r0

    .panic:
        ret.panic r0
    