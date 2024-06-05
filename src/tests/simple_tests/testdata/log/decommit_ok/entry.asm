        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
        ; this is the hash of the contract in 800000.asm
	    .cell 452312938437537823148903869859771978505772238111866864847149311043017845250
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r4
        near_call r4, @inner, @handler

        ret.ok r0
        
    inner:
        add @CPI0_0[0], r0, r1
        context.ergs_left r9
        ; extra cost
        add 2000, r0, r2
        log.decommit r1, r2, r3
        context.ergs_left r10

        ; so after the call, we should have burned at least 2k gas.
        sub.s 2000, r9, r11
        ; assert(r9-2000 >= r10) - make sure that we really burned 2k gas
        sub! r11, r10, r0 
        jump.lt @invalid_gas_burn

        ret.ok r0

    handler:
        ret.panic r0

    invalid_gas_burn:
        revert("Invalid gas burn in decommit")
    