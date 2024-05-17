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

        near_call r4, @inner, @.panic

        ret.ok r0




        add 15, r0, r1
        add 18, r0, r2

        ;
        ; Basic test to see that sread and treads are reading from different locations.
        ;

        ; write 15 to position 18
        log.swrite r1, r2, r0
        

        add 3, r0, r3
        context.ergs_left r7
        log.event r3, r7, r0

        ; swrite key, value, UNUSED
        ; tread key, UNUSED, destination
        ; log.event key, value, UNUSED

        log.sread r1, r0, r5
        ; assert r5 == 18
        sub! 18, r5, r0
        jump.ne @.panic

        ; tread should return empty from this slot.
        log.tread r1, r0, r6
        sub! 0, r6, r0
        jump.ne @.panic


        log.event r5, r6, r0


        near_call r4, @inner, @handler
        ; We should never get here - as the near_call should panic due to out of gas.
        ret.ok r0
        
    inner:
        add 15, r0, r1
        add 18, r0, r2

        ;
        ; Basic test to see that sread and treads are reading from different locations.
        ;

        log.sread r1, r0, r5
        ; assert r5 == 18
        sub! 0, r5, r0
        jump.ne @.panic

        ; write 15 to position 18
        log.swrite r1, r2, r0
        log.sread r1, r0, r5
        ; assert r5 == 18
        sub! 18, r5, r0
        jump.ne @.panic
        

    
        
        
        ret.ok r0

    handler:
        ; we expect the near_call to panic
        ret.ok r0

    .panic:
        ret.panic r0
    