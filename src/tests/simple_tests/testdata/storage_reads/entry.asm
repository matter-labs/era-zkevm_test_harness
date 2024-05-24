        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:

        add 10000, r0, r4
        shl.s 3, r4, r4

        near_call r4, @inner, @.panic

        ;
        ; Basic test to see that sread and treads are reading from different locations.
        ;

        ; write 28 to position 15
        add 15, r0, r1
        add 28, r0, r2

        log.swrite r1, r2, r0
        
        ; swrite key, value, UNUSED
        ; tread key, UNUSED, destination
        ; log.event key, value, UNUSED

        log.sread r1, r0, r5
        ; assert r5 == 28
        sub! 28, r5, r0
        jump.ne @.panic

        ; tread should return 19 from this slot (written in near call)
        log.tread r1, r0, r6
        sub! 19, r6, r0
        jump.ne @.panic

        near_call r4, @inner, @handler
        ; We should never get here - as the near_call should panic due to out of gas.
        ret.ok r0
        
    inner:
        add 15, r0, r1
        add 18, r0, r2
        add 19, r0, r3

        ;
        ; Write to the same slot in storage and temp storage.
        ;

        log.sread r1, r0, r5
        ; assert r5 == 0
        sub! 0, r5, r0
        jump.ne @.panic

        log.tread r1, r0, r5
        ; assert r5 == 0
        sub! 0, r5, r0
        jump.ne @.panic

        ; write 18 to position 15
        log.swrite r1, r2, r0
        ; write 19 to position 15 (but in temp storage)
        log.twrite r1, r3, r0
        log.sread r1, r0, r5
        ; assert r5 == 18
        sub! 18, r5, r0
        jump.ne @.panic

        log.tread r1, r0, r5
        ; assert r5 == 19
        sub! 19, r5, r0
        jump.ne @.panic
        
        ret.ok r0

    handler:
        ; we expect the near_call to panic
        ret.ok r0

    .panic:
        ret.panic r0
    