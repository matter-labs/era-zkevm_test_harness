        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; each write costs around 5k.
        ; start the test by giving 20k to do 2 writes
        add 20000, r0, r4
        
        ; just do 2 writes.
        near_call r4, @inner_2_writes_ok, @.panic

        ; now do the call that will run out of gas.
        add 10000, r0, r4
        near_call r4, @inner_out_of_gas_during_write, @inner_out_of_gas_handler
        ret.panic r0
        
    inner_out_of_gas_during_write:
        ; check that pubdata counter is 0
        context.meta r7
        and r10, r7, r7
        sub! 0, r7, r0
        jump.ne @.panic

        ; we'll be writing 24 in slot 25

        add 25, r0, r1
        add 24, r0, r2
        log.swrite r1, r2, r0

        ; check that pubdata counter is 65 (after first write)
        context.meta r7
        and r10, r7, r7
        sub! 65, r7, r0
        jump.ne @.panic

        ; and then the second write should fail out of gas.
        log.swrite r1, r2, r0
        
        ; if we ever get here - just return ok - as the caller will panic.
        ret.ok r0

    inner_out_of_gas_handler:
        ; check pubdata counter (should be equal to 130; from the first 2 writes)
        context.meta r7
        and r10, r7, r7
        sub! 130, r7, r8
        jump.ne @.panic

        ; expect the value in slot 25 to be 14 (from the second successful write)
        add 25, r0, r1
        log.sread r1, r0, r2
        sub! 14, r2, r0
        jump.ne @.panic

        ret.ok r0

    inner_2_writes_ok:
        ; prepare a 32-bit mask (0xffff..)
        add 1, r0, r10
        shl.s 32, r10, r10
        sub.s 1, r10, r10

        ; check pubdata counter (should be equal to 0)
        context.meta r7
        and r10, r7, r7
        sub! 0, r7, r0
        jump.ne @.panic
        
        ; we'll be writing 13 at slot 25
        add 25, r0, r1
        add 13, r0, r2
        log.swrite r1, r2, r0
        
        ; now pubdata counter should be equal to 65
        context.meta r7
        and r10, r7, r7
        sub! 65, r7, r0
        jump.ne @.panic

        ; write a value 14 again to the same slot
        add 1, r2, r2
        log.swrite r1, r2, r0

        ; now pubdata counter should be equal to 130
        context.meta r7
        and r10, r7, r7
        sub! 130, r7, r0
        jump.ne @.panic

        ret.ok r0

    .panic:
        ret.panic r0
    