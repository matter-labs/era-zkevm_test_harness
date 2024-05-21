        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r1
        add 1000, r0, r10
        ; precompile call - address 0x1, AuxData (additional costs - 0 for now)

        add 1, r0, r5
        shl.s 31, r5, r5
        sub.s 1, r5, r5

        add r5, r0, r6
        shl.s 32, r6, r6
        add r5, r6, r6

        log.precompile r2, r6, r4

        near_call r1, @inner, @handler
        ; We should never get here - as the near_call should panic due to out of gas.
        ret.panic r0
    inner:
        to_l1 r0, r1

        ; Add extra 16k cost (more than this near call has)
        add 1, r0, r3
        shl.s 32, r3, r3
        add 1, r3, r3
        shl.s 14, r3, r3

        ; precompile call - address 0x1, AuxData (additional costs - 16k for now)
        log.precompile r2, r3, r4
        ret.ok r0
    handler:
        ; we expect the near_call to panic
        ret.ok r0
        