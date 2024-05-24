        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; static writes & reads are not supported from kernel contracts yet
        ; so this test will crash.
        add 18000, r0, r2
        ;add 1, r0, r1
        ;uma.static_read r1, r2, r0, r0

        ;add 10000, r0, r1
        

        near_call r2, @inner, @handler

        ret.ok r0

    inner:
        uma.static_read r1, r2, r0, r0
        ret.ok r0

    handler:
        ret.ok r0
        