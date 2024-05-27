        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
__entry:
.main:  
        add 1000, r0, r3
        near_call r3, @test_invalid, @handler
        ret.panic r0

test_invalid:
        ret.panic r0

handler:
        log.swrite r0, r0, r0
        ret.ok r0