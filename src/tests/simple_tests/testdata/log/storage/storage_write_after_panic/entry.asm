        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
__entry:
.main:  
        add 1000, r0, r3
        near_call r3, @test_panic, @expected_panic
        revert("Near call not panicked")

test_panic:
        add 1000, r0, r3
        near_call r3, @test_panic2, @expected_panic2

expected_panic:
        ; check that we can access storage after panic
        log.swrite r0, r0, r0
        ret.ok r0

test_panic2:
        ret.ok r0

expected_panic2:
        ret.panic r0