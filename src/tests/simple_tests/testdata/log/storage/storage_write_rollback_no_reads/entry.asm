    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    near_call r0, @inner, @expected_panic

    revert("Near call not panicked")

inner:
    add 10000, r0, r1
    add 1000, r0, r10

    ; write 1000 to storage slot 10000
    sstore r1, r10
    
    ret.panic r0

expected_panic:
    context.ergs_left r15
    ret.ok r0