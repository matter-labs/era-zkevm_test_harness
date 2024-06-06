    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    near_call r0, @inner, @handler
    context.ergs_left r15
    
    ret.ok r0

inner:
    add 10000, r0, r1
    add 1000, r0, r10
    ; write 1000 to slot 10000
    sstore r1, r10
    ; write 0 to slot 10000
    sstore r1, r0

    ret.ok r0

handler:
    ret.panic r0