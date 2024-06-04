    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    near_call r1, @inner, @handler
    context.ergs_left r15
    ret.ok r0
inner:
    add 10000, r0, r1
    add 1000, r0, r10
    sstore r1, r10
    ret.panic r0
handler:
add 10000, r0, r1
    sload r1, r2
    ret.ok r0