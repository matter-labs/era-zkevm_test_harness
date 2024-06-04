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
    sstore r1, r10
    event r1, r10
    to_l1 r1, r10
    context.set_ergs_per_pubdata r10
    near_call r1, @inner, @handler
    context.ergs_left r15
    ret.ok r0
inner:
    to_l1 r0, r1
    ret.ok r0
handler:
    ret.ok r0