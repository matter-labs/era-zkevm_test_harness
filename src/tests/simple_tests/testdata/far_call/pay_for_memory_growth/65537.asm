    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; just return

    context.ergs_left r9
    add r9, r0, stack[0]
    add stack[0], r0, r10

    ; return 64 bits from heap
    add 64, r0, r1
    shl.s 96, r1, r1

    ret.ok r1