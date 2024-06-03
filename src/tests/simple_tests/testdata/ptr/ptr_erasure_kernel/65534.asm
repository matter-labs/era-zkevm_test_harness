    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; just return calldata. It is allowed in kernel mode

    ; forward pointer memory mode
    add 1, r0, r2
    shl.s 32, r2, r2
    shl.s 64, r2, r2
    shl.s 128, r2, r2
    ptr.pack r1, r2, r3

    ret.ok r3