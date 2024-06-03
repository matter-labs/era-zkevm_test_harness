    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; bytecode fill be greatly increased
    sstore r1, r1
    ${garbage}
    ret.ok r0