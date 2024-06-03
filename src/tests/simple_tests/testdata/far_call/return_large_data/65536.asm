    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; tries to return 2kb of data from the heap
    ; should not growth memory

    sstore r1, r1

    ; creating fat pointer for the return
    ; forwarding byte 2 (aux heap)
    add 2, r0, r1
    shl.s 136, r1, r1
    ; length 2048
    add 2048, r1, r1
    shl.s 32, r1, r1
    ; start at 128
    add 128, r1, r1
    shl.s 64, r1, r1

    ret.ok r1