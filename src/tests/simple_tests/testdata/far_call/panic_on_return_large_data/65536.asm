    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; tries to return 16kb of data from the heap
    ; memory stipend for user space contracts is 4kb, so we need to growth memory

    ; creating fat pointer for the return
    ; forwarding byte 0 (heap)
    add 0, r0, r1
    shl.s 136, r1, r1
    ; length 16000
    add 16000, r1, r1
    shl.s 32, r1, r1
    ; start at 128
    add 128, r1, r1
    shl.s 64, r1, r1

    ; should revert with "not enough ergs for memory growth"
    ret.ok r1