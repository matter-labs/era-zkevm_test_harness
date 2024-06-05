    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_0:
    .cell 65399
    .text
    .globl	__entry
__entry:
.main:
    ; We will try to call invalid precompile address inside 65399 contract

    ; create ABI for far_call
    ; use 0 for forwarding mode 
    add 0, r0, r1
    shl.s 32, r1, r1
    ; give 100k gas
    add 100000, r1, r1
    shl.s 96, r1, r1
    add 36, r1, r1
    shl.s 32, r1, r1
    add 64, r1, r1
    shl.s 64, r1, r1

    add @CPI0_0[0], r0, r2

    far_call r1, r2, @catch_all

    ret.ok r0
    
catch_all:
    ret.panic r0