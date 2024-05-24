    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_0:
    .cell 30272441630670900764332283662402067049651745785153368133042924362431065855
    .cell 30272434434303437454318367229716471635614919446304865000139367529706422272
CPI0_1:
    .cell 65536
    .text
    .globl	__entry
__entry:
.main:
    ; perform far call with limited ergs. create a fat pointer and clone it before VM designates
    ; it as one. then perform a sub and if fat pointer == fat pointer clone then we panic

    ; TODO r1 - pointer
    add 1000, r0, r1
    shl.s 128, r1, r1
    add 1024, r1, r1
    shl.s 32, r1, r1
    add 1024, r1, r1
    shl.s 32, r1, r1

    ; load ABI to r2
    add @CPI0_1[0], r0, r2

    context.ergs_left r9
    add r9, r0, stack[0]

    far_call r1, r2, @catch_all

    add stack[0], r0, r10
    
    context.ergs_left r9
    add r9, r0, stack[0]

    ret.ok r0
catch_all:
    ret.panic r0