    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_1:
    .cell 65536
    .text
    .globl	__entry
__entry:
.main:
    ; call with 2^13 gas.
    add 1, r0, r1
    shl.s 13, r1, r1

    near_call r1, @limited, @expected_panic
    revert("Near call not reverted")

limited:
    ; create ABI for far_call
    ; give 6k gas
    add 6000, r1, r1
    shl.s 192, r1, r1
    
    ; we are calling address 65536 where we deploy inflated dummy
    ; but we don't have enough gas to actually decommit it

    add @CPI0_1[0], r0, r2
    far_call r1, r2, @catch_all

    ret.ok r0

catch_all:
    ret.panic r0

expected_panic:
    ret.ok r0