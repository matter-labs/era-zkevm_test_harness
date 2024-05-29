    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_0:
    .cell 65534
    .text
    .globl	__entry
__entry:
.main:
    ; build ABI for far_call

    ; create new pointer memory forwarding mode
    add 0, r0, r1

    ; pass 100 ergs
    shl.s 32, r1, r1
    add 100, r1, r1

    shl.s 64, r1, r1

    ; create "pointer"
    add 1024, r0, r4
    shl.s 32, r4, r4
    add 1024, r4, r4
    shl.s 32, r4, r4
    add 2050, r4, r4
    shl.s 32, r4, r4

    ; add pointer to abi
    shl.s 128, r1, r1
    add r1, r4, r1
    
    ; clone "pointer" to stack
    add r4, r0, stack[0]

    add @CPI0_0[0], r0, r2

    ; we make the extra far call to create a pointer type
    far_call r1, r2, @far_call_handler

    ; load cloned "pointer"
    add stack[0], r0, r4

    ; we perform the subtraction in kernel mode, r1 should not be cleaned
    sub.s! r1, r4, r5
    jump.ne @cleaned_but_should_not
    sub! r1, r4, r5
    jump.ne @cleaned_but_should_not

    ret.ok r0

far_call_handler:
    ret.panic r0

cleaned_but_should_not:
    revert("Pointer cleaned")