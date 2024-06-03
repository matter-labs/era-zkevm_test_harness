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

    ; we perform the subtraction not in kernel mode, r1 should be cleaned
    sub.s! r1, r4, r5
    jump.eq @not_cleaned_but_should
    sub! r1, r4, r5
    jump.eq @not_cleaned_but_should

    ; clean tag and metadata

    add r1, r0, r3
    add 1024, r0, r4
    shl.s 96, r4, r4
    sub.s! r1, r4, r5
    jump.eq @ret_ok
    
    revert("Pointer invalid")

far_call_handler:
    ret.panic r0

not_cleaned_but_should:
    revert("Not cleaned pointer")

ret_ok:
    ret.ok r0