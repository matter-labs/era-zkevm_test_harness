    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; should not remove "pointer" tag from r1 out of kernel mode too
    add r1, r0, r4
    near_call r0, @try_add, @panic_handler
    ret.ok r0
    
try_add:
    ptr.add r1, r0, r5
    ret.ok r0

panic_handler:
    revert("Pointer tag cleared")