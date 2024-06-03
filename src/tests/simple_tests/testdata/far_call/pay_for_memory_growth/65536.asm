    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
CPI0_0:
    .cell 65537
    .text
    .globl	__entry
__entry:
.main:
    ; far call using 256 bits of data and pass 100 ergs
    ; should grow memory

    near_call r0, @get_heap_bound, @panic

    ; create ABI for far_call
    ; use 0 for forwarding mode (heap)
    ; pass 100 ergs 
    add 100, r0, r1
    shl.s 96, r1, r1
    ; length 256
    add 256, r1, r1
    shl.s 32, r1, r1
    ; start at heap bound
    add stack[0], r1, r1
    shl.s 64, r1, r1

    context.ergs_left r9
    add r9, r0, stack[0]
    
    ; we are calling 65537
    add @CPI0_0[0], r0, r2
    far_call r1, r2, @panic

    add stack[0], r0, r10
    context.ergs_left r9
    add r9, r0, stack[0]

    shl.s 96, r1, r1

    ret.ok r1

get_heap_bound:
    ; get metadata of callframe
    context.meta r5

    ; prepare 32-bits mask
    add 1, r0, r7
    shl.s 32, r7, r7
    sub.s 1, r7, r7

    ; unpack heap bound
    shr.s 64, r5, r6
    and r6, r7, stack[0]

    ret.ok r0
    
panic:
    ret.panic r0