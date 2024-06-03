        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; checking memory growth
        ; 4 KB for new non-kernel frames is "free"
        ; 2 MB for new kernel frames is "free"

        ; get initial bounds
        near_call r0, @get_heap_bound, @panic

        ; create fresh pointer to return from heap
        add 0, r0, r1
        shl.s 32, r1, r1
        shl.s 64, r1, r1

        ; length in pointer is too big
        add 16000, r0, r4
        add stack[0], r4, r4

        shl.s 32, r1, r1
        add r4, r1, r1
        shl.s 96, r1, r1

        ; should revert with out of gas
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

