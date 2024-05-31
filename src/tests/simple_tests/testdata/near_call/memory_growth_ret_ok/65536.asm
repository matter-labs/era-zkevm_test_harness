        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; open a near call frame, grow heap and return
        near_call r0, @inner, @panic

        ; load saved heap bound
        add stack[0], r0, r3
        ; get current heap bound
        near_call r0, @get_heap_bound, @panic

        ; heap bound should not revert
        sub! stack[0], r3, r0
        jump.ne @heap_bound_reverted

        st.1 100, r3

        ret.ok r0

    inner:
        sstore r1, r1

        add 2, r0, r1
        shl.s 136, r1, r1
        add 2000, r1, r1
        shl.s 32, r1, r1

        near_call r0, @get_heap_bound, @panic
        add stack[0], r0, r8
        add 32, r8, r8
        ; r8 now is beyond the heap bound

        ; grow memory in heap
        ; store r1 at r8
        st.1 r8, r1
        
        ; load from heap at r8 to r3
        ld.1 r8, r3

        ; check value in memory
        sub! r3, r1, r0
        jump.ne @memory_error

        ; write new heap bound to stack[0]
        near_call r0, @get_heap_bound, @panic

        ret.ok r0

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

    memory_error:
        revert("Memory error")

    heap_bound_reverted:
        revert("Heap bound reverted")

    panic:
        ret.panic r0