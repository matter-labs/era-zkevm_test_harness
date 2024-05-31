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
        near_call r0, @get_heap_bounds, @panic
        ; heap initial bound
        add stack[0], r0, r11
        ; aux heap initial bound
        add stack[1], r0, r12

        ; write 8 to last preallocated heap slot
        ; should not growth memory
        add r11, r0, r2
        sub.s 32, r2, r2
        add 8, r0, r3
        st.1 r2, r3

        ; write 8 to last preallocated aux heap slot
        ; should not growth memory
        add r12, r0, r2
        sub.s 32, r2, r2
        st.2 r2, r3

        ; check bounds
        ; bounds should not change
        near_call r0, @get_heap_bounds, @panic
        sub! stack[0], r11, r0
        jump.ne @unexpected_memory_growth
        sub! stack[1], r12, r0
        jump.ne @unexpected_memory_growth
        

        ; write 8 to fisrt out-of-bounds heap slot
        ; should growth memory
        add r11, r0, r2
        add 8, r0, r3
        st.1 r2, r3

        ; new expected bound for heap
        add 32, r11, r13

        ; aux bound should not change
        near_call r0, @get_heap_bounds, @panic
        sub! stack[0], r13, r0
        jump.ne @invalid_memory_growth
        sub! stack[1], r12, r0
        jump.ne @unexpected_memory_growth

        ; write 8 to fisrt out-of-bounds aux heap slot
        ; should growth memory
        add r12, r0, r2
        add 8, r0, r3
        st.2 r2, r3

        ; new expected bound for aux heap
        add 32, r12, r14

        ; bounds should be changed
        near_call r0, @get_heap_bounds, @panic
        sub! stack[0], r13, r0
        jump.ne @invalid_memory_growth
        sub! stack[1], r14, r0
        jump.ne @invalid_memory_growth

        ret.ok r0

    get_heap_bounds:
        ; get metadata of callframe
        context.meta r5

        ; prepare 32-bits mask
        add 1, r0, r7
        shl.s 32, r7, r7
        sub.s 1, r7, r7

        ; unpack heap bound
        shr.s 64, r5, r6
        and r6, r7, stack[0]

        ; unpack aux heap bound
        shr.s 96, r5, r6
        and r6, r7, stack[1]

        ret.ok r0
    
    panic:
        ret.panic r0

    invalid_memory_growth:
        revert("Should growth memory")

    unexpected_memory_growth:
        revert("Unexpected memory growth")

