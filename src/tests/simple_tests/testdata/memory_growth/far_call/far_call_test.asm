        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        CPI0_0:
	        .cell ${dummy_address}
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
        add stack[0], r0, stack[2]
        ; aux heap initial bound
        add stack[1], r0, r12
        add stack[1], r0, stack[3]

        ; create ABI for far_call
        ; pointer for heap memory
        add 0, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 100000, r1, r1
        shl.s 64, r1, r1
        shl.s 32, r1, r1
        ; length is greater than heap bound
        add r11, r1, r1
        add 32, r1, r1
        shl.s 96, r1, r1
        
        add @CPI0_0[0], r0, r2
        ; call the dummy contract
        ; should increase heap bound
        far_call r1, r2, @panic

        ; check bounds
        ; new expected bound for heap
        add stack[2], r0, r13
        add 32, r13, r13

        add stack[3], r0, r12

        near_call r0, @get_heap_bounds, @panic
        sub! stack[0], r13, r0
        jump.ne @invalid_memory_growth
        sub! stack[1], r12, r0
        jump.ne @unexpected_memory_growth

        ; create ABI for far_call
        ; pointer for aux heap memory
        add 2, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 100000, r1, r1
        shl.s 64, r1, r1
        shl.s 32, r1, r1
        ; length is greater than heap bounds
        add r12, r1, r1
        add 32, r1, r1
        shl.s 96, r1, r1

        add @CPI0_0[0], r0, r2
        ; call the dummy contract
        ; should increase aux heap bound
        far_call r1, r2, @panic

        ; check bounds
        ; new expected bounds for heaps
        add stack[2], r0, r13
        add 32, r13, r13

        add stack[3], r0, r14
        add 32, r14, r14

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
        print("PANIC HANDLER")
        ret.panic r0

    invalid_memory_growth:
        revert("Should growth memory")

    unexpected_memory_growth:
        revert("Unexpected memory growth")

