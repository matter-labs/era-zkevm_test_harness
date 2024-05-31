        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r0, @inner, @check_memory
        revert("Near_call not panicked")

    inner:
        add 5000, r0, r2
        add 1, r0, r3
        add 2, r0, r4

        ; write 1 to heap at address 5000
        st.1 r2, r3
        ; write 2 to aux heap at address 5000
        st.2 r2, r4

        ; write 3 to stack[0]
        add 3, r0, stack[0]
        
        ret.panic r0

    check_memory:
        add 5000, r0, r2

        ; read from heap at address 5000
        ld.1 r2, r3
        sub! 1, r3, r0
        jump.ne @heap_rollback

        ; read from aux heap at address 5000
        ld.2 r2, r4
        sub! 2, r4, r0
        jump.ne @aux_heap_rollback

        ; read and check from stack[0]
        add stack[0], r0, r5
        sub! 3, r5, r0
        jump.ne @stack_rollback

        sstore r0, r4

        ret.ok r0

    heap_rollback:
        revert("Unexpected memory rollback")

    aux_heap_rollback:
        revert("Unexpected aux memory rollback")

    stack_rollback:
        revert("Unexpected stack rollback")