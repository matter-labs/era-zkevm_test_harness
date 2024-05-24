        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    CPI0_0:
        ; this is 'user' contract
	    .cell 800000
        .text
        .globl	__entry
    __entry:
    .main:        
        add 65, r0, r1
        add 120, r0, r2

        ; write '120' in slot 65
        uma.heap_write r1, r2, r0, r0

        ; write '150' in slot 65 for AUX
        add 150, r0, r2
        uma.aux_heap_write r1, r2, r0, r0


        ; now reading.
        uma.heap_read r1, r0, r3, r0

        ; assert r3 == 120
        sub.s! 120, r3, r0
        jump.ne @.panic_wrong_read


        uma.aux_heap_read r1, r0, r3, r0
        sub.s! 150, r3, r4
        jump.ne @.panic_wrong_read

        ; static writes & reads are not supported from kernel contracts yet.
        ;add 180, r0, r2
        ;uma.static_write r1, r2, r0, r0

        ; create ABI for far_call
        ; use 2 for forwarding mode (Aux heap)
        add 2, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 100000, r1, r1
        shl.s 96, r1, r1
        add 36, r1, r1
        shl.s 32, r1, r1
        add 64, r1, r1
        shl.s 64, r1, r1
        add @CPI0_0[0], r0, r2
        ; call the other_asm contract
        far_call r1, r2, @user_call_handler

        add 10000, r0, r4
        ; set the register for near call (doing it before, as registers values should be persisted for near calls)
        add 65, r0, r1
        near_call r4, @inner, @near_call_handler
        ret.ok r0
        
    inner:
        uma.heap_read r1, r0, r3, r0
        ; assert r3 == 120
        sub.s! 120, r3, r0
        jump.ne @.panic_wrong_read


        uma.aux_heap_read r1, r0, r3, r0
        sub.s! 150, r3, r4
        jump.ne @.panic_wrong_read

        ret.ok r0

    user_call_handler:
        ret.panic r0

    near_call_handler:
        ret.panic r0

    .panic_wrong_read:
        revert("wrong value read")
    