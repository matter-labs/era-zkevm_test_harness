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
        ; static writes & reads are not supported from kernel contracts yet.
        ;add 180, r0, r2
        ;uma.static_write r1, r2, r0, r0

        ; create ABI for far_call
        ; use 2 for forwarding mode (Aux heap)
        add 2, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 100000, r1, r1
        
        add @CPI0_0[0], r0, r2
        ; call the other_asm contract
        far_call r1, r2, @user_call_handler

        ret.ok r0
        
    user_call_handler:
        ret.panic r0

