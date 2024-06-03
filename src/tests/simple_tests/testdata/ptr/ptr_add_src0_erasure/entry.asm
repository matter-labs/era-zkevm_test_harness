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
        ; add should not clear src0 pointer tag in kernel mode
        add r1, r0, r3
        ; panics if r1 isn't a pointer
        ptr.add r1, r4, r5

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

        far_call r1, r2, @.panic
        ret.ok r0
    .panic:
        ret.panic r0