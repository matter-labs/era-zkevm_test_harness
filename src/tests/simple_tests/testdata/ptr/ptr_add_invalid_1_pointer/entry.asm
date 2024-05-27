    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
    .main:
        sstore r0, r0
        event.first r0, r0
        to_l1.first r0, r0
        add 4, r0, r2
        add 8, r0, r3
        shl.s 128, r3, r3
        near_call r0, @should_panic, @handler
        revert("Not panicked but should")
    should_panic:
        ; trying to add pointer to pointer
        ptr.add r1, r1, r1
    handler:
        ret.ok r0