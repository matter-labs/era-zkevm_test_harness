    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    add 100, r0, r1

    ; pass 100 gas
    ; should revert inside
    near_call r1, @inner, @expected_panic

    revert("Near call not panicked")

inner:
    ; trying to send message to l1
    ; but do not have enough gas
    ; to_l1 does not have any pubdata cost
    to_l1 r0, r1
    ret.ok r0

expected_panic:
    near_call r0, @get_pubdata_counter, @panic
        
    ; check that pubdata counter is 0
    sub! stack[0], r0, r0
    jump.ne @panic_pubdata_counter_changed

    context.ergs_left r15

    ret.ok r0

get_pubdata_counter:
    ; prepare a 32-bit mask (0xffff..)
    add 1, r0, r10
    shl.s 32, r10, r10
    sub.s 1, r10, r10
        
    ; get the pubdata counter
    context.meta r7
    and r10, r7, stack[0]

    ret.ok r0

panic:
    ret.panic r0

panic_pubdata_counter_changed:
    revert("Pubdata counter changed")