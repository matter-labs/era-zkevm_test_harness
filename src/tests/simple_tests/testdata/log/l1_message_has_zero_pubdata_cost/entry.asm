    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    add 1000, r0, r1

    ; pass 1000 gas
    near_call r1, @inner, @failed_to_l1

    near_call r0, @get_pubdata_counter, @panic

    ; check that pubdata counter is 0
    sub! stack[0], r0, r0
    jump.ne @panic_pubdata_counter_changed

    ret.ok r0

inner:
    to_l1 r0, r1
    ret.ok r0

failed_to_l1:
    revert("Can not send a message")

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