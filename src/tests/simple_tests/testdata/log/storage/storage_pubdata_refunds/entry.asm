    .text
    .file "Test_26"
    .rodata.cst32
    .p2align    5
    .text
    .globl __entry
__entry:
.main:
    ; allocate 20k gas for 2 writes and 2 reads
    ; each write takes about 5k gas
    add 20000, r0, r4
    
    ; perform write via near call
    near_call r4, @inner_storage_handler, @.panic

    ret.ok r0

inner_storage_handler:
    ; we'll be writing 13 at slot 25 with a warm refund of 5400
    set_storage_warm(5400)
    add 25, r0, r1
    add 13, r0, r2
    context.ergs_left r7
    add r7, r0, stack[0]
    log.swrite r1, r2, r0
    context.ergs_left r7

    ; check that we spent less than 5k gas (we have refund)
    sub stack[0], r7, r7
    sub!.s 5000, r7, r0
    jump.gt @not_refunded_gas

    ; we'll be writing 19 at slot 25 with a cold storage refund
    set_storage_cold()
    add 19, r0, r2
    context.ergs_left r7
    add r7, r0, stack[0]
    log.swrite r1, r2, r0
    context.ergs_left r7

    ; check that we spent more than 5k gas (we do not have refund)
    sub stack[0], r7, r7
    sub!.s 5000, r7, r0
    jump.lt @not_enough_gas_spent_cold

    ; read slot 25 with a warm refund of 1900
    set_storage_warm(1900)
    log.sread r1, r0, r5

    ; read slot 19 with a cold storage refund
    set_storage_cold()
    add 19, r0, r1
    log.sread r1, r0, r6

    ret.ok r0

not_refunded_gas:
    revert("Gas for write not refunded")
    
not_enough_gas_spent_cold:
    revert("Cold write gas spent too low")

.panic:
    ret.panic r0