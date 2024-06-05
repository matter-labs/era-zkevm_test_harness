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

    add 5000, r0, r4
    near_call r4, @inner_storage_too_large_refund, @.expected_error_handler

    revert("Not panicked but should")
inner_storage_handler:
    ; we'll be writing 13 at slot 25 with a warm refund of 5400
    set_storage_warm(5400)
    add 25, r0, r1
    add 13, r0, r2
    log.swrite r1, r2, r0

    ; we'll be writing 19 at slot 25 with a cold storage refund
    set_storage_cold()
    add 19, r0, r2
    log.swrite r1, r2, r0

    ; read slot 25 with a warm refund of 1900
    set_storage_warm(1900)
    log.sread r1, r0, r5

    ; read slot 19 with a cold storage refund
    set_storage_cold()
    add 19, r0, r1
    log.sread r1, r0, r6

    ret.ok r0
inner_storage_too_large_refund:
    ; we'll be writing 13 at slot 25 with a warm refund of 5400
    ; this should cause it to fail because we refund more gas than we have
    ; available
    set_storage_warm(5400)
    add 25, r0, r1
    add 13, r0, r2
    log.swrite r1, r2, r0

    ret.ok r0
.panic:
    ret.panic r0
.expected_error_handler:
    ret.ok r0