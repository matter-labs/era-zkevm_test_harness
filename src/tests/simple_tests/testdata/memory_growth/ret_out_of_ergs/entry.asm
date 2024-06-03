        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        CPI0_0:
            ; heap test contract
	        .cell ${heap_test_contract_address}
        CPI0_1:
            ; aux test contract
	        .cell ${aux_heap_test_contract_address}
        .text
        .globl	__entry
    __entry:
    .main:
        ; we are checking memory growth in separate contract
        ; since our "bootloader" has MAX memory allocated in heaps

        ; memory stipend differs between kernel and non-kernel contracts

        jump @first_call

    first_call:
        ; create ABI for far_call
        add 2, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 10000, r1, r1
        shl.s 192, r1, r1
        
        ; check heap growth
        add @CPI0_0[0], r0, r2
        ; we expect far call to revert
        far_call r1, r2, @second_call
        revert("Far call not reverted")

    second_call:
        ; create ABI for far_call
        add 2, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 10000, r1, r1
        shl.s 192, r1, r1

        ; check aux growth
        add @CPI0_1[0], r0, r2
        ; we expect far call to revert
        far_call r1, r2, @ok
        revert("Far call not reverted")

    ok:
        ret.ok r0