        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
    HASHES:
        ; this is the hash of the contract in 800000.asm
        .cell <800000.asm>
    ADDRESSES:
	    .cell 800000
        .text
        .globl	__entry
    __entry:
    .main:
        ; create ABI fo far call
        ; use 0 for forwarding mode 
        add 0, r0, r1
        shl.s 32, r1, r1
        ; give 10k gas
        add 10000, r1, r1
        shl.s 96, r1, r1
        add 36, r1, r1
        shl.s 32, r1, r1
        add 64, r1, r1
        shl.s 64, r1, r1

        add @ADDRESSES[0], r0, r2

        ; far call should also decommit 800000
        far_call r1, r2, @panic

        ; now we are trying to decommit it again
        add 15000, r0, r4
        near_call r4, @inner, @panic

        ret.ok r0
        
    inner:
        add @HASHES[0], r0, r1
        ; add extra cost, we expect it to be refunded
        ; since we are decommiting already decomitted contract
        add 2000, r0, r2
        context.ergs_left r9
        log.decommit r1, r2, r3
        context.ergs_left r10

        ; so after the call, we should have burned some gas and received 2k refund.
        sub.s 2000, r9, r11
        ; assert(r9-2000 <= r10) - make sure that we did not burn 2k gas
        sub! r11, r10, r0 
        jump.gt @invalid_gas_burn

        ret.ok r0

    panic:
        ret.panic r0

    invalid_gas_burn:
        revert("Invalid gas burn in decommit")
    