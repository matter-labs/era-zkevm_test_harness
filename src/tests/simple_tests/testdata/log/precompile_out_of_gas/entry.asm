        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; 2 lower bytes of this contract address are used as precompile address
        ; we are in bootloader that should have address ending with 0x8001
        ; precompile call - address 0x1, ABI is empty, AuxData (additional costs - 0 for now)
        log.precompile r0, r3, r4

        add 10000, r0, r1
        ; pass 10k gas
        near_call r1, @inner, @handler

        revert("Near call not reverted")
    inner:
        to_l1 r0, r1

        ; Add extra ~16k cost (more than this near call has)
        ; extra pubdata cost 2^32 - 1
        add 1, r0, r3
        shl.s 32, r3, r3
        ; extra gas cost 2^14 (~16k)
        add 1, r3, r3
        shl.s 14, r3, r3

        ; precompile call - address 0x1, ABI is empty, AuxData (additional costs ~16k)
        log.precompile r0, r3, r4
        ret.ok r0
    handler:
        ; we expect the near_call to panic
        ret.ok r0
        