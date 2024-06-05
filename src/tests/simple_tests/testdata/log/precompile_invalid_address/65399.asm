    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
__entry:
.main:
    ; 2 lower bytes of this contract address are used as precompile address
    ; we are in 65399 that should have address ending with 0xFF77
    ; precompile call - address 0xFF77, ABI is empty, AuxData (additional costs - 0 for now)
    ; we are calling invalid precompile address, nothing should happen
    log.precompile r0, r3, r4

    ; Add extra ~16k cost
    ; extra pubdata cost 2^32 - 1
    add 1, r0, r3
    shl.s 32, r3, r3
    ; extra gas cost 2^14 (~16k)
    add 1, r3, r3
    shl.s 14, r3, r3

    ; precompile call - address 0xFF77 (invalid), ABI is empty, AuxData (additional costs ~16k)
    ; should burn gas
    context.ergs_left r9
    log.precompile r0, r3, r4
    context.ergs_left r10

    ; so after the precompile call, we should have burned at least 16k gas.
    sub.s 16000, r9, r11
    ; assert(r9-16000 >= r10) - make sure that we really burned 16k gas
    sub! r11, r10, r0 
    jump.lt @not_burned_gas

    add 10000, r0, r1
    ; pass 10k gas
    near_call r1, @out_of_gas_inner, @expected_panic

    revert("Near call not reverted")

out_of_gas_inner:
    to_l1 r0, r1

    ; Add extra ~16k cost (more than this near call has)
    ; extra pubdata cost 2^32 - 1
    add 1, r0, r3
    shl.s 32, r3, r3
    ; extra gas cost 2^14 (~16k)
    add 1, r3, r3
    shl.s 14, r3, r3

    ; precompile call - address 0xFF77 (invalid), ABI is empty, AuxData (additional costs ~16k)
    log.precompile r0, r3, r4
    ret.ok r0

expected_panic:
    ; we expect the near_call to panic
    ret.ok r0

not_burned_gas:
    revert("Precompile call not burned gas")
    