    .text
    .file	"Test_26"
    .rodata.cst32
    .p2align	5
    CPI0_0:
        ; just some random values
        .cell 30272441630670900764332283662402067049651745785153368133042924362431065855
        .cell 30272434434303437454318367229716471635614919446304865000139367529706422272
    .text
    .globl	__entry
__entry:
.main:
    ; this one reads some calldata, including partially beyond the bound,
    ; and completely beyond the bound, and returns

    sstore r1, r1
    event.first r1, r0
    to_l1.first r0, r1

    ; read first 32 bytes
    ld.inc r1, r2, r1
    ; should be equal to CPI0_0[0]
    sub! @CPI0_0[0], r2, r0
    jump.ne @invalid_first_slot

    ; read second 32 bytes
    ld.inc r1, r3, r1
    ; should be equal to first 4 bytes of CPI0_0[1]
    add @CPI0_0[1], r0, r4
    shr.s 224, r4, r4
    shl.s 224, r4, r4
    sub! r4, r3, r0
    jump.ne @invalid_second_slot

    ; read 32 bytes beyond the bound
    ; should be zero
    ld r1, r4
    sub! r4, r0, r0
    jump.ne @invalid_third_slot

    ret.ok r0

invalid_first_slot:
    revert("Invalid first slot")

invalid_second_slot:
    revert("Invalid second slot")

invalid_third_slot:
    revert("Invalid third slot")