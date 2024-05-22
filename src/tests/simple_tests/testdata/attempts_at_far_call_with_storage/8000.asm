        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; empty contract. Do not change, as its hash is hardcoded in entry.asm.
        add 18, r0, r1
        context.ergs_left r9

        log.event.first r1, r9, r1

        ret.ok r0