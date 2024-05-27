        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r1
        ; this decommit is invalid
        log.decommit r1, r2, r3
        ret.ok r0
        