        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r1
        ; this decommit is invalid - but it passes the Rust VM, and fails in circuits.
        log.decommit r1, r2, r3
        ret.ok r0
        