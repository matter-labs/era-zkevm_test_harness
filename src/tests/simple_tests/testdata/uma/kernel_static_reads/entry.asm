        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 18000, r0, r2
        add 1, r0, r1
        uma.static_read r1, r2, r0, r0

        ret.ok r0
        