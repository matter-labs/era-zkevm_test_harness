        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; now try accessing the static memory
        add 180, r0, r2
        ; currently this will fail the whole execution.
        uma.static_read r1, r2, r0, r0
    
        ; user contract
        ret.ok r0

