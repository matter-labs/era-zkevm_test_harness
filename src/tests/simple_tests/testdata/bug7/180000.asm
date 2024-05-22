        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        uma.fat_ptr_read r1, r1, r12, r13
        ;; move the pointer offset to (almost) max of u32.
        add 1, r0, r15
        shl.s 32, r15, r15
        sub.s 33, r15, r15

        ptr.add r1, r15, r12
        uma.fat_ptr_read r12, r1, r13, r14
        
        ret.ok r0
