        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:

        add 10, r0, r3
        shl.s 10, r3, r3

        near_call r3, @near_dst, @do_panic

        add 101, r0, r11
        uma.fat_ptr_read r1, r1, r12, r13
        ;uma.fat_ptr_read r2, r3, r4, r5
        context.ergs_left r9
        add 102, r0, r11
        ;; move the pointer offset to (almost) max of u32.
        add 1, r0, r15
        shl.s 32, r15, r15
        sub.s 33, r15, r15

        ptr.add r1, r15, r12
        context.ergs_left r9

        uma.fat_ptr_read r12, r1, r13, r14
        
        ret.ok r0


    near_dst:
        ; fat pointer on return
        add 1, r0, r3
        shl.s 224, r3, r3
        ptr.pack r1, r3, r1
        ; short circuit.
        ret.ok r1


    do_panic:
        ret.panic r0