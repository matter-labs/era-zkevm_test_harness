        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        ; we got fat pointer from the caller
        ; the first value should be 0
        uma.fat_ptr_read r1, r0, r3, r0
        sub.s! 0, r3, r0
        jump.ne @.panic_wrong_read

        ;; move the pointer offset to (almost) max of u32.
        add 1, r0, r15
        shl.s 32, r15, r15
        sub.s 33, r15, r15

        ptr.add r1, r15, r12
        uma.fat_ptr_read r12, r0, r13, r0
        ; check that we read 0
        sub.s! 0, r13, r0
        jump.ne @.panic_wrong_read


        ; but in the second value, we should see 150 (writen to aux heap in entry.asm)
        
        add 1, r0, r2
        ptr.add r1, r2, r1
        uma.fat_ptr_read r1, r0, r3, r0
        sub.s! 150, r3, r0
        jump.ne @.panic_wrong_read

        ; expect separate heap - which should be empty
        add 5, r0, r1
        ; now reading.
        uma.heap_read r1, r0, r3, r0
        ; assert r3 == 0
        sub.s! 0, r3, r0
        jump.ne @.panic_wrong_read

        uma.aux_heap_read r1, r0, r3, r0
        ; assert r3 == 0
        sub.s! 0, r3, r0
        jump.ne @.panic_wrong_read

        ret.ok r0

    .panic_wrong_read:
        revert("user: wrong value read")

