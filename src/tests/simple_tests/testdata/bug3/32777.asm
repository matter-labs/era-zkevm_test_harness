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
        
        ; writing to position 25
        add 25, r0, r10
        add 230, r0, r11
        log.swrite r10, r11, r0

        log.sread r10, r0, r5

        log.event.first r10, r5, r0



        


        ;ret.panic r0


        ret.ok r0