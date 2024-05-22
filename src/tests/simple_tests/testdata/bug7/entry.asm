        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
CPI0_0:
        ; this is the hash of the contract in 80000.asm
	    ;.cell 452312938437537823148903869859771978505772238111866864847149311043017845250
        ;.cell 7689318515769800037122090432902766219335146279714402117313248311537588447746 
        .cell 180000


        .text
        .globl	__entry
    __entry:
    .main:

        ptr.add r1, r2, r1

        add 211, r0, r5
        add 64, r0, r6
        st.1 r6, r5
        st.2 r6, r5
        

        ;add 15, r0, r11
        ;add 16, r0, r12
        ;context.ergs_left r9

        ; use 2 for forwarding mode
        add 2, r1, r1
        shl.s 32, r1, r1
        
        ; give lots of gas
        add 1, r0, r5
        shl.s 32, r5, r5
        sub.s 1, r5, r5


        add r5, r1, r1
        ;shl.s 192, r1, r1

        shl.s 96, r1, r1
        ; fat ptr length
        add 36, r1, r1
        shl.s 32, r1, r1
        ; fat ptr offset
        add 64, r1, r1
        shl.s 64, r1, r1
        context.ergs_left r9

        add 3, r0, r7
        context.set_context_u128 r7


        add @CPI0_0[0], r0, r5
        context.ergs_left r9
        ; extra cost
        add 2000, r0, r2
        log.decommit r5, r2, r3

        add @CPI0_0[0], r0, r2

        far_call r1, r2, @do_panic

    
        add 120, r0, r2
        log.sread r2, r0, r5
        add 25, r0, r10
        log.event.first r10, r5, r10

        ret.ok r0
    do_panic:
        ret.panic r0
        ;ret.ok r0

        