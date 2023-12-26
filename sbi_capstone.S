#include "sbi_capstone.h"

#ifndef DOM_REENTRY_POINT
_dom_reentry:
    j _dom_reentry
#define DOM_REENTRY_POINT _dom_reentry
#endif

_cap_trap_entry:
    CCSRRW(sp, CCSR_CSCRATCH, sp)

    CINCOFFSETIMM(sp, sp, -34 * 8)
    # set up stack
    # save context. TODO: assuming that there is no GPR containing a capability
    SAVE_REG(ra, sp)
    SAVE_REG(gp, sp)
    SAVE_REG(tp, sp)
    SAVE_REG(t0, sp)
    SAVE_REG(t1, sp)
    SAVE_REG(t2, sp)
    SAVE_REG(s0, sp)
    SAVE_REG(s1, sp)
    SAVE_REG(a0, sp)
    SAVE_REG(a1, sp)
    SAVE_REG(a2, sp)
    SAVE_REG(a3, sp)
    SAVE_REG(a4, sp)
    SAVE_REG(a5, sp)
    SAVE_REG(a6, sp)
    SAVE_REG(a7, sp)
    SAVE_REG(s2, sp)
    SAVE_REG(s3, sp)
    SAVE_REG(s4, sp)
    SAVE_REG(s5, sp)
    SAVE_REG(s6, sp)
    SAVE_REG(s7, sp)
    SAVE_REG(s8, sp)
    SAVE_REG(s9, sp)
    SAVE_REG(s10, sp)
    SAVE_REG(s11, sp)
    SAVE_REG(t3, sp)
    SAVE_REG(t4, sp)
    SAVE_REG(t5, sp)
    SAVE_REG(t6, sp)

    LDC(gp, sp, 32 * 8)


    csrr t0, mcause

    srli t1, t0, 63
    bne t1, x0, 1f
    li t1, CAUSE_SUPERVISOR_ECALL
    bne t0, t1, 2f

    call handle_trap_ecall
    mv a1, a0
    li a0, 0

    CCSRRW(t0, CCSR_CEPC, x0)
    addi t0, t0, 4
    CCSRRW(x0, CCSR_CEPC, t0)

    j return_to_sumode

2:
    j 2b

1:
    # handle interrupts
    slli t0, t0, 1
    srli a0, t0, 1

    call handle_interrupt

    RESTORE_REG(a0, sp)
    RESTORE_REG(a1, sp)

return_to_sumode:


    STC(gp, sp, 32 * 8)

    RESTORE_REG(ra, sp)
    RESTORE_REG(gp, sp)
    RESTORE_REG(tp, sp)
    RESTORE_REG(t0, sp)
    RESTORE_REG(t1, sp)
    RESTORE_REG(t2, sp)
    RESTORE_REG(s0, sp)
    RESTORE_REG(s1, sp)
    RESTORE_REG(a2, sp)
    RESTORE_REG(a3, sp)
    RESTORE_REG(a4, sp)
    RESTORE_REG(a5, sp)
    RESTORE_REG(a6, sp)
    RESTORE_REG(a7, sp)
    RESTORE_REG(s2, sp)
    RESTORE_REG(s3, sp)
    RESTORE_REG(s4, sp)
    RESTORE_REG(s5, sp)
    RESTORE_REG(s6, sp)
    RESTORE_REG(s7, sp)
    RESTORE_REG(s8, sp)
    RESTORE_REG(s9, sp)
    RESTORE_REG(s10, sp)
    RESTORE_REG(s11, sp)
    RESTORE_REG(t3, sp)
    RESTORE_REG(t4, sp)
    RESTORE_REG(t5, sp)
    RESTORE_REG(t6, sp)

    CINCOFFSETIMM(sp, sp, 34 * 8)

    CCSRRW(sp, CCSR_CSCRATCH, sp)

    # right before returning to S mode:
    # cscratch: sp  ->
    #      sp - 16  -> gp
    mret

call_into_smode:
    # TODO: if this is not the first time we call into S mode
    # we might need to restore its context
    # alternatively, we let the S mode handle this by itself
    STC(gp, sp, -16)
    CCSRRW(sp, CCSR_CSCRATCH, sp)
    li gp, 0

    mret
