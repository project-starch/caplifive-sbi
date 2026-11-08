/* capstone_cscheck.S -- MEASUREMENT ONLY: the monitor's emulation of CSCHECKR/CSCHECKW (custom-2 0x5b, funct3 1,
 * funct7 0x25/0x26) and CSKINDS (funct7 0x27) for a processor that decodes none of them (C.5a lineage, E5), so that
 * the native direct-register syscall route can run and be measured on silicon. Measurement only: it reads the
 * MUTABLE frame (the escape's slots at +64+16r and the kernel-written epoch word at +2336); C.5a has no hidden
 * escaped-register snapshot, so trusted frame rewrites are not excluded. llvm-capstone native/c5a-route records
 * the design (docs/history/08-11-2026_14-30-00_native-checked-emu-measurement.md).
 *
 *   cscheck_dispatch(a0 = a capability over the trap frame, cursor at S's x0 slot: S's x[n] at a0 + 8n)
 *     -> a0 = 0: not ours, nothing changed (the caller delivers the illegal instruction as before);
 *     -> a0 = 1: handled: rd written into the frame, mepc + 4. ra, sp, gp and tp are preserved; every other GPR is
 *        clobbered (the caller restores them all from the frame), including the loaded capability, cleared before.
 *
 * Operands are PHYSICAL (rs1 = the paused frame, 4 KiB aligned; rs2 = a 16-byte-aligned 48-byte descriptor inside
 * one page), so there is no Sv39 walk: every access goes through a NONLIN capability minted for its page (CSC_PHYS,
 * as capstone_csmint.S's CSM_PHYS), as capability mode requires of M.
 *
 * CSCHECKR/W, in capstone-qemu helper_cscheck's order where M can see it (rd = the first refusal, else 0):
 *   frame not page aligned, descriptor misaligned or crossing its page             -> 29
 *   epoch 0 or != frame+2336, slot outside 1..31, descriptor word 5 != 0,
 *   satp != frame+0 and != frame+928, srevroot (CSR 0x5C1) != frame+8               -> 29
 *   the slot's stored hi word 0                                                      -> 24
 *   the stored type field [29:27] != NONLIN in the STORED enum (2 on the RTL, 1 in QEMU: ISSUES Q-35)   -> 26
 *     (read BEFORE any load: an LDC of a LINEAR slot would move it out of the frame)
 *   LDC through the frame capability, LCC TYPE 7 (untagged)                          -> 24
 *   the id hi[63:34] dead in the FLAT RECYCLE table at srevroot: header RECYCLE set and PAGED clear,
 *     2 <= index < next and < capacity, record word 1 VALID and not FREE, generation [59:30+IB] == id >> IB   -> 25
 *   LCC PERM lacks R (CSCHECKR) or W (CSCHECKW)                                      -> 27
 *   cursor + offset overflows, leaves [base, end], end - address < bytes, or an address is not Sv39  -> 28
 *   else descriptor[4] = cursor + offset, rd = 0.
 * Every check that reaches the descriptor stamps descriptor word 5 with CSC_FINGERPRINT (the adapter counts the
 * stamps: firmware entries; a check the processor performs never writes word 5).
 *
 * CSKINDS rd, rs1 = frame: bit r (1..31) = slot r is tagged, by LDC through the frame capability; a slot whose hi word
 * is 0 reads 0; a slot whose stored type is not NONLIN is reported tagged without a load (it might be LINEAR).
 *
 * QEMU does not decode CAPCREATE, so this file cannot run there: it is for the FPGA build; capstone-qemu's
 * x-capstone-cscheck-frame models the same rules for gating the kernel path on the twin.
 */

#ifndef CSC_STORED_NONLIN
#define CSC_STORED_NONLIN 2          /* the RTL's cap_type_t NONLIN, as stored (Q-35) */
#endif
#ifndef CSC_INDEX_BITS
#define CSC_INDEX_BITS 20            /* E5's flat index: id = {generation[29:20], index[19:0]} */
#endif
#define CSC_FINGERPRINT 0x4353434845
#define CSC_GEN_SHIFT (30 + CSC_INDEX_BITS)

#define CSC_CAPCREATE(reg)           .insn r 0x7B, 0x0, 0x4, reg, x0, x0
#define CSC_CAPTYPE(rd, rs1)         .insn r 0x7B, 0x0, 0x5, rd, rs1, x0
#define CSC_CAPPERM(rd, rs1)         .insn r 0x7B, 0x0, 0x7, rd, rs1, x0
#define CSC_CAPBOUND(rd, rs1, rs2)   .insn r 0x7B, 0x0, 0x8, rd, rs1, rs2
#define CSC_CINCOFFSET(rd, rs1, rs2) .insn r 0x5B, 0x1, 0xc, rd, rs1, rs2
#define CSC_LDC(rd, rs1)             .insn i 0x5B, 0x3, rd, 0(rs1)
#define CSC_LCC_TYPE(rd, rs1)        .insn r 0x5B, 0x1, 0x4, rd, rs1, x1
#define CSC_LCC_CURSOR(rd, rs1)      .insn r 0x5B, 0x1, 0x4, rd, rs1, x2
#define CSC_LCC_BASE(rd, rs1)        .insn r 0x5B, 0x1, 0x4, rd, rs1, x3
#define CSC_LCC_END(rd, rs1)         .insn r 0x5B, 0x1, 0x4, rd, rs1, x4
#define CSC_LCC_PERM(rd, rs1)        .insn r 0x5B, 0x1, 0x4, rd, rs1, x5

/* CAP = a NONLIN RW capability over the 4 KiB page holding PA, cursor at PA. T1, T2 temporaries; all distinct. */
#define CSC_PHYS(CAP, PA, T1, T2) \
  CSC_CAPCREATE(CAP); li T1, 2; CSC_CAPTYPE(CAP, T1); \
  srli T1, PA, 12; slli T1, T1, 12; li T2, 4096; add T2, T1, T2; CSC_CAPBOUND(CAP, T1, T2); \
  li T2, 6; CSC_CAPPERM(CAP, T2); sub T1, PA, T1; CSC_CINCOFFSET(CAP, CAP, T1)

.align 2
.globl cscheck_dispatch
cscheck_dispatch:
  csrr t0, mstatus             /* from S only */
  srli t0, t0, 11
  andi t0, t0, 3
  li t1, 1
  bne t0, t1, csc_not_ours
  csrr t0, mtval               /* the instruction (C.5a reports it in mtval for an illegal custom encoding) */
  li t1, 0xfe00707f
  and t2, t0, t1
  li s11, 0
  li t1, 0x4a00105b            /* CSCHECKR */
  beq t2, t1, csc_decode
  li s11, 1
  li t1, 0x4c00105b            /* CSCHECKW */
  beq t2, t1, csc_decode
  li s11, 2
  li t1, 0x4e00105b            /* CSKINDS */
  bne t2, t1, csc_not_ours
csc_decode:
  srli s3, t0, 15
  andi s3, s3, 31              /* s3: rs1 */
  srli s4, t0, 20
  andi s4, s4, 31              /* s4: rs2 */
  srli s5, t0, 7
  andi s5, s5, 31              /* s5: rd */
  li t1, 2                     /* S's sp is in CSCRATCH, not the frame */
  beq s3, t1, csc_not_ours
  beq s4, t1, csc_not_ours
  beq s5, t1, csc_not_ours
  li a4, 0
  beqz s3, 1f
  slli t1, s3, 3
  CSC_CINCOFFSET(a0, a0, t1)
  ld a4, 0(a0)                 /* a4: the frame's physical address */
  sub t1, x0, t1
  CSC_CINCOFFSET(a0, a0, t1)
1:
  li a3, 0
  beqz s4, 2f
  slli t1, s4, 3
  CSC_CINCOFFSET(a0, a0, t1)
  ld a3, 0(a0)                 /* a3: the descriptor's physical address */
  sub t1, x0, t1
  CSC_CINCOFFSET(a0, a0, t1)
2:
  li s10, 29                   /* s10: the result */
  li s9, 0                     /* s9: 1 once the descriptor capability exists */
  li t2, 4095
  and t1, a4, t2
  bnez t1, csc_finish
  CSC_PHYS(s6, a4, t3, t4)     /* s6: the frame page */
  li t1, 2
  beq s11, t1, csc_kinds
  andi t1, a3, 15
  bnez t1, csc_finish
  li t2, 4095
  and t1, a3, t2
  addi t1, t1, 48
  li t2, 4096
  bltu t2, t1, csc_finish
  CSC_PHYS(s7, a3, t3, t4)     /* s7: the descriptor */
  li s9, 1
  ld s8, 0(s7)                 /* epoch */
  ld a7, 8(s7)                 /* slot */
  ld a5, 16(s7)                /* offset */
  ld a6, 24(s7)                /* bytes */
  ld t1, 40(s7)                /* reserved */
  bnez t1, csc_finish
  beqz s8, csc_finish
  li t2, 2336
  CSC_CINCOFFSET(t6, s6, t2)
  ld t1, 0(t6)
  bne s8, t1, csc_finish
  beqz a7, csc_finish
  li t1, 32
  bgeu a7, t1, csc_finish
  csrr t1, satp
  ld t2, 0(s6)
  beq t1, t2, 3f
  li t3, 928
  CSC_CINCOFFSET(t6, s6, t3)
  ld t2, 0(t6)
  bne t1, t2, csc_finish
3:
  csrr t1, 0x5c1
  ld t2, 8(s6)
  bne t1, t2, csc_finish
  /* ---- the slot */
  slli t1, a7, 4
  addi t1, t1, 64
  CSC_CINCOFFSET(t6, s6, t1)   /* t6: the slot */
  ld s1, 8(t6)                 /* s1: the stored hi word */
  li s10, 24
  beqz s1, csc_finish
  srli t1, s1, 27
  andi t1, t1, 7
  li t2, CSC_STORED_NONLIN
  li s10, 26
  bne t1, t2, csc_finish
  CSC_LDC(t5, t6)              /* t5: the slot's capability (NONLIN: a copy) */
  CSC_LCC_TYPE(t4, t5)
  li t1, 7
  li s10, 24
  beq t4, t1, csc_clear
  li t1, 1                     /* the TYPE query's NONLIN (RTL and QEMU agree, Q-35) */
  li s10, 26
  bne t4, t1, csc_clear
  /* ---- liveness in the flat RECYCLE table at srevroot */
  li s10, 25
  srli t1, s1, 34              /* the id */
  li t2, (1 << CSC_INDEX_BITS) - 1
  and t3, t1, t2               /* t3: index */
  srli t4, t1, CSC_INDEX_BITS  /* t4: generation */
  csrr t2, 0x5c1               /* t2: the table root */
  li a1, 4095
  and a2, t2, a1
  bnez a2, csc_clear
  CSC_PHYS(a1, t2, a2, s0)     /* a1: the header page */
  ld a2, 0(a1)                 /* capacity | RECYCLE << 63 | PAGED << 62 */
  srli s0, a2, 62
  li s2, 2                     /* RECYCLE set, PAGED clear */
  bne s0, s2, csc_clear
  slli a2, a2, 2
  srli a2, a2, 2               /* a2: capacity */
  ld s0, 8(a1)                 /* s0: next */
  li s2, 2
  bltu t3, s2, csc_clear
  bgeu t3, s0, csc_clear
  bgeu t3, a2, csc_clear
  slli a1, t3, 4
  add a1, a1, t2
  addi a1, a1, 8               /* a1: the record's word 1 */
  CSC_PHYS(a2, a1, s0, s2)
  ld a1, 0(a2)                 /* one 64-bit read: flags and generation together */
  srli s0, a1, 60
  andi s2, s0, 1
  beqz s2, csc_clear           /* not VALID */
  andi s2, s0, 4
  bnez s2, csc_clear           /* FREE */
  srli s0, a1, CSC_GEN_SHIFT
  li s2, (1 << (30 - CSC_INDEX_BITS)) - 1
  and s0, s0, s2
  bne s0, t4, csc_clear
  /* ---- permission */
  CSC_LCC_PERM(t1, t5)
  li t2, 4                     /* R */
  beqz s11, 4f
  li t2, 2                     /* W */
4:
  and t3, t1, t2
  li s10, 27
  bne t3, t2, csc_clear
  /* ---- bounds */
  CSC_LCC_CURSOR(t1, t5)
  CSC_LCC_BASE(t2, t5)
  CSC_LCC_END(t3, t5)
  li s10, 28
  add t4, t1, a5               /* address */
  bltu t4, t1, csc_clear       /* offset overflow */
  bltu t4, t2, csc_clear
  bltu t3, t4, csc_clear
  sub s0, t3, t4
  bltu s0, a6, csc_clear       /* end - address < bytes */
  slli s0, t4, 25
  srai s0, s0, 25
  bne s0, t4, csc_clear
  beqz a6, 5f
  add s0, t4, a6
  addi s0, s0, -1
  slli s2, s0, 25
  srai s2, s2, 25
  bne s2, s0, csc_clear
5:
  sd t4, 32(s7)                /* descriptor[4] = the address */
  li s10, 0
csc_clear:
  li t5, 0                     /* drop the loaded capability */
csc_finish:
  beqz s9, csc_write
  li t1, CSC_FINGERPRINT
  sd t1, 40(s7)
csc_write:
  beqz s5, 6f
  slli t1, s5, 3
  CSC_CINCOFFSET(a0, a0, t1)
  sd s10, 0(a0)                /* rd */
6:
  csrr t0, mepc
  addi t0, t0, 4
  csrw mepc, t0
  li a0, 1
  ret

/* CSKINDS: s6 = the frame page. */
csc_kinds:
  li s10, 0
  li a7, 1
7:
  slli t1, a7, 4
  addi t1, t1, 64
  CSC_CINCOFFSET(t6, s6, t1)
  ld t2, 8(t6)
  beqz t2, 9f                  /* a plain integer */
  srli t3, t2, 27
  andi t3, t3, 7
  li t4, CSC_STORED_NONLIN
  bne t3, t4, 8f               /* never load a slot that might be LINEAR: report it tagged */
  CSC_LDC(t5, t6)
  CSC_LCC_TYPE(t3, t5)
  li t5, 0
  li t4, 7
  beq t3, t4, 9f
8:
  li t1, 1
  sll t1, t1, a7
  or s10, s10, t1
9:
  addi a7, a7, 1
  li t1, 32
  bltu a7, t1, 7b
  j csc_write

csc_not_ours:
  li a0, 0
  ret
