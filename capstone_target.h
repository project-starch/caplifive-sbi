/* Per-target configuration of the Capstone monitor. Exactly one of CAPSTONE_TARGET_FPGA /
 * CAPSTONE_TARGET_QEMU is defined by the build (caplifive-buildroot Makefile, CAPSTONE_EXTRA_DEFS).
 *
 * Only macros live here, on purpose: the monitor is compiled by capstone-c, which emits every
 * function and every global (including bare prototypes, `extern`s and `static inline` bodies)
 * in declaration order, so a declaration added to a shared header changes the FPGA firmware's
 * generated assembly. Macros do not. */
#ifndef _CAPSTONE_TARGET_H_
#define _CAPSTONE_TARGET_H_

#if defined(CAPSTONE_TARGET_FPGA) && defined(CAPSTONE_TARGET_QEMU)
#error "CAPSTONE_TARGET_FPGA and CAPSTONE_TARGET_QEMU are both defined; pick one"
#endif
#if !defined(CAPSTONE_TARGET_FPGA) && !defined(CAPSTONE_TARGET_QEMU)
#error "define CAPSTONE_TARGET_FPGA or CAPSTONE_TARGET_QEMU (CAPSTONE_EXTRA_DEFS in the buildroot Makefile)"
#endif

#ifdef CAPSTONE_TARGET_FPGA
/* The monitor's trace/print instruction as the RTL implements it (a CSR write; the QEMU-only
 * `.insn r 0x5b, 0x1, 0x43` is an illegal instruction on the core). */
#define C_PRINT(v) __asm__ volatile("csrw 0x800, %0" :: "r"(v))
#define PRINT(rs1)     .insn r 0x7B, 0x0, 0x9, x0, rs1, x0
#define CSR_CIS          0x804 //Temp fix because 0x800 is taken
/* Table sizes as the board has run them since 2026-08-18 (regions raised 32 -> 96, the real
 * per-boot ceiling); the domain count was lowered to 32 in the 2025 bring-up without a stated
 * reason. Converging QEMU onto these values is a Phase B item (monitor-unification.md). */
#define CAPSTONE_MAX_DOM_N   32
/* R-55 (regions, 2026-10-15): 127. Exact remainders under a full-scheme encoder take more slots than the 96 the
 * board ran since 2026-08-18: R-43 a2's twelve invocations and its closing k800 need 111 by the replay
 * (r55-regions/); 0568f93a9's run used 89. 127 is the most capstone-c can carve: dom_init reserves each global with
 * one `addi t1, t1, -size`, a 12-bit immediate, and regions[] is 16 bytes a slot (160 slots failed to assemble).
 * The kernel module's MAX_REGION_N and libcapstone's must match. */
#define CAPSTONE_MAX_REGION_N   127
/* The top of the board's DRAM window: memory@80000000 is 0x3c2d2000 bytes (CMA at 0xac000000 + 256 MiB), and
 * nothing S-mode uses lies above 0xc0000000. cap_env_init ends Linux's region here, so every remainder is <= 1 GiB
 * and its granule <= 1 MiB (R-55 regions). */
#define CAPSTONE_DRAM_TOP   0xc0000000
#else
#define C_PRINT(v) __asm__ volatile(".insn r 0x5b, 0x1, 0x43, x0, %0, x0" :: "r"(v))
#define PRINT(reg)     .insn r 0x5b, 0x1, 0x43, x0, reg, x0
#define CSR_CIS          0x800
/* Phase B item 3 (2026-09-08): the board's geometry on QEMU too -- 32 domain slots (never reused
   on the unmanaged path, so there the per-boot domain budget; the process path reuses free ones)
   and 96 region slots. 96 > the kernel
   module's former 64-entry copy, which is what makes M-2 reproducible off the board. */
#define CAPSTONE_MAX_DOM_N   32
#define CAPSTONE_MAX_REGION_N   96
#endif

#endif
