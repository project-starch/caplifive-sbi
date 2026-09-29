/* Process platform ABI. Keep this wire definition identical in the driver
 * and monitor repositories. RV64 only; unavailable on the current FPGA target.
 * STEP returns the whole event in one ecall: the kind as the SBI value (a1),
 * then result, cause, pc and address in a2..a5. The driver issues STEP with
 * its own ecall that declares a2..a5 clobbered; every other function keeps the
 * SBI convention. No feature probe: driver and monitor are pinned together.
 */
#ifndef CAPSTONE_PROCESS_ABI_H
#define CAPSTONE_PROCESS_ABI_H
#define SBI_CAPSTONE_PROCESS_STEP 0x21
#define SBI_CAPSTONE_PROCESS_FORGET 0x23
#define SBI_CAPSTONE_PROCESS_DESTROY 0x24
#define SBI_CAPSTONE_PROCESS_REGION_CREATE 0x25
#define SBI_CAPSTONE_PROCESS_REGION_RESET 0x26
#define SBI_CAPSTONE_PROCESS_REGION_PREPARE 0x27
#define SBI_CAPSTONE_PROCESS_COLLECT 0x28
#define SBI_CAPSTONE_PROCESS_RESUME_SHARE 0x29
#define SBI_CAPSTONE_PROCESS_STATS 0x2a
#define SBI_CAPSTONE_PROCESS_ADOPT 0x2b

/* Context slots (docs/plans/delegation-threads.md in llvm-capstone). A
 * context is named by its slot and the slot's generation; create and ADOPT
 * return (generation << 32) | slot, and STEP, FORGET, DESTROY and ADOPT take
 * the two as separate arguments. A generation is never reissued and never
 * exceeds 0x7fffffff, so every id is positive as a long; a slot that has had
 * that generation is not used again. */
#define CAPSTONE_PROCESS_SLOT_MASK 0xffffffffUL

/* The monitor's slot table: every application's first context and every
 * adopted context holds one slot. */
#define CAPSTONE_PROCESS_SLOTS 32

/* STEP kinds after the supervisor's returned (0), preempted (1), fault (2). */
#define CAPSTONE_PROCESS_STEP_DEAD 3   /* the slot's seal was revoked */
#define CAPSTONE_PROCESS_STEP_STALE 4  /* (slot, generation) names no current context */
#define CAPSTONE_PROCESS_STEP_REFUSED 5 /* the seal would not run in C-mode; not entered */

/* Results of FORGET and ADOPT besides 0 and a context id. */
#define CAPSTONE_PROCESS_STALE -2      /* old generation or ticket */
#define CAPSTONE_PROCESS_EMPTY -3      /* no offer outstanding */
#define CAPSTONE_PROCESS_FULL -4       /* no slot or descriptor free; the offer stays */

/* The invocation descriptor a context receives in a1 on every call entry:
 * the result word at 0, the offer ticket at 16, the offered seal at 32. */
#define CAPSTONE_PROCESS_DESC_RESULT 0
#define CAPSTONE_PROCESS_DESC_TICKET 16
#define CAPSTONE_PROCESS_DESC_OFFER 32
#define CAPSTONE_PROCESS_DESC_BYTES 64
/* Per application, carved off the top of its data region: 8 descriptors, so
 * at most 8 of its contexts registered at once. The driver adds this to the
 * block it allocates, so the declared data is not reduced. */
#define CAPSTONE_PROCESS_DESC_AREA 512
#endif
