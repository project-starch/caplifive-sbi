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
#endif
