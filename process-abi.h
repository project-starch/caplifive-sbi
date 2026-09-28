/* Process platform ABI v1. Keep this wire definition identical in the driver
 * and monitor repositories. RV64 only; unavailable on the current FPGA target.
 * QUERY uses selectors 0..3 for low u32 and 4..7 for high u32 of
 * result/cause/pc/address, avoiding the legacy SBI -1 error sentinel.
 */
#ifndef CAPSTONE_PROCESS_ABI_H
#define CAPSTONE_PROCESS_ABI_H
#define CAPSTONE_PROCESS_FEATURES_V1 0x10001
#define SBI_CAPSTONE_PROCESS_CAPABILITIES 0x20
#define SBI_CAPSTONE_PROCESS_STEP 0x21
#define SBI_CAPSTONE_PROCESS_QUERY 0x22
#define SBI_CAPSTONE_PROCESS_FORGET 0x23
#define SBI_CAPSTONE_PROCESS_DESTROY 0x24
#define SBI_CAPSTONE_PROCESS_REGION_CREATE 0x25
#define SBI_CAPSTONE_PROCESS_REGION_RESET 0x26
#define SBI_CAPSTONE_PROCESS_REGION_PREPARE 0x27
#define SBI_CAPSTONE_PROCESS_COLLECT 0x28
#define SBI_CAPSTONE_PROCESS_RESUME_SHARE 0x29
#define SBI_CAPSTONE_PROCESS_STATS 0x2a
#endif
