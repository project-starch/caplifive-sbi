/**
 * NOTE: This file is to be compiled with Capstone-CC to generate sbi_capstone.S.
*/

#include "sbi_capstone.h"

/* Capstone-C defs */
#define __linear __attribute__((linear))
#define __dom __attribute__((dom))
#define __rev __attribute__((rev))
#define __domret __attribute__((domret))
#define __domasync __attribute__((domasync))
#define __domentry __attribute__((domentry))

#define C_READ_CSR(csr_name, v) __asm__("csrr %0, " #csr_name : "=r"(v))
#define C_READ_CCSR(ccsr_name, v) __asm__("ccsrrw(%0, " #ccsr_name ", x0)" : "=r"(v))
#define C_WRITE_CCSR(ccsr_name, v) __asm__("ccsrrw(x0, " #ccsr_name ", %0)" :: "r"(v))
#define C_SET_CURSOR(dest, cap, cursor) __asm__("scc(%0, %1, %2)" : "=r"(dest) : "r"(cap), "r"(cursor))
#define C_GEN_CAP(dest, base, end) __asm__(".insn r 0x5b, 0x1, 0x40, %0, %1, %2" : "=r"(dest) : "r"(base), "r"(end));
/* Was `while(1);` -- the error code was DISCARDED and the monitor spun silently, so
   every monitor-detected failure on the FPGA looked identical to a domain hang. That
   cost a board session: SQLite's first run stopped after "Loadable size" with no
   output, and "blob does not fit" could not be distinguished from "domain hung".
   Matches the QEMU monitor's definition now, so the two agree. */
/* I-4: C_PRINT is `csrw 0x800` -- it reaches the RTL TRACE, never the UART, so on the
   FPGA every monitor error looked identical (output stops, board dead, nothing printed)
   and cost several board sessions of guessing. capstone_error now ALSO writes a 4-char
   site TAG plus the code in hex to the 16550 UART (capstone_report(), below) before it
   spins. The C_PRINTs are unchanged, so the RTL trace is byte-for-byte what it was.
   `capstone_error_tag(tag, code)` lets a site name itself; `capstone_error(code)` is the
   historical one-argument form and reports the generic "CERR" tag.
   Tags are 4 ASCII characters packed into an integer -- deliberately NOT string
   literals, so this needs no .rodata (monitor .rodata delivery is its own open issue)
   and no varargs. Each printed line is TAG ':' 8-hex CRLF = 15 bytes, i.e. it fits in
   one 16-byte TX FIFO, and is flushed before the next line starts, so a console that
   truncates at 16 characters still shows every line whole. */
#define CAPSTONE_TAG_CERR 0x43455252 /* "CERR" generic capstone_error() */
#define CAPSTONE_TAG_IRQX 0x49525158 /* "IRQX" handle_interrupt: unhandled interrupt */
#define CAPSTONE_TAG_EXCX 0x45584358 /* "EXCX" handle_exception: unhandled cause */
#define CAPSTONE_TAG_ILLX 0x494c4c58 /* "ILLX" illegal instruction that is not CSR time */
#define CAPSTONE_TAG_CPMX 0x43504d58 /* "CPMX" swap_cpmp: no region covers the fault addr */
#define CAPSTONE_TAG_SPLA 0x53504c41 /* "SPLA" split_out_cap: no region covers the request */
#define CAPSTONE_TAG_SPLB 0x53504c42 /* "SPLB" split_out_cap: exact-fit region unsupported */
#define CAPSTONE_TAG_HOLE 0x484f4c45 /* "HOLE" split_out_cap: exact-fit slot retired in place (Q-03); value = slot index, RGNN follows */
/* context lines, printed after a site tag */
#define CAPSTONE_TAG_MCAU 0x4d434155 /* "MCAU" mcause */
#define CAPSTONE_TAG_MEPC 0x4d455043 /* "MEPC" mepc */
#define CAPSTONE_TAG_MTVL 0x4d54564c /* "MTVL" mtval */
#define CAPSTONE_TAG_MSTA 0x4d535441 /* "MSTA" mstatus -- MPP in bits [12:11] */
#define CAPSTONE_TAG_BASE 0x42415345 /* "BASE" requested base address */
#define CAPSTONE_TAG_ALEN 0x414c454e /* "ALEN" requested length */
#define CAPSTONE_TAG_DBAS 0x44424153 /* "DBAS" create_domain: the domain's LOAD BASE */
#define CAPSTONE_TAG_DENT 0x44454e54 /* "DENT" create_domain: entry_offset within that base */
/* Error codes for sites that previously had none (they spun with no code at all).
   0x1/0x2 (CAPSTONE_NO_REGION / CAPSTONE_NO_CPMP_REGION) keep their existing values so
   the RTL trace does not change. */
#define CAPSTONE_ERR_IRQ_UNHANDLED   0xe001
#define CAPSTONE_ERR_EXC_UNHANDLED   0xe002
#define CAPSTONE_ERR_ILLEGAL_INSN    0xe003
#define CAPSTONE_ERR_SPLIT_NO_REGION 0xe005
#define CAPSTONE_ERR_SPLIT_EXACT     0xe006 /* RETIRED 2026-09-07 (Q-03): no emitter. Kept so logs
     from before the hole fix stay decodable: SPLB:0000E006 = the unimplemented exact-fit spin. */
#define CAPSTONE_ERR_SPLIT_EXACT_MID 0xe010 /* RETIRED 2026-09-07 (Q-03): no emitter. Was the
     middle-slot exact-fit spin of the tail-only handling (0xe007 before that, colliding with
     CAPSTONE_ERR_SHARE_BAD_ID). */
#define CAPSTONE_ERR_SPLIT_EXACT_NONLIN 0xe011 /* exact fit on a NON-linear carve: would re-home the
     capability at a new index, the one index move the pool must never do. Unreachable: linear == 0
     only for the FOUR boot-time carves in cap_env_init, and none of those is an exact fit (the
     int-handler text is a head carve of genesis region 1, the other three sit inside region 0).
     Loud if it ever happens. */

/* Q-03 history. The exact-fit case of split_out_cap() was an unimplemented spin (SPLB:0000E006)
   and it was the BACKGROUND WEDGE of the 2026-08 board campaigns: the trivial control domain
   wedged at run 6-7 in 4 of 4 boots (2026-08-01), and the 5th create_dom of a boot spun twice in
   consecutive boots (2026-08-06) -- each time blaming whatever domain occupied that slot, once
   producing a confident, entirely false localization of a SQLite function that never executed.
   The first fix (2026-08-01, re-enabled 2026-08-06 after an A/B left it off) handled only the
   TAIL slot by shrinking the pool, which renumbers nothing but still spun at any other slot
   (SPLB:0000E010). Since 2026-09-07 an exact fit at ANY slot leaves a hole (make_hole below):
   region ids are guest-visible array indices the kernel module caches, so a slot is never
   renumbered or reused. There is no build knob; the handling is unconditional. */
/* ---- I-4, REGION-SHARE path -------------------------------------------------
   SQLite hangs inside its FIRST shared_region_annotated() call with NO monitor
   tag at all -- not ILLX, not SPLA, not SPLB -- so the wedge is at a site that
   none of the five original tags covers. The share path had exactly zero output
   of its own: every rejection returned -1 into a kernel-module caller that
   DISCARDS it, and the three spins it can reach (read_cpmp/write_cpmp default,
   the TRANSFERRED type check) were bare `while(1);`.
   Two kinds of tag are added below.
     * SITE tags, always compiled in, one per error/spin, printed with the
       operands that site has in scope. These follow SPLA/SPLB exactly:
       capstone_report(...) lines, then capstone_uart_flush(), then the spin.
     * PROGRESS tags (capstone_trace), at the handler entry and after each major
       step. An error tag only helps if control REACHES a tagged error; a hang
       with no output is localised by entry/step markers, which is precisely the
       situation here. The most load-bearing pair is SHA5/SHA6: SHA5 is the last
       thing printed before control leaves M-mode for the domain, so
       "SHA5 then silence" means the hang is inside the DOMAIN's region-share
       entry and NOT in the monitor, while "no SHA0" means the ecall never
       arrived.
   Progress tags are switchable because they are not free: up to 10 lines per
   share call, and capstone_puts_hex now prints 16 digits, so a line is
   4 + 1 + 16 + 2 = 23 bytes -- ~230 bytes, ~40 ms at 57600 baud per share. That
   would swamp any borrow-cost cycle measurement. Build a perf firmware with
   CAPSTONE_SHARE_TRACE_ENABLE undefined; the site tags stay on either way.
   NOTE for whoever reads the console: at 23 bytes a line no longer fits in the
   16-byte TX FIFO the comment above assumes (that text predates the 8->16 digit
   widening). capstone_putc polls THRE per character so nothing is dropped by the
   UART, but a console that truncates at 16 characters will now cut the low hex
   digits off every line. */
#ifdef CAPSTONE_TARGET_FPGA
#define CAPSTONE_SHARE_TRACE_ENABLE
#endif
/* share-path site tags */
#define CAPSTONE_TAG_EXTC 0x45585443 /* "EXTC" ext_code  (a7) -- positive control */
#define CAPSTONE_TAG_FNCC 0x464e4343 /* "FNCC" func_code (a6) -- positive control */
#define CAPSTONE_TAG_ARG1 0x41524731 /* "ARG1" arg1 at DISPATCH, before the handler */
#define CAPSTONE_TAG_ARG4 0x41524734 /* "ARG4" arg4 -- expected 0, sanity */
#define CAPSTONE_TAG_ECSA 0x45435341 /* "ECSA" ecall dispatch: REGION_SHARE_ANNOTATED entered */
#define CAPSTONE_TAG_ECSZ 0x4543535a /* "ECSZ" ecall dispatch: handler returned, value = res */
#define CAPSTONE_TAG_SHA0 0x53484130 /* "SHA0" shared_region_annotated: entered */
#define CAPSTONE_TAG_SHA1 0x53484131 /* "SHA1" ids accepted; value = region_cpmp[region_id] */
#define CAPSTONE_TAG_SHA2 0x53484132 /* "SHA2" region capability in hand; value = cap type */
#define CAPSTONE_TAG_SHA3 0x53484133 /* "SHA3" revocation annotation applied */
#define CAPSTONE_TAG_SHA4 0x53484134 /* "SHA4" permission annotation applied */
#define CAPSTONE_TAG_SHA5 0x53484135 /* "SHA5" about to leave M-mode for the domain */
#define CAPSTONE_TAG_SHA6 0x53484136 /* "SHA6" the domain returned from the share entry */
#define CAPSTONE_TAG_ENT0 0x454e5430 /* "ENT0" call_domain entered, value = dom_id */
#define CAPSTONE_TAG_ENT1 0x454e5431 /* "ENT1" about to leave M-mode INTO the domain */
#define CAPSTONE_TAG_ENT2 0x454e5432 /* "ENT2" the domain returned, value = its result */
#define CAPSTONE_TAG_ENTB 0x454e5442 /* "ENTB" bad dom_id, returns -1 without entering */
#define CAPSTONE_TAG_SHAB 0x53484142 /* "SHAB" bad dom_id/region_id (returns -1) */
#define CAPSTONE_TAG_SHAV 0x53484156 /* "SHAV" unknown annotation_rev (returns -1) */
#define CAPSTONE_TAG_SHAP 0x53484150 /* "SHAP" unknown annotation_perm (returns -1) */
#define CAPSTONE_TAG_SHAX 0x53484158 /* "SHAX" TRANSFERRED on a non-linear cap: spin */
#define CAPSTONE_TAG_RCPX 0x52435058 /* "RCPX" read_cpmp: cpmp index out of range: spin */
#define CAPSTONE_TAG_WCPX 0x57435058 /* "WCPX" write_cpmp: cpmp index out of range: spin */
#define CAPSTONE_TAG_DPIS 0x44504953 /* "DPIS" dpi_share_region entered; value = region_n */
#define CAPSTONE_TAG_RGNO 0x52474e4f /* "RGNO" region table full: spin (was silent overrun) */
#define CAPSTONE_TAG_DPIC 0x44504943 /* "DPIC" handle_dpi: dpi_call returned: spin */
#define CAPSTONE_TAG_DPIX 0x44504958 /* "DPIX" handle_dpi: unimplemented DPI function */
#define CAPSTONE_TAG_DRET 0x44524554 /* "DRET" DOM_RETURN: return_from_domain returned: spin */
/* extra context lines for the share path */
#define CAPSTONE_TAG_DOMN 0x444f4d4e /* "DOMN" dom_n */
#define CAPSTONE_TAG_RGNF 0x52474e46 /* "RGNF" region table full: a carve REFUSED before touching the pool (Phase B item 1), not a fault */
#define CAPSTONE_TAG_RGNN 0x52474e4e /* "RGNN" region_n */
#define CAPSTONE_TAG_RGID 0x52474944 /* "RGID" region_id */
#define CAPSTONE_TAG_CPID 0x43504944 /* "CPID" cpmp index */
#define CAPSTONE_TAG_AREV 0x41524556 /* "AREV" annotation_rev */
#define CAPSTONE_TAG_APRM 0x4150524d /* "APRM" annotation_perm */
#define CAPSTONE_TAG_CTYP 0x43545950 /* "CTYP" capability type (0 = linear) */
#define CAPSTONE_TAG_DPIF 0x44504946 /* "DPIF" DPI function code */
#define CAPSTONE_ERR_SHARE_BAD_ID    0xe007
#define CAPSTONE_ERR_SHARE_BAD_REV   0xe008
#define CAPSTONE_ERR_SHARE_BAD_PERM  0xe009
#define CAPSTONE_ERR_SHARE_NOT_LIN   0xe00a
#define CAPSTONE_ERR_CPMP_INDEX      0xe00b
#define CAPSTONE_ERR_REGION_OVERFLOW 0xe00c
#define CAPSTONE_ERR_DPI_CALL_RET    0xe00d
#define CAPSTONE_ERR_DPI_UNKNOWN     0xe00e
#define CAPSTONE_ERR_DOM_RETURN_RET  0xe00f
#ifdef CAPSTONE_SHARE_TRACE_ENABLE
#define capstone_trace(tag, v) capstone_report((tag), (v))
#else
#define capstone_trace(tag, v)
#endif
#ifdef CAPSTONE_TARGET_QEMU
/* QEMU has no UART path in the monitor (the virt board maps its UART with a different register
 * layout, and the harnesses read the trace instruction instead): a report is a pair of trace
 * prints, the flush is nothing, and the progress traces stay off. Macros, so the FPGA build is
 * untouched (see capstone_target.h for why nothing here may be a declaration). */
#define capstone_report(tag, v) do { C_PRINT(tag); C_PRINT(v); } while (0)
#define capstone_uart_flush() do { } while (0)
#endif
/* make_hole's signature differs per target and a shared two-argument signature is NOT free on
 * the FPGA build (capstone-c grows the frame for the unused parameter and shifts every spill
 * offset -- measured). The call sites use this macro; the definitions stay verbatim below. */
#ifdef CAPSTONE_TARGET_FPGA
/* plain statements, no do/while: capstone-c turns the wrapper into a bnez-x0 skeleton and
   re-allocates registers, which cost the QEMU arm its byte-identity for nothing */
#define REPORT_REGION_OVERFLOW() capstone_report(CAPSTONE_TAG_RGNF, CAPSTONE_ERR_REGION_OVERFLOW); capstone_report(CAPSTONE_TAG_RGNN, region_n); capstone_uart_flush()
#define MAKE_HOLE(i, tag) make_hole((i))
#else
#define MAKE_HOLE(i, tag) make_hole((i), (tag))
#define REPORT_REGION_OVERFLOW() C_PRINT(0x1237); C_PRINT(region_n)
#endif
#define capstone_error_tag(tag, err_code) do { C_PRINT(CAPSTONE_ERR_STARTER); C_PRINT(err_code); capstone_report((tag), (err_code)); while(1); } while(0)
#define capstone_error(err_code) capstone_error_tag(CAPSTONE_TAG_CERR, (err_code))
/* csinit rd, rs1, rs2: UNINIT(cursor==end) -> LIN with cursor = base + rs2.
 * No __init builtin exists, so emit the instruction directly (funct7 0x9),
 * same style as C_PRINT/C_GEN_CAP. */
#define C_INIT(dest, cap, offset) __asm__(".insn r 0x5b, 0x1, 0x9, %0, %1, %2" : "=r"(dest) : "r"(cap), "r"(offset))
#define cap_base(cap) __capfield((cap), 3)
#define cap_end(cap) __capfield((cap), 4)
#define cap_type(cap) __capfield((cap), 1)
#ifdef CAPSTONE_DEBUG_ENABLE
#define debug_counter_inc(counter_no, delta) __asm__ volatile(".insn r 0x5b, 0x1, 0x45, x0, %0, %1" :: "r"(counter_no), "r"(delta))
#define debug_counter_tick(counter_no) debug_counter_inc((counter_no), 1)
#else
#define debug_counter_inc(counter_no, delta)
#define debug_counter_tick(counter_no)
#endif

/* C_PRINT: per target, capstone_target.h */

#define CPMP_COUNT 16
#define DOMAIN_DATA_N    96
#define DOMAIN_DATA_SIZE (16 * DOMAIN_DATA_N)
// gp-free domain ABI (silicon): fixed image offset where the domain's globals
// begin (must equal the value in tests/runtime-qemu/gp-free-domain/link-gpfree.ld).
// The monitor SPLITs the code image here into an execute code cap (PCC) and an
// R/W globals cap (gp). .text must fit in [0, GPFREE_GLOBALS_OFFSET).
#define GPFREE_GLOBALS_OFFSET 0x1000
#define CSR_TIME 0xC0102073

// toggle the following for swapping between cpmp swapping and gen_cap (hack)
// #define USE_GEN_CAP

unsigned *mtime;
unsigned *mtimecmp;
__dom void *domains[CAPSTONE_MAX_DOM_N];
void *regions[CAPSTONE_MAX_REGION_N];
/* the cpmp entry each region is associated with; -1 if unassociated */
unsigned region_cpmp[CAPSTONE_MAX_REGION_N];
/* 1 if the slot holds a live region; 0 for a HOLE (consumed by an exact fit) or a never-used
   slot. Region ids are guest-visible ARRAY INDICES and the kernel module caches page geometry
   by them (modcapstone/module/capstone.c:33), so the pool must never renumber a slot or
   shrink below one the module may hold: a consumed slot keeps its index. (Q-03, 2026-09-07) */
unsigned region_live[CAPSTONE_MAX_REGION_N];
/* the region each cpmp entry is associated with; -1 if unassociated */
unsigned cpmp_region[CPMP_COUNT];
unsigned dom_n, region_n;
unsigned next_eject_cpmp;

__domret void *caller_dom;
unsigned* caller_buf;

/* has S-mode been executed? */
unsigned smode_initialised;
/* saved context of S-mode at the last SBI dom-return call */
unsigned *smode_saved_context;

#ifdef CAPSTONE_TARGET_FPGA
/* ---------------------------------------------------------------------------
 * I-4: making monitor errors VISIBLE on the FPGA console.
 *
 * The monitor runs in capability memory mode, so it cannot just dereference
 * 0x10000000 -- it needs a capability over the UART, minted exactly the way
 * `mtime` already is: split_out_cap(base, len, 0) out of the genesis region
 * (see cap_env_init in ../sbi_capstone_dom.c). `capstone_uart` is that
 * capability; `capstone_uart_ready` is a plain scalar flag so that an error
 * raised BEFORE the capability exists (e.g. inside cap_env_init's own
 * split_out_cap calls) degrades to a silent no-op instead of faulting.
 *
 * Register layout, from platform/fpga/ariane/platform.c:21-26
 *     ARIANE_UART_ADDR 0x10000000, REG_SHIFT 2, REG_WIDTH 4
 * and lib/utils/serial/uart8250.c get_reg()/set_reg(): register N sits at
 * base + (N << 2) and is accessed 32 bits wide (readl/writel). So
 *     THR = +0x00   (offset 0)
 *     LSR = +0x14   (offset 20)   bit 5 = THRE, bit 6 = TEMT
 * The TX FIFO is 16 bytes deep; THRE means it will accept a byte.
 *
 * Deliberately plain C: this runs in M-mode on an already-wedged machine, and
 * it is compiled by capstone-c (a C-subset compiler that accumulates `*`
 * across declarators on one line and has miscompiled nested ternaries). So:
 * one declarator per line, no ternaries, no varargs, no early `return`, no
 * string literals, and every poll loop is BOUNDED so a dead UART can never
 * turn a diagnosable wedge into a hang inside the diagnostic.
 */
#define CAPSTONE_UART_BASE 0x10000000
#define CAPSTONE_UART_LEN  0x100
#define CAPSTONE_UART_THRE 0x20
#define CAPSTONE_UART_TEMT 0x40
/* ~200k MMIO polls; one character at 57600 baud is ~174 us, so this is a wide
   margin over the worst case (a full FIFO drain) and still bounded. */
#define CAPSTONE_UART_SPIN 200000

unsigned *capstone_uart;
unsigned capstone_uart_ready;

static void capstone_putc(unsigned c) {
    unsigned *u;
    unsigned lsr;
    unsigned i;
    if(capstone_uart_ready != 0) {
        u = capstone_uart;
        for(i = 0; i < CAPSTONE_UART_SPIN; i += 1) {
            /* LSR at +20, 32-bit read through the UART capability */
            __asm__ volatile ("lw %0, 20(%1)" : "=r"(lsr) : "r"(u));
            if((lsr & CAPSTONE_UART_THRE) != 0)
                break;
        }
        /* THR at +0, 32-bit write */
        __asm__ volatile ("sw %0, 0(%1)" :: "r"(c), "r"(u));
    }
}

/* Wait for the transmitter to go completely empty (TEMT), so the message
   survives the `while(1)` that follows it. */
static void capstone_uart_flush(void) {
    unsigned *u;
    unsigned lsr;
    unsigned i;
    if(capstone_uart_ready != 0) {
        u = capstone_uart;
        for(i = 0; i < CAPSTONE_UART_SPIN; i += 1) {
            __asm__ volatile ("lw %0, 20(%1)" : "=r"(lsr) : "r"(u));
            if((lsr & CAPSTONE_UART_TEMT) != 0)
                break;
        }
    }
}

/* 8 hex digits, most significant first. Max shift is 28: capstone-c evaluates
   `>> 32` at 32 bits and yields 0 (see the create_domain comment below), so a
   64-bit-wide printer would need two halves -- 8 digits is what every code and
   CSR value used here needs. */
/* 8 digits (low 32 bits), NOT 16. A 16-digit line is "TAG:" + 16 + CRLF = 23 bytes, past
   the 16-byte 16550 TX FIFO this reporting depends on, so the console would truncate the
   low hex digits off EVERY operand -- silently corrupting the numbers the tags exist to
   deliver. An earlier widening here was never exercised because the on-disk .c.S was
   stale; it would have shipped that corruption the moment the wrapper was regenerated.
   The 32-bit truncation that motivated widening is a non-problem in practice: the faulting
   pc was attributed by printing a known load base from the host and subtracting, which
   needs only the low half. If a full 64-bit value is ever required, print it as two
   8-digit halves under separate tags rather than one long line. */
static void capstone_puts_hex(unsigned long v) {
    unsigned i;
    unsigned sh;
    unsigned nib;
    for(i = 0; i < 8; i += 1) {
        sh = (7 - i) * 4;
        nib = (v >> sh) & 0xf;
        if(nib < 10)
            capstone_putc(nib + 0x30);
        else
            capstone_putc(nib + 0x37);
    }
}

/* 4 ASCII characters packed into `tag`, most significant byte first. */
static void capstone_puts_tag(unsigned tag) {
    unsigned i;
    unsigned sh;
    unsigned ch;
    for(i = 0; i < 4; i += 1) {
        sh = (3 - i) * 8;
        ch = (tag >> sh) & 0xff;
        if(ch != 0)
            capstone_putc(ch);
    }
}

/* One line: TAG ':' 8-hex CRLF == 15 bytes, then flush. */
static void capstone_report(unsigned tag, unsigned long v) {
    capstone_puts_tag(tag);
    capstone_putc(0x3a);
    capstone_puts_hex(v);
    capstone_putc(0x0d);
    capstone_putc(0x0a);
    capstone_uart_flush();
}
#endif /* CAPSTONE_TARGET_FPGA: UART reporting */

static __linear void *read_cpmp(unsigned n) {
    __linear void *res;
    switch(n) {
        case 0:
            C_READ_CCSR(cpmp(0), res);
            break;
        case 1:
            C_READ_CCSR(cpmp(1), res);
            break;
        case 2:
            C_READ_CCSR(cpmp(2), res);
            break;
        case 3:
            C_READ_CCSR(cpmp(3), res);
            break;
        case 4:
            C_READ_CCSR(cpmp(4), res);
            break;
        case 5:
            C_READ_CCSR(cpmp(5), res);
            break;
        case 6:
            C_READ_CCSR(cpmp(6), res);
            break;
        case 7:
            C_READ_CCSR(cpmp(7), res);
            break;
        case 8:
            C_READ_CCSR(cpmp(8), res);
            break;
        case 9:
            C_READ_CCSR(cpmp(9), res);
            break;
        case 10:
            C_READ_CCSR(cpmp(10), res);
            break;
        case 11:
            C_READ_CCSR(cpmp(11), res);
            break;
        case 12:
            C_READ_CCSR(cpmp(12), res);
            break;
        case 13:
            C_READ_CCSR(cpmp(13), res);
            break;
        case 14:
            C_READ_CCSR(cpmp(14), res);
            break;
        case 15:
            C_READ_CCSR(cpmp(15), res);
            break;
        default:
            /* I-4 site RCPX: a cpmp index outside [0, CPMP_COUNT). Reached from the
               region-share path as read_cpmp(region_cpmp[region_id]), so a corrupt
               region_cpmp[] entry used to wedge the board here with no output at
               all. n is the offending index. */
            capstone_report(CAPSTONE_TAG_RCPX, CAPSTONE_ERR_CPMP_INDEX);
            capstone_report(CAPSTONE_TAG_CPID, n);
            capstone_uart_flush();
            while(1);
    }
    return res;
}

static void write_cpmp(unsigned n, __linear void *v) {
    switch(n) {
        case 0:
            C_WRITE_CCSR(cpmp(0), v);
            break;
        case 1:
            C_WRITE_CCSR(cpmp(1), v);
            break;
        case 2:
            C_WRITE_CCSR(cpmp(2), v);
            break;
        case 3:
            C_WRITE_CCSR(cpmp(3), v);
            break;
        case 4:
            C_WRITE_CCSR(cpmp(4), v);
            break;
        case 5:
            C_WRITE_CCSR(cpmp(5), v);
            break;
        case 6:
            C_WRITE_CCSR(cpmp(6), v);
            break;
        case 7:
            C_WRITE_CCSR(cpmp(7), v);
            break;
        case 8:
            C_WRITE_CCSR(cpmp(8), v);
            break;
        case 9:
            C_WRITE_CCSR(cpmp(9), v);
            break;
        case 10:
            C_WRITE_CCSR(cpmp(10), v);
            break;
        case 11:
            C_WRITE_CCSR(cpmp(11), v);
            break;
        case 12:
            C_WRITE_CCSR(cpmp(12), v);
            break;
        case 13:
            C_WRITE_CCSR(cpmp(13), v);
            break;
        case 14:
            C_WRITE_CCSR(cpmp(14), v);
            break;
        case 15:
            C_WRITE_CCSR(cpmp(15), v);
            break;
        default:
            /* I-4 site WCPX: same as RCPX, on the write-back leg. The share path
               writes the mrev'd / de-linearised region back through here. */
            capstone_report(CAPSTONE_TAG_WCPX, CAPSTONE_ERR_CPMP_INDEX);
            capstone_report(CAPSTONE_TAG_CPID, n);
            capstone_uart_flush();
            while(1);
    }
}

#ifdef CAPSTONE_TARGET_FPGA
static void print_regions(void) {
    int region_id;
    void *tmp;
    for(region_id = 0; region_id < region_n; region_id += 1) {
        if(region_live[region_id] == 0)
            continue;
        if(region_cpmp[region_id] != -1) {
            tmp = read_cpmp(region_cpmp[region_id]);
            write_cpmp(region_cpmp[region_id], tmp);
        } else {
            tmp = regions[region_id];
            regions[region_id] = tmp;
        }
    }
}
#else /* CAPSTONE_TARGET_QEMU */
static void print_regions(void) {
    int region_id;
    void *tmp;
    for(region_id = 0; region_id < region_n; region_id += 1) {
        if(region_cpmp[region_id] != -1) {
            C_PRINT(region_cpmp[region_id]);
            tmp = read_cpmp(region_cpmp[region_id]);
            C_PRINT(tmp);
            write_cpmp(region_cpmp[region_id], tmp);
        } else {
            C_PRINT(-1);
            tmp = regions[region_id];
            C_PRINT(tmp);
            regions[region_id] = tmp;
        }
    }
}
#endif

#ifdef CAPSTONE_TARGET_FPGA
static void print_cpmps(void) {
    int cpmp_id;
    void *tmp;
    for(cpmp_id = 0; cpmp_id < CPMP_COUNT; cpmp_id += 1) {
        if(cpmp_region[cpmp_id] != -1) {
            tmp = read_cpmp(cpmp_id);
            write_cpmp(cpmp_id, tmp);
        }
    }
}
#else /* CAPSTONE_TARGET_QEMU */
static void print_cpmps(void) {
    int cpmp_id;
    void *tmp;
    for(cpmp_id = 0; cpmp_id < CPMP_COUNT; cpmp_id += 1) {
        if(cpmp_region[cpmp_id] != -1) {
            C_PRINT(cpmp_id);
            tmp = read_cpmp(cpmp_id);
            C_PRINT(tmp);
            write_cpmp(cpmp_id, tmp);
        }
    }
}
#endif

/* Q-03: a slot whose region has been consumed by an exact fit becomes a HOLE. It keeps its
   index forever (see region_live above); compacting was refuted by audit on exactly that,
   and the tail is not special -- the tail-only shrink of 2026-08-01 is gone with this. Every
   hole prints (HOLE i, RGNN region_n) so the change cannot pass silently. Ported from the
   QEMU stand-in monitor, where the design was audited and validated 2026-09-05. */
#ifdef CAPSTONE_TARGET_FPGA
unsigned make_hole(unsigned i) {
    if(region_cpmp[i] != -1) {
        cpmp_region[region_cpmp[i]] = -1;
        region_cpmp[i] = -1;
    }
    region_live[i] = 0;
    regions[i] = 0;
    capstone_report(CAPSTONE_TAG_HOLE, i);
    capstone_report(CAPSTONE_TAG_RGNN, region_n);
    return 0;
}
#else /* CAPSTONE_TARGET_QEMU */
unsigned make_hole(unsigned i, unsigned tag) {
    if(region_cpmp[i] != -1) {
        cpmp_region[region_cpmp[i]] = -1;
        region_cpmp[i] = -1;
    }
    region_live[i] = 0;
    regions[i] = 0;
    C_PRINT(tag);
    C_PRINT(i);
    C_PRINT(region_n);
    return 0;
}
#endif

static void *split_out_cap(unsigned base, unsigned len, unsigned linear) {
    __linear void *region;

#ifdef USE_GEN_CAP
    C_GEN_CAP(region, base, base + len);
#else
    __linear void *mem_l;
    __linear void *mem_r;
    unsigned i;
    unsigned region_base, region_end;

    for(i = 0; i < region_n; i += 1) {
        if(region_live[i] == 0)
            continue;
        if(region_cpmp[i] != -1)
            mem_l = read_cpmp(region_cpmp[i]);
        else
            mem_l = regions[i];
        region_base = cap_base(mem_l);
        region_end = cap_end(mem_l);
        if(base >= region_base && base + len <= region_end)
            break;
        if(region_cpmp[i] != -1)
            write_cpmp(region_cpmp[i], mem_l);
        else
            regions[i] = mem_l;
    }

    /* I-4 site SPLA: no existing region covers [base, base+len). Printing the
       request is what makes this actionable -- the address tells you which
       split_out_cap() call failed. */
#ifdef CAPSTONE_TARGET_FPGA
    if(i >= region_n) {
        capstone_report(CAPSTONE_TAG_SPLA, CAPSTONE_ERR_SPLIT_NO_REGION);
        capstone_report(CAPSTONE_TAG_BASE, base);
        capstone_report(CAPSTONE_TAG_ALEN, len);
        capstone_uart_flush();
        while(1);
    }
#else
    if(i >= region_n)
        capstone_error(CAPSTONE_NO_REGION);
#endif

    if(base == region_base)
        region = mem_l;
    else
        region = __split(mem_l, base);

    if (base + len == region_end) {
        if(base == region_base) {
            /* EXACT FIT (Q-03): the whole region is consumed and slot i becomes a hole, at ANY
               position. The tail-only shrink and the middle-slot spin (SPLB/EXACT_MID) are gone. */
            if(!linear) {
#ifdef CAPSTONE_TARGET_FPGA
                capstone_report(CAPSTONE_TAG_SPLB, CAPSTONE_ERR_SPLIT_EXACT_NONLIN);
                capstone_report(CAPSTONE_TAG_RGID, i);
                capstone_report(CAPSTONE_TAG_RGNN, region_n);
                capstone_uart_flush();
#else
                C_PRINT(0x1238);
                C_PRINT(i);
#endif
                while(1);
            }
            MAKE_HOLE(i, 0x1236);
        } else {
            if(region_cpmp[i] != -1)
                write_cpmp(region_cpmp[i], mem_l);
            else
                regions[i] = mem_l;
        }
    } else {
        mem_r = __split(region, base + len);

        if(base == region_base) {
            if(region_cpmp[i] != -1)
                write_cpmp(region_cpmp[i], mem_r);
            else
                regions[i] = mem_r;
        } else {
            if(region_cpmp[i] != -1)
                write_cpmp(region_cpmp[i], mem_l);
            else
                regions[i] = mem_l;

            if(region_n >= CAPSTONE_MAX_REGION_N) {
                /* I-4 site RGNO. Was UNGUARDED: three of the four appends had no bounds check,
                   so the table simply ran past regions[] into region_cpmp[]/cpmp_region[] --
                   a silent wrong answer instead of a stop. Measured 2026-08-06: region ids
                   reach 24/25 by the FOURTH SQLite domain against CAPSTONE_MAX_REGION_N = 32,
                   so this overrun is ~1 domain away on every board session, and it is exactly
                   what a "fix" to the exact-fit spin would have unmasked. */
                capstone_report(CAPSTONE_TAG_RGNO, CAPSTONE_ERR_REGION_OVERFLOW);
                capstone_report(CAPSTONE_TAG_RGNN, region_n);
                capstone_uart_flush();
                while(1);
            }
            regions[region_n] = mem_r;
            region_live[region_n] = 1;
            region_n += 1;
            /* we load regions into cpmp lazily*/
        }
    }
#endif

    __linear void *region_linear;
    unsigned ty = cap_type(region);
    if(linear && ty != CAP_TYPE_LINEAR) {
        capstone_error(CAPSTONE_NO_REGION);
    } else if(!linear && ty == CAP_TYPE_LINEAR) {
        region_linear = region;
        region = __delin(region_linear);
    }

    if(!linear) {
        if(region_n >= CAPSTONE_MAX_REGION_N) {
            /* I-4 site RGNO. Was UNGUARDED: three of the four appends had no bounds check,
               so the table simply ran past regions[] into region_cpmp[]/cpmp_region[] --
               a silent wrong answer instead of a stop. Measured 2026-08-06: region ids
               reach 24/25 by the FOURTH SQLite domain against CAPSTONE_MAX_REGION_N = 32,
               so this overrun is ~1 domain away on every board session, and it is exactly
               what a "fix" to the exact-fit spin would have unmasked. */
            capstone_report(CAPSTONE_TAG_RGNO, CAPSTONE_ERR_REGION_OVERFLOW);
            capstone_report(CAPSTONE_TAG_RGNN, region_n);
            capstone_uart_flush();
            while(1);
        }
        regions[region_n] = region;
        region_live[region_n] = 1;
        region_n += 1;
    }

    return region;
}
/* ONE create_domain for both targets (Phase B item 5, 2026-09-08). Until then the file carried two
   whole copies under #ifdef CAPSTONE_TARGET_FPGA / #else, which differed at nine sites; the record of
   each and its gate is in docs/plans/monitor-unification.md. What remains per-target inside this
   function is only what the macros hide: REPORT_REGION_OVERFLOW (UART tags vs C_PRINT) and
   capstone_trace (FPGA only; expands to nothing on QEMU). gpoff comes from the packed globals offset
   the loader supplies (0 = the image declares no globals region: no blob copy, no gp carve, no
   cscratch slot); every board image links link-gpfree.ld and so packs a nonzero one (0x1000 for the
   ladder rungs, 0x150000 for SQLite, measured on the staged images 2026-09-08). */
/* globals_off: image offset where the domain's globals region starts, i.e. the value
   the linker script put in __gpfree_globals_base minus the image base. 0 means "not
   supplied" and falls back to the historical fixed 0x1000, so a caller that does not
   pass it gets byte-for-byte the old behaviour and every existing rung keeps working
   against this firmware.

   It has to be a parameter rather than a constant because .text must fit BELOW it:
   0x1000 is right for a BEEBS kernel and hopeless for SQLite, whose .text is 2.2 MB,
   and one firmware has to serve both. Keeping it a #define also made DOMAIN_WINDOW=32k
   silently WRONG whenever the copy path was in use -- the glue computed blob offsets
   from base+0x8000 while the monitor filled dom_data from base+0x1000. That was masked
   only because every 32k rung also set LADDER_NO_RO_COPY=1. */
static unsigned create_domain(unsigned base_addr, unsigned code_size,
                          unsigned tot_size, unsigned entry_offset,
                          unsigned globals_off)
{
    /* entry_offset carries the GLOBALS OFFSET in its high 32 bits (packed by
       libcapstone; the kernel module forwards the word untouched). 0 in the high half
       means "not supplied" and falls back to the historical 0x1000, so any domain
       built before this creates exactly as it used to. */
    /* TWO 16-BIT SHIFTS, not one 32-bit shift. capstone-c holds the full 64-bit value
       (the print above shows 0x800000000000 arriving intact) but `>> 32` yields 0 --
       the shift is evaluated at 32 bits. Measured, not assumed: with `>> 32` the
       monitor computed gpoff = 0x1000 from an entry_offset of 0x800000000000. */
    unsigned packed_gpoff = (entry_offset >> 16) >> 16;
    entry_offset = entry_offset & 0xffffffff;
    /* Plain if/else, not a nested ternary. With the ternary form capstone-c produced
       gpoff = 0x1000 even though packed_gpoff printed as 0x8000 immediately above --
       i.e. the conditional did not select the branch its own condition implied. */
    /* 0 means THE IMAGE DECLARES NO GLOBALS REGION -- and that must NOT fall back to
       GPFREE_GLOBALS_OFFSET. The fallback was the bug: it made the gp carve below
       unconditional, so a domain linked with my_first_domain/link.ld (no globals at
       0x1000, no gp read from cscratch, ~78 build scripts use it) had its code
       capability split at base+0x1000 anyway. Two symptoms, one cause, and they look
       nothing alike:
         image <  0x1000  -> the SPLIT itself is out of bounds; QEMU asserts in
                             helper_cssplit and aborts before the domain exists.
         image >= 0x1000  -> the split succeeds and TRUNCATES the code cap to exactly
                             4096 bytes; the entry glue's first read past it faults
                             (measured: coremark, bounds = [base, base+0x1000),
                              access at base+0x6278).
       That is the whole red core tier -- smoke, coremark, rv8, beebs, authority and the
       rest -- from one unconditional split. Only a gp-free/cap-table image has a
       globals boundary, and those always declare it (.capstone_gp_initdesc, verified
       present in a built board domain), so keying on it is exact rather than heuristic. */
    unsigned gpoff = 0;
    if (globals_off) {
        gpoff = globals_off;
    }
    if (packed_gpoff) {
        gpoff = packed_gpoff;
    }
    // alignment requirement
    code_size = (((code_size - 1) >> 4) + 1) << 4;
    /* CAPABILITY-BOUNDS REPRESENTABILITY (issue C-13, root-caused 2026-07-29).
       The register file stores capability metadata COMPRESSED. compress_bounds
       (capstone-ariane core/include/ariane_pkg.sv:749-800) has an exact "cursorless"
       encoding only while start == cursor; otherwise it truncates the BASE DOWNWARD to
       a 2^(E+3) granule (:788 `B[13:3] = {bounds.start >> E}[13:3]`, with no round-up,
       unlike the top at :790).

       dom_data leaves SPLIT cursorless-exact, but the C_SET_CURSOR below (used to park
       gp at the top of the region) moves the cursor off the start, so the very next
       writeback re-encodes with the lossy form and PERMANENTLY truncates the base. With
       code_size rounded only to 16, base+code_size+DOMAIN_DATA_SIZE was 96 bytes past a
       128-byte granule, so the domain's sp reported a base 96 bytes BELOW where the
       monitor had copied the blob. The glue then read its own base+8 for `count`, landed
       in the zeroed seal tail, got 0, skipped the entire table build, never established
       gp, and the domain faulted on its first `ldc gp[i]`. Verified numerically: a
       line-for-line model of compress_bounds reproduces the board's measured
       sp.base (+5632) and size (125440) exactly.

       So round code_size up to the region's REPRESENTABILITY granule, not to 16. The
       granule depends on the region length, so it must be computed: 128 bytes for a
       128 KiB domain, 1024 for SQLite's 2 MiB one. Hardcoding 128 would silently fail
       at SQLite scale, which is the case this whole fix exists to unblock.

       Only the SPLIT geometry moves. The blob extent stays (code_size - gpoff) off the
       ORIGINAL 16-rounded size, so the copy still reads exactly the image bytes and
       never past the loaded image. */
    unsigned repr_len;
    unsigned repr_tmp;
    unsigned repr_hb;
    unsigned repr_e;
    unsigned repr_gran;
    unsigned split_size;
    unsigned data_off;
    repr_len = tot_size - code_size - DOMAIN_DATA_SIZE;
    repr_hb = 0;
    repr_tmp = repr_len;
    for (repr_tmp = repr_len; repr_tmp > 1; repr_tmp = repr_tmp >> 1) {
        repr_hb = repr_hb + 1;
    }
    repr_e = 0;
    if (repr_hb > 12) {
        repr_e = repr_hb - 12;
    }
    repr_gran = 1 << (repr_e + 3);
    split_size = code_size + repr_gran - 1;
    split_size = split_size - (split_size & (repr_gran - 1));
    data_off = DOMAIN_DATA_SIZE + repr_gran - 1;
    data_off = data_off - (data_off & (repr_gran - 1));
    /* ONE DECLARATOR PER DECLARATION (Phase B item 5A, 2026-09-08): capstone-c accumulates the `*`
       across declarators, so the merged line typed dom_code as void** and dom_data as void*** and the
       copy below stepped 16 bytes per subscript through ldc/stc. Exact on QEMU, lossy on silicon
       (R-10/C-13); the FPGA arm has carried this form since 82a241a. Same form on both now. */
    __linear void *mem_l;
    __linear void *dom_code;
    __linear void *dom_data;
    __linear void *mem_r;
    __linear void **dom_seal;

    /* needs one slot for the domain's own region: refuse BEFORE carving (item 1's check, here since
       item 5; on the board it precedes what used to be split_out_cap's post-carve RGNO spin) */
    if(region_n + 1 > CAPSTONE_MAX_REGION_N) {
        REPORT_REGION_OVERFLOW();
        return -1;
    }
    /* DBAS/DENT: the domain's LOAD BASE and entry offset.
     *
     * Without these a wedge's latched mepc is UNINTERPRETABLE. On 2026-08-12 the new
     * debug mux finally produced one -- trap mepc = 0x828897FC -- and it could not be
     * mapped to an instruction, because nothing in the entire boot transcript reveals
     * where the domain was loaded. The only addresses printed are the shared regions,
     * which are nowhere near it. An address without its base names nothing.
     *
     * With these two, mepc - base_addr is a file offset into the .dom and the faulting
     * instruction can be disassembled directly -- which is what discriminates the two
     * readings of mcause 25 (R-24): UNEXPECTED_OPERAND from the execute path, or
     * INVALID_CAPABILITY on the PC capability from commit_stage.
     *
     * Emitted BEFORE split_out_cap, so they appear even if the carve itself fails. */
    capstone_trace(CAPSTONE_TAG_DBAS, base_addr);
    capstone_trace(CAPSTONE_TAG_DENT, entry_offset);

    dom_code = split_out_cap(base_addr, tot_size, 1);

    dom_seal = __split(dom_code, base_addr + split_size);
    dom_data = __split(dom_seal, base_addr + split_size + data_off);

    /* Large-.rodata delivery (issue C-4b). Copy the initialized-globals bytes of the
       loaded image, [base+GPFREE_GLOBALS_OFFSET, base+code_size), into the FRONT of
       dom_data, so that dom_data[k] == image[base+GPFREE_GLOBALS_OFFSET + k].

       WHY THIS IS NEEDED. The cap-table glue otherwise materializes an initialized
       global with an unrolled li/sd immediate sequence. That has a hard ceiling: a
       single global must be a multiple of 8 bytes and fit a 12-bit store offset
       (~2 KB), and the code it emits competes for the domain's PCC window. beebs_ns
       hit it exactly -- "2512 B of *initialized* data overflows the 12-bit store
       offset and is not copy-eligible" -- and SQLite's static tables are far past it.
       With the bytes present in dom_data the glue can copy them instead, which scales
       to any table size.

       WHY THE MONITOR DOES IT. The initializer bytes physically exist in the loaded
       image, but after the dom_gp split below the image is covered for the domain only
       by an EXECUTE-authority cap, and the 2026-07-22 root cause established that a
       code-authority cap cannot load data on captype-fixed CVA6. The monitor runs in
       M-mode with authority over the image, so it can read it and write into the
       fresh dom_data region -- the data-authority-over-a-data-region case that already
       works on the board. The domain therefore never reads data through an execute cap.

       PLACEMENT is load-bearing, in three ways:
         - BEFORE the dom_gp __split below, while dom_code still spans
           [base, base+code_size) and so still covers the globals.
         - BEFORE the C_SET_CURSOR calls that move dom_code's and dom_data's cursors:
           indexed access here is cursor-relative.
         - AFTER the dom_data __split, so dom_data is the fresh region and index 0 is
           its front.

       The word-copy idiom (cap-to-cap, the same shape capstone-c uses for enclave
       setup) is exact for this payload: .rodata const tables carry no capability tags,
       so there is nothing for a plain word copy to lose.

       Board owner's stated preference is for the HOST USERSPACE process to do this
       rather than the monitor ("but for now whatever works is fine"). This is the
       prototype; keeping it as one self-contained block is what makes moving it out of
       M-mode later a local change. */
    /* Bounds guard, deliberately explicit. dom_data spans
       [base+code_size+DOMAIN_DATA_SIZE, base+tot_size), so it holds
       tot_size - code_size - DOMAIN_DATA_SIZE bytes, while the blob is
       code_size - GPFREE_GLOBALS_OFFSET bytes. A domain with a large image and a
       small data region would otherwise run the copy past dom_data's end, and an
       out-of-bounds capability store HERE is an M-mode fault -- i.e. it takes the
       whole machine down, not just the domain. Skipping the copy instead is safe:
       the glue only reads the blob for globals that took the copy path, and a
       domain that does not fit simply keeps the old unrolled-immediate behaviour. */
    /* gpoff != 0 FIRST: with no declared globals region gpoff is 0 and `code_size > 0`
       is trivially true, which would run the globals blob copy over the whole image for
       a domain that has no globals at all. */
    if(gpoff != 0
       && code_size > gpoff
       && tot_size > split_size + data_off
       && (code_size - gpoff) > (tot_size - split_size - DOMAIN_DATA_SIZE)) {
        /* The blob does not fit in dom_data. This used to SKIP the copy silently,
           on the reasoning that "the glue only reads the blob for globals that took
           the copy path" -- which is exactly backwards once a global DOES take it:
           the domain then runs with uninitialized globals, computes wrong answers and
           never faults. A domain whose globals were not delivered is not a degraded
           domain, it is a wrong one, so fail loudly and let the build-time budget
           check (which is where this belongs) catch it earlier next time. */
        capstone_error(0xB10B);
    }
    if(gpoff != 0
       && code_size > gpoff
       && tot_size > split_size + data_off) {
        /* 8-BYTE UNITS, not 16. With dom_code/dom_data correctly typed as `__linear void *`
           (one declarator per line above), subscripting steps ONE WORD and the loop body emits a
           scalar ld/sd -- which is the whole point: it never touches compress_cap, so plain data
           round-trips exactly (R-10). Byte extent and start offset are unchanged (gpoff_c*8 ==
           gpoff), and both endpoints stay 8-aligned because code_size is rounded up to 16 and gpoff
           is a page multiple. The earlier "16-byte units, exact for this payload" comment here was
           false on silicon (R-10) and is gone. */
        unsigned gpoff_c = gpoff >> 3;                          /* image offset, in words */
        unsigned glob_c  = (code_size - gpoff) >> 3;
        unsigned ci;
        for(ci = 0; ci < glob_c; ci += 1)
            dom_data[ci] = dom_code[gpoff_c + ci];
    }

    int i;
#ifdef CAPSTONE_DOMAIN_TRAP_VECTOR
    unsigned dom_trap_vec;   /* function scope: capstone-c rejects a nested-block decl; plain
                              * `unsigned` to match the local idiom (`unsigned mepc_val` etc.) */
#endif
    for(i = 0; i < DOMAIN_DATA_N; i += 1) {
        dom_seal[i] = 0;
    }

    // gp-free domain ABI (silicon): derive the domain's `gp` from real authority
    // by SPLITting the code image at the fixed globals boundary
    // (GPFREE_GLOBALS_OFFSET, matching link-gpfree.ld) into an execute code cap
    // (PCC) and an R/W globals cap (gp). SPLIT only partitions existing authority,
    // so -- unlike the QEMU-only debug op C_GEN_CAP (funct 0x40, absent on the RTL,
    // which fabricates a cap and hangs the monitor on silicon) -- this works on
    // real hardware. gp is delivered via the cscratch (dom_data) top-16 slot; the
    // entry glue does `ldc gp, END-16; delin`.
    /* Carve gp ONLY for an image that declares a globals boundary, and only when the
       boundary is genuinely inside the code region. Both conditions are required:
       gpoff == 0 means no globals region at all, and gpoff >= code_size would be a
       degenerate or out-of-range split even for an image that does declare one. */
    __linear void *dom_gp = 0;
    if (gpoff != 0 && code_size > gpoff) {
        dom_gp = __split(dom_code, base_addr + gpoff);
        // dom_code -> [base, base+gpoff) (code); dom_gp -> [.., +code_size) (globals)
    }

    C_SET_CURSOR(dom_code, dom_code, base_addr + entry_offset);

    // store gp (linear; glue delins on first entry) into the cscratch top slot
    if (dom_gp != 0) {
        C_SET_CURSOR(dom_data, dom_data, base_addr + tot_size - 16);
        *(__linear void **)dom_data = dom_gp;
        C_SET_CURSOR(dom_data, dom_data, base_addr + split_size + data_off);
    }

    // construct the sealed region of the domain
    dom_seal[0] = dom_code;
#ifdef CAPSTONE_DOMAIN_TRAP_VECTOR
    /* THE ACCEPTANCE TEST for "a domain enters with NO trap vector".
     *
     * Slot 1 is the trap-vector slot -- csr_regfile.sv:407 restores it as
     * {ctvec_tag_q, ctvec_q, mtvec_q}, and the RTL's own interrupt.S:67 stores ctvec at byte
     * offset 16 -- and the zeroing loop above leaves it 0 while slots 0, 2 and 3 get written.
     * The domain switch is an EXCHANGE, so it parks the monitor's live vector in this slot and
     * loads the zero: the domain runs with mtvec = 0 AND ctvec = 0, and any exception it takes
     * vectors to address 0. Confirmed on silicon -- mtvec reads 0x0 at every wedge, and a
     * deliberate benign capability fault (cincoffsetimm on a plain 0xBEEF) kills the board
     * exactly as the real S-12 fault does.
     *
     * `lla` rather than a C declaration: _cap_trap_entry is an assembly label with no prototype,
     * and this is how sbi_capstone_dom.c:30 already reaches it. The temporary is declared at
     * function scope beside `int i` because capstone-c panics (dag_builder.rs:1258,
     * `assertion failed: self.decl_type.is_none()`) on a declaration inside a nested block.
     *
     * EXPECTED TO BE INSUFFICIENT, and still worth running, because the outcomes discriminate.
     * frontend.sv:425-427 redirects the PC on an exception while :443-444 leaves npc_metadata_q
     * untouched, capmode_q is sticky (csr_regfile.sv:295), and commit_stage.sv:222-223 raises
     * cause 28 when the PC leaves the PC-capability's bounds. So vectoring to _cap_trap_entry
     * (~0x8002xxxx) while still holding the DOMAIN's PC capability (bounded ~0x828xxxxx) should
     * trade a cause-2 storm for a cause-28 one:
     *
     *   mcause 28 at the next wedge -> the vector TOOK. The firmware half is right and the
     *                                  missing half is in RTL: slot 1 is meant to hold a trap
     *                                  vector CAPABILITY (cursor->mtvec, metadata->ctvec) and
     *                                  the core never installs ctvec as the PC capability.
     *   mcause 2 still               -> the vector did NOT take; this diagnosis is wrong.
     *   EXCX + a returned CAPSTONE_DOMAIN_FAULT_RETVAL
     *                                -> the prediction was too pessimistic and this alone fixes
     *                                   it, making every capability fault reportable instead of
     *                                   fatal.
     */
    __asm__ ("lla %0, _cap_trap_entry" : "=r"(dom_trap_vec));
    dom_seal[1] = dom_trap_vec;
#endif
    dom_seal[2] = dom_data;
    dom_seal[3] = (3 << 38) | (2 << 34);

    __dom void *dom = __seal(dom_seal);

    // PRINT(dom);

    domains[dom_n] = dom;

    dom_n += 1;

    return dom_n - 1;
}

static unsigned call_domain(unsigned dom_id) {
    /* THE ENTER PATH WAS COMPLETELY UNINSTRUMENTED, and that has been costing verdicts.
       Every SHA and ECSZ tag belongs to the REGION-SHARE path; nothing here emitted anything. So
       a domain that produced `SQ: G/enter` and then went silent could have died in this
       function, in the domain switch, at its first instruction, in the carve loop, or in
       __capstone_cap_init -- all indistinguishable, because `SQ: G/enter` is printed by the
       HOST before it even calls in.

       That ambiguity was being read as "entered and wedged -- a REAL result" (the board-run
       skill's classification rule), which it is not: it is an UNATTRIBUTED result. ENT1/ENT2
       are the enter-path equivalent of SHA5/SHA6 and make the distinction the rule assumes:
         ENT0 then silence -> died in this function before the switch
         ENT1 then silence -> control genuinely left M-mode; the domain owns the wedge
         ENT2             -> the domain returned; value is its result */
    capstone_trace(CAPSTONE_TAG_ENT0, dom_id);
    if(dom_id >= dom_n) {
        capstone_trace(CAPSTONE_TAG_ENTB, dom_id);
        return -1;
    }

    unsigned res;
    __dom void *d = domains[dom_id];
    capstone_trace(CAPSTONE_TAG_ENT1, dom_id);
    d = __domcallsaves(d, CAPSTONE_DPI_CALL, &res);
    capstone_trace(CAPSTONE_TAG_ENT2, res);
    domains[dom_id] = d;

    return res;
}


static unsigned call_domain_with_cap(unsigned dom_id, unsigned base, unsigned len, unsigned cursor) {
    void *region = split_out_cap(base, len, 1);
    __asm__ ("scc(%0, %1, %2)" : "=r"(region) : "r"(region), "r"(cursor));

    __dom void *d = domains[dom_id];
    d = __domcallsaves(d, CAPSTONE_DPI_CALL, region);
    domains[dom_id] = d;

    return 0;
}

static unsigned create_region(unsigned base, unsigned len) {
    /* needs up to two slots (a right-hand fragment, then the region): refuse BEFORE carving.
       Phase B item 1 (2026-09-08): shared by both targets; the board used to carve first and
       report RGNO after, leaving a half-completed split behind. The host sees -1 (REGION_CREATE
       failed) instead of a monitor spin. */
    if(region_n + 2 > CAPSTONE_MAX_REGION_N) {
        REPORT_REGION_OVERFLOW();
        return -1;
    }
    void *region = split_out_cap(base, len, 1);

    if(region_n >= CAPSTONE_MAX_REGION_N) {
        /* I-4 site RGNO. Was UNGUARDED: three of the four appends had no bounds check,
           so the table simply ran past regions[] into region_cpmp[]/cpmp_region[] --
           a silent wrong answer instead of a stop. Measured 2026-08-06: region ids
           reach 24/25 by the FOURTH SQLite domain against CAPSTONE_MAX_REGION_N = 32,
           so this overrun is ~1 domain away on every board session, and it is exactly
           what a "fix" to the exact-fit spin would have unmasked. */
        capstone_report(CAPSTONE_TAG_RGNO, CAPSTONE_ERR_REGION_OVERFLOW);
        capstone_report(CAPSTONE_TAG_RGNN, region_n);
        capstone_uart_flush();
        while(1);
    }
    regions[region_n] = region;
    region_live[region_n] = 1;
    region_n += 1;

    return region_n - 1;
}

static unsigned shared_region_annotated(unsigned dom_id, unsigned region_id, unsigned annotation_perm, unsigned annotation_rev) {
    /* I-4 progress SHA0: the handler was entered at all. If SHA0 never appears the
       ecall did not reach the monitor and the problem is kernel-module side. */
    /* Snapshot the incoming arguments into locals BEFORE any call. The first
       instrumented run printed dom_id=0 (correct) then region_id/perm/rev all 0
       (wrong -- the host passed 12/0x1/0x2), which is exactly what a clobber of the
       argument registers across the first capstone_trace() call looks like: the first
       value survives, every later one reads whatever a1-a3 now hold. capstone-c is a
       custom compiler for a C subset and its handling of live argument registers
       across calls is not something to assume. If these locals print correctly, the
       arguments were always fine and the tags were destroying their own evidence. */
    unsigned t_dom;
    unsigned t_rgn;
    unsigned t_prm;
    unsigned t_rev;
    t_dom = dom_id;
    t_rgn = region_id;
    t_prm = annotation_perm;
    t_rev = annotation_rev;
    capstone_trace(CAPSTONE_TAG_SHA0, t_dom);
    capstone_trace(CAPSTONE_TAG_RGID, t_rgn);
    capstone_trace(CAPSTONE_TAG_APRM, t_prm);
    capstone_trace(CAPSTONE_TAG_AREV, t_rev);
    if(dom_id >= dom_n || region_id >= region_n) {
        /* I-4 site SHAB: the request is rejected. This RETURNS rather than spinning,
           and ioctl_share_region_annotated() drops the return value on the floor, so
           without a tag a rejected share is indistinguishable from a successful one
           on the console. dom_n/region_n say which of the two bounds failed. */
        capstone_report(CAPSTONE_TAG_SHAB, CAPSTONE_ERR_SHARE_BAD_ID);
        capstone_report(CAPSTONE_TAG_DOMN, dom_n);
        capstone_report(CAPSTONE_TAG_RGNN, region_n);
        capstone_uart_flush();
        return -1;
    }
    /* separate statement, NOT a third || operand: Capstone-C evaluates every operand of ||
       (an out-of-range id would index region_live[] and fault M-mode) */
    if(region_live[region_id] == 0) {
        return -1;
    }
    /* I-4 progress SHA1: ids accepted. The value is region_cpmp[region_id], which
       selects the cpmp-resident vs table-resident branch below -- the one thing that
       differs between two callers passing byte-identical ioctl arguments. */
    capstone_trace(CAPSTONE_TAG_SHA1, region_cpmp[region_id]);

    __dom void *d = domains[dom_id];

    __linear void *r;
    if (region_cpmp[region_id] != -1) {
        r = read_cpmp(region_cpmp[region_id]);
    }
    else {
        r = regions[region_id];
    }
    /* I-4 progress SHA2: the region capability is in hand. Type (0 = linear) decides
       the REV_SHARED/REV_TRANSFERRED branches; base/length identify WHICH region. */
    capstone_trace(CAPSTONE_TAG_SHA2, cap_type(r));
    capstone_trace(CAPSTONE_TAG_BASE, cap_base(r));
    capstone_trace(CAPSTONE_TAG_ALEN, cap_end(r) - cap_base(r));

    if (annotation_rev == CAPSTONE_ANNOTATION_REV_DEFAULT) {
        // capability type: non-linear; post-return revoke: yes
        __rev void *rev = __mrev(r);

        if (region_cpmp[region_id] != -1) {
            write_cpmp(region_cpmp[region_id], rev);
        }
        else {
            regions[region_id] = rev;
        }
        r = __delin(r);
    }
    else if (annotation_rev == CAPSTONE_ANNOTATION_REV_BORROWED) {
        // capability type: linear; post-return revoke: yes
        /* Re-share after a prior revoke: revoking the linear borrow left the
         * retained handle UNINIT (with cursor==end, per helper_csrevoke). mrev
         * requires a LIN input, so re-initialise first: csinit(offset 0) ->
         * LIN, cursor=base. On the first share r is already LIN, so skip. This
         * is the explicit owner reclaim step for a linear borrow. */
        if (cap_type(r) == 3 /* CAP_TYPE_UNINIT */) {
            C_INIT(r, r, 0);
        }
        __rev void *rev = __mrev(r);

        if (region_cpmp[region_id] != -1) {
            write_cpmp(region_cpmp[region_id], rev);
        }
        else {
            regions[region_id] = rev;
        }
    }
    else if (annotation_rev == CAPSTONE_ANNOTATION_REV_SHARED) {
        // capability type: non-linear; post-return revoke: no
        if (cap_type(r) == CAP_TYPE_LINEAR) {
            r = __delin(r);

            if (region_cpmp[region_id] != -1) {
                write_cpmp(region_cpmp[region_id], r);
            }
            else {
                regions[region_id] = r;
            }
        }
    }
    else if (annotation_rev == CAPSTONE_ANNOTATION_REV_TRANSFERRED) {
#ifdef CAPSTONE_TARGET_FPGA
        // capability type: linear; post-return revoke: no
        if (cap_type(r) != CAP_TYPE_LINEAR) {
            //C_PRINT(0xdeadbeef);
            /* I-4 site SHAX: a TRANSFERRED share needs a linear capability and this
               one is not linear (it was already de-linearised by an earlier SHARED or
               DEFAULT share of the same region). Previously a bare `while(1);` with
               the C_PRINT commented out, i.e. a completely silent wedge. */
            capstone_report(CAPSTONE_TAG_SHAX, CAPSTONE_ERR_SHARE_NOT_LIN);
            capstone_report(CAPSTONE_TAG_RGID, region_id);
            capstone_report(CAPSTONE_TAG_CTYP, cap_type(r));
            capstone_uart_flush();
            while(1);
        }

#else /* CAPSTONE_TARGET_QEMU */
        // capability type: linear; post-return revoke: no
        if (cap_type(r) != 0) {
            C_PRINT(0xdeadbeef);
            while(1);
        }
#endif
        /* The region leaves the pool for good: its slot becomes a hole -- on BOTH targets since
           Phase B item 2B (2026-09-08). QEMU had this since Q-05 (2026-09-07: it used to keep a
           stale duplicate of the transferred capability through which swap_cpmp served the host's
           later accesses to pages it had given away). The board used to clear only the CPMP
           association and leave the nulled slot live, so a later host access to those pages reached
           cap_base(null) in M-mode -- the silent-wedge shape named in the Q-05 close-out. Now a
           later access finds no region and takes the ordinary NO_CPMP_REGION path. Board evidence:
           boots sw36 (transfer probe on the old arm) and sw37 (this form, one HOLE line). */
        MAKE_HOLE(region_id, 0x1239);
    }
    else {
        /* I-4 site SHAV: annotation_rev is not one of the four defined values. */
        capstone_report(CAPSTONE_TAG_SHAV, CAPSTONE_ERR_SHARE_BAD_REV);
        capstone_report(CAPSTONE_TAG_AREV, annotation_rev);
        capstone_uart_flush();
        return -1;
    }
    /* I-4 progress SHA3: the revocation annotation has been applied (mrev/delin done,
       region table or cpmp updated). */
    capstone_trace(CAPSTONE_TAG_SHA3, annotation_rev);

    if (annotation_perm == CAPSTONE_ANNOTATION_PERM_IN) {
        r = __tighten(r, 4);
    }
    else if (annotation_perm == CAPSTONE_ANNOTATION_PERM_INOUT) {
        r = __tighten(r, 6);
    }
    else if (annotation_perm == CAPSTONE_ANNOTATION_PERM_OUT) {
        r = __tighten(r, 2);
    }
    else if (annotation_perm == CAPSTONE_ANNOTATION_PERM_EXE) {
        r = __tighten(r, 1);
    }
    else if (annotation_perm == CAPSTONE_ANNOTATION_PERM_FULL) {
        r = __tighten(r, 7);
    }
    else {
        /* I-4 site SHAP: annotation_perm is not one of the five defined values. */
        capstone_report(CAPSTONE_TAG_SHAP, CAPSTONE_ERR_SHARE_BAD_PERM);
        capstone_report(CAPSTONE_TAG_APRM, annotation_perm);
        capstone_uart_flush();
        return -1;
    }
    /* I-4 progress SHA4: the permission annotation has been applied (tighten done). */
    capstone_trace(CAPSTONE_TAG_SHA4, annotation_perm);

    /* I-4 progress SHA5: everything the MONITOR does is finished; the next
       instruction leaves M-mode for the domain's region-share entry. This is the
       split that the SQLite hang needs: SHA5 followed by silence means the domain
       never came back and the monitor is exonerated; no SHA5 means the wedge is in
       one of the monitor steps above. */
    capstone_trace(CAPSTONE_TAG_SHA5, dom_id);
    d = __domcallsaves(d, CAPSTONE_DPI_REGION_SHARE, r);
    /* I-4 progress SHA6: the domain returned from the share entry. */
    capstone_trace(CAPSTONE_TAG_SHA6, dom_id);
    domains[dom_id] = d;

    return 0;
}

/* Share a child sub-region [offset, offset+len) split-derived from parent_id so a
 * later revoke_region(parent_id) cascades to it (the paper's H primitive:
 * sqlite3_close revokes the connection and every statement/value pointer beneath
 * it). The parent's senior revocation handle is minted with __mrev and retained
 * under parent_id; the child (and the split-off head/tail fragments) are junior in
 * the parent's rev lineage, so __revoke(parent_rev) invalidates them. Unlike two
 * independent create_region()s (independent rev roots -- no cascade), the child
 * here is __split out of the parent's own cap. */
static unsigned share_child_region(unsigned dom_id, unsigned parent_id,
                                   unsigned offset, unsigned len, unsigned perm) {
    if(dom_id >= dom_n || parent_id >= region_n) {
        return -1;
    }
    /* separate statement, NOT a third || operand: Capstone-C evaluates every operand of ||
       (an out-of-range id would index region_live[] and fault M-mode) */
    if(region_live[parent_id] == 0) {
        return -1;
    }
    /* needs up to two slots (head, tail): refuse BEFORE touching the parent (item 1, shared) */
    if(region_n + 2 > CAPSTONE_MAX_REGION_N) {
        REPORT_REGION_OVERFLOW();
        return -1;
    }

    __dom void *d = domains[dom_id];

    __linear void *r;
    if (region_cpmp[parent_id] != -1) {
        r = read_cpmp(region_cpmp[parent_id]);
    }
    else {
        r = regions[parent_id];
    }

    /* A prior revoke may have left the retained parent handle UNINIT; re-init so
     * __mrev sees a LIN input (same reclaim step as REV_BORROWED). */
    if (cap_type(r) == 3 /* CAP_TYPE_UNINIT */) {
        C_INIT(r, r, 0);
    }

    unsigned pbase = cap_base(r);
    unsigned pend = cap_end(r);
    unsigned cstart = pbase + offset;
    unsigned cend = cstart + len;
    if (len == 0 || offset > pend - pbase || cend > pend) {
        return -1;
    }

    /* 1. Mint the senior revocation handle and retain it under parent_id, so
     *    revoke_region(parent_id) -> __revoke(rev) invalidates the junior run. */
    __rev void *rev = __mrev(r); /* rev: senior (depth d); r: junior (depth d+1) */

    /* 2. Carve the child [cstart, cend) out of the now-junior parent cap. The
     *    split products stay junior to rev, so a parent revoke cascades to them.
     *    Retain the head/tail fragments in regions[] the same way split_out_cap
     *    does (do not drop linear caps); the child is shared last so the
     *    borrower's REGION_COUNT-1 query resolves to it. */
    __linear void *head = 0;
    __linear void *body;
    if (offset != 0) {
        body = __split(r, cstart); /* r -> [pbase,cstart); body -> [cstart,pend) */
        head = r;
    }
    else {
        body = r;
    }

    __linear void *tail = 0;
    if (cend != pend) {
        tail = __split(body, cend); /* body -> [cstart,cend); tail -> [cend,pend) */
    }

    if (region_cpmp[parent_id] != -1) {
        write_cpmp(region_cpmp[parent_id], rev);
    }
    else {
        regions[parent_id] = rev;
    }

    if (head) {
        regions[region_n] = head;
        region_live[region_n] = 1;
        region_n += 1;
    }
    if (tail) {
        regions[region_n] = tail;
        region_live[region_n] = 1;
        region_n += 1;
    }

    /* 3. Tighten permission and share the child (linear borrow). */
    __linear void *child = body;
    if (perm == CAPSTONE_ANNOTATION_PERM_IN) {
        child = __tighten(child, 4);
    }
    else if (perm == CAPSTONE_ANNOTATION_PERM_INOUT) {
        child = __tighten(child, 6);
    }
    else if (perm == CAPSTONE_ANNOTATION_PERM_OUT) {
        child = __tighten(child, 2);
    }
    else if (perm == CAPSTONE_ANNOTATION_PERM_FULL) {
        child = __tighten(child, 7);
    }
    else {
        return -1;
    }

    d = __domcallsaves(d, CAPSTONE_DPI_REGION_SHARE, child);
    domains[dom_id] = d;

    return 0;
}

// This function has been deprecated, use shared_region_annotated instead
static unsigned share_region(unsigned dom_id, unsigned region_id) {
    if(dom_id >= dom_n || region_id >= region_n) {
        return -1;
    }
    /* separate statement, NOT a third || operand: Capstone-C evaluates every operand of ||
       (an out-of-range id would index region_live[] and fault M-mode) */
    if(region_live[region_id] == 0) {
        return -1;
    }

    __dom void *d = domains[dom_id];

    if (region_cpmp[region_id] != -1) {
        d = __domcallsaves(d, CAPSTONE_DPI_REGION_SHARE, read_cpmp(region_cpmp[region_id]));
    }
    else {
        d = __domcallsaves(d, CAPSTONE_DPI_REGION_SHARE, regions[region_id]);
    }

    domains[dom_id] = d;

    return 0;
}

static unsigned revoke_region(unsigned region_id) {
    if(region_id >= region_n) {
        return -1;
    }
    /* separate statement, NOT a third || operand: Capstone-C evaluates every operand of ||
       (an out-of-range id would index region_live[] and fault M-mode) */
    if(region_live[region_id] == 0) {
        return -1;
    }

    if (region_cpmp[region_id] != -1) {
        __rev void *rev = read_cpmp(region_cpmp[region_id]);
        void *r = __revoke(rev);
        write_cpmp(region_cpmp[region_id], r);
    }
    else {
        __rev void *rev = regions[region_id];
        void *r = __revoke(rev);
        regions[region_id] = r;
    }

    return 0;
}

static unsigned pop_region(unsigned pop_num) {
	if (pop_num > region_n) {
		return -1;
    }

    unsigned i;
    for(i = 0; i < pop_num; i += 1) {
        unsigned region_i = region_n - i - 1;
        if (region_cpmp[region_i] != -1) {
            cpmp_region[region_cpmp[region_i]] = -1;
        }

        region_cpmp[region_i] = -1;
        region_live[region_i] = 0;
    }

    region_n -= pop_num;

    return 0;
}

static unsigned region_de_linear(unsigned region_id) {
    if(region_id >= region_n) {
        return -1;
    }
    /* separate statement, NOT a third || operand: Capstone-C evaluates every operand of ||
       (an out-of-range id would index region_live[] and fault M-mode) */
    if(region_live[region_id] == 0) {
        return -1;
    }

    if (region_cpmp[region_id] != -1) {
        __linear void *r = read_cpmp(region_cpmp[region_id]);
        void *r_delin = __delin(r);
        write_cpmp(region_cpmp[region_id], r_delin);
    }
    else {
        __linear void *r = regions[region_id];
        regions[region_id] = __delin(r);
    }

    return 0;
}

static void return_from_domain(unsigned retval) {
    debug_counter_tick(DEBUG_COUNTER_SWITCH_S);

    *caller_buf = retval;
    __domreturnsaves(caller_dom, DOM_REENTRY_POINT, 0);
}

/* Step B: terminate the currently-running domain because it hit an
 * unrecoverable capability/access fault, and return control cleanly to the
 * caller (the lender/host) with a fault sentinel -- rather than spinning in
 * capstone_error(). This reuses the exact domain-return path a normal
 * DOM_RETURN ecall takes (return_from_domain -> __domreturnsaves), which is
 * already invoked from inside _cap_trap_entry, so it composes with the trap
 * context. The cause is emitted for the log but the caller only needs to see
 * that the call faulted (CAPSTONE_DOMAIN_FAULT_RETVAL). Does not return. */
static void fault_return_from_domain(unsigned cause) {
    C_PRINT(CAPSTONE_ERR_STARTER);
    C_PRINT(cause);
    return_from_domain(CAPSTONE_DOMAIN_FAULT_RETVAL);
}

static unsigned query_region(unsigned region_id, unsigned field) {
    if(region_id >= region_n) {
        return -1;
    }
    /* separate statement, NOT a third || operand: Capstone-C evaluates every operand of ||
       (an out-of-range id would index region_live[] and fault M-mode) */
    if(region_live[region_id] == 0) {
        return -1;
    }

    __linear void *region;
    if(region_cpmp[region_id] != -1) {
        region = read_cpmp(region_cpmp[region_id]);
    } else {
        region = regions[region_id];
    }

    unsigned res;
    switch(field) {
        case CAPSTONE_REGION_FIELD_BASE:
            res = cap_base(region);
            break;
        case CAPSTONE_REGION_FIELD_END:
            res = cap_end(region);
            break;
        case CAPSTONE_REGION_FIELD_LEN:
            res = cap_end(region) - cap_base(region);
            break;
        default:
            res = -1;
    }

    if(region_cpmp[region_id] != -1) {
        write_cpmp(region_cpmp[region_id], region);
    } else {
        regions[region_id] = region;
    }

    return res;
}

// submit the specified domain to the interrupt handler for scheduling
static unsigned schedule_domain(unsigned dom_id) {
    if(dom_id >= dom_n) {
        return -1;
    }
    __dom void *d = domains[dom_id];
    d = __ihdomcallsaves(CAPSTONE_IHI_THREAD_SPAWN, d); // TODO: this shall
    domains[dom_id] = d;
    return 0;
}

// SBI implementation
unsigned handle_trap_ecall(unsigned arg0, unsigned arg1,
                           unsigned arg2, unsigned arg3,
                           unsigned arg4, unsigned arg5,
                           unsigned func_code, unsigned ext_code) {
    // PRINT(ext_code);
    // PRINT(func_code);
    unsigned res = 0, err = 0;
    switch(ext_code) {
        case SBI_EXT_BASE:
            switch(func_code) {
                case SBI_EXT_BASE_GET_SPEC_VERSION:
                    res = SBI_SPEC_VERSION;
                    break;
                case SBI_EXT_BASE_GET_IMP_ID:
                case SBI_EXT_BASE_GET_IMP_VERSION:
                    res = 0;
                    break;
                case SBI_EXT_BASE_PROBE_EXT:
                    // we only have time and Capstone extensions
                    res = arg0 == SBI_EXT_TIME || arg0 == SBI_EXT_CAPSTONE;
                    break;
                case SBI_EXT_BASE_GET_MVENDORID:
                    C_READ_CSR(mvendorid, res);
                    break;
                case SBI_EXT_BASE_GET_MARCHID:
                    C_READ_CSR(marchid, res);
                    break;
                case SBI_EXT_BASE_GET_MIMPID:
                    C_READ_CSR(mimpid, res);
                    break;
                default:
                    err = 1;
            }
            break;
        case SBI_EXT_TIME:
            if (func_code == SBI_EXT_TIME_SET_TIMER) {
                __asm__ volatile ("csrc mip, %0" :: "r"(MIP_STIP | MIP_MTIP));
                *mtimecmp = arg0;
                __asm__ volatile ("csrs mie, %0" :: "r"(MIP_MTIP));
            } else {
                err = 1;
            }
            break;
        case SBI_EXT_CAPSTONE:
            switch(func_code) {
                case SBI_EXT_CAPSTONE_DOM_CREATE:
                    res = create_domain(arg0, arg1, arg2, arg3, arg4);
                    break;
                case SBI_EXT_CAPSTONE_DOM_CALL:
                    res = call_domain(arg0);
                    break;
                case SBI_EXT_CAPSTONE_DOM_CALL_WITH_CAP:
                    res = call_domain_with_cap(arg0, arg1, arg2, arg3);
                    break;
                case SBI_EXT_CAPSTONE_REGION_CREATE:
                    res = create_region(arg0, arg1);
                    break;
                case SBI_EXT_CAPSTONE_REGION_SHARE:
                    res = share_region(arg0, arg1);
                    break;
                case SBI_EXT_CAPSTONE_DOM_RETURN:
                    return_from_domain(arg0);
                    /* I-4 site DRET: return_from_domain() ends in __domreturnsaves
                       and must not come back. Reached on the return leg of every
                       domain call, including the region-share entry. */
                    capstone_report(CAPSTONE_TAG_DRET, CAPSTONE_ERR_DOM_RETURN_RET);
                    capstone_uart_flush();
                    while(1); /* should not reach here */
                case SBI_EXT_CAPSTONE_REGION_QUERY:
                    res = query_region(arg0, arg1);
                    break;
                case SBI_EXT_CAPSTONE_DOM_SCHEDULE:
                    res = schedule_domain(arg0);
                    break;
                case SBI_EXT_CAPSTONE_REGION_COUNT:
                    res = region_n;
                    break;
                case SBI_EXT_CAPSTONE_REGION_SHARE_ANNOTATED:
                    /* I-4 progress ECSA/ECSZ: bracket the handler at the DISPATCH,
                       so "the ecall arrived" is distinguishable from "the handler
                       started" (SHA0) even if the handler's own prologue wedges. */
                    /* Print the FULL register picture, not just arg0. dom_id is
                       legitimately 0, so arg0 cannot distinguish "arrived" from "lost" --
                       that ambiguity has already masked three hypotheses. func_code and
                       ext_code live in a6/a7 and MUST have arrived (we are in this case at
                       all), so they are the positive control: if they print correctly
                       while arg1..arg3 print zero, then a0/a6/a7 survive the trap while
                       a1..a5 do not, which localises the defect to the trap save/restore
                       of the middle argument registers rather than to any SBI mapping. */
                    capstone_trace(CAPSTONE_TAG_ECSA, arg0);
                    capstone_trace(CAPSTONE_TAG_EXTC, ext_code);
                    capstone_trace(CAPSTONE_TAG_FNCC, func_code);
                    capstone_trace(CAPSTONE_TAG_ARG1, arg1);
                    capstone_trace(CAPSTONE_TAG_ARG4, arg4);
                    res = shared_region_annotated(arg0, arg1, arg2, arg3);
                    capstone_trace(CAPSTONE_TAG_ECSZ, res);
                    break;
                case SBI_EXT_CAPSTONE_REGION_REVOKE:
                    res = revoke_region(arg0);
                    break;
                case SBI_EXT_CAPSTONE_REGION_DE_LINEAR:
                    res = region_de_linear(arg0);
                    break;
                case SBI_EXT_CAPSTONE_REGION_POP:
                    res = pop_region(arg0);
                    break;
                case SBI_EXT_CAPSTONE_REGION_SHARE_CHILD:
                    res = share_child_region(arg0, arg1, arg2, arg3, arg4);
                    break;
                default:
                    err = 1;
            }
            break;
        default:
            err = 1;
    }
    return res;
}

void handle_interrupt(unsigned int_code) {
    switch(int_code) {
        case IRQ_M_TIMER:
            __asm__ volatile ("csrc mie, %0" :: "r"(MIP_MTIP));
            __asm__ volatile ("csrs mip, %0" :: "r"(MIP_STIP));
            break;
#ifdef CAPSTONE_TARGET_FPGA
        default:
            /* I-4 site IRQX: an interrupt the monitor does not service. Printing
               int_code is the whole point -- it says WHICH interrupt. */
            capstone_report(CAPSTONE_TAG_IRQX, CAPSTONE_ERR_IRQ_UNHANDLED);
            capstone_report(CAPSTONE_TAG_MCAU, int_code);
            capstone_uart_flush();
            while(1);
#endif
    }
}

static void swap_cpmp(unsigned badaddr) {
    unsigned region_id, cpmp_id, start_addr, end_addr;
    unsigned ejected_region_id;
    __linear void *tmp;
    for(region_id = 0; region_id < region_n; region_id += 1) {
        if(region_live[region_id] == 0) // a hole holds no capability
            continue;
        if(region_cpmp[region_id] != -1) // already loaded
            continue;
        tmp = regions[region_id];
        start_addr = cap_base(tmp);
        end_addr = cap_end(tmp);
        regions[region_id] = tmp;
        if(start_addr <= badaddr && badaddr < end_addr)
            break;
    }
    if(region_id >= region_n) {
        /* MERGE 2026-08-18: both sides kept, because they are orthogonal.
         *
         * The UART reporting below is the diagnostic half -- without it a monitor-detected
         * failure on the FPGA is indistinguishable from a domain hang, which cost several
         * board sessions. The fault_return_from_domain call is the control-flow half: no
         * region covers badaddr, so this is an unrecoverable domain fault (a use-after-revoke
         * store whose region was revoked, or an out-of-bounds access) and the domain is
         * terminated with the fault returned to the caller rather than spinning in M-mode.
         *
         * Reporting FIRST, because fault_return_from_domain does not return. */
#ifdef CAPSTONE_TARGET_FPGA
        print_regions();
        print_cpmps();
        capstone_report(CAPSTONE_TAG_MTVL, badaddr);
        capstone_report(CAPSTONE_TAG_CPMX, CAPSTONE_NO_CPMP_REGION);
        capstone_uart_flush();
#else
        C_PRINT(badaddr);
        C_PRINT(region_n);
#endif
        fault_return_from_domain(CAPSTONE_NO_CPMP_REGION);
        return; /* not reached: fault_return_from_domain switches domains */
    }

    // check if there is free cpmp entry
    for(cpmp_id = 0; cpmp_id < CPMP_COUNT; cpmp_id += 1) {
        if(cpmp_region[cpmp_id] == -1)
            break;
    }
    if(cpmp_id >= CPMP_COUNT) {
        // no free cpmp entry, round robin to eject
        tmp = read_cpmp(next_eject_cpmp);
        ejected_region_id = cpmp_region[next_eject_cpmp];
        regions[ejected_region_id] = tmp;
        region_cpmp[ejected_region_id] = -1;

        cpmp_id = next_eject_cpmp;
        next_eject_cpmp = (next_eject_cpmp + 1) & 0xf;
    }

    // free cpmp entry, directly use it
    cpmp_region[cpmp_id] = region_id;
    region_cpmp[region_id] = cpmp_id;
    tmp = regions[region_id];
    write_cpmp(cpmp_id, tmp);
}

#ifdef CAPSTONE_TARGET_FPGA
unsigned handle_exception(unsigned cause) {
    unsigned badaddr;
    unsigned time_val;
    unsigned dbg_epc;
    unsigned dbg_mstatus;
    switch(cause) {
        case CAUSE_ILLEGAL_INSTRUCTION:
            // __asm__ ("1: j 1b");
            C_READ_CSR(mtval, badaddr);
            if (((badaddr & 0xFFF0707F) == CSR_TIME)) {
                time_val = *mtime;
                break;
            }
            else {
                /* I-4 site ILLX: an illegal instruction that is not the `time`
                   CSR read the monitor emulates. This is the site that a board
                   session already burned days on (an FP store with mstatus.FS=Off,
                   then a second unservicable userspace instruction) -- with no
                   output at all, it was indistinguishable from a domain hang.
                   badaddr is mtval, i.e. the offending instruction word, which
                   identifies WHICH instruction the monitor cannot service. */
                capstone_report(CAPSTONE_TAG_ILLX, CAPSTONE_ERR_ILLEGAL_INSN);
                capstone_report(CAPSTONE_TAG_MTVL, badaddr);
                C_READ_CSR(mepc, dbg_epc);
                capstone_report(CAPSTONE_TAG_MEPC, dbg_epc);
                capstone_uart_flush();
                /* kept: a debugger halting the wedged core still finds mcause in
                   a5 and mepc in a6 (the existing gdb workflow). */
                __asm__ ("csrr a5, mcause");
                __asm__ ("csrr a6, mepc");
                while(1);
            }
        break;
        case CAUSE_LOAD_ACCESS:
        case CAUSE_STORE_ACCESS:
        case CAUSE_FETCH_ACCESS:
            C_READ_CSR(mtval, badaddr);
            debug_counter_tick(DEBUG_COUNTER_CPMP_SWAP);
            swap_cpmp(badaddr);
            time_val = -1;
            break;
        default:
            /* I-4 site EXCX: a trap cause the monitor does not handle at all. */
            capstone_report(CAPSTONE_TAG_EXCX, CAPSTONE_ERR_EXC_UNHANDLED);
            capstone_report(CAPSTONE_TAG_MCAU, cause);
            C_READ_CSR(mepc, dbg_epc);
            capstone_report(CAPSTONE_TAG_MEPC, dbg_epc);
            C_READ_CSR(mtval, badaddr);
            capstone_report(CAPSTONE_TAG_MTVL, badaddr);
            /* MSTA: mstatus, for MPP -- bits [12:11]. Without it MEPC cannot be interpreted.
               On 2026-08-15 four boots latched an unhandled trap and MEPC was symbolised against
               the firmware, twice, before the RTL showed the cause code was only reachable BELOW
               M-mode (translation is gated on priv_lvl != M), i.e. the address was a virtual one
               and named nothing in the monitor. MPP is one CSR read and decides that outright:
                 MPP=3 -> the address IS a firmware address, symbolise it;
                 MPP<3 -> it is a guest virtual address, do NOT. */
            C_READ_CSR(mstatus, dbg_mstatus);
            capstone_report(CAPSTONE_TAG_MSTA, dbg_mstatus);
            capstone_uart_flush();
            /* MERGE 2026-08-18: report first, then terminate rather than spin.
             *
             * The reporting above (EXCX/MCAU/MEPC/MTVL/MSTA) is what makes a latched trap
             * interpretable at all, and it must run BEFORE the domain is torn down.
             *
             * The spin it used to end in -- `csrr a5,mcause; csrr a6,mepc; 1: j 1b` -- is
             * replaced by fault_return_from_domain, which terminates the faulting domain and
             * returns the cause to the caller. A non-access-fault synchronous cause from a
             * domain (RISCV_EXCP_INVALID_CAP from a use-after-revoke, a bounds or tag
             * violation) is unrecoverable, and returning it beats hanging the board.
             *
             * CONSEQUENCE FOR S-07, and it is not small: on the next monitor rebuild an S-07
             * capability fault stops presenting as "the domain entered and never returned"
             * and starts presenting as a returned fault code. That is strictly better for
             * diagnosis, but it changes the observable every S-07 result to date was
             * classified on, so the wedge-rate baseline must be re-established and
             * tests/rtl-smoke/s07-rate.py's S07-WEDGE class re-checked against the new shape
             * before old and new numbers are compared. */
            fault_return_from_domain(cause);
            time_val = -1;
    }
    return time_val;
}
#else /* CAPSTONE_TARGET_QEMU */
void handle_exception(unsigned cause) {
    unsigned badaddr;
    switch(cause) {
        case CAUSE_LOAD_ACCESS:
        case CAUSE_STORE_ACCESS:
        case CAUSE_FETCH_ACCESS:
            C_READ_CSR(mtval, badaddr);
            debug_counter_tick(DEBUG_COUNTER_CPMP_SWAP);
            swap_cpmp(badaddr);
            break;
        default:
            /* A non-access-fault synchronous cause reaching the monitor from a
             * domain (e.g. RISCV_EXCP_INVALID_CAP from a use-after-revoke, a
             * bounds/tag violation) is an unrecoverable domain fault. Terminate
             * the domain and return the fault to the caller instead of spinning
             * in capstone_error(). */
            fault_return_from_domain(cause);
    }
}
#endif


/* DPI */

static void dpi_call(void *arg) {
    caller_buf = arg;
    if(smode_initialised) {
        __asm__ volatile ("movc(a0, %0); j resume_smode" :: "r"(smode_saved_context));
    } else {
        smode_initialised = 1;
        __asm__ volatile ("j call_into_smode");
    }
}

static void dpi_share_region(void *region) {
    /* I-4 progress DPIS: a DOMAIN shared a region back into the monitor (the reverse
       leg of the share path). value = region_n, i.e. the slot it lands in. */
    capstone_trace(CAPSTONE_TAG_DPIS, region_n);
    if(region_n >= CAPSTONE_MAX_REGION_N) {
        /* I-4 site RGNO: the region table is full. This used to write one past the
           end of regions[] and silently corrupt the globals laid out after it
           (region_cpmp/cpmp_region/dom_n/region_n) -- a wrong answer with no output
           rather than a hang, which is worse. A named spin is strictly better. */
        capstone_report(CAPSTONE_TAG_RGNO, CAPSTONE_ERR_REGION_OVERFLOW);
        capstone_report(CAPSTONE_TAG_RGNN, region_n);
        capstone_uart_flush();
        while(1);
    }
    regions[region_n] = region;
    region_live[region_n] = 1;
    region_n += 1;
}

unsigned handle_dpi(unsigned func, void *arg) {
    unsigned handled = 0;

    switch(func) {
        case CAPSTONE_DPI_CALL:
            dpi_call(arg);
            /* I-4 site DPIC: dpi_call() ends in a jump into S-mode and must not
               return. */
            capstone_report(CAPSTONE_TAG_DPIC, CAPSTONE_ERR_DPI_CALL_RET);
            capstone_uart_flush();
            while(1); /* should not reach here */
        case CAPSTONE_DPI_REGION_SHARE:
            dpi_share_region(arg);
            handled = 1;
            break;
        default:
            /* I-4 site DPIX: a DPI function code the monitor does not implement.
               Behaviour is unchanged (handled stays 0); it just says so now, because
               what the caller does with handled == 0 is not visible from here. */
            capstone_report(CAPSTONE_TAG_DPIX, CAPSTONE_ERR_DPI_UNKNOWN);
            capstone_report(CAPSTONE_TAG_DPIF, func);
            capstone_uart_flush();
            break;
    }

    return handled;
}

static void save_smode_context(unsigned *ctx) {
    smode_saved_context = ctx;
}
// }
