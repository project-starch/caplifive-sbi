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
#define C_PRINT(v) __asm__ volatile(".insn r 0x5b, 0x1, 0x43, x0, %0, x0" :: "r"(v))
#define C_GEN_CAP(dest, base, end) __asm__(".insn r 0x5b, 0x1, 0x40, %0, %1, %2" : "=r"(dest) : "r"(base), "r"(end));
/* csinit rd, rs1, rs2: UNINIT(cursor==end) -> LIN with cursor = base + rs2.
 * No __init builtin exists, so emit the instruction directly (funct7 0x9),
 * same style as C_PRINT/C_GEN_CAP. */
#define C_INIT(dest, cap, offset) __asm__(".insn r 0x5b, 0x1, 0x9, %0, %1, %2" : "=r"(dest) : "r"(cap), "r"(offset))
#define capstone_error(err_code) do { C_PRINT(CAPSTONE_ERR_STARTER); C_PRINT(err_code); while(1); } while(0)
#define cap_base(cap) __capfield((cap), 3)
#define cap_end(cap) __capfield((cap), 4)
#define cap_type(cap) __capfield((cap), 1)
#define debug_counter_inc(counter_no, delta) __asm__ volatile(".insn r 0x5b, 0x1, 0x45, x0, %0, %1" :: "r"(counter_no), "r"(delta))
#define debug_counter_tick(counter_no) debug_counter_inc((counter_no), 1)

#define CPMP_COUNT 16
#define DOMAIN_DATA_N    96
#define DOMAIN_DATA_SIZE (16 * DOMAIN_DATA_N)
// gp-free domain ABI (silicon): fixed image offset where the domain's globals
// begin (must equal the value in tests/runtime-qemu/gp-free-domain/link-gpfree.ld).
#define GPFREE_GLOBALS_OFFSET 0x1000


// toggle the following for swapping between cpmp swapping and gen_cap (hack)
// #define USE_GEN_CAP

unsigned *mtime;
unsigned *mtimecmp;

__dom void *domains[CAPSTONE_MAX_DOM_N];
void *regions[CAPSTONE_MAX_REGION_N];
/* the cpmp entry each region is associated with; -1 if unassociated */
unsigned region_cpmp[CAPSTONE_MAX_REGION_N];
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
            C_PRINT(0x8888888);
            C_PRINT(n);
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
            C_PRINT(0x9999999);
            C_PRINT(n);
            while(1);
    }
}

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

    if(i >= region_n)
        capstone_error(CAPSTONE_NO_REGION);

    if(base == region_base)
        region = mem_l;
    else
        region = __split(mem_l, base);

    if (base + len == region_end) {
        if(base == region_base) {
            // matching region. We don't support this for now
            C_PRINT(0x1234);
            while(1);
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

            regions[region_n] = mem_r;
            region_n += 1;
            /* we load regions into cpmp lazily*/
        }
    }
#endif

    __linear void *region_linear;
    unsigned ty = __capfield(region, 1);
    if(linear && ty != 0) {
        capstone_error(CAPSTONE_NO_REGION);
    } else if(!linear && ty == 0) {
        region_linear = region;
        region = __delin(region_linear);
    }

    if(!linear) {
        regions[region_n] = region;
        region_n += 1;
    }

    return region;
}


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
    __linear void *mem_l, *dom_code, *dom_data, *mem_r;
    __linear void **dom_seal;

    dom_code = split_out_cap(base_addr, tot_size, 1);

    dom_seal = __split(dom_code, base_addr + code_size);
    dom_data = __split(dom_seal, base_addr + code_size + DOMAIN_DATA_SIZE);

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
       && tot_size > code_size + DOMAIN_DATA_SIZE
       && (code_size - gpoff) > (tot_size - code_size - DOMAIN_DATA_SIZE)) {
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
       && tot_size > code_size + DOMAIN_DATA_SIZE) {
        /* Index in 16-BYTE units, not 8. These are `__linear void *`, so subscripting
           steps one CAPABILITY (16 B) and the generated access is a 16-byte ldc/stc --
           `dom_seal`'s own zeroing loop runs to DOMAIN_DATA_N with
           DOMAIN_DATA_SIZE = 16 * DOMAIN_DATA_N, which is the same convention.
           Computing the trip count with `>> 3` (as the earlier draft of this copy did)
           walks TWICE the intended distance and stores past dom_data's end. That is not
           a theoretical concern: it faulted on the first run --
             Cap mem access OOB: cursor = 101562000, size = 16,
                                 bounds = (101560000, 101561020)
           i.e. it reached +0x2000 into a 0x1020-byte region.
           Both endpoints are 16-aligned by construction: code_size is rounded up to a
           multiple of 16 at the top of this function, and GPFREE_GLOBALS_OFFSET is
           0x1000, so the byte count is always a whole number of capabilities.
           Copying through capability-sized accesses is exact for this payload: the
           image bytes here are const initializer data with no capability tags, so the
           128 bits round-trip unchanged. */
        unsigned gpoff_c = gpoff >> 4;                          /* image offset, in caps */
        unsigned glob_c  = (code_size - gpoff) >> 4;
        unsigned ci;
        for(ci = 0; ci < glob_c; ci += 1)
            dom_data[ci] = dom_code[gpoff_c + ci];
    }

    int i;
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
        C_SET_CURSOR(dom_data, dom_data, base_addr + code_size + DOMAIN_DATA_SIZE);
    }

    // construct the sealed region of the domain
    dom_seal[0] = dom_code;
    dom_seal[2] = dom_data;
    dom_seal[3] = (3 << 38) | (2 << 34);

    __dom void *dom = __seal(dom_seal);

    // PRINT(dom);

    domains[dom_n] = dom;

    dom_n += 1;

    return dom_n - 1;
}

static unsigned call_domain(unsigned dom_id) {
    if(dom_id >= dom_n) {
        return -1;
    }
    
    unsigned res;
    __dom void *d = domains[dom_id];
    d = __domcallsaves(d, CAPSTONE_DPI_CALL, &res);
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
    void *region = split_out_cap(base, len, 1);

    regions[region_n] = region;
    region_n += 1;

    return region_n - 1;
}

static unsigned shared_region_annotated(unsigned dom_id, unsigned region_id, unsigned annotation_perm, unsigned annotation_rev) {
    if(dom_id >= dom_n || region_id >= region_n) {
        return -1;
    }

    __dom void *d = domains[dom_id];

    __linear void *r;
    if (region_cpmp[region_id] != -1) {
        r = read_cpmp(region_cpmp[region_id]);
    }
    else {
        r = regions[region_id];
    }

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
        if (cap_type(r) == 0) {
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
        // capability type: linear; post-return revoke: no
        // TODO: regions[region_id] should be added to a free list
        if (cap_type(r) != 0) {
            C_PRINT(0xdeadbeef);
            while(1);
        }

        if (region_cpmp[region_id] != -1) {
            cpmp_region[region_cpmp[region_id]] = -1;
            region_cpmp[region_id] = -1;
        }
    }
    else {
        return -1;
    }

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
        return -1;
    }

    d = __domcallsaves(d, CAPSTONE_DPI_REGION_SHARE, r);
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
        region_n += 1;
    }
    if (tail) {
        regions[region_n] = tail;
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
    }

    region_n -= pop_num;

    return 0;
}

static unsigned region_de_linear(unsigned region_id) {
    if(region_id >= region_n) {
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
                    res = shared_region_annotated(arg0, arg1, arg2, arg3);
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
    }
}

static void swap_cpmp(unsigned badaddr) {
    unsigned region_id, cpmp_id, start_addr, end_addr;
    unsigned ejected_region_id;
    __linear void *tmp;
    for(region_id = 0; region_id < region_n; region_id += 1) {
        if(region_cpmp[region_id] != -1) // already loaded
            continue;
        start_addr = cap_base(regions[region_id]);
        end_addr = cap_end(regions[region_id]);
        if(start_addr <= badaddr && badaddr < end_addr)
            break;
    }
    if(region_id >= region_n) {
        /* No region covers badaddr: this is not a recoverable CPMP miss but an
         * unrecoverable domain fault (e.g. a use-after-revoke store, whose
         * region was revoked, or an out-of-bounds access). Terminate the domain
         * and return the fault to the caller instead of spinning. */
        C_PRINT(badaddr);
        C_PRINT(region_n);
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
    regions[region_n] = region;
    region_n += 1;
}

unsigned handle_dpi(unsigned func, void *arg) {
    unsigned handled = 0;

    switch(func) {
        case CAPSTONE_DPI_CALL:
            dpi_call(arg);
            while(1); /* should not reach here */
        case CAPSTONE_DPI_REGION_SHARE:
            dpi_share_region(arg);
            handled = 1;
            break;
    }

    return handled;
}

static void save_smode_context(unsigned *ctx) {
    smode_saved_context = ctx;
}
