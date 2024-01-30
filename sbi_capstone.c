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
#define capstone_error(err_code) do { C_PRINT(CAPSTONE_ERR_STARTER); C_PRINT(err_code); while(1); } while(0)
#define cap_base(cap) __capfield((cap), 3)
#define cap_end(cap) __capfield((cap), 4)


// FIXME: swapping cmmu is currently very slow
// toggle the following for swapping between cmmu swapping and gen_cap (hack)
// #define USE_GEN_CAP

unsigned *mtime;
unsigned *mtimecmp;

__dom void* domains[CAPSTONE_MAX_DOM_N];
void* regions[CAPSTONE_MAX_REGION_N];
unsigned dom_n, region_n;
unsigned cmmu_region_id; /* the ID of the region currently in cmmu */

__domret void *caller_dom;
unsigned* caller_buf;

/* has S-mode been executed? */
unsigned smode_initialised;
/* saved context of S-mode at the last SBI dom-return call */
unsigned *smode_saved_context;

static void *split_out_cap(unsigned base, unsigned len, unsigned linear) {
    void *region;

#ifdef USE_GEN_CAP
    C_GEN_CAP(region, base, base + len);
#else
    void *mem_l, *mem_r;
    unsigned i;
    unsigned region_base, region_end;

    for(i = 0; i < region_n; i += 1) {
        if(i == cmmu_region_id)
            C_READ_CCSR(cmmu, mem_l);
        else
            mem_l = regions[i];
        region_base = cap_base(mem_l);
        region_end = cap_end(mem_l);
        if(base >= region_base && base + len <= region_end)
            break;
        if(i == cmmu_region_id)
            C_WRITE_CCSR(cmmu, mem_l);
        else
            regions[i] = mem_l;
    }

    if(i >= region_n)
        capstone_error(CAPSTONE_NO_REGION);

    if(base == region_base)
        region = mem_l;
    else
        region = __split(mem_l, base);

    mem_r = __split(region, base + len);

    if(base == region_base) {
        regions[i] = mem_r;
    } else {
        if(i == cmmu_region_id)
            C_WRITE_CCSR(cmmu, mem_l);
        else
            regions[i] = mem_l;

        regions[region_n] = mem_r;
        region_n += 1;
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


static unsigned create_domain(unsigned base_addr, unsigned code_size,
                          unsigned tot_size, unsigned entry_offset)
{
    // alignment requirement
    code_size = (((code_size - 1) >> 4) + 1) << 4;
    __linear void *mem_l, *dom_code, *dom_data, *mem_r;
    __linear void **dom_seal;

    dom_code = split_out_cap(base_addr, tot_size, 1);

    dom_seal = __split(dom_code, base_addr + code_size);
    dom_data = __split(dom_seal, base_addr + code_size + (16 * 64));

    int i;
    for(i = 0; i < 64; i += 1) {
        dom_seal[i] = 0;
    }

    C_SET_CURSOR(dom_code, dom_code, base_addr + entry_offset);

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
    __linear void *r = regions[region_id];

    if (annotation_rev == CAPSTONE_ANNOTATION_REV_DEFAULT) {
        // capability type: non-linear; post-return revoke: yes
        __rev void *rev = __mrev(r);
        regions[region_id] = rev;
        r = __delin(r);
    }
    else if (annotation_rev == CAPSTONE_ANNOTATION_REV_BORROWED) {
        // capability type: linear; post-return revoke: yes
        __rev void *rev = __mrev(r);
        regions[region_id] = rev;
    }
    else if (annotation_rev == CAPSTONE_ANNOTATION_REV_SHARED) {
        // capability type: non-linear; post-return revoke: no
        r = __delin(r);
        regions[region_id] = r;
    }
    else if (annotation_rev == CAPSTONE_ANNOTATION_REV_TRANSFERRED) {
        // capability type: linear; post-return revoke: no
        // TODO: regions[region_id] should be added to a free list
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

static unsigned share_region(unsigned dom_id, unsigned region_id) {
    if(dom_id >= dom_n || region_id >= region_n) {
        return -1;
    }

    __dom void *d = domains[dom_id];
    d = __domcallsaves(d, CAPSTONE_DPI_REGION_SHARE, regions[region_id]);
    domains[dom_id] = d;
    
    return 0;
}

static unsigned revoke_region(unsigned region_id) {
    if(region_id >= region_n) {
        return -1;
    }
    
    __rev void *rev = regions[region_id];
    void *r = __revoke(rev);

    regions[region_id] = r;

    return 0;
}

static unsigned pop_region(unsigned pop_num) {
    if (pop_num > region_n) {
        return -1;
    }

    region_n -= pop_num;

    return 0;
}

static unsigned region_de_linear(unsigned region_id) {
    if(region_id >= region_n) {
        return -1;
    }

    __linear void *r = regions[region_id];
    regions[region_id] = __delin(r);

    return 0;
}

static void return_from_domain(unsigned retval) {
    *caller_buf = retval;
    __domreturnsaves(caller_dom, DOM_REENTRY_POINT, 0);
}

static unsigned query_region(unsigned region_id, unsigned field) {
    if(region_id >= region_n) {
        return -1;
    }

    void *region;
    if(region_id == cmmu_region_id) {
        C_READ_CCSR(cmmu, region);
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

    if(region_id == cmmu_region_id) {
        C_WRITE_CCSR(cmmu, region);
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
                    res = create_domain(arg0, arg1, arg2, arg3);
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
                    // TODO: implement dom-schedule
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

static void swap_cmmu(unsigned badaddr) {
    unsigned i, start_addr, end_addr;
    void *tmp;
    for(i = 0; i < region_n; i += 1) {
        if(i == cmmu_region_id)
            continue;
        start_addr = cap_base(regions[i]);
        end_addr = cap_end(regions[i]);
        if(start_addr <= badaddr && badaddr < end_addr)
            break;
    }
    if(i >= region_n) {
        capstone_error(CAPSTONE_NO_CMMU_REGION);
    }
    C_READ_CCSR(cmmu, tmp);
    regions[cmmu_region_id] = tmp;
    tmp = regions[i];
    C_WRITE_CCSR(cmmu, tmp);
    cmmu_region_id = i;
}

void handle_exception(unsigned cause) {
    unsigned badaddr;
    switch(cause) {
        case CAUSE_LOAD_ACCESS:
        case CAUSE_STORE_ACCESS:
        case CAUSE_FETCH_ACCESS:
            C_READ_CSR(mtval, badaddr);
            swap_cmmu(badaddr);
            break;
        default:
            capstone_error(CAPSTONE_UNKNOWN_EXCP);
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
