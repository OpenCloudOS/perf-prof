#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <errno.h>
#include <linux/refcount.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>


static struct global_syms {
    struct ksyms *ksyms;
    struct syms_cache *syms_cache;
    refcount_t ksyms_ref;
    refcount_t syms_ref;
} ctx;

/*
 * ffffffff81ad6db9 system_call_fastpath+0x16 ([kernel.kallsyms])
 * 00007efd88d7ea20 __write_nocancel+0x7 (/usr/lib64/libc-2.17.so)
 * addr             symbol  +offset      (dso)
 *
 * addr symbol+offset (dso)...addr symbol+offset (dso)
 *                         ^                          ^
 *                         `seperate                  `end
**/
struct callchain_ctx {
    u64 kernel      : 1, /* need kernel symbols, /proc/kallsyms */
        user        : 1, /* need user symbols, /proc/pid/maps */
        addr        : 1, /* print addr */
        symbol      : 1, /* print symbol */
        offset      : 1, /* print +offset */
        dso         : 1, /* print (dso) */
        reverse     : 1, /* reverse, down to top */
        __reserved  : 1;
    char seperate;
    char end;
    FILE *fout;
};

static int global_syms_ref(bool kernel, bool user)
{
    if (kernel) {
        if (!ctx.ksyms) {
            ctx.ksyms = ksyms__load();
            if (!ctx.ksyms)
                return -1;
            refcount_set(&ctx.ksyms_ref, 1);
        } else
            refcount_inc(&ctx.ksyms_ref);
    }
    if (user) {
        if (!ctx.syms_cache) {
            ctx.syms_cache = syms_cache__new();
            if (!ctx.syms_cache)
                return -1;
            refcount_set(&ctx.syms_ref, 1);
        } else
            refcount_inc(&ctx.syms_ref);
    }
    return 0;
}

static void global_syms_unref(bool kernel, bool user)
{
    if (kernel && ctx.ksyms && refcount_dec_and_test(&ctx.ksyms_ref)) {
        ksyms__free(ctx.ksyms);
        ctx.ksyms = NULL;
    }
    if (user && ctx.syms_cache && refcount_dec_and_test(&ctx.syms_ref)) {
        syms_cache__free(ctx.syms_cache);
        ctx.syms_cache = NULL;
    }
}

struct callchain_ctx *callchain_ctx_new(int flags, FILE *fout)
{
    struct callchain_ctx *cc;
    bool kernel = flags & CALLCHAIN_KERNEL;
    bool user   = flags & CALLCHAIN_USER;

    if (kernel == false && user == false)
        return NULL;

    if (global_syms_ref(kernel, user) < 0)
        return NULL;

    cc = calloc(1, sizeof(*cc));
    if (!cc)
        return NULL;

    cc->kernel = kernel;
    cc->user   = user;
    cc->addr   = 1;
    cc->symbol = 1;
    cc->offset = 1;
    cc->dso    = 1;
    cc->reverse = 1;
    cc->seperate = '\n';
    cc->end = '\n';
    cc->fout = fout;
    return cc;
}

void callchain_ctx_free(struct callchain_ctx *cc)
{
    if (!cc)
        return ;
    global_syms_unref(cc->kernel, cc->user);
    free(cc);
}

static void __print_callchain_kernel(struct callchain_ctx *cc, u64 ip, bool *printed)
{
    const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
    if (*printed)
        fprintf(cc->fout, "%c", cc->seperate);
    if (cc->addr)
        fprintf(cc->fout, "    %016lx", ip);
    if (cc->symbol)
        fprintf(cc->fout, "%s%s", cc->addr ? " " : "", ksym ? ksym->name : "Unknown");
    if (cc->offset)
        fprintf(cc->fout, "+0x%lx", ksym ? ip - ksym->addr : 0L);
    if (cc->dso)
        fprintf(cc->fout, "%s([kernel.kallsyms])", (cc->offset || cc->symbol || cc->addr) ? " " : "");
    if (cc->addr || cc->symbol || cc->offset || cc->dso)
        *printed = true;
}

static void __print_callchain_user(struct callchain_ctx *cc, struct syms *syms, u64 ip, bool *printed)
{
    struct dso *dso;
    const char *symbol = "Unknown";
    u64 offset = 0L;
    const char *dso_name = "Unknown";

    dso = syms__find_dso(syms, ip, &offset);
    if (dso) {
        const struct sym *sym = dso__find_sym(dso, offset);
        if (sym) {
            symbol = sym->name;
            offset = offset - sym->start;
            dso_name = dso__name(dso)?:"Unknown";
        }
    }

    if (*printed)
        fprintf(cc->fout, "%c", cc->seperate);
    if (cc->addr)
        fprintf(cc->fout, "    %016lx", ip);
    if (cc->symbol)
        fprintf(cc->fout, "%s%s", cc->addr ? " " : "", symbol);
    if (cc->offset)
        fprintf(cc->fout, "+0x%lx", offset);
    if (cc->dso)
        fprintf(cc->fout, "%s(%s)", (cc->offset || cc->symbol || cc->addr) ? " " : "", dso_name);
    if (cc->addr || cc->symbol || cc->offset || cc->dso)
        *printed = true;
}

static bool __print_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    u64 i;
    bool kernel = false, user = false, printed = false;
    struct syms *syms = NULL;

    for (i = 0; i < callchain->nr; i++) {
        u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = cc->kernel;
            user = false;
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = false;
            if (ctx.syms_cache && cc->user) {
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
                user = syms ? true : false;
            }
            continue;
        }
        if (kernel) {
            __print_callchain_kernel(cc, ip, &printed);
        } else if (user) {
            __print_callchain_user(cc, syms, ip, &printed);
        }
    }
    return printed;
}

static bool __print_callchain_reverse(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    u64 i, kstart = 0, kend = 0, ustart = 0, uend = 0;
    struct syms *syms = NULL;
    bool printed = false;

    for (i = 0; i < callchain->nr; i++) {
        u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kstart = i + 1;
            kend = callchain->nr - 1;
            if (!cc->user)
                break;
        } else if (ip == PERF_CONTEXT_USER) {
            if (ctx.syms_cache && cc->user)
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
            kend = i - 1;
            ustart = i + 1;
            uend = callchain->nr - 1;
            break;
        }
    }
    if (cc->user && syms && ustart) {
        for (; uend >= ustart; uend--)
            __print_callchain_user(cc, syms, callchain->ips[uend], &printed);
    }
    if (cc->kernel && kstart) {
        for (; kend >= kstart; kend--)
            __print_callchain_kernel(cc, callchain->ips[kend], &printed);
    }
    return printed;
}

void print_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    if (cc == NULL ||
        callchain == NULL || callchain->nr == 0)
        return ;
    if (cc->kernel == false && cc->user == false)
        return ;
    if (ctx.ksyms == NULL &&
        ctx.syms_cache == NULL)
        return ;

    if ((cc->reverse ? __print_callchain_reverse : __print_callchain)(cc, callchain, pid))
        fprintf(cc->fout, "%c", cc->end);
}

void print_callchain_common(struct callchain_ctx *cc, struct callchain *callchain, u32 pid)
{
    __u64 i;
    bool kernel = false, user = false;
    struct syms *syms;

    if (ctx.ksyms == NULL &&
        ctx.syms_cache == NULL)
        return ;

    for (i = 0; i < callchain->nr; i++) {
        __u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = cc->kernel;
            user = false;
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = false;
            if (ctx.syms_cache) {
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
                if (syms)
                    user = cc->user;
            }
            continue;
        }
        if (kernel) {
            const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
            fprintf(cc->fout, "    %016llx %s+0x%llx ([kernel.kallsyms])\n", ip, ksym ? ksym->name : "Unknown",
                                ksym ? ip - ksym->addr : 0L);
        } else if (user) {
            struct dso *dso;
            uint64_t offset;
            dso = syms__find_dso(syms, ip, &offset);
            if (dso) {
                const struct sym *sym = dso__find_sym(dso, offset);
                fprintf(cc->fout, "    %016llx %s+0x%lx (%s)\n", ip, sym ? sym->name : "Unknown",
                                sym ? offset - sym->start : 0L, dso__name(dso)?:"Unknown");
            } else
                fprintf(cc->fout, "    %016llx %s (%s)\n", ip, "Unknown", "Unknown");
        } else
            fprintf(cc->fout, "    %016llx\n", ip);
    }
}

void task_exit_free_syms(union perf_event *event)
{
    if (ctx.syms_cache &&
        event->fork.pid == event->fork.tid) {
        syms_cache__free_syms(ctx.syms_cache, event->fork.pid);
    }
}

