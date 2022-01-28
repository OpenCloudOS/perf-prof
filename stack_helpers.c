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


static struct callchain_ctx {
    struct ksyms *ksyms;
    struct syms_cache *syms_cache;
    refcount_t ksyms_ref;
    refcount_t syms_ref;
} ctx;

int callchain_ctx_init(bool kernel, bool user)
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

void callchain_ctx_deinit(bool kernel, bool user)
{
    if (kernel && ctx.ksyms && refcount_dec_and_test(&ctx.ksyms_ref)) {
        ksyms__free(ctx.ksyms);
    }
    if (user && ctx.syms_cache && refcount_dec_and_test(&ctx.syms_ref)) {
        syms_cache__free(ctx.syms_cache);
    }
}

void print_callchain(FILE *f, struct callchain *callchain, u32 pid)
{
    __u64 i;
    bool kernel = !!ctx.ksyms, user = false;
    struct syms *syms;

    if (ctx.ksyms == NULL &&
        ctx.syms_cache == NULL)
        return ;

    for (i = 0; i < callchain->nr; i++) {
        __u64 ip = callchain->ips[i];
        if (ip == PERF_CONTEXT_KERNEL) {
            kernel = !!ctx.ksyms;
            user = false;
            continue;
        } else if (ip == PERF_CONTEXT_USER) {
            kernel = false;
            user = false;
            if (ctx.syms_cache) {
                syms = syms_cache__get_syms(ctx.syms_cache, pid);
                if (syms)
                    user = true;
            }
            continue;
        }
        if (kernel) {
            const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
            fprintf(f, "    %016llx %s+0x%llx ([kernel.kallsyms])\n", ip, ksym ? ksym->name : "Unknown",
                                ksym ? ip - ksym->addr : 0L);
        } else if (user) {
            struct dso *dso;
            uint64_t offset;
            dso = syms__find_dso(syms, ip, &offset);
            if (dso) {
                const struct sym *sym = dso__find_sym(dso, offset);
                fprintf(f, "    %016llx %s+0x%lx (%s)\n", ip, sym ? sym->name : "Unknown",
                                sym ? offset - sym->start : 0L, dso__name(dso)?:"Unknown");
            } else
                fprintf(f, "    %016llx %s (%s)\n", ip, "Unknown", "Unknown");
        } else
            fprintf(f, "    %016llx\n", ip);
    }
}




