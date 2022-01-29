#ifndef __STACK_HELPERS_H
#define __STACK_HELPERS_H

struct callchain {
    __u64   nr;
    __u64   ips[0];
};

struct callchain_ctx;
enum {
    CALLCHAIN_KERNEL = 1,
    CALLCHAIN_USER = 2,
};
struct callchain_ctx *callchain_ctx_new(int flags, FILE *fout);
void callchain_ctx_free(struct callchain_ctx *cc);
void print_callchain(struct callchain_ctx *cc, struct callchain *callchain, u32 pid);
void print_callchain_common(struct callchain_ctx *cc, struct callchain *callchain, u32 pid);
void task_exit_free_syms(union perf_event *event);

#endif