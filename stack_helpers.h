#ifndef __STACK_HELPERS_H
#define __STACK_HELPERS_H

struct callchain {
    __u64   nr;
    __u64   ips[0];
};

int callchain_ctx_init(bool kernel, bool user);
void callchain_ctx_deinit(bool kernel, bool user);
void print_callchain(FILE *f, struct callchain *callchain, u32 pid);
void task_exit_free_syms(union perf_event *event);

#endif