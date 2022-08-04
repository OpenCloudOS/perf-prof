// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 duanery

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define BREAK    0
#define CONTINUE 1


// irq_disabled
//   irq_disabled = true,  Interrupt cleared, continue.
//   irq_disabled = false, Interrupt enabled, continue.
//
// if (!((EFLAGS >> EFLAGS_IF_BIT) & 1) == irqs_disabled)
//     continue;
// else
//     break;
const volatile bool filter_irqs_disabled = false;
const volatile bool irqs_disabled = false;
#if defined(__TARGET_ARCH_x86)
#define X86_EFLAGS_IF_BIT   9
#define EFLAGS_IF_BIT   X86_EFLAGS_IF_BIT
#define EFLAGS flags
#endif


// tif_need_resched
//   tif_need_resched = true,  TIF_NEED_RESCHED set, continue.
//   tif_need_resched = false, TIF_NEED_RESCHED not set, continue.
//
// if (((flags >> TIF_NEED_RESCHED) & 1) == tif_need_resched)
//     continue;
// else
//     break;
const volatile bool filter_tif_need_resched = false;
const volatile bool tif_need_resched = false;
#if defined(__TARGET_ARCH_x86)
#define TIF_NEED_RESCHED    3
#elif defined(__TARGET_ARCH_arm)
#define TIF_NEED_RESCHED    1
#elif defined(__TARGET_ARCH_arm64)
#define TIF_NEED_RESCHED    1
#endif


// nr_running
//   nr_running is greater than `nr_running_min', less than `nr_running_max', continue.
//
// if (nr_running_min < nr_running < nr_running_max)
//     continue;
// else
//     break;
const volatile bool filter_nr_running = false;
const volatile u32 nr_running_min = 0;
const volatile u32 nr_running_max = 0xffffffff;


int perf_event_do_filter(struct bpf_perf_event_data *ctx)
{
    struct task_struct *task;
    struct rq *rq;
    u32 nr_running = 0;
    unsigned long flags;

    if (filter_irqs_disabled) {
        if (((ctx->regs.EFLAGS >> EFLAGS_IF_BIT) & 1) == irqs_disabled)
            return BREAK;
    }

    task = (void*)bpf_get_current_task();

    if (filter_tif_need_resched) {
        flags = BPF_CORE_READ(task, thread_info.flags);
        if (((flags >> TIF_NEED_RESCHED) & 1) != tif_need_resched)
            return BREAK;
    }

    if (filter_nr_running) {
        rq = BPF_CORE_READ(task, se.cfs_rq, rq);
        if (rq)
            nr_running = BPF_CORE_READ(rq, nr_running);
        else
            nr_running = BPF_CORE_READ(task, se.cfs_rq, nr_running);

        if (nr_running < nr_running_min)
            return BREAK;
        if (nr_running > nr_running_max)
            return BREAK;
    }

    return CONTINUE;
}

char LICENSE[] SEC("license") = "GPL";
