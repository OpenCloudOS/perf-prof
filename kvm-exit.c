#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/rblist.h>
#include <linux/const.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <latency_helpers.h>


#define ALIGN(x, a)  __ALIGN_KERNEL((x), (a))

#define KVM_ISA_VMX   1
#define KVM_ISA_SVM   2
#define EXIT_REASON_HLT                 12
#define SVM_EXIT_HLT           0x078

#include "kvm_exit_reason.c"

struct monitor kvm_exit;
struct sample_type_raw;

static struct monitor_ctx {
    int nr_ins;
    struct sample_type_raw *perins_kvm_exit;
    int *perins_kvm_exit_valid;
    __u64 kvm_exit;
    __u64 kvm_entry;
    struct latency_dist *lat_dist;
    struct heatmap *heatmap;
    struct env *env;
} ctx;

struct trace_kvm_exit1 {
    unsigned short common_type;//	offset:0;	size:2;	signed:0;
	unsigned char common_flags;//	offset:2;	size:1;	signed:0;
	unsigned char common_preempt_count;//	offset:3;	size:1;	signed:0;
	int common_pid;//	offset:4;	size:4;	signed:1;
	int common_lock_depth;//	offset:8;	size:4;	signed:1;

	unsigned int exit_reason;//	offset:12;	size:4;	signed:0;
	unsigned long guest_rip;//	offset:16;	size:8;	signed:0;
};
struct trace_kvm_exit2 {
    unsigned short common_type;//	offset:0;	size:2;	signed:0;
	unsigned char common_flags;//	offset:2;	size:1;	signed:0;
	unsigned char common_preempt_count;//	offset:3;	size:1;	signed:0;
	int common_pid;//	offset:4;	size:4;	signed:1;

	unsigned int exit_reason;//	offset:8;	size:4;	signed:0;
	unsigned long guest_rip;//	offset:16;	size:8;	signed:0;
	u32 isa;//	offset:24;	size:4;	signed:0;
	u64 info1;//	offset:32;	size:8;	signed:0;
	u64 info2;//	offset:40;	size:8;	signed:0;
};
struct trace_kvm_exit3 {
    unsigned short common_type;//	offset:0;	size:2;	signed:0;
	unsigned char common_flags;//	offset:2;	size:1;	signed:0;
	unsigned char common_preempt_count;//	offset:3;	size:1;	signed:0;
	int common_pid;//	offset:4;	size:4;	signed:1;

	unsigned int exit_reason;//	offset:8;	size:4;	signed:0;
	unsigned long guest_rip;//	offset:16;	size:8;	signed:0;
	u32 isa;//	offset:24;	size:4;	signed:0;
	u64 info1;//	offset:32;	size:8;	signed:0;
	u64 info2;//	offset:40;	size:8;	signed:0;
	unsigned int vcpu_id;//  offset:48;	size:4;	signed:0;
};
union trace_kvm_exit {
    struct trace_kvm_exit1 e1;
    struct trace_kvm_exit2 e2;
    struct trace_kvm_exit3 e3;
};

struct trace_kvm_entry {
    unsigned short common_type;//      offset:0;       size:2; signed:0;
    unsigned char common_flags;//      offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//      offset:3;       size:1; signed:0;
    int common_pid;//  offset:4;       size:4; signed:1;

    unsigned int vcpu_id;//    offset:8;       size:4; signed:0;
};

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
struct sample_type_raw {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    struct {
        __u32   size;
        union {
            __u8    data[0];
            unsigned short common_type;
            union trace_kvm_exit kvm_exit;
            struct trace_kvm_entry kvm_entry;
        } __packed;
    } raw;
};

#define START_OF_KERNEL 0xffff000000000000UL

static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    ctx.nr_ins = monitor_nr_instance();
    ctx.perins_kvm_exit = calloc(ctx.nr_ins, sizeof(struct sample_type_raw));
    ctx.perins_kvm_exit_valid = calloc(ctx.nr_ins, sizeof(int));
    if (!ctx.perins_kvm_exit || !ctx.perins_kvm_exit_valid)
        return -1;

    ctx.lat_dist = latency_dist_new(env->perins, true, sizeof(u64));
    if (!ctx.lat_dist)
        return -1;

    if (env->heatmap)
        ctx.heatmap = heatmap_open("ns", "ns", env->heatmap);
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    free(ctx.perins_kvm_exit);
    free(ctx.perins_kvm_exit_valid);
    latency_dist_free(ctx.lat_dist);
    if (ctx.env->heatmap)
        heatmap_close(ctx.heatmap);
    tep__unref();
}

static int kvm_exit_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (kvm_exit.pages << 12) / 3,
    };
    struct perf_evsel *evsel;
    int id;

    if (monitor_ctx_init(env) < 0)
        return -1;

    id = tep__event_id("kvm", "kvm_exit");
    if (id < 0)
        return -1;
    attr.config = ctx.kvm_exit = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    id = tep__event_id("kvm", "kvm_entry");
    if (id < 0)
        return -1;
    attr.config = ctx.kvm_entry = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

struct print_info {
    bool started;
    bool print_header;
    u64 instance;
};
static void print_latency_node(void *opaque, struct latency_node *node)
{
    struct print_info *info = opaque;
    unsigned int exit_reason = node->key & 0xffffffff;
    u32 isa = node->key >> 32;

    if (!info->started ||
        info->instance != node->instance) {
        if (!info->started) {
            print_time(stdout);
            printf("\n");
        }
        info->started = true;
        info->print_header = true;
        info->instance = node->instance;
    }
    if (info->print_header) {
        info->print_header = false;
        if (ctx.env->perins)
            if (monitor_instance_oncpu())
                printf("kvm-exit latency CPU %d\n", monitor_instance_cpu((int)node->instance));
            else
                printf("kvm-exit latency THREAD %d\n", monitor_instance_thread((int)node->instance));
        else
            printf("kvm-exit latency\n");
        printf("%-*s %8s %16s %9s %9s %12s %6s\n", isa == KVM_ISA_VMX ? 20 : 32,
                "exit_reason", "calls", "total(us)", "min(us)", "avg(us)", "max(us)", "%gsys");
        printf("%s %8s %16s %9s %9s %12s %6s\n", isa == KVM_ISA_VMX ? "--------------------" : "--------------------------------",
                "--------", "----------------", "---------", "---------", "------------", "------");
    }
    printf("%-*s %8lu %16.3f %9.3f %9.3f %12.3f %6.2f\n", isa == KVM_ISA_VMX ? 20 : 32,
            find_exit_reason(isa, exit_reason),
            node->n, node->sum/1000.0,
            node->min/1000.0, node->sum/node->n/1000.0, node->max/1000.0,
            node->extra[0]*100.0/node->sum);
}

static void print_latency_interval(void)
{
    struct print_info info;

    info.started = false;
    latency_dist_print(ctx.lat_dist, print_latency_node, &info);
    printf("\n");
}

static void kvm_exit_interval(void)
{
    print_latency_interval();
}

static int kvm_exit_filter(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    int err = 0;

    if (env->filter) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            struct perf_event_attr *attr = perf_evsel__attr(evsel);
            if (attr->config == ctx.kvm_exit) {
                err = perf_evsel__apply_filter(evsel, env->filter);
                if (err < 0)
                    return err;
            }
        }
    }
    return 0;
}

static void kvm_exit_deinit(struct perf_evlist *evlist)
{
    kvm_exit_interval();
    monitor_ctx_exit();
}

static inline int __exit_reason(struct sample_type_raw *raw, unsigned int *exit_reason, u32 *isa, unsigned long *guest_rip)
{
    unsigned short common_type = raw->raw.common_type;

    if (common_type == ctx.kvm_exit) {
        switch (raw->raw.size) {
        case ALIGN(sizeof(struct trace_kvm_exit1)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            *exit_reason = raw->raw.kvm_exit.e1.exit_reason;
            *isa = KVM_ISA_VMX;
            *guest_rip = raw->raw.kvm_exit.e1.guest_rip;
            break;
        case ALIGN(sizeof(struct trace_kvm_exit2)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            *exit_reason = raw->raw.kvm_exit.e2.exit_reason;
            *isa = raw->raw.kvm_exit.e2.isa;
            *guest_rip = raw->raw.kvm_exit.e2.guest_rip;
            break;
        case ALIGN(sizeof(struct trace_kvm_exit3)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            *exit_reason = raw->raw.kvm_exit.e3.exit_reason;
            *isa = raw->raw.kvm_exit.e3.isa;
            *guest_rip = raw->raw.kvm_exit.e3.guest_rip;
            break;
        default:
            return -1;
        }
    }
    return 0;
}

static void __print_raw(struct sample_type_raw *raw, const char *str)
{
    print_time(stdout);
    if (str)
        printf("%s", str);
    tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);
}

static void __process_fast(struct sample_type_raw *rkvm_exit, struct sample_type_raw *rkvm_entry, int instance)
{
    unsigned int exit_reason = -1, hlt = EXIT_REASON_HLT;
    u32 isa = KVM_ISA_VMX;
    unsigned long guest_rip = 0;
    __u64 delta = rkvm_entry->time - rkvm_exit->time;
    u64 key = 0;
    struct latency_node *node;

    if (__exit_reason(rkvm_exit, &exit_reason, &isa, &guest_rip) < 0)
        return;
    if (isa == KVM_ISA_SVM) {
        hlt = SVM_EXIT_HLT;
    }

    key = ((u64)isa<<32)|exit_reason;
    node = latency_dist_input(ctx.lat_dist, ctx.env->perins?instance:0, key, delta);
    if (node && guest_rip >= START_OF_KERNEL)
        node->extra[0] += delta;

    if (ctx.env->heatmap)
        heatmap_write(ctx.heatmap, rkvm_exit->time, delta);

    if (ctx.env->greater_than &&
        exit_reason != hlt &&
        delta > ctx.env->greater_than) {
        __print_raw(rkvm_exit, NULL);
        __print_raw(rkvm_entry, NULL);
    }
}

static void kvm_exit_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_raw *raw = (void *)event->sample.array;
    unsigned short common_type = raw->raw.common_type;
    unsigned int exit_reason;
    u32 isa;
    unsigned long guest_rip;

    if (ctx.env->verbose >= 2) {
        print_time(stdout);
        tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);
    }

    if (common_type == ctx.kvm_exit) {
        if (__exit_reason(raw, &exit_reason, &isa, &guest_rip) < 0)
            return;
        ctx.perins_kvm_exit_valid[instance] = 1;
        ctx.perins_kvm_exit[instance] = *raw;
    } else if (common_type == ctx.kvm_entry) {
        if (ctx.perins_kvm_exit_valid[instance] == 1) {
            struct sample_type_raw *raw_kvm_exit = &ctx.perins_kvm_exit[instance];
            if (raw->tid_entry.tid == raw_kvm_exit->tid_entry.tid &&
                raw->time > raw_kvm_exit->time) {
                __process_fast(raw_kvm_exit, raw, instance);
                ctx.perins_kvm_exit_valid[instance] = 0;
            } else {
                if (raw->tid_entry.tid != raw_kvm_exit->tid_entry.tid) {
                    if (ctx.env->verbose >= 1) {
                        __print_raw(raw_kvm_exit, "WARN");
                        __print_raw(raw, "WARN");
                    }
                }
            }
        }
    }
}

struct monitor kvm_exit = {
    .name = "kvm-exit",
    .pages = 64,
    .init = kvm_exit_init,
    .filter = kvm_exit_filter,
    .deinit = kvm_exit_deinit,
    .interval = kvm_exit_interval,
    .sample = kvm_exit_sample,
};
MONITOR_REGISTER(kvm_exit)


