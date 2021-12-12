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
#define ALIGN(x, a)  __ALIGN_KERNEL((x), (a))

#define KVM_ISA_VMX   1
#define KVM_ISA_SVM   2
#define EXIT_REASON_HLT                 12
#define SVM_EXIT_HLT           0x078

#include "kvm_exit_reason.c"

struct monitor kvm_exit;
struct sample_type_raw;

struct monitor_ctx {
    int nr_cpus;
    struct sample_type_raw *pcpu_kvm_exit;
    int *pcpu_kvm_exit_valid;
    __u64 kvm_exit;
    __u64 kvm_entry;
    struct hist hist;
    struct hist *pcpu_hist;
    struct rblist exit_reason_stat;
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
        } __packed;
    } raw;
};

struct exit_reason_stat {
    struct rb_node rbnode;
    unsigned int isa;
    unsigned int exit_reason;
    const char *name;
    __u64 min;
    __u64 max;
    __u64 n;
    __u64 sum;
};

static int node_cmp(struct rb_node *rbn, const void *entry)
{
    struct exit_reason_stat *a = container_of(rbn, struct exit_reason_stat, rbnode);
    const struct exit_reason_stat *b = entry;

    if (a->exit_reason > b->exit_reason)
        return 1;
    else if (a->exit_reason < b->exit_reason)
        return -1;
    else
        return 0;
}

static struct rb_node *node_new(struct rblist *rlist, const void *new_entry)
{
    const struct exit_reason_stat *e = new_entry;
    struct exit_reason_stat *b = malloc(sizeof(struct exit_reason_stat));
    if (b) {
        b->isa = e->isa;
        b->exit_reason = e->exit_reason;
        b->name = find_exit_reason(b->isa, b->exit_reason); //TODO
        b->min = ~0UL;
        b->max = 0;
        b->n = 0;
        b->sum = 0;
        RB_CLEAR_NODE(&b->rbnode);
        return &b->rbnode;
    } else
        return NULL;
}

static void node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct exit_reason_stat *b = container_of(rb_node, struct exit_reason_stat, rbnode);
    free(b);
}

static void node_delete_empty(struct rblist *rblist, struct rb_node *rb_node)
{
}

static int sorted_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct exit_reason_stat *a = container_of(rbn, struct exit_reason_stat, rbnode);
    const struct exit_reason_stat *b = entry;

    if (a->sum > b->sum)
        return -1;
    else if (a->sum < b->sum)
        return 1;
    else
        return 0;
}

static struct rb_node *sorted_node_new(struct rblist *rlist, const void *new_entry)
{
    struct exit_reason_stat *b = (void *)new_entry;
    RB_CLEAR_NODE(&b->rbnode);
    return &b->rbnode;
}

static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    ctx.nr_cpus = get_possible_cpus();
    ctx.pcpu_kvm_exit = calloc(ctx.nr_cpus, sizeof(struct sample_type_raw));
    ctx.pcpu_kvm_exit_valid = calloc(ctx.nr_cpus, sizeof(int));
    if (!ctx.pcpu_kvm_exit || !ctx.pcpu_kvm_exit_valid)
        return -1;
    memset(&ctx.hist, 0, sizeof(ctx.hist));
    if (env->percpu) {
        ctx.pcpu_hist = calloc(ctx.nr_cpus, sizeof(struct hist));
        if (!ctx.pcpu_hist)
            return -1;
    }
    rblist__init(&ctx.exit_reason_stat);
    ctx.exit_reason_stat.node_cmp = node_cmp;
    ctx.exit_reason_stat.node_new = node_new;
    ctx.exit_reason_stat.node_delete = node_delete;
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
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

static void kvm_exit_interval(struct perf_cpu_map *cpus)
{
    struct exit_reason_stat *stat;
    struct rb_node *rbn;
    struct rblist sorted;
    int print_header = 1;

    print_time(stdout);
    printf("\n");
    if (!ctx.env->percpu) {
        print_log2_hist(ctx.hist.slots, MAX_SLOTS, "kvm-exit latency(ns)");
        memset(&ctx.hist, 0, sizeof(ctx.hist));
    } else {
        int cpu, idx;
        char buff[128];
        perf_cpu_map__for_each_cpu(cpu, idx, cpus) {
            snprintf(buff, sizeof(buff), "[%03d] latency(ns)", cpu);
            print_log2_hist(ctx.pcpu_hist[cpu].slots, MAX_SLOTS, buff);
            memset(&ctx.pcpu_hist[cpu], 0, sizeof(struct hist));
        }
    }

    if (rblist__empty(&ctx.exit_reason_stat))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = sorted_node_cmp;
    sorted.node_new = sorted_node_new;
    sorted.node_delete = ctx.exit_reason_stat.node_delete;
    ctx.exit_reason_stat.node_delete = node_delete_empty; //empty, not really delete

    /* sort, remove from `ctx.exit_reason_stat', add to `sorted'. */
    do {
        rbn = rblist__entry(&ctx.exit_reason_stat, 0);
        stat = container_of(rbn, struct exit_reason_stat, rbnode);
        rblist__remove_node(&ctx.exit_reason_stat, rbn);
        rblist__add_node(&sorted, stat);
    } while (!rblist__empty(&ctx.exit_reason_stat));

    do {
        rbn = rblist__entry(&sorted, 0);
        stat = container_of(rbn, struct exit_reason_stat, rbnode);

        if (print_header) {
            printf("%-*s %8s %16s %9s %9s %12s\n", stat->isa == KVM_ISA_VMX ? 20 : 32,
                "exit_reason", "calls", "total(us)", "min(us)", "avg(us)", "max(us)");
            printf("%s %8s %16s %9s %9s %12s\n", stat->isa == KVM_ISA_VMX ? "--------------------" : "--------------------------------",
                "--------", "----------------", "---------", "---------", "------------");
            print_header = 0;
        }
        printf("%-*s %8llu %16.3f %9.3f %9.3f %12.3f\n", stat->isa == KVM_ISA_VMX ? 20 : 32,
                stat->name, stat->n, stat->sum/1000.0,
                stat->min/1000.0, stat->sum/stat->n/1000.0, stat->max/1000.0);

        rblist__remove_node(&sorted, rbn);
    } while (!rblist__empty(&sorted));

    ctx.exit_reason_stat.node_delete = sorted.node_delete;
}

static void kvm_exit_deinit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
    kvm_exit_interval(perf_evsel__cpus(perf_evlist__next(evlist, NULL)));
}

static __always_inline u64 __log2(u32 v)
{
	u32 shift, r;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);

	return r;
}

static __always_inline u64 __log2l(u64 v)
{
	u32 hi = v >> 32;

	if (hi)
		return __log2(hi) + 32;
	else
		return __log2(v);
}

static int __exit_reason(struct sample_type_raw *raw, unsigned int *exit_reason, u32 *isa)
{
    unsigned short common_type = raw->raw.common_type;

    if (common_type == ctx.kvm_exit) {
        switch (raw->raw.size) {
        case ALIGN(sizeof(struct trace_kvm_exit1)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            *exit_reason = raw->raw.kvm_exit.e1.exit_reason;
            *isa = KVM_ISA_VMX;
            break;
        case ALIGN(sizeof(struct trace_kvm_exit2)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            *exit_reason = raw->raw.kvm_exit.e2.exit_reason;
            *isa = raw->raw.kvm_exit.e2.isa;
            break;
        case ALIGN(sizeof(struct trace_kvm_exit3)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            *exit_reason = raw->raw.kvm_exit.e3.exit_reason;
            *isa = raw->raw.kvm_exit.e3.isa;
            break;
        default:
            return -1;
        }
    }
    return 0;
}

static void kvm_exit_sample(union perf_event *event)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_raw *raw = (void *)event->sample.array;
    unsigned short common_type = raw->raw.common_type;
    u32 cpu = raw->cpu_entry.cpu;
    unsigned int exit_reason, hlt = EXIT_REASON_HLT;
    u32 isa;

    if (ctx.env->verbose) {
        print_time(stdout);
        tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);
    }

    if (common_type == ctx.kvm_exit) {
        if (__exit_reason(raw, &exit_reason, &isa) < 0)
            return;
        ctx.pcpu_kvm_exit_valid[cpu] = 1;
        ctx.pcpu_kvm_exit[cpu] = *raw;
    } else if (common_type == ctx.kvm_entry) {
        if (ctx.pcpu_kvm_exit_valid[cpu] == 1) {
            struct sample_type_raw *raw_kvm_exit = &ctx.pcpu_kvm_exit[cpu];
            if (raw->cpu_entry.cpu == raw_kvm_exit->cpu_entry.cpu &&
                raw->tid_entry.tid == raw_kvm_exit->tid_entry.tid &&
                raw->time > raw_kvm_exit->time) {
                struct exit_reason_stat stat, *pstat;
                struct rb_node *rbn;
                __u64 delta = raw->time - raw_kvm_exit->time;
                int slot;

                __exit_reason(raw_kvm_exit, &exit_reason, &isa);

                if (isa == KVM_ISA_SVM) {
                    hlt = SVM_EXIT_HLT;
                }

                if (exit_reason != hlt) {
                    slot = (int)__log2l(delta);
                    if (slot > MAX_SLOTS)
                        slot = MAX_SLOTS;
                    if (!ctx.env->percpu)
                        ctx.hist.slots[slot] ++;
                    else
                        ctx.pcpu_hist[cpu].slots[slot] ++;
                }

                stat.isa = isa;
                stat.exit_reason = exit_reason;
                rbn = rblist__findnew(&ctx.exit_reason_stat, &stat);
                if (rbn) {
                    pstat = container_of(rbn, struct exit_reason_stat, rbnode);
                    if (delta < pstat->min)
                        pstat->min = delta;
                    if (delta > pstat->max)
                        pstat->max = delta;
                    pstat->n ++;
                    pstat->sum += delta;
                }

                if (ctx.env->greater_than &&
                    exit_reason != hlt &&
                    delta > ctx.env->greater_than * 1000UL) {
                    print_time(stdout);
                    tep__print_event(raw_kvm_exit->time/1000, raw_kvm_exit->cpu_entry.cpu, raw_kvm_exit->raw.data, raw_kvm_exit->raw.size);
                    print_time(stdout);
                    tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);
                }
                ctx.pcpu_kvm_exit_valid[cpu] = 0;
            }
        }
    }
}

struct monitor kvm_exit = {
    .name = "kvm-exit",
    .pages = 64,
    .init = kvm_exit_init,
    .deinit = kvm_exit_deinit,
    .interval = kvm_exit_interval,
    .sample = kvm_exit_sample,
};
MONITOR_REGISTER(kvm_exit)


