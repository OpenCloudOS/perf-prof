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

struct monitor kvm_exit;
struct sample_type_raw;

struct monitor_ctx {
    int nr_cpus;
    struct sample_type_raw *pcpu_kvm_exit;
    int *pcpu_kvm_exit_valid;
    __u64 kvm_exit;
    __u64 kvm_entry;
    struct hist hist;
    struct env *env;
} ctx;

#define KVM_ISA_VMX   1
#define KVM_ISA_SVM   2
#define EXIT_REASON_HLT                 12
#define SVM_EXIT_HLT           0x078

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

static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    ctx.nr_cpus = get_possible_cpus();
    ctx.pcpu_kvm_exit = calloc(ctx.nr_cpus, sizeof(struct sample_type_raw));
    ctx.pcpu_kvm_exit_valid = calloc(ctx.nr_cpus, sizeof(int));
    memset(&ctx.hist, 0, sizeof(ctx.hist));
    ctx.env = env;
    return ctx.pcpu_kvm_exit && ctx.pcpu_kvm_exit_valid ? 0 : -1;
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

static void kvm_exit_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
    print_log2_hist(ctx.hist.slots, MAX_SLOTS, "kvm-exit latency(ns)");
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

static void kvm_exit_sample(union perf_event *event)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_raw *raw = (void *)event->sample.array;
    unsigned short common_type = raw->raw.common_type;
    unsigned int exit_reason, hlt = EXIT_REASON_HLT;
    u32 isa = KVM_ISA_VMX;
    u32 cpu = raw->cpu_entry.cpu;

    if (ctx.env->verbose) {
        print_time(stdout);
        tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);
    }

    if (common_type == ctx.kvm_exit) {
        switch (raw->raw.size) {
        case ALIGN(sizeof(struct trace_kvm_exit1)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            exit_reason = raw->raw.kvm_exit.e1.exit_reason;
            break;
        case ALIGN(sizeof(struct trace_kvm_exit2)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            exit_reason = raw->raw.kvm_exit.e2.exit_reason;
            isa = raw->raw.kvm_exit.e2.isa;
            break;
        case ALIGN(sizeof(struct trace_kvm_exit3)+sizeof(u32), sizeof(u64)) - sizeof(u32):
            exit_reason = raw->raw.kvm_exit.e3.exit_reason;
            isa = raw->raw.kvm_exit.e3.isa;
            break;
        default:
            return;
        }
        if (isa == KVM_ISA_SVM) {
            hlt = SVM_EXIT_HLT;
        }
        if (exit_reason == hlt)
            ctx.pcpu_kvm_exit_valid[cpu] = 0;
        else {
            ctx.pcpu_kvm_exit_valid[cpu] = 1;
            ctx.pcpu_kvm_exit[cpu] = *raw;
        }
    } else if (common_type == ctx.kvm_entry) {
        if (ctx.pcpu_kvm_exit_valid[cpu] == 1) {
            struct sample_type_raw *raw_kvm_exit = &ctx.pcpu_kvm_exit[cpu];
            if (raw->cpu_entry.cpu == raw_kvm_exit->cpu_entry.cpu &&
                raw->tid_entry.tid == raw_kvm_exit->tid_entry.tid &&
                raw->time > raw_kvm_exit->time) {
                __u64 delta = raw->time - raw_kvm_exit->time;
                int slot = (int)__log2l(delta);
                if (slot > MAX_SLOTS)
                    slot = MAX_SLOTS;
                ctx.hist.slots[slot] ++;
            }
        }
    }
}

struct monitor kvm_exit = {
    .name = "kvm-exit",
    .pages = 64,
    .init = kvm_exit_init,
    .deinit = kvm_exit_exit,
    .sample = kvm_exit_sample,
};
MONITOR_REGISTER(kvm_exit)


