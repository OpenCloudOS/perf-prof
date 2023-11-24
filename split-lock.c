#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/time64.h>
#include "monitor.h"
#include "stack_helpers.h"


/******************************************************
split-lock test
******************************************************/
#pragma pack(push, 2)
struct counter
{
    char buf[62];
    long long c;
};
#pragma pack(pop)

static void *do_split_lock(void *unused) {
    struct counter *p;
    int size = sizeof(struct counter);
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    p = (struct counter *) mmap(0, size, prot, flags, -1, 0);
    while (1) {
        __sync_fetch_and_add(&p->c, 1);
    }
    return NULL;
}

/******************************************************
split-lock ctx
******************************************************/
struct split_lock_ctx {
    int nr_ins;
    struct lock_info {
        uint64_t counter; // sample counter
        uint64_t polling; // read
        uint64_t ena;
        uint64_t run;
    } *p;
    struct callchain_ctx *cc;
};

static void monitor_ctx_exit(struct prof_dev *dev);
static int monitor_ctx_init(struct prof_dev *dev)
{
    struct split_lock_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;
    ctx->nr_ins = prof_dev_nr_ins(dev);
    ctx->p = calloc(ctx->nr_ins, sizeof(*ctx->p));
    if (!ctx->p)
        goto failed;

    if (dev->env->callchain) {
        ctx->cc = callchain_ctx_new(callchain_flags(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER), stdout);
    }
    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct split_lock_ctx *ctx = dev->private;
    if (ctx->p)
        free(ctx->p);
    free(ctx);
}

static int split_lock_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct perf_event_attr attr = {
        .type        = PERF_TYPE_RAW,
        .config      = 0x10f4,   //split_lock, Intel
        .size        = sizeof(struct perf_event_attr),
        .sample_period = env->trigger_freq,  //每trigger_freq个split_lock发起一个PMI中断, 发起1个采样.
        .sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ |
                       (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
        .pinned      = 0,
        .disabled    = 1,
        .exclude_host = env->exclude_host,  //是否只采样guest模式.
        .exclude_callchain_user = exclude_callchain_user(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .exclude_callchain_kernel = exclude_callchain_kernel(dev, CALLCHAIN_KERNEL | CALLCHAIN_USER),
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;
    pthread_t t;
    int vendor = get_cpu_vendor();

    if (vendor != X86_VENDOR_INTEL && vendor != X86_VENDOR_AMD) {
        fprintf(stderr, "split-lock exists only on intel/amd platforms\n");
        return -1;
    }

    if (vendor == X86_VENDOR_AMD) {
        // PMCx025 [Retired Lock Instructions] (Core::X86::Pmc::Core::LsLocks)
        // UnitMask events are ORed.
        // PMCx025
        // Bits Description
        // 7:4  Reserved.
        // 3    SpecLockHiSpec. Read-write. Reset: 0. High speculative cacheable lock speculation succeeded.
        // 2    SpecLockLoSpec. Read-write. Reset: 0. Low speculative cacheable lock speculation succeeded.
        // 1    NonSpecLock. Read-write. Reset: 0. Non speculative cacheable lock.
        // 0    BusLock. Read-write. Reset: 0. Non-cacheable or cacheline-misaligned lock.
        //      Comparable to legacy bus lock.
        attr.config = 0x125;
    }

    if (env->test)
        pthread_create(&t, NULL, do_split_lock, NULL);

    if (monitor_ctx_init(dev) < 0)
        return -1;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to init split-lock\n");
        goto failed;
    }
    perf_evlist__add(evlist, evsel);
    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static void split_lock_exit(struct prof_dev *dev)
{
    monitor_ctx_exit(dev);
}

static int split_lock_read(struct prof_dev *dev, struct perf_evsel *evsel, struct perf_counts_values *count, int instance)
{
    struct split_lock_ctx *ctx = dev->private;
    uint64_t counter = 0;
    uint64_t enabled = 0;
    uint64_t running = 0;

    if (count->val > ctx->p[instance].polling) {
        counter = count->val - ctx->p[instance].polling;
        ctx->p[instance].polling = count->val;
    }
    if (count->ena > ctx->p[instance].ena) {
        enabled = count->ena - ctx->p[instance].ena;
        ctx->p[instance].ena = count->ena;
    }
    if (count->run > ctx->p[instance].run) {
        running = count->run - ctx->p[instance].run;
        ctx->p[instance].run = count->run;
    }
    if (counter) {
        print_time(stdout);
        printf("cpu %3d split-lock %lu run %lu%%\n", prof_dev_ins_cpu(dev, instance), counter, running*100/enabled);
    }
    return 0;
}

static void split_lock_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct split_lock_ctx *ctx = dev->private;
    // in linux/perf_event.h
    // PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_READ,
    struct sample_type_data {
        __u64   ip;
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        __u64 counter; //split-lock次数
        __u64 enabled;
        __u64 running;
        struct callchain callchain;
    } *data = (void *)event->sample.array;
    uint64_t counter = 0;

    if (data->counter > ctx->p[instance].counter) {
        counter = data->counter - ctx->p[instance].counter;
        ctx->p[instance].counter = data->counter;
    }
    if (counter) {
        print_time(stdout);
        printf("    pid %6d tid %6d [%03d] %llu.%06llu: split-lock: %lu ip %08llx\n", data->tid_entry.pid, data->tid_entry.tid,
                        data->cpu_entry.cpu, data->time / NSEC_PER_SEC, (data->time % NSEC_PER_SEC)/1000, counter, data->ip);
        if (dev->env->callchain)
            print_callchain_common(ctx->cc, &data->callchain, data->tid_entry.pid);
    }
}


static const char *split_lock_desc[] = PROFILER_DESC("split-lock",
    "[OPTION...] [-T trig] [-G] [--test]",
    "Split-lock on x86 platform.", "",
    "SYNOPSIS",
    "    Super Queue lock splits across a cache line.", "",
    "EXAMPLES",
    "    "PROGRAME" split-lock -i 1000 --test",
    "    "PROGRAME" split-lock -T 1000 -i 1000 -G");
static const char *split_lock_argv[] = PROFILER_ARGV("split-lock",
    PROFILER_ARGV_OPTION,
    "FILTER OPTION:",
    "exclude-host", "user-callchain", "kernel-callchain",
    PROFILER_ARGV_PROFILER, "trigger", "perins", "call-graph", "test");
struct monitor split_lock = {
    .name = "split-lock",
    .desc = split_lock_desc,
    .argv = split_lock_argv,
    .pages = 1,
    .init = split_lock_init,
    .deinit = split_lock_exit,
    .read = split_lock_read,
    .sample = split_lock_sample,
};
MONITOR_REGISTER(split_lock)

