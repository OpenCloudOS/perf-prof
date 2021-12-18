#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include "monitor.h"

struct monitor split_lock;

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
struct monitor_ctx {
    int nr_cpus;
    uint64_t *counter;
    uint64_t *polling;
} ctx;

static int monitor_ctx_init(void)
{
    ctx.nr_cpus = get_possible_cpus();
    ctx.counter = calloc(ctx.nr_cpus, sizeof(uint64_t));
    ctx.polling = calloc(ctx.nr_cpus, sizeof(uint64_t));
    return ctx.counter && ctx.polling ? 0 : -1;
}

static void monitor_ctx_exit(void)
{
    if (ctx.counter) {
        free(ctx.counter);
        ctx.counter = NULL;
    }
    if (ctx.polling) {
        free(ctx.polling);
        ctx.polling = NULL;
    }
}

static int split_lock_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type        = PERF_TYPE_RAW,
        .config      = 0x10f4,   //split_lock, Intel
        .size        = sizeof(struct perf_event_attr),
        .sample_period = env->trigger_freq,  //每trigger_freq个split_lock发起一个PMI中断, 发起1个采样.
        .sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ,
        .read_format = 0,
        .exclude_host = env->guest,  //是否只采样guest模式.
        .pinned        = 1,
        .disabled    = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;
    pthread_t t;

    if (env->test)
        pthread_create(&t, NULL, do_split_lock, NULL);

    if (!env->interval)
        split_lock.read = NULL;
    
    if (monitor_ctx_init() < 0)
        return -1;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        fprintf(stderr, "failed to init split-lock\n");
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static void split_lock_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void split_lock_read(struct perf_evsel *evsel, struct perf_counts_values *count, int instance)
{
    int cpu = monitor_instance_cpu(instance);
    uint64_t counter = 0;

    if (count->val > ctx.polling[cpu]) {
        counter = count->val - ctx.polling[cpu];
        ctx.polling[cpu] = count->val;
    }
    if (counter) {
        print_time(stdout);
        printf("cpu %d split-lock %lu\n", cpu, counter);
    }
}

static void split_lock_sample(union perf_event *event)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        __u64 counter; //split-lock次数
    } *data = (void *)event->sample.array;
    __u32 size = event->header.size - sizeof(struct perf_event_header);
    uint64_t counter = 0;

    if (size != sizeof(struct sample_type_data)) {
        fprintf(stderr, "size != sizeof sample_type_data\n");
    }
    if (data->counter > ctx.counter[data->cpu_entry.cpu]) {
        counter = data->counter - ctx.counter[data->cpu_entry.cpu];
        ctx.counter[data->cpu_entry.cpu] = data->counter;
    }
    if (counter) {
        print_time(stdout);
        printf("cpu %d pid %d tid %d split-lock %lu\n", data->cpu_entry.cpu, data->tid_entry.pid, data->tid_entry.tid, counter);
    }
}

struct monitor split_lock = {
    .name = "split-lock",
    .pages = 1,
    .init = split_lock_init,
    .deinit = split_lock_exit,
    .read = split_lock_read,
    .sample = split_lock_sample,
};
MONITOR_REGISTER(split_lock)

