#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"
#include "trace_helpers.h"

struct monitor irq_off;
static void irq_off_read(struct perf_evsel *evsel, struct perf_counts_values *count, int cpu);

struct monitor_ctx {
    int nr_cpus;
    uint64_t *counter;
    uint64_t *temp;
    struct ksyms *ksyms;
    struct env *env;
} ctx;
static int monitor_ctx_init(struct env *env)
{
    ctx.nr_cpus = get_possible_cpus();
    ctx.counter = calloc(ctx.nr_cpus, sizeof(uint64_t));
    if (!ctx.counter) {
        return -1;
    }
    ctx.temp = calloc(ctx.nr_cpus, sizeof(uint64_t));
    if (!ctx.temp) {
        free(ctx.counter);
        return -1;
    }
    if (env->callchain) {
        ctx.ksyms = ksyms__load();
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    ksyms__free(ctx.ksyms);
    free(ctx.counter);
    free(ctx.temp);
}

static int irq_off_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_CPU_CLOCK,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = env->latency / 2 * 1000UL, //ns
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_user  = env->precise ? 0 : 1,
        .exclude_idle  = env->precise ? 0 : 1,
        .exclude_callchain_user = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (!env->precise) {
        env->interval = env->latency / 3 / 1000; //ms
        irq_off.read = irq_off_read;
    }

    if (env->callchain)
        irq_off.pages *= 2;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
    
}

static void irq_off_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void irq_off_read(struct perf_evsel *evsel, struct perf_counts_values *count, int cpu)
{
    uint64_t counter;
    uint64_t bound = ctx.env->latency / 2 * 1000UL;
    counter = count->val - ctx.temp[cpu];
    if (counter <= bound) {
        ctx.counter[cpu] = count->val;
    } else if (ctx.env->verbose) {
        print_time(stdout);
        printf("cpu %d counter %lu %lu %lu\n", cpu, counter, ctx.temp[cpu], ctx.counter[cpu]);
    }
    ctx.temp[cpu] = count->val;
}

static void irq_off_sample(union perf_event *event)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ | PERF_SAMPLE_CALLCHAIN
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        __u64 counter;
        struct {
            __u64   nr;
	        __u64   ips[0];
        } callchain;
    } *data = (void *)event->sample.array;
    __u32 size = event->header.size - sizeof(struct perf_event_header);
    uint64_t counter = 0;

    if (size != sizeof(struct sample_type_data) +
            (ctx.env->callchain ? data->callchain.nr * sizeof(__u64) : -sizeof(__u64))) {
        fprintf(stderr, "size(%u) != sizeof sample_type_data\n", size);
    }

    if (data->counter > ctx.counter[data->cpu_entry.cpu]) {
        counter = data->counter - ctx.counter[data->cpu_entry.cpu];
        ctx.counter[data->cpu_entry.cpu] = data->counter;
    }

    if (counter > ctx.env->latency * 1000UL + 1000UL) {
        print_time(stdout);
        printf("cpu %d pid %d tid %d irq-off %lu ns\n", data->cpu_entry.cpu, data->tid_entry.pid, data->tid_entry.tid, counter);
        if (ctx.env->callchain && ctx.ksyms) {
            __u64 i;
            for (i = 0; i < data->callchain.nr; i++) {
                __u64 ip = data->callchain.ips[i];
                const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
                printf("    %016llx %s+0x%llx\n", ip, ksym ? ksym->name : "Unknown", ip - ksym->addr);
            }
        }
    } else if (ctx.env->verbose) {
        print_time(stdout);
        printf("cpu %d pid %d tid %d irq-off %lu ns %llu\n", data->cpu_entry.cpu, data->tid_entry.pid, data->tid_entry.tid, counter, data->counter);
    }
}

struct monitor irq_off = {
    .name = "irq-off",
    .pages = 2,
    .init = irq_off_init,
    .deinit = irq_off_exit,
    .sample = irq_off_sample,
};
MONITOR_REGISTER(irq_off)

