#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"
#include "trace_helpers.h"

struct monitor profile;
struct monitor_ctx {
    int nr_cpus;
    uint64_t *counter;
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
    if (env->callchain) {
        ctx.ksyms = ksyms__load();
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    ksyms__free(ctx.ksyms);
}

static int profile_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_HARDWARE,
        .config        = PERF_COUNT_HW_CPU_CYCLES,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = env->freq,
        .freq          = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_CPU | PERF_SAMPLE_READ |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (env->callchain)
        profile.pages = 4;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static void profile_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void profile_sample(union perf_event *event)
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

    print_time(stdout);
    printf("cpu %d pid %d tid %d %lu cycles\n", data->cpu_entry.cpu, data->tid_entry.pid, data->tid_entry.tid, counter);
    if (ctx.env->callchain && ctx.ksyms) {
        __u64 i;
        for (i = 0; i < data->callchain.nr; i++) {
            __u64 ip = data->callchain.ips[i];
            const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
            printf("    %016llx %s+0x%llx\n", ip, ksym ? ksym->name : "Unknown", ip - ksym->addr);
        }
    }
}

struct monitor profile = {
    .name = "profile",
    .pages = 2,
    .init = profile_init,
    .deinit = profile_exit,
    .sample = profile_sample,
};
MONITOR_REGISTER(profile)

