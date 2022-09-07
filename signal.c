#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>


struct monitor monitor_signal;
static void signal_sample_callchain(union perf_event *event, int instance);
static struct monitor_ctx {
    struct callchain_ctx *cc;
    struct env *env;
} ctx;
static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    if (env->callchain) {
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
        monitor_signal.pages *= 2;
        monitor_signal.sample = signal_sample_callchain;
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain) {
        callchain_ctx_free(ctx.cc);
    }
    tep__unref();
}

static int signal_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW |
                         (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int id;

    if (monitor_ctx_init(env) < 0)
        return -1;

    id = tep__event_id("signal", "signal_generate");
    if (id < 0)
        return -1;

    attr.config = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static int signal_filter(struct perf_evlist *evlist, struct env *env)
{
    char filter[64];
    struct perf_evsel *evsel;
    int err;
    if (env->filter) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            snprintf(filter, sizeof(filter), "comm~\"%s\"", env->filter);
            err = perf_evsel__apply_filter(evsel, filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void signal_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void signal_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_data {
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
	        __u8    data[0];
        } raw;
    } *data = (void *)event->sample.array;

    tep__update_comm(NULL, data->tid_entry.tid);
    print_time(stdout);
    tep__print_event(data->time/1000, data->cpu_entry.cpu, data->raw.data, data->raw.size);
}

static void signal_sample_callchain(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_data {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        struct callchain callchain;
    } *data = (void *)event->sample.array;
    struct {
        __u32   size;
        __u8    data[0];
    } *raw = (void *)data->callchain.ips + data->callchain.nr * sizeof(__u64);

    tep__update_comm(NULL, data->tid_entry.tid);
    print_time(stdout);
    tep__print_event(data->time/1000, data->cpu_entry.cpu, raw->data, raw->size);
    if (ctx.env->callchain) {
        print_callchain_common(ctx.cc, &data->callchain, 0/*only kernel stack*/);
    }
}

struct monitor monitor_signal = {
    .name = "signal",
    .pages = 2,
    .init = signal_init,
    .filter = signal_filter,
    .deinit = signal_exit,
    .comm   = monitor_tep__comm,
    .sample = signal_sample,
};
MONITOR_REGISTER(monitor_signal)

