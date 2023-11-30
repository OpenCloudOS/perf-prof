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

static int monitor_ctx_init(struct prof_dev *dev)
{
    tep__ref();
    if (dev->env->callchain) {
        dev->private = callchain_ctx_new(callchain_flags(dev, CALLCHAIN_KERNEL), stdout);
        dev->pages *= 2;
    }
    return 0;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    if (dev->env->callchain) {
        callchain_ctx_free(dev->private);
    }
    tep__unref();
}

static int signal_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
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
        .exclude_callchain_user = exclude_callchain_user(dev, CALLCHAIN_KERNEL),
        .exclude_callchain_kernel = exclude_callchain_kernel(dev, CALLCHAIN_KERNEL),
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int id;

    if (monitor_ctx_init(dev) < 0)
        return -1;

    reduce_wakeup_times(dev, &attr);

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

static int signal_filter(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
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

static void signal_exit(struct prof_dev *dev)
{
    monitor_ctx_exit(dev);
}

static void signal_sample(struct prof_dev *dev, union perf_event *event, int instance)
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
    } *raw = (void *)&data->callchain;

    if (dev->env->callchain)
        raw = (void *)data->callchain.ips + data->callchain.nr * sizeof(__u64);

    tep__update_comm(NULL, data->tid_entry.tid);
    if (dev->print_title) print_time(stdout);
    tep__print_event(data->time/1000, data->cpu_entry.cpu, raw->data, raw->size);
    if (dev->env->callchain)
        print_callchain_common(dev->private, &data->callchain, data->tid_entry.pid);
}


static const char *signal_desc[] = PROFILER_DESC("signal",
    "[OPTION...] [--filter comm] [-g]",
    "Demo", "",
    "TRACEPOINT",
    "    signal:signal_generate", "",
    "EXAMPLES",
    "    "PROGRAME" signal --filter python");
static const char *signal_argv[] = PROFILER_ARGV("signal",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER,
    PROFILER_ARGV_PROFILER, "filter", "call-graph");
struct monitor monitor_signal = {
    .name = "signal",
    .desc = signal_desc,
    .argv = signal_argv,
    .pages = 2,
    .init = signal_init,
    .filter = signal_filter,
    .deinit = signal_exit,
    .comm   = monitor_tep__comm,
    .sample = signal_sample,
};
PROFILER_REGISTER(monitor_signal)

