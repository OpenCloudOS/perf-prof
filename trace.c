#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>

struct monitor trace;
struct monitor_ctx {
    struct env *env;
} ctx;
static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    tep__unref();
}

static int trace_init(struct perf_evlist *evlist, struct env *env)
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
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (env->event) {
        char *sys = strtok(env->event, ":");
        char *name = strtok(NULL, ":");
         int id = tep__event_id(sys, name);
        if (id < 0)
            return -1;
        attr.config = id;
    } else
        return -1;

    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);
    return 0;
}

static int trace_filter(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    int err;
    if (env->filter) {
        perf_evlist__for_each_evsel(evlist, evsel) {
            err = perf_evsel__apply_filter(evsel, env->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void trace_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

static void trace_sample(union perf_event *event)
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

struct monitor trace = {
    .name = "trace",
    .pages = 2,
    .init = trace_init,
    .filter = trace_filter,
    .deinit = trace_exit,
    .sample = trace_sample,
};
MONITOR_REGISTER(trace)

