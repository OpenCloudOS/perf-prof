#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <monitor.h>
#include <tep.h>


static profiler event_lost;

static struct monitor_ctx {
    struct perf_evlist *evlist;
    struct tp_list *tp_list;
    struct env *env;
} ctx;

static int monitor_ctx_init(struct env *env)
{
    if (!env->event)
        return -1;

    tep__ref();

    ctx.tp_list = tp_list_new(env->event);
    if (!ctx.tp_list)
        return -1;

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    tp_list_free(ctx.tp_list);
    tep__unref();
}

static int event_lost_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_READ,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_ctx_init(env) < 0)
        return -1;

    reduce_wakeup_times(&event_lost, &attr);

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];

        tp->counters = calloc(monitor_nr_instance(), sizeof(unsigned long));
        if (!tp->counters)
            return -1;

        attr.config = tp->id;
        evsel = perf_evsel__new(&attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);

        tp->evsel = evsel;
    }

    ctx.evlist = evlist;
    return 0;
}

static int event_lost_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, err;

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];
        if (tp->filter && tp->filter[0]) {
            err = perf_evsel__apply_filter(tp->evsel, tp->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void event_lost_exit(struct perf_evlist *evlist)
{
    int i;

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];
        if (tp->counters)
            free(tp->counters);
    }

    monitor_ctx_exit();
}

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
struct sample_type_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    __u64   stream_id;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    __u64		period;
    u64         counter;
    u64         id;
};

static void event_lost_sample(union perf_event *event, int instance)
{
    struct sample_type_header *hdr = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct tp *tp = NULL;
    int i;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, hdr->stream_id, NULL);
    if (!evsel) {
        fprintf(stderr, "failed to find evsel\n");
        return ;
    }

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        tp = &ctx.tp_list->tp[i];
        if (tp->evsel == evsel)
            goto found;
    }
    fprintf(stderr, "failed to find tracepoint\n");
    return ;

found:
    if (hdr->counter - tp->counters[instance] != 1) {
        fprintf(stderr, "lost %lu events\n", hdr->counter - tp->counters[instance] - 1);
    }
    tp->counters[instance] = hdr->counter;
}


static const char *event_lost_desc[] = PROFILER_DESC("event-lost",
    "[OPTION...] -e EVENT",
    "Determine if any events are lost.", "",
    "EXAMPLES", "",
    "    "PROGRAME" event-lost -e sched:sched_wakeup -m 64");
static const char *event_lost_argv[] = PROFILER_ARGV("event-lost",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event");
static profiler event_lost = {
    .name = "event-lost",
    .desc = event_lost_desc,
    .argv = event_lost_argv,
    .pages = 2,
    .init = event_lost_init,
    .filter = event_lost_filter,
    .deinit = event_lost_exit,
    .sample = event_lost_sample,
};
PROFILER_REGISTER(event_lost);


