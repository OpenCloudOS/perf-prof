#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>


static profiler trace;
static struct monitor_ctx {
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct tp_list *tp_list;
    time_t time;
    char time_str[32];
    struct env *env;
} ctx;

static void trace_interval(void);
static int monitor_ctx_init(struct env *env)
{
    if (!env->event)
        return -1;

    tep__ref();

    ctx.tp_list = tp_list_new(env->event);
    if (!ctx.tp_list)
        return -1;

    ctx.time = 0;
    ctx.time_str[0] = '\0';
    if (env->callchain || ctx.tp_list->nr_need_stack) {
        if (!env->flame_graph)
            ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL | CALLCHAIN_USER, stdout);
        else {
            ctx.flame = flame_graph_open(CALLCHAIN_KERNEL | CALLCHAIN_USER, env->flame_graph);
            if (env->interval) {
                trace_interval();
                trace.interval = trace_interval;
            }
        }
        trace.pages *= 2;
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    if (ctx.env->callchain || ctx.tp_list->nr_need_stack) {
        if (!ctx.env->flame_graph)
            callchain_ctx_free(ctx.cc);
        else {
            flame_graph_output(ctx.flame);
            flame_graph_close(ctx.flame);
        }
    }
    tp_list_free(ctx.tp_list);
    tep__unref();
}

static int trace_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD |
                         PERF_SAMPLE_RAW | (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (env->overwrite) {
        attr.write_backward = 1,
        attr.watermark      = 1,
        attr.wakeup_watermark = trace.pages;
    } else
        reduce_wakeup_times(&trace, &attr);

    for (i = 0; i < ctx.tp_list->nr_tp; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];

        attr.config = tp->id;
        if (!env->callchain) {
            if (tp->stack)
                attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
            else
                attr.sample_type &= (~PERF_SAMPLE_CALLCHAIN);
        }
        attr.sample_max_stack = tp->max_stack;

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

static int trace_filter(struct perf_evlist *evlist, struct env *env)
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

static void trace_exit(struct perf_evlist *evlist)
{
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
};
struct sample_type_callchain {
    struct sample_type_header h;
    struct callchain callchain;
};
struct sample_type_raw {
    struct sample_type_header h;
    struct {
        __u32   size;
        __u8    data[0];
    } raw;
};

static void __raw_size(union perf_event *event, void **praw, int *psize, bool callchain)
{
    if (callchain) {
        struct sample_type_callchain *data = (void *)event->sample.array;
        struct {
            __u32   size;
            __u8    data[0];
        } *raw = (void *)data->callchain.ips + data->callchain.nr * sizeof(__u64);
        *praw = raw->data;
        *psize = raw->size;
    } else {
        struct sample_type_raw *raw = (void *)event->sample.array;
        *praw = raw->raw.data;
        *psize = raw->raw.size;
    }
}

static inline void __print_callchain(union perf_event *event, bool callchain)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (callchain) {
        if (!ctx.env->flame_graph)
            print_callchain_common(ctx.cc, &data->callchain, data->h.tid_entry.pid);
        else {
            const char *comm = tep__pid_to_comm((int)data->h.tid_entry.pid);
            flame_graph_add_callchain_at_time(ctx.flame, &data->callchain, data->h.tid_entry.pid,
                                              !strcmp(comm, "<...>") ? NULL : comm,
                                              ctx.time, ctx.time_str);
        }
    }
}

static inline bool have_callchain(union perf_event *event)
{
    if (ctx.env->callchain)
        return true;

    if (ctx.tp_list->nr_need_stack == ctx.tp_list->nr_tp)
        return true;

    if (ctx.tp_list->need_stream_id) {
        struct perf_evsel *evsel;
        struct sample_type_header *data = (void *)event->sample.array;
        evsel = perf_evlist__id_to_evsel(ctx.evlist, data->stream_id, NULL);
        if (!evsel) {
            fprintf(stderr, "Can't find evsel, please set read_format = PERF_FORMAT_ID\n");
            exit(1);
        }
        return !!(perf_evsel__attr(evsel)->sample_type & PERF_SAMPLE_CALLCHAIN);
    }

    return false;
}

static void trace_sample(union perf_event *event, int instance)
{
    struct sample_type_header *data = (void *)event->sample.array;
    void *raw;
    int size;
    bool callchain = have_callchain(event);

    __raw_size(event, &raw, &size, callchain);
    tep__update_comm(NULL, data->tid_entry.tid);
    print_time(stdout);
    tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
    __print_callchain(event, callchain);
}

static void trace_interval(void)
{
    ctx.time = time(NULL);
    strftime(ctx.time_str, sizeof(ctx.time_str), "%Y-%m-%d;%H:%M:%S", localtime(&ctx.time));
    flame_graph_output(ctx.flame);
    flame_graph_reset(ctx.flame);
}

static void trace_help(struct help_ctx *hctx)
{
    int i, j;
    struct env *env = hctx->env;

    printf(PROGRAME " %s ", trace.name);
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".");
            if (!env->callchain)
                printf("[stack/]");
            if (i != hctx->nr_list - 1)
                printf(",");
        }
    }
    printf("\" ");

    if (env->callchain)
        printf("-g ");
    if (env->flame_graph)
        printf("--flame-graph %s ", env->flame_graph);
    common_help(hctx, true, true, true, true, true, true, false);

    if (!env->callchain)
        printf("[-g] ");
    if (!env->flame_graph)
        printf("[--flame-graph .] ");
    common_help(hctx, false, true, true, true, true, true, false);
    printf("\n");
}

static profiler trace = {
    .name = "trace",
    .pages = 2,
    .help = trace_help,
    .init = trace_init,
    .filter = trace_filter,
    .deinit = trace_exit,
    .sample = trace_sample,
};
PROFILER_REGISTER(trace)

