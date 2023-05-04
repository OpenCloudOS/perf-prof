#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/zalloc.h>
#include <linux/strlist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <latency_helpers.h>

static profiler num_dist;

static struct monitor_ctx {
    int nr_ins;
    int nr_points;
    struct tp_list *tp_list;
    struct latency_dist *dist;
    int max_len;
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct heatmap **heatmaps;
    struct env *env;
} ctx;

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
        union {
            __u8    data[0];
            unsigned short common_type;
        } __packed;
    } raw;
};


static int monitor_ctx_init(struct env *env)
{
    int i, stacks = 0;

    if (!env->event)
        return -1;

    tep__ref();

    ctx.nr_ins = monitor_nr_instance();

    ctx.tp_list = tp_list_new(env->event);
    if (!ctx.tp_list) {
        return -1;
    }
    if (ctx.tp_list->nr_num == 0) {
        fprintf(stderr, "Please use the multi-trace profiler\n");
        tp_list_free(ctx.tp_list);
        return -1;
    }
    if (ctx.tp_list->nr_tp != ctx.tp_list->nr_num) {
        fprintf(stderr, "The number of 'num' attr is not equal to the number of event\n");
        tp_list_free(ctx.tp_list);
        return -1;
    }

    ctx.nr_points = ctx.tp_list->nr_tp;

    ctx.dist = latency_dist_new_quantile(env->perins, true, 0);
    if (!ctx.dist)
        return -1;

    for (i = 0; i < ctx.nr_points; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];

        if (strlen(tp->alias?:tp->name) > ctx.max_len)
            ctx.max_len = strlen(tp->alias?:tp->name);
        stacks += tp->stack;

        if (env->verbose)
            printf("name %s id %d filter %s stack %d\n", tp->name, tp->id, tp->filter, tp->stack);
    }

    if (stacks || env->callchain) {
        ctx.cc = callchain_ctx_new(callchain_flags(CALLCHAIN_KERNEL), stdout);
        num_dist.pages *= 2;
    } else
        ctx.cc = NULL;

    if (env->heatmap) {
        char buff[1024];
        struct tp *tp;

        ctx.heatmaps = calloc(ctx.nr_points, sizeof(*ctx.heatmaps));
        if (!ctx.heatmaps)
            return -1;
        for (i = 0; i < ctx.nr_points; i++) {
            tp = &ctx.tp_list->tp[i];
            snprintf(buff, sizeof(buff), "%s-%s", env->heatmap, tp->name);
            ctx.heatmaps[i] = heatmap_open("ns", "ns", buff);
        }
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    tp_list_free(ctx.tp_list);
    latency_dist_free(ctx.dist);
    callchain_ctx_free(ctx.cc);
    if (ctx.env->heatmap) {
        int i;
        for (i = 0; i < ctx.nr_points; i++)
            heatmap_close(ctx.heatmaps[i]);
        free(ctx.heatmaps);
    }
    tep__unref();
}

static int num_dist_init(struct perf_evlist *evlist, struct env *env)
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
        .exclude_callchain_user = exclude_callchain_user(CALLCHAIN_KERNEL),
        .exclude_callchain_kernel = exclude_callchain_kernel(CALLCHAIN_KERNEL),
        .watermark     = 1,
    };
    int i;

    if (monitor_ctx_init(env) < 0)
        return -1;

    attr.wakeup_watermark = (num_dist.pages << 12) / 3;
    for (i = 0; i < ctx.nr_points; i++) {
        struct perf_evsel *evsel;
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

static int num_dist_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, err;

    for (i = 0; i < ctx.nr_points; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];
        if (tp->filter && tp->filter[0]) {
            err = perf_evsel__apply_filter(tp->evsel, tp->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

struct print_info {
    bool started;
};
static void print_num_node(void *opaque, struct latency_node *node)
{
    struct print_info *info = opaque;
    int oncpu = monitor_instance_oncpu();
    struct tp *tp = &ctx.tp_list->tp[node->key];
    double p99 = tdigest_quantile(node->td, 0.99);
    int i;

    if (!info->started) {
        info->started = true;

        print_time(stdout);
        printf("\n");

        if (ctx.env->perins)
            printf(oncpu ? "[CPU] " : "[THREAD] ");
        printf("%-*s", ctx.max_len, "event");
        printf(" %8s %16s %12s %12s %12s %12s\n", "calls", "total", "min", "avg", "p99", "max");

        if (ctx.env->perins)
            printf(oncpu ? "----- " : "-------- ");
        for (i=0; i<ctx.max_len; i++) printf("-");
        printf(" %8s %16s %12s %12s %12s %12s\n",
                        "--------", "----------------", "------------", "------------", "------------", "------------");
    }

    if (ctx.env->perins) {
        if (oncpu)
            printf("[%03d] ", monitor_instance_cpu(node->instance));
        else
            printf("%-8d ", monitor_instance_thread(node->instance));
    }
    printf("%*s", ctx.max_len, tp->alias ?: tp->name);
    printf(" %8lu %16lu %12lu %12lu %12lu %12lu\n",
        node->n, node->sum, node->min, node->sum/node->n, (u64)p99, node->max);
}

static void print_interval(void)
{
    struct print_info info;

    info.started = false;
    latency_dist_print(ctx.dist, print_num_node, &info);
}

static void num_dist_interval(void)
{
    print_interval();
}

static void num_dist_exit(struct perf_evlist *evlist)
{
    num_dist_interval();
    monitor_ctx_exit();
}

static void __raw_size(union perf_event *event, void **praw, int *psize, struct tp *tp)
{
    if (tp->stack || ctx.env->callchain) {
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

static void __print_callchain(union perf_event *event, struct tp *tp)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (tp->stack || ctx.env->callchain) {
        print_callchain_common(ctx.cc, &data->callchain, data->h.tid_entry.pid);
    }
}

static void num_dist_sample(union perf_event *event, int instance)
{
    struct sample_type_header *hdr = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;
    void *raw;
    int size;
    __u64 delta;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, hdr->stream_id, NULL);
    if (!evsel)
        return;

    for (i = 0; i < ctx.nr_points; i++) {
        if (ctx.tp_list->tp[i].evsel == evsel)
            break;
    }
    if (i == ctx.nr_points)
        return ;

    tp = &ctx.tp_list->tp[i];
    __raw_size(event, &raw, &size, tp);

    delta = tp_get_num(tp, raw, size);
    latency_dist_input(ctx.dist, ctx.env->perins?instance:0, i, delta);

    if (ctx.env->heatmap)
        heatmap_write(ctx.heatmaps[i], hdr->time, delta);

    if ((ctx.env->greater_than && delta > ctx.env->greater_than) ||
        ctx.env->verbose >= VERBOSE_EVENT) {
        print_time(stdout);
        tep__update_comm(NULL, hdr->tid_entry.tid);
        tep__print_event(hdr->time/1000, hdr->cpu_entry.cpu, raw, size);
        __print_callchain(event, tp);
    }
}

static void num_dist_help(struct help_ctx *hctx)
{
    int i, j;
    struct env *env = hctx->env;

    printf(PROGRAME " %s ", num_dist.name);
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/num=%s/alias=%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".",
                             tp->num?:".", tp->alias?:".");
            if (!env->callchain)
                printf("[stack/]");
            if (i != hctx->nr_list - 1 ||
                j != hctx->tp_list[i]->nr_tp - 1)
                printf(",");
        }
    }
    printf("\" ");

    if (env->perins)
        printf("--perins ");
    if (env->greater_than)
        printf("--than %lu ", env->greater_than);
    if (env->heatmap)
        printf("--heatmap %s ", env->heatmap);
    common_help(hctx, true, true, true, true, false, false, true);

    if (!env->perins)
        printf("[--perins] ");
    if (!env->greater_than)
        printf("[--than .] ");
    if (!env->heatmap)
        printf("[--heatmap .] ");
    common_help(hctx, false, true, true, true, false, false, true);
    printf("\n");
}


static const char *num_dist_desc[] = PROFILER_DESC("num-dist",
    "[OPTION...] -e EVENT [--perins] [--than ns] [--heatmap file] [-g]",
    "Numerical distribution. Get 'num' data from the event itself.", "",
    "EXAMPLES", "",
    "    "PROGRAME" num-dist -e sched:sched_stat_runtime help",
    "    "PROGRAME" num-dist -e sched:sched_stat_runtime//num=runtime/ -C 0 -i 1000",
    "    "PROGRAME" num-dist -e 'sched:sched_stat_runtime//num=\"runtime/1000\"/alias=runtime(us)/' -C 0 -i 1000");
static const char *num_dist_argv[] = PROFILER_ARGV("num-dist",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_CALLCHAIN_FILTER,
    PROFILER_ARGV_PROFILER, "event", "perins", "than", "heatmap", "call-graph");
static profiler num_dist = {
    .name = "num-dist",
    .desc = num_dist_desc,
    .argv = num_dist_argv,
    .pages = 64,
    .help = num_dist_help,
    .init = num_dist_init,
    .filter = num_dist_filter,
    .deinit = num_dist_exit,
    .interval = num_dist_interval,
    .sample = num_dist_sample,
};
PROFILER_REGISTER(num_dist)


