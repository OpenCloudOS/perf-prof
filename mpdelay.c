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

static profiler mpdelay;

static struct monitor_ctx {
    int nr_ins;
    int nr_points;
    struct tp_list *tp_list;
    struct latency_dist *lat_dist;
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
    if (ctx.tp_list->nr_delay == 0) {
        fprintf(stderr, "Please use the multi-trace profiler\n");
        tp_list_free(ctx.tp_list);
        return -1;
    }
    if (ctx.tp_list->nr_tp != ctx.tp_list->nr_delay) {
        fprintf(stderr, "The number of delay attr is not equal to the number of event\n");
        tp_list_free(ctx.tp_list);
        return -1;
    }

    ctx.nr_points = ctx.tp_list->nr_tp;

    ctx.lat_dist = latency_dist_new(env->perins, true, 0);
    if (!ctx.lat_dist)
        return -1;

    for (i = 0; i < ctx.nr_points; i++) {
        struct tp *tp = &ctx.tp_list->tp[i];

        if (strlen(tp->name) > ctx.max_len)
            ctx.max_len = strlen(tp->name);
        stacks += tp->stack;

        if (env->verbose)
            printf("name %s id %d filter %s stack %d\n", tp->name, tp->id, tp->filter, tp->stack);
    }

    if (stacks) {
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
        mpdelay.pages *= 2;
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
    latency_dist_free(ctx.lat_dist);
    callchain_ctx_free(ctx.cc);
    if (ctx.env->heatmap) {
        int i;
        for (i = 0; i < ctx.nr_points; i++)
            heatmap_close(ctx.heatmaps[i]);
        free(ctx.heatmaps);
    }
    tep__unref();
}

static int mpdelay_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = 1,
        .watermark     = 1,
    };
    int i;

    if (monitor_ctx_init(env) < 0)
        return -1;

    attr.wakeup_watermark = (mpdelay.pages << 12) / 3;
    for (i = 0; i < ctx.nr_points; i++) {
        struct perf_evsel *evsel;
        struct tp *tp = &ctx.tp_list->tp[i];

        attr.config = tp->id;
        if (tp->stack)
            attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
        else
            attr.sample_type &= (~PERF_SAMPLE_CALLCHAIN);
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

static int mpdelay_filter(struct perf_evlist *evlist, struct env *env)
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
static void print_latency_node(void *opaque, struct latency_node *node)
{
    struct print_info *info = opaque;
    int oncpu = monitor_instance_oncpu();
    struct tp *tp = &ctx.tp_list->tp[node->key];
    int i;

    if (!info->started) {
        info->started = true;

        print_time(stdout);
        printf("\n");

        if (ctx.env->perins)
            printf(oncpu ? "[CPU] " : "[THREAD] ");
        printf("%-*s", ctx.max_len, "event");
        printf(" %8s %16s %9s %9s %12s\n", "calls", "total(us)", "min(us)", "avg(us)", "max(us)");

        if (ctx.env->perins)
            printf(oncpu ? "----- " : "-------- ");
        for (i=0; i<ctx.max_len; i++) printf("-");
        printf(" %8s %16s %9s %9s %12s\n",
                        "--------", "----------------", "---------", "---------", "------------");
    }

    if (ctx.env->perins) {
        if (oncpu)
            printf("[%03d] ", monitor_instance_cpu(node->instance));
        else
            printf("%-8d ", monitor_instance_thread(node->instance));
    }
    printf("%*s", ctx.max_len, tp->name);
    printf(" %8lu %16.3f %9.3f %9.3f %12.3f\n",
        node->n, node->sum/1000.0, node->min/1000.0, node->sum/node->n/1000.0, node->max/1000.0);
}

static void print_latency_interval(void)
{
    struct print_info info;

    info.started = false;
    latency_dist_print(ctx.lat_dist, print_latency_node, &info);
}

static void mpdelay_interval(void)
{
    print_latency_interval();
}

static void mpdelay_exit(struct perf_evlist *evlist)
{
    mpdelay_interval();
    monitor_ctx_exit();
}

static void __raw_size(union perf_event *event, void **praw, int *psize, struct tp *tp)
{
    if (tp->stack) {
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

    if (tp->stack) {
        print_callchain_common(ctx.cc, &data->callchain, 0/*only kernel stack*/);
    }
}

static void mpdelay_sample(union perf_event *event, int instance)
{
    struct sample_type_header *hdr = (void *)event->sample.array;
    struct tep_record record;
    struct tep_handle *tep;
    struct tep_event *e;
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

    memset(&record, 0, sizeof(record));
    record.ts = hdr->time/1000;
    record.cpu = hdr->cpu_entry.cpu;
    record.size = size;
    record.data = raw;

    tep = tep__ref();
    e = tep_find_event_by_record(tep, &record);
    if (tep_get_field_val(NULL, e, tp->delay, &record, &delta, 0) < 0) {
        tep__unref();
        return;
    }
    tep__unref();

    latency_dist_input(ctx.lat_dist, ctx.env->perins?instance:0, i, delta);

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

static void mpdelay_help(struct help_ctx *hctx)
{
    int i, j;
    struct env *env = hctx->env;

    printf(PROGRAME " %s ", mpdelay.name);
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/delay=%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".",
                             tp->delay?:".");
            if (i != hctx->nr_list - 1)
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


static profiler mpdelay = {
    .name = "mpdelay",
    .pages = 64,
    .help = mpdelay_help,
    .init = mpdelay_init,
    .filter = mpdelay_filter,
    .deinit = mpdelay_exit,
    .interval = mpdelay_interval,
    .sample = mpdelay_sample,
};
PROFILER_REGISTER(mpdelay)


