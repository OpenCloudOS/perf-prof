#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <linux/zalloc.h>
#include <linux/strlist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

static profiler mpdelay;

struct delay_stat {
    __u64 min;
    __u64 max;
    __u64 n;
    __u64 sum;
};
struct mpdelay_stat {
    u64  time;
    unsigned short common_type;
    int i;
    struct delay_stat stat[0];
};
struct monitor_ctx {
    int nr_ins;
    int nr_points;
    int nr_delay;
    struct tp_list *tp_list;
    struct mpdelay_stat *perins_stat;
    struct mpdelay_stat *tolins_stat;
    int max_len;
    int ins_size;
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


static void perins_stat_reset(void)
{
    struct mpdelay_stat *mp_stat;
    struct delay_stat *stat;
    int i, j;

    for (i = 0; i < ctx.nr_ins+1; i++) {
        mp_stat = (void *)ctx.perins_stat + i * ctx.ins_size;
        mp_stat->time = 0;
        mp_stat->common_type = 0;
        for (j = 0; j < ctx.nr_points; j++) {
            stat = &mp_stat->stat[j];
            stat->min = ~0UL;
            stat->max = 0UL;
            stat->n = 0UL;
            stat->sum = 0UL;
        }
    }
}

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
    if (ctx.tp_list->nr_delay == 0 && ctx.tp_list->nr_tp <= 1) {
        fprintf(stderr, "event <= 1\n");
        tp_list_free(ctx.tp_list);
        return -1;
    }
    if (ctx.tp_list->nr_delay && ctx.tp_list->nr_tp != ctx.tp_list->nr_delay) {
        fprintf(stderr, "The number of delay attr is not equal to the number of event\n");
        tp_list_free(ctx.tp_list);
        return -1;
    }

    ctx.nr_points = ctx.tp_list->nr_tp;
    ctx.nr_delay = ctx.tp_list->nr_delay;

    ctx.ins_size = offsetof(struct mpdelay_stat, stat[ctx.nr_points]);
    ctx.perins_stat = zalloc((ctx.nr_ins+1) * ctx.ins_size);
    if (!ctx.perins_stat)
        return -1;
    ctx.tolins_stat = (void *)ctx.perins_stat + ctx.nr_ins * ctx.ins_size;
    perins_stat_reset();

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
        struct tp *tp1, *tp2;
        int bit = ctx.nr_delay ? 0 : 1;

        ctx.heatmaps = calloc(ctx.nr_points, sizeof(*ctx.heatmaps));
        if (!ctx.heatmaps)
            return -1;
        for (i = bit; i < ctx.nr_points; i++) {
            tp1 = &ctx.tp_list->tp[i-bit];
            tp2 = &ctx.tp_list->tp[i];
            if (!ctx.nr_delay)
                snprintf(buff, sizeof(buff), "%s-%s-%s", env->heatmap, tp1->name, tp2->name);
            else
                snprintf(buff, sizeof(buff), "%s-%s", env->heatmap, tp1->name);
            ctx.heatmaps[i] = heatmap_open("ns", "ns", buff);
        }
    }
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    tp_list_free(ctx.tp_list);
    zfree(&ctx.perins_stat);
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

static void __print_instance(int i, int oncpu)
{
    struct mpdelay_stat *mp_stat;
    struct delay_stat *stat;
    struct tp *tp1, *tp2;
    int j;
    int bit = ctx.nr_delay ? 0 : 1;

    mp_stat = (void *)ctx.perins_stat + i * ctx.ins_size;
    for (j = bit; j < ctx.nr_points; j++) {
        tp1 = &ctx.tp_list->tp[j-bit];
        tp2 = &ctx.tp_list->tp[j];
        stat = &mp_stat->stat[j];

        if (stat->n) {
            if (ctx.env->perins) {
                if (oncpu)
                    printf("[%03d] ", monitor_instance_cpu(i));
                else
                    printf("%-8d ", monitor_instance_thread(i));
            }
            printf("%*s", ctx.max_len, tp1->name);
            if (!ctx.nr_delay)
                printf(" => %-*s", ctx.max_len, tp2->name);
            printf(" %8llu %16.3f %9.3f %9.3f %12.3f\n",
                stat->n, stat->sum/1000.0, stat->min/1000.0, stat->sum/stat->n/1000.0, stat->max/1000.0);
        }
    }
}

static void mpdelay_interval(void)
{
    int oncpu = monitor_instance_oncpu();
    int i;

    print_time(stdout);
    printf("\n");

    if (ctx.env->perins)
        printf(oncpu ? "[CPU] " : "[THREAD] ");
    if (ctx.nr_delay)
        printf("%-*s", ctx.max_len, "event");
    else
        printf("%*s => %-*s", ctx.max_len, "start", ctx.max_len, "end");
    printf(" %8s %16s %9s %9s %12s\n", "calls", "total(us)", "min(us)", "avg(us)", "max(us)");

    if (ctx.env->perins)
        printf(oncpu ? "----- " : "-------- ");
    for (i=0; i<ctx.max_len; i++) printf("-");
    if (!ctx.nr_delay) {
        printf("    ");
        for (i=0; i<ctx.max_len; i++) printf("-");
    }
    printf(" %8s %16s %9s %9s %12s\n",
                    "--------", "----------------", "---------", "---------", "------------");

    if (ctx.env->perins)
        for (i = 0; i < ctx.nr_ins; i++) {
            __print_instance(i, oncpu);
        }
    else
        __print_instance(ctx.nr_ins, oncpu);

    perins_stat_reset();
}

static void mpdelay_exit(struct perf_evlist *evlist)
{
    mpdelay_interval();
    monitor_ctx_exit();
}

static void __raw_size(union perf_event *event, void **praw, int *psize, unsigned short *pcommon_type, int i)
{
    struct tp *tp = &ctx.tp_list->tp[i];
    if (tp->stack) {
        struct sample_type_callchain *data = (void *)event->sample.array;
        struct {
            __u32   size;
            union {
                __u8    data[0];
                unsigned short common_type;
            } __packed;
        } *raw = (void *)data->callchain.ips + data->callchain.nr * sizeof(__u64);
        *praw = raw->data;
        *psize = raw->size;
        *pcommon_type = raw->common_type;
    } else {
        struct sample_type_raw *raw = (void *)event->sample.array;
        *praw = raw->raw.data;
        *psize = raw->raw.size;
        *pcommon_type = raw->raw.common_type;
    }
}

static void __print_callchain(union perf_event *event, int t)
{
    struct sample_type_callchain *data = (void *)event->sample.array;
    struct tp *tp = &ctx.tp_list->tp[t];

    if (tp->stack) {
        print_callchain_common(ctx.cc, &data->callchain, 0/*only kernel stack*/);
    }
}

static void mpdelay_sample(union perf_event *event, int instance)
{
    struct sample_type_header *hdr = (void *)event->sample.array;
    unsigned short common_type;
    struct mpdelay_stat *mp_stat;
    struct delay_stat *stat;
    struct tp *tp_prev;
    struct perf_evsel *evsel;
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

    __raw_size(event, &raw, &size, &common_type, i);

    if (ctx.env->verbose) {
        print_time(stdout);
        tep__update_comm(NULL, hdr->tid_entry.tid);
        tep__print_event(hdr->time/1000, hdr->cpu_entry.cpu, raw, size);
    }

    mp_stat = (void *)ctx.perins_stat + instance * ctx.ins_size;
    stat = &mp_stat->stat[i];

    if (ctx.nr_delay) {
        struct tep_record record;
        struct tep_handle *tep = tep__ref();
        struct trace_seq s;
        struct tep_event *e;
        trace_seq_init(&s);
        memset(&record, 0, sizeof(record));
        record.ts = hdr->time/1000;
        record.cpu = hdr->cpu_entry.cpu;
        record.size = size;
        record.data = raw;

        e = tep_find_event_by_record(tep, &record);
        if (tep_get_field_val(&s, e, ctx.tp_list->tp[i].delay, &record, &delta, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            tep__unref();
            goto __return;
        }
        tep__unref();
    } else {
        if (i == 0 ||
            mp_stat->time == 0) {
            goto __return;
        }

        tp_prev = &ctx.tp_list->tp[i-1];
        if (mp_stat->common_type == tp_prev->id &&
            hdr->time > mp_stat->time) {
            delta = hdr->time - mp_stat->time;
        } else {
            if (mp_stat->common_type != tp_prev->id ||
                hdr->time <= mp_stat->time) {
                //TODO
                goto __return;
            }
        }
    }


    if (delta < stat->min)
        stat->min = delta;
    if (delta > stat->max)
        stat->max = delta;
    stat->n ++;
    stat->sum += delta;

    stat = &ctx.tolins_stat->stat[i];
    if (delta < stat->min)
        stat->min = delta;
    if (delta > stat->max)
        stat->max = delta;
    stat->n ++;
    stat->sum += delta;

    if (ctx.env->heatmap)
        heatmap_write(ctx.heatmaps[i], hdr->time, delta);

    if (ctx.env->greater_than &&
        delta > ctx.env->greater_than) {
        print_time(stdout);
        if (!ctx.nr_delay)
            printf("%.6f ", mp_stat->time/1000/1000000.0);
        tep__update_comm(NULL, hdr->tid_entry.tid);
        tep__print_event(hdr->time/1000, hdr->cpu_entry.cpu, raw, size);
        __print_callchain(event, i);
    }

__return:
    mp_stat->time = hdr->time;
    mp_stat->common_type = common_type;
}

static profiler mpdelay = {
    .name = "mpdelay",
    .pages = 64,
    .init = mpdelay_init,
    .filter = mpdelay_filter,
    .deinit = mpdelay_exit,
    .interval = mpdelay_interval,
    .sample = mpdelay_sample,
};
PROFILER_REGISTER(mpdelay)


