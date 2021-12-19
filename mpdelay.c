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

struct monitor mpdelay;

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
struct tp_list {
    int id;
    char *name;
};
struct monitor_ctx {
    int nr_ins;
    int nr_points;
    struct tp_list *tp_list;
    struct mpdelay_stat *perins_stat;
    struct mpdelay_stat *tolins_stat;
    int max_len;
    int ins_size;
    struct env *env;
} ctx;
static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    ctx.nr_ins = monitor_nr_instance();
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    tep__unref();
}

static void perins_stat_reset(void)
{
    struct mpdelay_stat *mp_stat;
    struct delay_stat *stat;
    int i, j;

    for (i = 0; i < ctx.nr_ins+1; i++) {
        mp_stat = (void *)ctx.perins_stat + i * ctx.ins_size;
        mp_stat->time = 0;
        mp_stat->common_type = 0;
        for (j = 0; j < ctx.nr_points-1; j++) {
            stat = &mp_stat->stat[j];
            stat->min = ~0UL;
            stat->max = 0UL;
            stat->n = 0UL;
            stat->sum = 0UL;
        }
    }
}

static int mpdelay_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
        .wakeup_watermark = (mpdelay.pages << 12) / 3,
    };
    char *s = env->event;
    char *sep;
    int i;

    if (!s)
        return -1;

    if (monitor_ctx_init(env) < 0)
        return -1;

    ctx.nr_points = 0;
    while ((sep = strchr(s, ',')) != NULL) {
        ctx.nr_points ++;
        s = sep + 1;
    }
    if (*s)
        ctx.nr_points ++;
    if (ctx.nr_points <= 1)
        return -1;

    ctx.tp_list = zalloc(ctx.nr_points * sizeof(struct tp_list));
    if (!ctx.tp_list)
        return -1;

    ctx.ins_size = offsetof(struct mpdelay_stat, stat[ctx.nr_points-1]);
    ctx.perins_stat = zalloc((ctx.nr_ins+1) * ctx.ins_size);
    if (!ctx.perins_stat)
        return -1;
    ctx.tolins_stat = (void *)ctx.perins_stat + ctx.nr_ins * ctx.ins_size;
    perins_stat_reset();

    s = env->event;
    i = 0;
    while ((sep = strchr(s, ',')) != NULL) {
        ctx.tp_list[i++].name = s;
        *sep = '\0';
        s = sep + 1;
    }
    if (*s)
        ctx.tp_list[i++].name = s;

    for (i = 0; i < ctx.nr_points; i++) {
        struct perf_evsel *evsel;
        struct tp_list *tp = &ctx.tp_list[i];
        char *sys = strtok(tp->name, ":");
        char *name = strtok(NULL, ":");
        int id = tep__event_id(sys, name);
        if (id < 0)
            return -1;

        attr.config = id;
        evsel = perf_evsel__new(&attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);

        tp->id = id;
        tp->name[strlen(sys)] = ':';
        if (strlen(tp->name) > ctx.max_len)
            ctx.max_len = strlen(tp->name);
    }
    return 0;
}

static void __print_instance(int i)
{
    struct mpdelay_stat *mp_stat;
    struct delay_stat *stat;
    struct tp_list *tp1, *tp2;
    int j;

    mp_stat = (void *)ctx.perins_stat + i * ctx.ins_size;
    for (j = 0; j < ctx.nr_points-1; j++) {
        tp1 = &ctx.tp_list[j];
        tp2 = &ctx.tp_list[j+1];
        stat = &mp_stat->stat[j];

        if (stat->n) {
            if (ctx.env->perins)
                printf("[%03d] ", monitor_instance_cpu(i));
            printf("%*s => %-*s %8llu %16.3f %9.3f %9.3f %12.3f\n", ctx.max_len, tp1->name, ctx.max_len, tp2->name,
                stat->n, stat->sum/1000.0, stat->min/1000.0, stat->sum/stat->n/1000.0, stat->max/1000.0);
        }
    }
}

static void mpdelay_interval(void)
{
    int i;

    if (ctx.env->perins)
        printf("[CPU] ");
    printf("%*s => %-*s %8s %16s %9s %9s %12s\n", ctx.max_len, "FROM", ctx.max_len, "TO",
                    "calls", "total(us)", "min(us)", "avg(us)", "max(us)");
    if (ctx.env->perins)
        printf("----- ");
    for (i=0; i<ctx.max_len*2+4; i++) printf("-");
    printf(" %8s %16s %9s %9s %12s\n",
                    "--------", "----------------", "---------", "---------", "------------");

    if (ctx.env->perins)
        for (i = 0; i < ctx.nr_ins; i++) {
            __print_instance(i);
        }
    else
        __print_instance(ctx.nr_ins);

    perins_stat_reset();
}

static void mpdelay_exit(struct perf_evlist *evlist)
{
    mpdelay_interval();
    zfree(&ctx.tp_list);
    zfree(&ctx.perins_stat);
    monitor_ctx_exit();
}

static void mpdelay_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_data {
        __u64   time;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        struct {
            __u32   size;
            union {
                __u8    data[0];
                unsigned short common_type;
            } __packed;
        } raw;
    } *raw = (void *)event->sample.array;
    unsigned short common_type = raw->raw.common_type;
    struct mpdelay_stat *mp_stat;
    struct delay_stat *stat;
    int i;

    if (ctx.env->verbose) {
        print_time(stdout);
        tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);
    }

    for (i = 0; i < ctx.nr_points; i++) {
        if (ctx.tp_list[i].id == common_type)
            break;
    }
    if (i == ctx.nr_points)
        return ;

    mp_stat = (void *)ctx.perins_stat + instance * ctx.ins_size;
    if (i == 0 ||
        mp_stat->time == 0) {
        goto __return;
    }

    stat = &mp_stat->stat[i-1];
    if (mp_stat->common_type == ctx.tp_list[i-1].id &&
        raw->time > mp_stat->time) {
        __u64 delta = raw->time - mp_stat->time;
        if (delta < stat->min)
            stat->min = delta;
        if (delta > stat->max)
            stat->max = delta;
        stat->n ++;
        stat->sum += delta;

        stat = &ctx.tolins_stat->stat[i-1];
        if (delta < stat->min)
            stat->min = delta;
        if (delta > stat->max)
            stat->max = delta;
        stat->n ++;
        stat->sum += delta;
    }
__return:
    mp_stat->time = raw->time;
    mp_stat->common_type = common_type;
}

struct monitor mpdelay = {
    .name = "mpdelay",
    .pages = 64,
    .init = mpdelay_init,
    .deinit = mpdelay_exit,
    .interval = mpdelay_interval,
    .sample = mpdelay_sample,
};
MONITOR_REGISTER(mpdelay)


