#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/compiler.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

typedef u64 sector_t;

static profiler blktrace;

enum block_tp {
    BLOCK_GETRQ,
    BLOCK_RQ_INSERT,
    BLOCK_RQ_ISSUE,
    BLOCK_RQ_COMPLETE,
    BLOCK_MAX,
};
struct request_track {
    struct rb_node rbnode;
    enum block_tp tp;
    dev_t dev;
    sector_t sector;
    unsigned int nr_sector;
    u64 time;
};
struct block_iostat {
    const char *name;
    __u64 type;
    __u64 min;
    __u64 max;
    __u64 n;
    __u64 sum;
};

static struct blktrace_ctx {
    struct perf_evlist *evlist;
    struct block_iostat stats[BLOCK_MAX];
    dev_t  dev;
    int max_name_len;
    struct rblist rq_tracks;
    struct env *env;
} ctx;

struct trace_block_getrq {
    unsigned short common_type;//       offset:0;       size:2; signed:0;
    unsigned char common_flags;//       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//       offset:3;       size:1; signed:0;
    int common_pid;//   offset:4;       size:4; signed:1;

    dev_t dev;//        offset:8;       size:4; signed:0;
    sector_t sector;//  offset:16;      size:8; signed:0;
    unsigned int nr_sector;//   offset:24;      size:4; signed:0;
    char rwbs[8];//     offset:28;      size:8; signed:1;
    char comm[16];//    offset:36;      size:16;        signed:1;
};

struct trace_block_rq_insert {
    unsigned short common_type;//       offset:0;       size:2; signed:0;
    unsigned char common_flags;//       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//       offset:3;       size:1; signed:0;
    int common_pid;//   offset:4;       size:4; signed:1;

    dev_t dev;//        offset:8;       size:4; signed:0;
    sector_t sector;//  offset:16;      size:8; signed:0;
    unsigned int nr_sector;//   offset:24;      size:4; signed:0;
    unsigned int bytes;//       offset:28;      size:4; signed:0;
    char rwbs[8];//     offset:32;      size:8; signed:1;
    char comm[16];//    offset:40;      size:16;        signed:1;
    //__data_loc char[] cmd;    offset:56;      size:4; signed:1;
};

struct trace_block_rq_issue {
    unsigned short common_type;//       offset:0;       size:2; signed:0;
    unsigned char common_flags;//       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//       offset:3;       size:1; signed:0;
    int common_pid;//   offset:4;       size:4; signed:1;

    dev_t dev;//        offset:8;       size:4; signed:0;
    sector_t sector;//  offset:16;      size:8; signed:0;
    unsigned int nr_sector;//   offset:24;      size:4; signed:0;
    unsigned int bytes;//       offset:28;      size:4; signed:0;
    char rwbs[8];//     offset:32;      size:8; signed:1;
    char comm[16];//    offset:40;      size:16;        signed:1;
    //__data_loc char[] cmd;    offset:56;      size:4; signed:1;
};

struct trace_block_rq_complete {
    unsigned short common_type;//       offset:0;       size:2; signed:0;
    unsigned char common_flags;//       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//       offset:3;       size:1; signed:0;
    int common_pid;//   offset:4;       size:4; signed:1;

    dev_t dev;//        offset:8;       size:4; signed:0;
    sector_t sector;//  offset:16;      size:8; signed:0;
    unsigned int nr_sector;//   offset:24;      size:4; signed:0;
    int error;//        offset:28;      size:4; signed:1;
    char rwbs[8];//     offset:32;      size:8; signed:1;
    //__data_loc char[] cmd;    offset:40;      size:4; signed:1;
};


// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
struct sample_type_raw {
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
        union {
            __u8    data[0];
            unsigned short common_type;
            struct trace_block_getrq getrq;
            struct trace_block_rq_insert rq_insert;
            struct trace_block_rq_issue rq_issue;
            struct trace_block_rq_complete rq_complete;
        } __packed;
    } raw;
};

#define MINORBITS   20
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

//linux fs/stat.c
static inline dev_t new_decode_dev(u32 dev)
{
    unsigned major = (dev & 0xfff00) >> 8;
    unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    return MKDEV(major, minor);
}

static int request_track_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct request_track *rq = container_of(rbn, struct request_track, rbnode);
    const struct request_track *r = entry;

    if (rq->dev > r->dev)
        return 1;
    else if (r->dev < r->dev)
        return -1;

    if (rq->sector >= r->sector + r->nr_sector)
        return 1;
    else if (rq->sector + rq->nr_sector <= r->sector)
        return -1;
    else
        return 0;
}
static struct rb_node *request_track_node_new(struct rblist *rlist, const void *new_entry)
{
    const struct request_track *r = new_entry;
    struct request_track *rq = malloc(sizeof(*rq));
    if (rq) {
        *rq = *r;
        RB_CLEAR_NODE(&rq->rbnode);
        return &rq->rbnode;
    } else
        return NULL;
}
static void request_track_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct request_track *rq = container_of(rb_node, struct request_track, rbnode);
    free(rq);
}

static void iostat_reset(void)
{
    int i;
    for (i = 0; i < BLOCK_MAX; i ++) {
        ctx.stats[i].min = ~0UL;
        ctx.stats[i].max = 0UL;
        ctx.stats[i].n = 0UL;
        ctx.stats[i].sum = 0UL;
    }
}

static int monitor_ctx_init(struct env *env)
{
    struct stat st;

    if (!env->device)
        return -1;

    if (stat(env->device, &st) < 0)
        return -1;

    ctx.dev = new_decode_dev((u32)st.st_rdev);

    iostat_reset();

    rblist__init(&ctx.rq_tracks);
    ctx.rq_tracks.node_cmp = request_track_node_cmp;
    ctx.rq_tracks.node_new = request_track_node_new;
    ctx.rq_tracks.node_delete = request_track_node_delete;

    tep__ref();
    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    rblist__exit(&ctx.rq_tracks);
    tep__unref();
}

static struct perf_evsel *add_tp_event(struct perf_evlist *evlist, const char *sys, const char *name, int i)
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
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int id;

    id = tep__event_id(sys, name);
    if (id < 0)
        return NULL;

    attr.config = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return NULL;
    }
    perf_evlist__add(evlist, evsel);

    ctx.stats[i].name = name;
    ctx.stats[i].type = id;
    if (strlen(name) > ctx.max_name_len)
        ctx.max_name_len = strlen(name);

    return evsel;
}

static int blktrace_init(struct perf_evlist *evlist, struct env *env)
{
    if (monitor_ctx_init(env) < 0)
        return -1;

    add_tp_event(evlist, "block", "block_getrq", BLOCK_GETRQ);
    add_tp_event(evlist, "block", "block_rq_insert", BLOCK_RQ_INSERT);
    add_tp_event(evlist, "block", "block_rq_issue", BLOCK_RQ_ISSUE);
    add_tp_event(evlist, "block", "block_rq_complete", BLOCK_RQ_COMPLETE);

    ctx.evlist = evlist;
    return 0;
}

static int blktrace_filter(struct perf_evlist *evlist, struct env *env)
{
    char filter[128];
    struct perf_evsel *evsel;
    int err;

    snprintf(filter, sizeof(filter), "dev==%u", (unsigned int)ctx.dev);
    perf_evlist__for_each_evsel(evlist, evsel) {
        err = perf_evsel__apply_filter(evsel, filter);
        if (err < 0)
            return err;
    }
    return 0;
}

static void blktrace_interval(void)
{
    int i;

    print_time(stdout);
    printf("\n");

    printf("%*s => %-*s %8s %16s %9s %9s %12s\n", ctx.max_name_len, "start", ctx.max_name_len, "end",
                    "calls", "total(us)", "min(us)", "avg(us)", "max(us)");

    for (i=0; i<ctx.max_name_len; i++) printf("-");
    printf("    ");
    for (i=0; i<ctx.max_name_len; i++) printf("-");
    printf(" %8s %16s %9s %9s %12s\n",
                    "--------", "----------------", "---------", "---------", "------------");

    for (i = 1; i < BLOCK_MAX; i++) {
        struct block_iostat *iostat1 = &ctx.stats[i-1];
        struct block_iostat *iostat = &ctx.stats[i];
        if (iostat->n)
        printf("%*s => %-*s %8llu %16.3f %9.3f %9.3f %12.3f\n",
                ctx.max_name_len, iostat1->name,
                ctx.max_name_len, iostat->name,
                iostat->n, iostat->sum/1000.0, iostat->min/1000.0,
                iostat->sum/iostat->n/1000.0, iostat->max/1000.0);
    }
    iostat_reset();
}

static void blktrace_exit(struct perf_evlist *evlist)
{
    blktrace_interval();
    monitor_ctx_exit();
}

#define IF(i, trace) \
if (common_type == ctx.stats[i].type) { \
    r.tp = i; \
    r.dev = data->raw.trace.dev; \
    r.sector = data->raw.trace.sector; \
    r.nr_sector = data->raw.trace.nr_sector; \
}

static void blktrace_sample(union perf_event *event, int instance)
{
    struct sample_type_raw *data = (void *)event->sample.array;
    void *raw = data->raw.data;
    int size = data->raw.size;
    unsigned short common_type = data->raw.common_type;
    struct request_track *rq, *prev_rq, r;
    struct block_iostat *iostat;
    struct rb_node *rbn = NULL;
    u64 delta;
    const char *print = NULL;

    r.time = data->time;
    IF(BLOCK_GETRQ, getrq)
    else IF(BLOCK_RQ_INSERT, rq_insert)
    else IF(BLOCK_RQ_ISSUE, rq_issue)
    else IF(BLOCK_RQ_COMPLETE, rq_complete)
    else return;

    // sector == -1: flush req
    if (r.sector == (sector_t)-1)
        return;

    iostat = &ctx.stats[r.tp];

    rbn = rblist__find(&ctx.rq_tracks, &r);
    if (rbn) {
        prev_rq = container_of(rbn, struct request_track, rbnode);

        if (r.tp == BLOCK_GETRQ)
            print = "EXIST";
        else if (prev_rq->tp != r.tp - 1) {
            if (r.tp == BLOCK_RQ_ISSUE)
                print = "BYPASS_INSERT";
            else
                print = "LOST";
        }

        delta = r.time - prev_rq->time;
        if (delta < iostat->min)
            iostat->min = delta;
        if (delta > iostat->max)
            iostat->max = delta;
        iostat->n ++;
        iostat->sum += delta;

        if (ctx.env->greater_than &&
            delta > ctx.env->greater_than * 1000000) {
            print = "GREATER_THAN";
        }

        if (r.tp != BLOCK_RQ_COMPLETE) {
            rq = prev_rq;
            rq->tp = r.tp;
            rq->dev = r.dev;
            rq->sector = r.sector;
            rq->nr_sector = r.nr_sector;
            rq->time = r.time;
        } else
            rblist__remove_node(&ctx.rq_tracks, rbn);
    }
    else if (r.tp != BLOCK_RQ_COMPLETE)
        rblist__add_node(&ctx.rq_tracks, &r);

    if (ctx.env->verbose &&
        (print || ctx.env->verbose >= 2)) {
        tep__update_comm(NULL, data->tid_entry.tid);
        print_time(stdout);
        if (print)
            printf("%s", print);
        tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
    }
}

static profiler blktrace = {
    .name = "blktrace",
    .pages = 8,
    .init = blktrace_init,
    .filter = blktrace_filter,
    .deinit = blktrace_exit,
    .interval = blktrace_interval,
    .sample = blktrace_sample,
};
PROFILER_REGISTER_NAME(order(&blktrace), blktrace)

