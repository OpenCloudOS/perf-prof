#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <monitor.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>

#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2


struct monitor kmemleak;
struct kmemleak_stat {
    __u64 alloc_num;
    __u64 free_num;
    __u64 alloc_mem;
    __u64 free_mem;
    __u64 total_alloc;
    __u64 total_free;
};
struct monitor_ctx {
    struct perf_evlist *evlist;
    struct ksyms *ksyms;
    __u64 tp_alloc;
    __u64 tp_free;
    struct rblist alloc;
    struct rblist gc_free;
    struct kmemleak_stat stat;
    struct env *env;
} ctx;
struct perf_event_backup {
    struct rb_node rbnode;
    __u64    ptr;
    __u64    config;
    union perf_event event;
};
struct perf_event_entry {
    __u64    ptr;
    int      insert;
    int      config;
    union perf_event *event;
};

// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
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
};

static int node_cmp(struct rb_node *rbn, const void *entry)
{
    struct perf_event_backup *b = container_of(rbn, struct perf_event_backup, rbnode);
    const struct perf_event_entry *e = entry;

    if (b->ptr > e->ptr)
        return 1;
    else if (b->ptr < e->ptr)
        return -1;
    else {
        struct sample_type_header *b1 = (void *)b->event.sample.array;
        struct sample_type_header *e1 = (void *)e->event->sample.array;
        if (b1->time > e1->time)
            return 1;
        else if (e->insert && b1->time < e1->time)
            return -1;
        else
            return 0;
    }
}

static struct rb_node *node_new(struct rblist *rlist, const void *new_entry)
{
    const struct perf_event_entry *e = new_entry;
    const union perf_event *event = e->event;
    size_t size = offsetof(struct perf_event_backup, event) + event->header.size;
    struct perf_event_backup *b = malloc(size);
    if (b) {
        b->ptr = e->ptr;
        b->config = e->config;
        RB_CLEAR_NODE(&b->rbnode);
        memmove(&b->event, event, event->header.size);
        if (b->config == ctx.tp_alloc) {
            ctx.stat.alloc_num ++;
            ctx.stat.alloc_mem += size;
        } else if (b->config == ctx.tp_free) {
            ctx.stat.free_num ++;
            ctx.stat.free_mem += size;
        }
        return &b->rbnode;
    } else
        return NULL;
}
static void node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct perf_event_backup *b = container_of(rb_node, struct perf_event_backup, rbnode);
    size_t size = offsetof(struct perf_event_backup, event) + b->event.header.size;
    if (b->config == ctx.tp_alloc) {
        ctx.stat.alloc_num --;
        ctx.stat.alloc_mem -= size;
    } else if (b->config == ctx.tp_free) {
        ctx.stat.free_num --;
        ctx.stat.free_mem -= size;
    }
    free(b);
}
static void node_delete_empty(struct rblist *rblist, struct rb_node *rb_node)
{
}

static int gc_free_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct perf_event_backup *b = container_of(rbn, struct perf_event_backup, rbnode);
    const struct perf_event_entry *e = entry;
    struct sample_type_header *b1 = (void *)b->event.sample.array;
    struct sample_type_header *e1 = (void *)e->event->sample.array;

    if (b1->time > e1->time)
        return 1;
    else if (b1->time < e1->time)
        return -1;
    else {
        if (b->ptr > e->ptr)
            return 1;
        else if (b->ptr < e->ptr)
            return -1;
        else
            return 0;
    }
}
static int sorted_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct perf_event_backup *b = container_of(rbn, struct perf_event_backup, rbnode);
    const struct perf_event_backup *e = entry;
    struct sample_type_header *b1 = (void *)b->event.sample.array;
    struct sample_type_header *e1 = (void *)e->event.sample.array;

    if (b1->time > e1->time)
        return 1;
    else if (b1->time < e1->time)
        return -1;
    else {
        if (b->ptr > e->ptr)
            return 1;
        else if (b->ptr < e->ptr)
            return -1;
        else
            return 0;
    }
}
static struct rb_node *sorted_node_new(struct rblist *rlist, const void *new_entry)
{
    struct perf_event_backup *b = (void *)new_entry;
    RB_CLEAR_NODE(&b->rbnode);
    return &b->rbnode;
}

static int monitor_ctx_init(struct env *env)
{
    tep__ref();
    if (env->callchain) {
        ctx.ksyms = ksyms__load();
        kmemleak.pages *= 2;
    }
    rblist__init(&ctx.alloc);
    ctx.alloc.node_cmp = node_cmp;
    ctx.alloc.node_new = node_new;
    ctx.alloc.node_delete = node_delete;

    rblist__init(&ctx.gc_free);
    ctx.gc_free.node_cmp = gc_free_node_cmp;
    ctx.gc_free.node_new = node_new;
    ctx.gc_free.node_delete = node_delete;

    memset(&ctx.stat, 0, sizeof(ctx.stat));
    ctx.env = env;
    return 0;
}

static void report_kmemleak(void);
static void monitor_ctx_exit(void)
{
    report_kmemleak();
    rblist__exit(&ctx.alloc);
    rblist__exit(&ctx.gc_free);
    if (ctx.env->callchain) {
        ksyms__free(ctx.ksyms);
    }
    tep__unref();
}

static int kmemleak_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = 1,
        .wakeup_events = 1, //1个事件
    };
    struct perf_evsel *evsel;
    int id;
    char *sys;
    char *name;

    if (monitor_ctx_init(env) < 0)
        return -1;

    sys = strtok(env->tp_alloc, ":");
    name = strtok(NULL, ":");
    id = tep__event_id(sys, name);
    if (id < 0)
        return -1;
    attr.config = ctx.tp_alloc = id;
    attr.sample_type |= (env->callchain ? PERF_SAMPLE_CALLCHAIN : 0);
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    sys = strtok(env->tp_free, ":");
    name = strtok(NULL, ":");
    id = tep__event_id(sys, name);
    if (id < 0)
        return -1;
    attr.config = ctx.tp_free = id;
    attr.sample_type &= ~PERF_SAMPLE_CALLCHAIN;
    evsel = perf_evsel__new(&attr);
    if (!evsel) {
        return -1;
    }
    perf_evlist__add(evlist, evsel);

    //perf_evlist__set_leader(evlist);
    ctx.evlist = evlist;
    return 0;
}

static void kmemleak_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
}

struct sample_type_callchain {
    struct sample_type_header h;
    struct {
        __u64   nr;
        __u64   ips[0];
    } callchain;
};
struct sample_type_raw {
    struct sample_type_header h;
    struct {
        __u32   size;
        __u8    data[0];
    } raw;
};

static void __raw_size(union perf_event *event, __u64 config, void **praw, int *psize)
{
    if (ctx.env->callchain && config == ctx.tp_alloc) {
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

static void __print_callchain(union perf_event *event, __u64 config)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (ctx.env->callchain && ctx.ksyms && config == ctx.tp_alloc) {
        __u64 i;
        for (i = 0; i < data->callchain.nr; i++) {
            __u64 ip = data->callchain.ips[i];
            const struct ksym *ksym = ksyms__map_addr(ctx.ksyms, ip);
            printf("    %016llx %s+0x%llx\n", ip, ksym ? ksym->name : "Unknown", ip - ksym->addr);
        }
    }
}

static int gc_need_free(union perf_event *event)
{
    struct sample_type_header *data = (void *)event->sample.array, *data0;
    struct rb_node *rbn;
    struct perf_event_backup *free;

    if (rblist__nr_entries(&ctx.gc_free) > 1) {
        rbn = rblist__entry(&ctx.gc_free, 0);
        free = container_of(rbn, struct perf_event_backup, rbnode);
        data0 = (void *)free->event.sample.array;
        if (data->time > data0->time &&
            data->time - data0->time > NSEC_PER_SEC) {
            return 1;
        }
    }
    return 0;
}

static void __gc_free_first(void)
{
    struct rb_node *rbn, *rbn_alloc;
    struct perf_event_backup *free;
    struct perf_event_entry entry;

    rbn = rblist__entry(&ctx.gc_free, 0);
    free = container_of(rbn, struct perf_event_backup, rbnode);

    entry.ptr = free->ptr;
    entry.insert = 0;
    entry.event = &free->event;
    rbn_alloc = rblist__find(&ctx.alloc, &entry);
    if (rbn_alloc)
        rblist__remove_node(&ctx.alloc, rbn_alloc);
    rblist__remove_node(&ctx.gc_free, rbn);
}

static void gc_free(union perf_event *event)
{
    do {
        __gc_free_first();
    } while (gc_need_free(event));
}

static void report_kmemleak_stat(void)
{
    print_time(stdout);
    printf("\nKMEMLEAK STATS:\n");
    printf("ALLOC LIST num %llu mem %llu\n"
           "FREE LIST  num %llu mem %llu\n"
           "TOTAL alloc %llu free %llu\n\n",
           ctx.stat.alloc_num, ctx.stat.alloc_mem,
           ctx.stat.free_num, ctx.stat.free_mem,
           ctx.stat.total_alloc, ctx.stat.total_free);
}

static void report_kmemleak(void)
{
    struct rb_node *rbn;
    struct perf_event_backup *alloc;
    union perf_event *event;
    struct sample_type_header *data;
    void *raw;
    int size;
    struct rblist sorted;

    while (!rblist__empty(&ctx.gc_free)) {
        __gc_free_first();
    }

    if (rblist__empty(&ctx.alloc))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = sorted_node_cmp;
    sorted.node_new = sorted_node_new;
    sorted.node_delete = ctx.alloc.node_delete;
    ctx.alloc.node_delete = node_delete_empty; //empty, not really delete

    /* sort, remove from `ctx.alloc', add to `sorted'. */
    do {
        rbn = rblist__entry(&ctx.alloc, 0);
        alloc = container_of(rbn, struct perf_event_backup, rbnode);
        rblist__remove_node(&ctx.alloc, rbn);
        rblist__add_node(&sorted, alloc);
    } while (!rblist__empty(&ctx.alloc));

    report_kmemleak_stat();
    print_time(stdout);
    printf("\nKMEMLEAK REPORT: %u\n", rblist__nr_entries(&sorted));
    do {
        rbn = rblist__entry(&sorted, 0);
        alloc = container_of(rbn, struct perf_event_backup, rbnode);
        event = &alloc->event;
        data = (void *)event->sample.array;

        __raw_size(event, ctx.tp_alloc, &raw, &size);
        tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
        __print_callchain(event, ctx.tp_alloc);

        rblist__remove_node(&sorted, rbn);
    } while (!rblist__empty(&sorted));
}

static void kmemleak_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_header *data = (void *)event->sample.array;//, *data0;
    struct perf_evsel *evsel;
    struct perf_event_entry entry;
    struct tep_record record;
    struct tep_handle *tep;
    struct trace_seq s;
    struct tep_event *e;
    struct rb_node *rbn;
    //struct perf_event_backup *free;
    unsigned long long ptr;
    __u64 config;
    int rc;
    void *raw;
    int size;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, data->stream_id, NULL);
    if (!evsel)
        return;

    config = perf_evsel__attr(evsel)->config;
    __raw_size(event, config, &raw, &size);

    if (ctx.env->verbose) {
        tep__update_comm(NULL, data->tid_entry.tid);
        tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
        __print_callchain(event, config);
    }

    trace_seq_init(&s);

    memset(&record, 0, sizeof(record));
    record.ts = data->time/1000;
    record.cpu = data->cpu_entry.cpu;
    record.size = size;
    record.data = raw;

    tep = tep__ref();

    e = tep_find_event_by_record(tep, &record);
    if (config == ctx.tp_alloc) {
        if (tep_get_field_val(&s, e, "ptr", &record, &ptr, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            goto __return;
        }

        entry.ptr = (__u64)ptr;
        entry.insert = 1;
        entry.config = (int)config;
        entry.event = event;
        rc = rblist__add_node(&ctx.alloc, &entry);
        if (rc == -EEXIST) {
            fprintf(stderr, "ptr %p EEXIST\n", (void*)ptr);
            rbn = rblist__find(&ctx.alloc, &entry);
            rblist__remove_node(&ctx.alloc, rbn);
            rblist__add_node(&ctx.alloc, &entry);
        }
        ctx.stat.total_alloc ++;
    } else if (config == ctx.tp_free) {
        if (tep_get_field_val(&s, e, "ptr", &record, &ptr, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            goto __return;
        }

        entry.ptr = (__u64)ptr;
        entry.insert = 0;
        entry.config = (int)config;
        entry.event = event;
        rbn = rblist__find(&ctx.alloc, &entry);
        if (rbn == NULL) {
            entry.insert = 1;
            rc = rblist__add_node(&ctx.gc_free, &entry);
            if (gc_need_free(event)) {
                gc_free(event);
            }
        } else
            rblist__remove_node(&ctx.alloc, rbn);
        ctx.stat.total_free ++;
    }
__return:
    trace_seq_destroy(&s);
    tep__unref();
}

static void kmemleak_sigusr1(int signum)
{
    report_kmemleak_stat();
}

struct monitor kmemleak = {
    .name = "kmemleak",
    .pages = 4,
    .init = kmemleak_init,
    .deinit = kmemleak_exit,
    .sigusr1 = kmemleak_sigusr1,
    .comm   = monitor_tep__comm,
    .sample = kmemleak_sample,
};
MONITOR_REGISTER(kmemleak)

