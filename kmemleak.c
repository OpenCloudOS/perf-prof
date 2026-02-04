#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>

#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2

struct kmemleak_stat {
    __u64 alloc_num;
    __u64 free_num;
    __u64 alloc_mem;
    __u64 free_mem;
    __u64 total_alloc;
    __u64 total_free;
};
struct kmemleak_ctx {
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct tp_list *tp_alloc;
    struct tp_list *tp_free;
    struct rblist alloc;
    struct rblist gc_free;
    struct kmemleak_stat stat;
    struct list_head lost_list;
    bool report_leaked_bytes;
    bool user;
};
struct perf_event_backup {
    struct rb_node rbnode;
    __u64    ptr;
    unsigned long bytes_alloc;
    __u64    is_alloc:1;
    __u64    is_free:1;
    __u64    callchain:1;
    union perf_event event;
};
struct perf_event_entry {
    __u64    ptr;
    unsigned long bytes_alloc;
    int      insert;
    int      is_alloc:1;
    int      is_free:1;
    int      callchain:1;
    union perf_event *event;
};

struct kmemleak_lost_node {
    struct list_head lost_link;
    int ins;
    bool reclaim;
    u64 start_time;
    u64 end_time;
    u64 lost_id; // struct perf_record_lost::id
    u64 lost;
};


// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
struct sample_type_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    __u64   id;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
};

static int perf_event_backup_node_cmp(struct rb_node *rbn, const void *entry)
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

static struct rb_node *perf_event_backup_node_new(struct rblist *rlist, const void *new_entry)
{
    struct kmemleak_ctx *ctx;
    const struct perf_event_entry *e = new_entry;
    const union perf_event *event = e->event;
    size_t size = offsetof(struct perf_event_backup, event) + event->header.size;
    struct perf_event_backup *b = malloc(size);
    if (b) {
        b->ptr = e->ptr;
        b->bytes_alloc = e->bytes_alloc;
        b->is_alloc = e->is_alloc;
        b->is_free = e->is_free;
        b->callchain = e->callchain;
        RB_CLEAR_NODE(&b->rbnode);
        memmove(&b->event, event, event->header.size);
        if (b->is_alloc) {
            ctx = container_of(rlist, struct kmemleak_ctx, alloc);
            ctx->stat.alloc_num ++;
            ctx->stat.alloc_mem += size;
        } else if (b->is_free) {
            ctx = container_of(rlist, struct kmemleak_ctx, gc_free);
            ctx->stat.free_num ++;
            ctx->stat.free_mem += size;
        }
        return &b->rbnode;
    } else
        return NULL;
}
static void perf_event_backup_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct kmemleak_ctx *ctx;
    struct perf_event_backup *b = container_of(rb_node, struct perf_event_backup, rbnode);
    size_t size = offsetof(struct perf_event_backup, event) + b->event.header.size;
    if (b->is_alloc) {
        ctx = container_of(rblist, struct kmemleak_ctx, alloc);
        ctx->stat.alloc_num --;
        ctx->stat.alloc_mem -= size;
    } else if (b->is_free) {
        ctx = container_of(rblist, struct kmemleak_ctx, gc_free);
        ctx->stat.free_num --;
        ctx->stat.free_mem -= size;
    }
    free(b);
}
static void perf_event_backup_node_delete_empty(struct rblist *rblist, struct rb_node *rb_node)
{
}

static int perf_event_backup_gc_free_node_cmp(struct rb_node *rbn, const void *entry)
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
static int perf_event_backup_sorted_node_cmp(struct rb_node *rbn, const void *entry)
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
static struct rb_node *perf_event_backup_sorted_node_new(struct rblist *rlist, const void *new_entry)
{
    struct perf_event_backup *b = (void *)new_entry;
    RB_CLEAR_NODE(&b->rbnode);
    return &b->rbnode;
}
static void perf_event_backup_sorted_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct perf_event_backup *b = container_of(rb_node, struct perf_event_backup, rbnode);
    free(b);
}

static int monitor_ctx_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct kmemleak_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    if (!env->tp_alloc ||
        !env->tp_free) {
        free(ctx);
        return -1;
    }
    INIT_LIST_HEAD(&ctx->lost_list);

    tep__ref();
    ctx->user = !prof_dev_ins_oncpu(dev);

    rblist__init(&ctx->alloc);
    ctx->alloc.node_cmp = perf_event_backup_node_cmp;
    ctx->alloc.node_new = perf_event_backup_node_new;
    ctx->alloc.node_delete = perf_event_backup_node_delete;

    rblist__init(&ctx->gc_free);
    ctx->gc_free.node_cmp = perf_event_backup_gc_free_node_cmp;
    ctx->gc_free.node_new = perf_event_backup_node_new;
    ctx->gc_free.node_delete = perf_event_backup_node_delete;

    memset(&ctx->stat, 0, sizeof(ctx->stat));
    ctx->report_leaked_bytes = false;

    return 0;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct kmemleak_ctx *ctx = dev->private;
    struct kmemleak_lost_node *lost, *next;

    list_for_each_entry_safe(lost, next, &ctx->lost_list, lost_link)
        free(lost);

    rblist__exit(&ctx->alloc);
    rblist__exit(&ctx->gc_free);
    callchain_ctx_free(ctx->cc);
    if (dev->env->flame_graph) {
        flame_graph_output(ctx->flame);
        flame_graph_close(ctx->flame);
    }
    tp_list_free(ctx->tp_alloc);
    tp_list_free(ctx->tp_free);
    tep__unref();
    free(ctx);
}

static int add_tp_list(struct prof_dev *dev, struct tp_list *tp_list, bool callchain)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW |
                         (callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = prof_dev_ins_oncpu(dev),
        .watermark     = 1,
    };
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;

    prof_dev_env2attr(dev, &attr);

    for_each_real_tp(tp_list, tp, i) {

        if (!tp->mem_ptr) {
            fprintf(stderr, "%s:%s//ptr=?/ ptr attribute is not set\n", tp->sys, tp->name);
            return -1;
        }

        if (!callchain) {
            if (tp->stack)
                attr.sample_type |= PERF_SAMPLE_CALLCHAIN;
            else
                attr.sample_type &= (~PERF_SAMPLE_CALLCHAIN);
        }

        evsel = tp_evsel_new(tp, &attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);
    }
    return 0;
}

static int kmemleak_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct kmemleak_ctx *ctx;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    ctx->tp_alloc = tp_list_new(dev, env->tp_alloc);
    if (!ctx->tp_alloc)
        goto failed;

    ctx->tp_free = tp_list_new(dev, env->tp_free);
    if (!ctx->tp_free)
        goto failed;

    if (!env->callchain)
        env->callchain = (ctx->tp_alloc->nr_need_stack == ctx->tp_alloc->nr_real_tp);

    if (env->callchain || ctx->tp_alloc->nr_need_stack || ctx->tp_free->nr_need_stack) {
        int user = ctx->user ? CALLCHAIN_USER : 0;
        ctx->cc = callchain_ctx_new(CALLCHAIN_KERNEL | user, stdout);
        if (env->flame_graph)
            ctx->flame = flame_graph_open(CALLCHAIN_KERNEL | user, env->flame_graph);
        dev->pages *= 2;
    }

    if (add_tp_list(dev, ctx->tp_alloc, env->callchain) < 0)
        goto failed;
    if (add_tp_list(dev, ctx->tp_free, false) < 0)
        goto failed;

    if (ctx->tp_alloc->nr_mem_size == ctx->tp_alloc->nr_real_tp) {
        ctx->report_leaked_bytes = true;
        if (!env->verbose && !env->callchain)
            fprintf(stderr, "Support LEAKED BYTES REPORT, need -g to enable callchain.\n");
        if (!env->verbose && env->callchain && env->flame_graph)
            fprintf(stderr, "Support LEAKED BYTES REPORT, will disable flame graph.\n");
    }

    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static int kmemleak_filter(struct prof_dev *dev)
{
    struct kmemleak_ctx *ctx = dev->private;
    int err;

    if ((err = tp_list_apply_filter(dev, ctx->tp_alloc)) < 0)
        return err;

    if ((err = tp_list_apply_filter(dev, ctx->tp_free)) < 0)
        return err;

    return 0;
}

static void report_kmemleak(struct prof_dev *dev);
static void kmemleak_exit(struct prof_dev *dev)
{
    report_kmemleak(dev);
    monitor_ctx_exit(dev);
}

static inline void lost_reclaim(struct prof_dev *dev)
{
    struct kmemleak_ctx *ctx = dev->private;

    if (!list_empty(&ctx->lost_list)) {
        struct kmemleak_lost_node *lost = list_first_entry(&ctx->lost_list, struct kmemleak_lost_node, lost_link);
        struct perf_record_lost lost_event = {
            .header = {PERF_RECORD_LOST, 0, sizeof(struct perf_record_lost)},
            .id = lost->lost_id,
            .lost = lost->lost,
        };
        if (!rblist__empty(&ctx->alloc))
            dev->lost_print_time = 0; // force print lost now
        print_lost_fn(dev, (union perf_event *)&lost_event, lost->ins);
    }

    if (!rblist__empty(&ctx->alloc)) {
        print_time(stdout);
        printf("Report memory leaks in advance due to lost\n");

        report_kmemleak(dev);
    } else
        rblist__exit(&ctx->gc_free);
}

static void kmemleak_lost(struct prof_dev *dev, union perf_event *event, int ins, u64 lost_start, u64 lost_end)
{
    struct kmemleak_ctx *ctx = dev->private;
    struct kmemleak_lost_node *pos;
    struct kmemleak_lost_node *lost;

    if (!using_order(dev)) {
        print_lost_fn(dev, event, ins);
        lost_reclaim(dev);
        return;
    }

    // When order is enabled, event loss will be sensed in advance, but it
    // needs to be processed later.
    lost = malloc(sizeof(*lost));
    if (lost) {
        lost->ins = ins;
        lost->reclaim = false;
        lost->start_time = lost_start;
        lost->end_time = lost_end;
        lost->lost_id = event->lost.id;
        lost->lost = event->lost.lost;

        list_for_each_entry(pos, &ctx->lost_list, lost_link) {
            if (pos->start_time > lost_start)
                break;
        }
        list_add_tail(&lost->lost_link, &pos->lost_link);
    }
}


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

static void __raw_size(union perf_event *event, bool callchain, void **praw, int *psize)
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

static void __print_callchain(struct prof_dev *dev, union perf_event *event, bool callchain)
{
    struct kmemleak_ctx *ctx = dev->private;
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (callchain) {
        print_callchain_common(ctx->cc, &data->callchain, data->h.tid_entry.pid);
        if (dev->env->flame_graph) {
            if (ctx->user) {
                const char *comm = tep__pid_to_comm((int)data->h.tid_entry.tid);
                flame_graph_add_callchain(ctx->flame, &data->callchain, data->h.tid_entry.pid, !strcmp(comm, "<...>") ? NULL : comm);
            } else
                flame_graph_add_callchain(ctx->flame, &data->callchain, 0/*only kernel stack*/, NULL);
        }
    }
}

struct leaked_bytes {
    unsigned long leaked;
    int pid;
};

static void collect_leaked_bytes(struct kmemleak_ctx *ctx, struct key_value_paires *kv_pairs, struct perf_event_backup *alloc)
{
    union perf_event *event = &alloc->event;
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (alloc->callchain) {
        struct leaked_bytes *leaked = keyvalue_pairs_add_key(kv_pairs, (struct_key *)&data->callchain);
        leaked->leaked += alloc->bytes_alloc;
        if (ctx->user)
            leaked->pid = data->h.tid_entry.pid;
        else
            leaked->pid = 0;
    }
}

static int __leak_cmp(void **value1, void **value2)
{
    struct leaked_bytes *b1 = *(struct leaked_bytes **)value1;
    struct leaked_bytes *b2 = *(struct leaked_bytes **)value2;

    if (b1->leaked < b2->leaked)
        return 1;
    else if (b1->leaked > b2->leaked)
        return -1;
    else
        return b1->pid - b2->pid;
}

static void __print_leak(void *opaque, struct_key *key, void *value, unsigned int n)
{
    struct kmemleak_ctx *ctx = opaque;
    struct leaked_bytes *leaked = value;
    printf("Leak of %lu bytes in %u objects allocated from:\n", leaked->leaked, n);
    print_callchain_common(ctx->cc, key, leaked->pid);
}

static int gc_need_free(struct kmemleak_ctx *ctx, union perf_event *event)
{
    struct sample_type_header *data = (void *)event->sample.array, *data0;
    struct rb_node *rbn;
    struct perf_event_backup *free;

    if (rblist__nr_entries(&ctx->gc_free) > 1) {
        rbn = rblist__entry(&ctx->gc_free, 0);
        free = container_of(rbn, struct perf_event_backup, rbnode);
        data0 = (void *)free->event.sample.array;
        if (data->time > data0->time &&
            data->time - data0->time > NSEC_PER_SEC) {
            return 1;
        }
    }
    return 0;
}

static void __gc_free_first(struct kmemleak_ctx *ctx)
{
    struct rb_node *rbn, *rbn_alloc;
    struct perf_event_backup *free;
    struct perf_event_entry entry;

    rbn = rblist__entry(&ctx->gc_free, 0);
    free = container_of(rbn, struct perf_event_backup, rbnode);

    entry.ptr = free->ptr;
    entry.insert = 0;
    entry.event = &free->event;
    rbn_alloc = rblist__find(&ctx->alloc, &entry);
    if (rbn_alloc)
        rblist__remove_node(&ctx->alloc, rbn_alloc);
    rblist__remove_node(&ctx->gc_free, rbn);
}

static void gc_free(struct kmemleak_ctx *ctx, union perf_event *event)
{
    do {
        __gc_free_first(ctx);
    } while (gc_need_free(ctx, event));
}

static void report_kmemleak_stat(struct kmemleak_ctx *ctx, bool from_sigusr1)
{
    if (ctx->stat.total_alloc == 0)
        return;
    print_time(stdout);
    printf("\nKMEMLEAK STATS:\n");
    if (from_sigusr1)
        printf("ALLOC LIST num %llu mem %llu\n"
           "FREE LIST  num %llu mem %llu\n"
           "TOTAL alloc %llu free %llu\n\n",
           ctx->stat.alloc_num, ctx->stat.alloc_mem,
           ctx->stat.free_num, ctx->stat.free_mem,
           ctx->stat.total_alloc, ctx->stat.total_free);
    else
        printf("TOTAL alloc %llu free %llu\n\n",
           ctx->stat.total_alloc, ctx->stat.total_free);
}

static void report_kmemleak(struct prof_dev *dev)
{
    struct kmemleak_ctx *ctx = dev->private;
    struct rb_node *rbn;
    struct perf_event_backup *alloc;
    union perf_event *event;
    struct sample_type_header *data;
    void *raw;
    int size;
    struct rblist sorted;
    struct key_value_paires *kv_pairs = NULL;
    bool selected = true;
    u64 time_ns = 0UL;

    while (!rblist__empty(&ctx->gc_free)) {
        __gc_free_first(ctx);
    }

    report_kmemleak_stat(ctx, false);

    if (rblist__empty(&ctx->alloc))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = perf_event_backup_sorted_node_cmp;
    sorted.node_new = perf_event_backup_sorted_node_new;
    sorted.node_delete = perf_event_backup_sorted_node_delete;
    ctx->alloc.node_delete = perf_event_backup_node_delete_empty; //empty, not really delete

    /* sort, remove from `ctx->alloc', add to `sorted'. */
    do {
        rbn = rblist__entry(&ctx->alloc, 0);
        alloc = container_of(rbn, struct perf_event_backup, rbnode);
        rblist__remove_node(&ctx->alloc, rbn);
        rblist__add_node(&sorted, alloc);
    } while (!rblist__empty(&ctx->alloc));

    if (dev->env->greater_than) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        time_ns = tv.tv_sec * NSEC_PER_SEC + tv.tv_usec * 1000;
    }

    if (ctx->report_leaked_bytes) {
        kv_pairs = keyvalue_pairs_new(sizeof(struct leaked_bytes));
    }
    if (!kv_pairs || dev->env->verbose) {
        printf("KMEMLEAK REPORT: %u\n", rblist__nr_entries(&sorted));
    }
    do {
        rbn = rblist__entry(&sorted, 0);
        alloc = container_of(rbn, struct perf_event_backup, rbnode);
        event = &alloc->event;
        data = (void *)event->sample.array;
        if (time_ns) {
            u64 realtime_ns = evclock_to_realtime_ns(dev, (evclock_t)(u64)data->time);
            selected = realtime_ns ? (time_ns - realtime_ns > dev->env->greater_than) : true;
        }

        if (kv_pairs && selected) {
            collect_leaked_bytes(ctx, kv_pairs, alloc);
        }
        if ((!kv_pairs && selected) || dev->env->verbose) {
            __raw_size(event, alloc->callchain, &raw, &size);
            tep__print_event(data->time, data->cpu_entry.cpu, raw, size);
            __print_callchain(dev, event, alloc->callchain);
        }

        rblist__remove_node(&sorted, rbn);
    } while (!rblist__empty(&sorted));

    if (kv_pairs) {
        printf("LEAKED BYTES REPORT:\n");
        keyvalue_pairs_sorted_foreach(kv_pairs, __leak_cmp, __print_leak, ctx);
        keyvalue_pairs_free(kv_pairs);
    }
    ctx->alloc.node_delete = perf_event_backup_node_delete;
}

static inline bool config_is_alloc(struct kmemleak_ctx *ctx, struct tp *p)
{
    struct tp *tp;
    int i;
    for_each_real_tp(ctx->tp_alloc, tp, i)
        if (tp == p)
            return true;
    return false;
}

static inline int kmemleak_event_lost(struct prof_dev *dev, union perf_event *event)
{
    struct kmemleak_ctx *ctx = dev->private;
    struct sample_type_header *data = (void *)event->sample.array;
    struct kmemleak_lost_node *lost, *next;

    if (likely(list_empty(&ctx->lost_list)))
        return 0;

    list_for_each_entry_safe(lost, next, &ctx->lost_list, lost_link) {
        // Events before lost->start_time are processed normally.
        if (data->time <= lost->start_time)
            return 0;

        if (!lost->reclaim) {
            lost_reclaim(dev);
            lost->reclaim = true;
        }

        // Within the lost range, new events are also unsafe.
        if (data->time < lost->end_time) {
            return -1;
        } else {
            // Re-process subsequent events normally.
            list_del(&lost->lost_link);
            free(lost);
        }
    }
    return 0;
}

static long kmemleak_ftrace_filter(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct kmemleak_ctx *ctx = dev->private;
    struct sample_type_header *data = (void *)event->sample.array;
    struct perf_evsel *evsel = perf_evlist__id_to_evsel(dev->evlist, data->id, NULL);
    struct tp *tp = evsel ? perf_evsel_tp(evsel) : NULL;
    bool callchain = tp ? tp->stack : !!(perf_evsel__attr(evsel)->sample_type & PERF_SAMPLE_CALLCHAIN);
    void *raw;
    int size;
    long err;
    struct expr_global *glo;

    __raw_size(event, callchain, &raw, &size);
    glo = GLOBAL(data->cpu_entry.cpu, data->tid_entry.pid, raw, size);
    if (tp) {
        if (!tp->ftrace_filter)
            return 1;
        return tp_prog_run(tp, tp->ftrace_filter, glo);
    }
    err = tp_list_ftrace_filter(dev, ctx->tp_alloc, glo);
    if (err < 0)
        err = tp_list_ftrace_filter(dev, ctx->tp_free, glo);
    return err;
}

static void kmemleak_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct kmemleak_ctx *ctx = dev->private;
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_header *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct perf_event_entry entry;
    struct rb_node *rbn;
    struct tp *tp = NULL;
    void *ptr = NULL;
    unsigned long long bytes_alloc = 0;
    int rc;
    void *raw;
    int size;
    bool is_alloc;
    bool callchain;
    struct expr_global *glo;

    /* PERF_SAMPLE_ID:
     * alloc need stack, free does not need stack, PERF_SAMPLE_ID must be set.
     * Because, there is no way to know whether there is a callchain in the perf_event sample.
     *
     * You can use the common_type of traceevent, but you need to get the raw location first.
     * To get the raw location, you must know whether there is a callchain in perf_event.
     */
    evsel = perf_evlist__id_to_evsel(dev->evlist, data->id, NULL);
    tp = tp_from_evsel(evsel, ctx->tp_alloc);
    if (!tp) {
        tp = tp_from_evsel(evsel, ctx->tp_free);
        if (!tp)
            return;
    }

    is_alloc = config_is_alloc(ctx, tp);

    callchain = (is_alloc && dev->env->callchain) || tp->stack;
    __raw_size(event, callchain, &raw, &size);

    if (dev->env->verbose >= VERBOSE_EVENT) {
        tep__update_comm(NULL, data->tid_entry.tid);
        tep__print_event(data->time, data->cpu_entry.cpu, raw, size);
        __print_callchain(dev, event, callchain);
    }

    if (kmemleak_event_lost(dev, event) < 0)
        return;

    if (ctx->user) {
        tep__update_comm(NULL, data->tid_entry.tid);
    }

    glo = GLOBAL(data->cpu_entry.cpu, data->tid_entry.pid, raw, size);
    if (is_alloc) {
        ptr = tp_get_mem_ptr(tp, glo);
        if (tp->mem_size_prog)
            bytes_alloc = tp_get_mem_size(tp, glo);

        entry.ptr = (__u64)ptr;
        entry.bytes_alloc = (unsigned long)bytes_alloc;
        entry.insert = 1;
        entry.is_alloc = 1;
        entry.is_free = 0;
        entry.callchain = callchain;
        entry.event = event;
        rc = rblist__add_node(&ctx->alloc, &entry);
        if (rc == -EEXIST) {
            fprintf(stderr, "ptr %p EEXIST\n", (void*)ptr);
            rbn = rblist__find(&ctx->alloc, &entry);
            rblist__remove_node(&ctx->alloc, rbn);
            rblist__add_node(&ctx->alloc, &entry);
        }
        ctx->stat.total_alloc ++;
    } else {
        ptr = tp_get_mem_ptr(tp, glo);

        entry.ptr = (__u64)ptr;
        entry.insert = 0;
        entry.is_alloc = 0;
        entry.is_free = 1;
        entry.callchain = callchain;
        entry.event = event;
        rbn = rblist__find(&ctx->alloc, &entry);
        if (rbn == NULL) {
            entry.insert = 1;
            rc = rblist__add_node(&ctx->gc_free, &entry);
            if (gc_need_free(ctx, event)) {
                gc_free(ctx, event);
            }
        } else
            rblist__remove_node(&ctx->alloc, rbn);
        ctx->stat.total_free ++;
    }
}

static void kmemleak_sigusr(struct prof_dev *dev, int signum)
{
    if (signum == SIGUSR1)
        report_kmemleak_stat(dev->private, true);
}

static void kmemleak_help(struct help_ctx *hctx)
{
    int j;
    struct env *env = hctx->env;
    struct tp_list *tp_alloc, *tp_free;
    struct tp *tp;

    if (hctx->nr_list != 2)
        return ;

    tp_alloc = hctx->tp_list[0];
    tp_free = hctx->tp_list[1];
    printf(PROGRAME " kmemleak ");
    printf("--alloc \"");
    for_each_real_tp(tp_alloc, tp, j) {
        printf("%s:%s/%s/ptr=%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".",
                         tp->mem_ptr?:".");
        if (tp->mem_size)
            printf("size=%s/", tp->mem_size);
        else
            printf("[size=./]");
        if (!env->callchain)
            printf("[stack/]");
        if (j != tp_alloc->nr_tp - 1)
            printf(",");
    }
    printf("\" ");

    printf("--free \"");
    for_each_real_tp(tp_free, tp, j) {
        printf("%s:%s/%s/ptr=%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".",
                         tp->mem_ptr?:".");
        if (j != tp_free->nr_tp - 1)
            printf(",");
    }
    printf("\" ");

    if (env->callchain)
        printf("-g ");
    if (env->flame_graph)
        printf("--flame-graph %s ", env->flame_graph);
    common_help(hctx, true, true, true, false, true, true, true);

    if (!env->callchain)
        printf("[-g] ");
    if (!env->flame_graph)
        printf("[--flame-graph .] ");
    common_help(hctx, false, true, true, false, true, true, true);
    printf("\n");
}


static const char *kmemleak_desc[] = PROFILER_DESC("kmemleak",
    "[OPTION...] --alloc EVENT[...] --free EVENT[...] [-g [--flame-graph file]]",
    "Generic memory leak analyzer for user/kernel allocators.",
    "",
    "SYNOPSIS",
    "    Memory leak: Allocated memory that is never freed.",
    "",
    "    This is a generic memory leak analyzer supporting arbitrary user-space and kernel-space",
    "    allocators. --alloc specifies memory allocation events, --free specifies memory free",
    "    events. Allocation and free events are matched via `ptr` ATTR. After extended collection,",
    "    unmatched allocation events are considered leaks.",
    "",
    "    Supports call stack aggregation, leak event reports, leaked bytes statistics, and flame",
    "    graph generation.",
    "",
    "EXAMPLES",
    "    "PROGRAME" kmemleak --alloc kmem:kmalloc//ptr=ptr/size=bytes_alloc/stack/ --free kmem:kfree//ptr=ptr/ --order -m 128 -g",
    "    "PROGRAME" kmemleak --alloc kmem:kmalloc//ptr=ptr/size=bytes_alloc/stack/,kmem:kmalloc_node//ptr=ptr/size=bytes_alloc/stack/ \\",
    "                       --free kmem:kfree//ptr=ptr/ --order -m 128 -g");
static const char *kmemleak_argv[] = PROFILER_ARGV("kmemleak",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "alloc", "free", "call-graph", "flame-graph",
    "than\nMemory allocation exceeded the specified time.");
struct monitor kmemleak = {
    .name = "kmemleak",
    .desc = kmemleak_desc,
    .argv = kmemleak_argv,
    .pages = 4,
    .help = kmemleak_help,
    .init = kmemleak_init,
    .filter = kmemleak_filter,
    .deinit = kmemleak_exit,
    .sigusr = kmemleak_sigusr,
    .lost = kmemleak_lost,
    .ftrace_filter = kmemleak_ftrace_filter,
    .sample = kmemleak_sample,
};
MONITOR_REGISTER(kmemleak)

