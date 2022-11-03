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
#include <stack_helpers.h>

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
static struct kmemleak_ctx {
    struct perf_evlist *evlist;
    struct callchain_ctx *cc;
    struct flame_graph *flame;
    struct tp_list *tp_alloc;
    struct tp_list *tp_free;
    struct rblist alloc;
    struct rblist gc_free;
    struct kmemleak_stat stat;
    bool report_leaked_bytes;
    bool user;
    struct env *env;
} ctx;
struct perf_event_backup {
    struct rb_node rbnode;
    __u64    ptr;
    unsigned long bytes_alloc;
    __u64    is_alloc:1;
    __u64    is_free:1;
    union perf_event event;
};
struct perf_event_entry {
    __u64    ptr;
    unsigned long bytes_alloc;
    int      insert;
    int      is_alloc:1;
    int      is_free:1;
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
    const struct perf_event_entry *e = new_entry;
    const union perf_event *event = e->event;
    size_t size = offsetof(struct perf_event_backup, event) + event->header.size;
    struct perf_event_backup *b = malloc(size);
    if (b) {
        b->ptr = e->ptr;
        b->bytes_alloc = e->bytes_alloc;
        b->is_alloc = e->is_alloc;
        b->is_free = e->is_free;
        RB_CLEAR_NODE(&b->rbnode);
        memmove(&b->event, event, event->header.size);
        if (b->is_alloc) {
            ctx.stat.alloc_num ++;
            ctx.stat.alloc_mem += size;
        } else if (b->is_free) {
            ctx.stat.free_num ++;
            ctx.stat.free_mem += size;
        }
        return &b->rbnode;
    } else
        return NULL;
}
static void perf_event_backup_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct perf_event_backup *b = container_of(rb_node, struct perf_event_backup, rbnode);
    size_t size = offsetof(struct perf_event_backup, event) + b->event.header.size;
    if (b->is_alloc) {
        ctx.stat.alloc_num --;
        ctx.stat.alloc_mem -= size;
    } else if (b->is_free) {
        ctx.stat.free_num --;
        ctx.stat.free_mem -= size;
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

static int monitor_ctx_init(struct env *env)
{
    if (!env->tp_alloc ||
        !env->tp_free)
        return -1;

    tep__ref();
    ctx.user = !monitor_instance_oncpu();
    if (env->callchain) {
        int user = ctx.user ? CALLCHAIN_USER : 0;
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL | user, stdout);
        if (env->flame_graph)
            ctx.flame = flame_graph_open(CALLCHAIN_KERNEL | user, env->flame_graph);
        kmemleak.pages *= 2;
    }
    rblist__init(&ctx.alloc);
    ctx.alloc.node_cmp = perf_event_backup_node_cmp;
    ctx.alloc.node_new = perf_event_backup_node_new;
    ctx.alloc.node_delete = perf_event_backup_node_delete;

    rblist__init(&ctx.gc_free);
    ctx.gc_free.node_cmp = perf_event_backup_gc_free_node_cmp;
    ctx.gc_free.node_new = perf_event_backup_node_new;
    ctx.gc_free.node_delete = perf_event_backup_node_delete;

    memset(&ctx.stat, 0, sizeof(ctx.stat));
    ctx.report_leaked_bytes = false;
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
        callchain_ctx_free(ctx.cc);
        if (ctx.env->flame_graph) {
            flame_graph_output(ctx.flame);
            flame_graph_close(ctx.flame);
        }
    }
    tep__unref();
}

static int add_tp_list(struct perf_evlist *evlist, struct tp_list *tp_list, bool callchain)
{
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW |
                         (callchain ? PERF_SAMPLE_CALLCHAIN : 0),
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .exclude_callchain_user = monitor_instance_oncpu(),
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    reduce_wakeup_times(&kmemleak, &attr);

    for (i = 0; i < tp_list->nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];

        attr.config = tp->id;
        if (!callchain) {
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
    return 0;
}

static int kmemleak_init(struct perf_evlist *evlist, struct env *env)
{
    if (monitor_ctx_init(env) < 0)
        return -1;

    ctx.tp_alloc = tp_list_new(env->tp_alloc);
    if (!ctx.tp_alloc)
        return -1;

    ctx.tp_free = tp_list_new(env->tp_free);
    if (!ctx.tp_free)
        return -1;

    if (add_tp_list(evlist, ctx.tp_alloc, env->callchain) < 0)
        return -1;
    if (add_tp_list(evlist, ctx.tp_free, false) < 0)
        return -1;

    if (ctx.tp_alloc->nr_mem_size == ctx.tp_alloc->nr_tp) {
        ctx.report_leaked_bytes = true;
        if (!env->verbose && !env->callchain)
            fprintf(stderr, "Support LEAKED BYTES REPORT, need -g to enable callchain.\n");
        if (!env->verbose && env->callchain && env->flame_graph)
            fprintf(stderr, "Support LEAKED BYTES REPORT, will disable flame graph.\n");
    }

    ctx.evlist = evlist;
    return 0;
}

static int kmemleak_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, err;

    for (i = 0; i < ctx.tp_alloc->nr_tp; i++) {
        struct tp *tp = &ctx.tp_alloc->tp[i];
        if (tp->filter && tp->filter[0]) {
            err = perf_evsel__apply_filter(tp->evsel, tp->filter);
            if (err < 0)
                return err;
        }
    }
    for (i = 0; i < ctx.tp_free->nr_tp; i++) {
        struct tp *tp = &ctx.tp_free->tp[i];
        if (tp->filter && tp->filter[0]) {
            err = perf_evsel__apply_filter(tp->evsel, tp->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void kmemleak_exit(struct perf_evlist *evlist)
{
    monitor_ctx_exit();
    tp_list_free(ctx.tp_alloc);
    tp_list_free(ctx.tp_free);
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

static void __raw_size(union perf_event *event, bool is_alloc, void **praw, int *psize)
{
    if (ctx.env->callchain && is_alloc) {
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

static void __print_callchain(union perf_event *event, bool is_alloc)
{
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (ctx.env->callchain && is_alloc) {
        print_callchain_common(ctx.cc, &data->callchain, data->h.tid_entry.pid);
        if (ctx.env->flame_graph) {
            if (ctx.user) {
                const char *comm = tep__pid_to_comm((int)data->h.tid_entry.tid);
                flame_graph_add_callchain(ctx.flame, &data->callchain, data->h.tid_entry.pid, !strcmp(comm, "<...>") ? NULL : comm);
            } else
                flame_graph_add_callchain(ctx.flame, &data->callchain, 0/*only kernel stack*/, NULL);
        }
    }
}

struct leaked_bytes {
    unsigned long leaked;
    int pid;
};

static void collect_leaked_bytes(struct key_value_paires *kv_pairs, struct perf_event_backup *alloc)
{
    union perf_event *event = &alloc->event;
    struct sample_type_callchain *data = (void *)event->sample.array;

    if (ctx.env->callchain) {
        struct leaked_bytes *leaked = keyvalue_pairs_add_key(kv_pairs, (struct_key *)&data->callchain);
        leaked->leaked += alloc->bytes_alloc;
        if (ctx.user)
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
    struct leaked_bytes *leaked = value;
    printf("Leak of %lu bytes in %u objects allocated from:\n", leaked->leaked, n);
    print_callchain_common(ctx.cc, key, leaked->pid);
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

static void report_kmemleak_stat(bool from_sigusr1)
{
    print_time(stdout);
    printf("\nKMEMLEAK STATS:\n");
    if (from_sigusr1)
        printf("ALLOC LIST num %llu mem %llu\n"
           "FREE LIST  num %llu mem %llu\n"
           "TOTAL alloc %llu free %llu\n\n",
           ctx.stat.alloc_num, ctx.stat.alloc_mem,
           ctx.stat.free_num, ctx.stat.free_mem,
           ctx.stat.total_alloc, ctx.stat.total_free);
    else
        printf("TOTAL alloc %llu free %llu\n\n",
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
    struct key_value_paires *kv_pairs = NULL;

    while (!rblist__empty(&ctx.gc_free)) {
        __gc_free_first();
    }

    report_kmemleak_stat(false);

    if (rblist__empty(&ctx.alloc))
        return;

    rblist__init(&sorted);
    sorted.node_cmp = perf_event_backup_sorted_node_cmp;
    sorted.node_new = perf_event_backup_sorted_node_new;
    sorted.node_delete = ctx.alloc.node_delete;
    ctx.alloc.node_delete = perf_event_backup_node_delete_empty; //empty, not really delete

    /* sort, remove from `ctx.alloc', add to `sorted'. */
    do {
        rbn = rblist__entry(&ctx.alloc, 0);
        alloc = container_of(rbn, struct perf_event_backup, rbnode);
        rblist__remove_node(&ctx.alloc, rbn);
        rblist__add_node(&sorted, alloc);
    } while (!rblist__empty(&ctx.alloc));


    if (ctx.report_leaked_bytes) {
        kv_pairs = keyvalue_pairs_new(sizeof(struct leaked_bytes));
    }
    if (!kv_pairs || ctx.env->verbose) {
        printf("KMEMLEAK REPORT: %u\n", rblist__nr_entries(&sorted));
    }
    do {
        rbn = rblist__entry(&sorted, 0);
        alloc = container_of(rbn, struct perf_event_backup, rbnode);
        event = &alloc->event;
        data = (void *)event->sample.array;

        if (kv_pairs) {
            collect_leaked_bytes(kv_pairs, alloc);
        }
        if (!kv_pairs || ctx.env->verbose) {
            __raw_size(event, true, &raw, &size);
            tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
            __print_callchain(event, true);
        }

        rblist__remove_node(&sorted, rbn);
    } while (!rblist__empty(&sorted));

    if (kv_pairs) {
        printf("LEAKED BYTES REPORT:\n");
        keyvalue_pairs_sorted_foreach(kv_pairs, __leak_cmp, __print_leak, NULL);
        keyvalue_pairs_free(kv_pairs);
    }
}

static bool config_is_alloc(__u64 config, struct tp **p)
{
    int i;

    for (i = 0; i < ctx.tp_alloc->nr_tp; i++) {
        struct tp *tp = &ctx.tp_alloc->tp[i];
        if (tp->id == config) {
            *p = tp;
            return true;
        }
    }
    return false;
}

static bool config_is_free(__u64 config, struct tp **p)
{
    int i;

    for (i = 0; i < ctx.tp_free->nr_tp; i++) {
        struct tp *tp = &ctx.tp_free->tp[i];
        if (tp->id == config) {
            *p = tp;
            return true;
        }
    }
    return false;
}

static void kmemleak_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW
    struct sample_type_header *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct perf_event_entry entry;
    struct tep_record record;
    struct tep_handle *tep;
    struct trace_seq s;
    struct tep_event *e;
    struct rb_node *rbn;
    struct tp *tp = NULL;
    unsigned long long ptr;
    unsigned long long bytes_alloc = 0;
    __u64 config;
    int rc;
    void *raw;
    int size;
    bool is_alloc;

    /* PERF_SAMPLE_STREAM_ID:
     * alloc need stack, free does not need stack, PERF_SAMPLE_STREAM_ID must be set.
     * Because, there is no way to know whether there is a callchain in the perf_event sample.
     *
     * You can use the common_type of traceevent, but you need to get the raw location first.
     * To get the raw location, you must know whether there is a callchain in perf_event.
     */
    evsel = perf_evlist__id_to_evsel(ctx.evlist, data->stream_id, NULL);
    if (!evsel)
        return;

    config = perf_evsel__attr(evsel)->config;
    is_alloc = config_is_alloc(config, &tp);
    __raw_size(event, is_alloc, &raw, &size);

    tep = tep__ref();

    if (ctx.user && !tep_is_pid_registered(tep, data->tid_entry.tid))
        tep__update_comm(NULL, data->tid_entry.tid);

    if (ctx.env->verbose >= VERBOSE_EVENT) {
        tep__update_comm(NULL, data->tid_entry.tid);
        tep__print_event(data->time/1000, data->cpu_entry.cpu, raw, size);
        __print_callchain(event, is_alloc);
    }

    trace_seq_init(&s);

    memset(&record, 0, sizeof(record));
    record.ts = data->time/1000;
    record.cpu = data->cpu_entry.cpu;
    record.size = size;
    record.data = raw;

    e = tep_find_event_by_record(tep, &record);
    if (is_alloc) {
        if (tep_get_field_val(&s, e, tp->mem_ptr, &record, &ptr, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            goto __return;
        }
        if (tp->mem_size &&
            tep_get_field_val(&s, e, tp->mem_size, &record, &bytes_alloc, 0) < 0) {
            bytes_alloc = 1;
        }

        entry.ptr = (__u64)ptr;
        entry.bytes_alloc = (unsigned long)bytes_alloc;
        entry.insert = 1;
        entry.is_alloc = 1;
        entry.is_free = 0;
        entry.event = event;
        rc = rblist__add_node(&ctx.alloc, &entry);
        if (rc == -EEXIST) {
            fprintf(stderr, "ptr %p EEXIST\n", (void*)ptr);
            rbn = rblist__find(&ctx.alloc, &entry);
            rblist__remove_node(&ctx.alloc, rbn);
            rblist__add_node(&ctx.alloc, &entry);
        }
        ctx.stat.total_alloc ++;
    } else if (config_is_free(config, &tp)) {
        if (tep_get_field_val(&s, e, tp->mem_ptr, &record, &ptr, 1) < 0) {
            trace_seq_putc(&s, '\n');
            trace_seq_do_fprintf(&s, stderr);
            goto __return;
        }

        entry.ptr = (__u64)ptr;
        entry.insert = 0;
        entry.is_alloc = 0;
        entry.is_free = 1;
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
    report_kmemleak_stat(true);
}

static void kmemleak_help(struct help_ctx *hctx)
{
    int j;
    struct env *env = hctx->env;
    struct tp_list *tp_alloc, *tp_free;

    if (hctx->nr_list != 2)
        return ;

    tp_alloc = hctx->tp_list[0];
    tp_free = hctx->tp_list[1];
    printf(PROGRAME " %s ", kmemleak.name);
    printf("--alloc \"");
    for (j = 0; j < tp_alloc->nr_tp; j++) {
        struct tp *tp = &tp_alloc->tp[j];
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
    for (j = 0; j < tp_free->nr_tp; j++) {
        struct tp *tp = &tp_free->tp[j];
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
    "Memory leak analysis. Both user and kernel allocators are supported.", "",
    "SYNOPSIS", "",
    "    Memory leak: Allocated but not freed.", "",
    "    --alloc specify memory allocation events. --free specify memory free events.",
    "    'alloc' and 'free' events are associated via 'ptr' ATTR.", "",
    "EXAMPLES", "",
    "    "PROGRAME" kmemleak --alloc kmem:kmalloc//ptr=ptr/size=bytes_alloc/stack/ --free kmem:kfree//ptr=ptr/ --order --order-mem 64M -m 128 -g",
    "    "PROGRAME" kmemleak --alloc kmem:kmalloc//ptr=ptr/size=bytes_alloc/stack/,kmem:kmalloc_node//ptr=ptr/size=bytes_alloc/stack/ \\",
    "                       --free kmem:kfree//ptr=ptr/ --order --order-mem 64M -m 128 -g");
static const char *kmemleak_argv[] = PROFILER_ARGV("kmemleak",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "alloc", "free", "call-graph", "flame-graph");
struct monitor kmemleak = {
    .name = "kmemleak",
    .desc = kmemleak_desc,
    .argv = kmemleak_argv,
    .pages = 4,
    .help = kmemleak_help,
    .init = kmemleak_init,
    .filter = kmemleak_filter,
    .deinit = kmemleak_exit,
    .sigusr1 = kmemleak_sigusr1,
    .comm   = monitor_tep__comm,
    .sample = kmemleak_sample,
};
MONITOR_REGISTER(kmemleak)

