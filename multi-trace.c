#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/string.h>
#include <linux/zalloc.h>
#include <linux/strlist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <two-event.h>

static profiler multi_trace;

struct perf_event_backup {
    struct rb_node rbnode;
    u64    key;
    struct tp *tp;
    union perf_event *event;
};

static struct multi_trace_ctx {
    int nr_ins;
    int nr_list;
    struct tp_list **tp_list;
    struct two_event_impl *impl;
    struct two_event_class *class;
    struct rblist backup;
    struct callchain_ctx *cc;
    struct perf_evlist *evlist;
    struct env *env;
} ctx;

static int perf_event_backup_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct perf_event_backup *b = container_of(rbn, struct perf_event_backup, rbnode);
    const struct perf_event_backup *e = entry;

    if (b->key > e->key)
        return 1;
    else if (b->key < e->key)
        return -1;
    else
        return 0;
}

static struct rb_node *perf_event_backup_node_new(struct rblist *rlist, const void *new_entry)
{
    const struct perf_event_backup *e = new_entry;
    const union perf_event *event = e->event;
    union perf_event *new_event = memdup(event, event->header.size);
    struct perf_event_backup *b = malloc(sizeof(*b));
    if (b && new_event) {
        b->key = e->key;
        b->tp = e->tp;
        b->event = new_event;
        RB_CLEAR_NODE(&b->rbnode);
        return &b->rbnode;
    } else
        return NULL;
}

static void perf_event_backup_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct perf_event_backup *b = container_of(rb_node, struct perf_event_backup, rbnode);
    free(b->event);
    free(b);
}

static int monitor_ctx_init(struct env *env)
{
    int i, j, stacks = 0;
    struct two_event_options options = {
        .keytype = monitor_instance_oncpu() ? K_CPU : K_THREAD,
        .perins = env->perins,
    };

    if (env->nr_events < 2)
        return -1;

    tep__ref();

    ctx.nr_ins = monitor_nr_instance();
    ctx.nr_list = env->nr_events;
    ctx.tp_list = calloc(ctx.nr_list, sizeof(*ctx.tp_list));
    if (!ctx.tp_list)
        return -1;

    for (i = 0; i < ctx.nr_list; i++) {
        ctx.tp_list[i] = tp_list_new(env->events[i]);
        if (!ctx.tp_list[i]) {
            return -1;
        }
        stacks += ctx.tp_list[i]->nr_need_stack;
        for (j = 0; j < ctx.tp_list[i]->nr_tp; j++) {
            struct tp *tp = &ctx.tp_list[i]->tp[j];
            if (env->verbose)
                printf("name %s id %d filter %s stack %d\n", tp->name, tp->id, tp->filter, tp->stack);
        }
    }

    if (stacks) {
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
        multi_trace.pages *= 2;
    } else
        ctx.cc = NULL;

    ctx.impl = impl_get(TWO_EVENT_DELAY_ANALYSIS);
    ctx.class = ctx.impl->class_new(ctx.impl, &options);

    rblist__init(&ctx.backup);
    ctx.backup.node_cmp = perf_event_backup_node_cmp;
    ctx.backup.node_new = perf_event_backup_node_new;
    ctx.backup.node_delete = perf_event_backup_node_delete;

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    int i;

    rblist__exit(&ctx.backup);

    ctx.impl->class_delete(ctx.class);
    callchain_ctx_free(ctx.cc);

    for (i = 0; i < ctx.nr_list; i++)
        tp_list_free(ctx.tp_list[i]);
    free(ctx.tp_list);

    tep__unref();
}

static int multi_trace_init(struct perf_evlist *evlist, struct env *env)
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
    int i, j, k;

    if (monitor_ctx_init(env) < 0)
        return -1;

    attr.wakeup_watermark = (multi_trace.pages << 12) / 3;

    for (i = 0; i < ctx.nr_list; i++) {
        for (j = 0; j < ctx.tp_list[i]->nr_tp; j++) {
            struct perf_evsel *evsel;
            struct tp *tp = &ctx.tp_list[i]->tp[j];

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
    }

    for (k = 0; k < ctx.nr_list - 1; k++) {
        for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
            struct tp *tp1 = &ctx.tp_list[k]->tp[i];
            for (j = 0; j < ctx.tp_list[k+1]->nr_tp; j++) {
                struct tp *tp2 = &ctx.tp_list[k+1]->tp[j];
                ctx.impl->object_new(ctx.class, tp1, tp2);
            }
        }
    }
    ctx.evlist = evlist;

    return 0;
}

static int multi_trace_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, j, err;

    for (i = 0; i < ctx.nr_list; i++) {
        for (j = 0; j < ctx.tp_list[i]->nr_tp; j++) {
            struct tp *tp = &ctx.tp_list[i]->tp[j];
            if (tp->filter && tp->filter[0]) {
                err = perf_evsel__apply_filter(tp->evsel, tp->filter);
                if (err < 0)
                    return err;
            }
        }
    }
    return 0;
}

static void multi_trace_interval(void)
{
    int i, j, k;
    int header = 0;

    for (k = 0; k < ctx.nr_list - 1; k++) {
        for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
            struct tp *tp1 = &ctx.tp_list[k]->tp[i];
            for (j = 0; j < ctx.tp_list[k+1]->nr_tp; j++) {
                struct tp *tp2 = &ctx.tp_list[k+1]->tp[j];
                struct two_event *two = ctx.impl->object_find(ctx.class, tp1, tp2);
                if (!header) {
                    header = ctx.class->print_header(two);
                }
                ctx.class->print(two);
            }
        }
    }
    rblist__exit(&ctx.backup);
}

static void multi_trace_exit(struct perf_evlist *evlist)
{
    multi_trace_interval();
    monitor_ctx_exit();
}

static void __raw_size(union perf_event *event, void **praw, int *psize, struct tp *tp)
{
    if (tp->stack) {
        struct multi_trace_type_callchain *data = (void *)event->sample.array;
        struct {
            __u32   size;
            __u8    data[0];
        } *raw = (void *)data->callchain.ips + data->callchain.nr * sizeof(__u64);
        *praw = raw->data;
        *psize = raw->size;
    } else {
        struct multi_trace_type_raw *raw = (void *)event->sample.array;
        *praw = raw->raw.data;
        *psize = raw->raw.size;
    }
}

void multi_trace_print(union perf_event *event, struct tp *tp)
{
    struct multi_trace_type_callchain *data = (void *)event->sample.array;
    void *raw;
    int size;

    __raw_size(event, &raw, &size, tp);

    print_time(stdout);
    tep__update_comm(NULL, data->h.tid_entry.tid);
    tep__print_event(data->h.time/1000, data->h.cpu_entry.cpu, raw, size);

    if (tp->stack) {
        print_callchain_common(ctx.cc, &data->callchain, 0/*only kernel stack*/);
    }
}

static void multi_trace_sample(union perf_event *event, int instance)
{
    struct multi_trace_type_header *hdr = (void *)event->sample.array;
    struct tp *tp = NULL;
    struct perf_evsel *evsel;
    int i, j;
    __u64 key;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, hdr->stream_id, NULL);
    if (!evsel)
        return;

    for (i = 0; i < ctx.nr_list; i++) {
        for (j = 0; j < ctx.tp_list[i]->nr_tp; j++) {
            tp = &ctx.tp_list[i]->tp[j];
            if (tp->evsel == evsel)
                goto found;
        }
    }
    return;

found:

    if (ctx.env->verbose) {
        multi_trace_print(event, tp);
    }

    //get key
    key = monitor_instance_oncpu() ? monitor_instance_cpu(instance) : monitor_instance_thread(instance);

    // find prev event
    if (i != 0) {
        struct perf_event_backup backup = {
            .key = key,
        };
        struct rb_node *rbn = rblist__find(&ctx.backup, &backup);
        if (rbn) {
            struct perf_event_backup *prev;
            struct two_event *two;
            prev = container_of(rbn, struct perf_event_backup, rbnode);
            two = ctx.impl->object_find(ctx.class, prev->tp, tp);
            if (two)
                ctx.class->two(two, prev->event, event, key);
            rblist__remove_node(&ctx.backup, rbn);
        }
    }

    // backup event
    if (i != ctx.nr_list - 1) {
        struct perf_event_backup backup = {
            .key = key,
            .tp = tp,
            .event = event,
        };
        int err = rblist__add_node(&ctx.backup, &backup);
        if (err == -EEXIST) {
            struct rb_node *rbn = rblist__find(&ctx.backup, &backup);
            rblist__remove_node(&ctx.backup, rbn);
            rblist__add_node(&ctx.backup, &backup);
        }
    }
}

static profiler multi_trace = {
    .name = "multi-trace",
    .pages = 64,
    .init = multi_trace_init,
    .filter = multi_trace_filter,
    .deinit = multi_trace_exit,
    .interval = multi_trace_interval,
    .sample = multi_trace_sample,
};
PROFILER_REGISTER(multi_trace)


