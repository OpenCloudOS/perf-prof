#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/zalloc.h>
#include <linux/strlist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <two-event.h>

static profiler *base_profiler;

struct timeline_node {
    struct rb_node timeline_node;
    u64    time;
    struct rb_node key_node;
    u64    key;
    struct tp *tp;
    u32 unneeded : 1;
    struct list_head needed;
    union perf_event *event;
};

struct timeline_stat {
    u64 new;
    u64 delete;
    u64 unneeded;
    u64 mem_bytes;
    u64 unneeded_bytes;
} tl_stat;

struct __dup_stat {
    u64 nr_samples;
    u64 nr_free;
} dup_stat;

struct __backup_stat {
    u64 new;
    u64 delete;
    u64 mem_bytes;
} backup_stat;

static struct multi_trace_ctx {
    int nr_ins;
    int nr_list;
    struct tp_list **tp_list;
    struct two_event_impl *impl;
    struct two_event_class *class;
    struct rblist backup;
    struct rblist timeline;
    struct list_head needed_list;
    bool need_timeline;
    bool nested;
    bool impl_based_on_call;
    struct callchain_ctx *cc;
    struct perf_evlist *evlist;
    struct env *env;
} ctx;

static int perf_event_backup_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct timeline_node *b = container_of(rbn, struct timeline_node, key_node);
    const struct timeline_node *e = entry;

    if (b->key > e->key)
        return 1;
    else if (b->key < e->key)
        return -1;
    else
        return 0;
}

static int perf_event_backup_node_find(const void *entry, const struct rb_node *rbn)
{
    struct timeline_node *b = container_of(rbn, struct timeline_node, key_node);
    const struct timeline_node *e = entry;

    if (b->key > e->key)
        return -1;
    else if (b->key < e->key)
        return 1;
    else
        return 0;
}

static struct rb_node *perf_event_backup_node_new(struct rblist *rlist, const void *new_entry)
{
    if (ctx.need_timeline) {
        struct timeline_node *b = (void *)new_entry;
        /*
         * With --order enabled, events are backed up in chronological order. Therefore, it
         * can be directly added to the end of the queue `needed_list' without reordering.
        **/
        list_add_tail(&b->needed, &ctx.needed_list);
        RB_CLEAR_NODE(&b->key_node);
        return &b->key_node;
    } else {
        const struct timeline_node *e = new_entry;
        union perf_event *event = e->event;
        union perf_event *new_event = base_profiler->dup ? event : memdup(event, event->header.size);
        struct timeline_node *b = malloc(sizeof(*b));
        if (b && new_event) {
            b->time = e->time;
            b->key = e->key;
            b->tp = e->tp;
            b->unneeded = 0;
            b->event = new_event;
            RB_CLEAR_NODE(&b->timeline_node);
            RB_CLEAR_NODE(&b->key_node);
            INIT_LIST_HEAD(&b->needed);
            backup_stat.new ++;
            backup_stat.mem_bytes += event->header.size;
            return &b->key_node;
        } else
            return NULL;
    }
}

static void perf_event_backup_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct timeline_node *b = container_of(rb_node, struct timeline_node, key_node);
    if (ctx.need_timeline) {
        b->unneeded = 1;
        list_del_init(&b->needed);
        tl_stat.unneeded ++;
        tl_stat.unneeded_bytes += b->event->header.size;
    } else {
        backup_stat.delete ++;
        backup_stat.mem_bytes -= b->event->header.size;
        free(b->event);
        free(b);
    }
}

static int timeline_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct timeline_node *b = container_of(rbn, struct timeline_node, timeline_node);
    const struct timeline_node *e = entry;

    if (b->time > e->time)
        return 1;
    else if (b->time < e->time)
        return -1;
    else if (b->key > e->key)
        return 1;
    else if (b->key < e->key)
        return -1;
    else
        return 0;
}

static struct rb_node *timeline_node_new(struct rblist *rlist, const void *new_entry)
{
    const struct timeline_node *e = new_entry;
    union perf_event *event = e->event;
    union perf_event *new_event = base_profiler->dup ? event : memdup(event, event->header.size);
    struct timeline_node *b = malloc(sizeof(*b));
    if (b && new_event) {
        b->time = e->time;
        b->key = e->key;
        b->tp = e->tp;
        b->unneeded = e->unneeded;
        b->event = new_event;
        RB_CLEAR_NODE(&b->timeline_node);
        RB_CLEAR_NODE(&b->key_node);
        INIT_LIST_HEAD(&b->needed);
        tl_stat.new ++;
        if (b->unneeded) {
            tl_stat.unneeded ++;
            tl_stat.unneeded_bytes += event->header.size;
        }
        tl_stat.mem_bytes += event->header.size;
        return &b->timeline_node;
    } else
        return NULL;
}

static void timeline_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct timeline_node *b = container_of(rb_node, struct timeline_node, timeline_node);
    tl_stat.delete ++;
    tl_stat.mem_bytes -= b->event->header.size;
    if (b->unneeded) {
        tl_stat.unneeded --;
        tl_stat.unneeded_bytes -= b->event->header.size;
    }
    free(b->event);
    free(b);
}

static void timeline_free_unneeded(bool lost)
{
    struct rb_node *next = rb_first_cached(&ctx.timeline.entries);
    struct timeline_node *tl;
    u64 unneeded_before = 0UL;
    u64 unneeded = 0, backup = 0;

    /*
     * When there are events lost, events cannot be paired.
     * Therefore, actively release some old events.
    **/
    if (lost) {
        struct rb_node *last = rb_last(&ctx.timeline.entries.rb_root);
        struct timeline_node *tl_last = rb_entry_safe(last, struct timeline_node, timeline_node);
        u64 interval = ctx.env->interval ? : 3000;
        if (tl_last)
            unneeded_before = tl_last->time - interval * 1000000UL;
    } else if (ctx.env->before_event1) {
        struct timeline_node *needed_first;
        if (!list_empty(&ctx.needed_list))
            needed_first = list_first_entry(&ctx.needed_list, struct timeline_node, needed);
        else {
            struct rb_node *unneeded_last = rb_last(&ctx.timeline.entries.rb_root);
            needed_first = rb_entry_safe(unneeded_last, struct timeline_node, timeline_node);
        }
        if (needed_first && needed_first->time > ctx.env->before_event1)
            unneeded_before = needed_first->time - ctx.env->before_event1;
    }

    while (next) {
        tl = rb_entry(next, struct timeline_node, timeline_node);

        // if lost: before `tl_last->time - interval` on the timeline
        // elif before_event1: before `needed_first->time - before_event1` on the timeline
        // else: unneeded
        if ((unneeded_before == 0UL && tl->unneeded) ||
            tl->time < unneeded_before) {
            /*
             * When there are events lost, the event is backed up but not consumed.
             * Remove from ctx.backup.
            **/
            if (tl->unneeded == 0) {
                if (RB_EMPTY_NODE(&tl->key_node)) {
                    printf("BUG: rb key_node is empty\n");
                } else
                    rblist__remove_node(&ctx.backup, &tl->key_node);
                backup ++;
            } else
                unneeded ++;

            rblist__remove_node(&ctx.timeline, next);
        } else
            break;

        next = rb_first_cached(&ctx.timeline.entries);
    }
    if (lost) {
        print_time(stderr);
        fprintf(stderr, "free unneeded %lu, backup %lu\n", unneeded, backup);
    }
}

static void timeline_stat(void)
{
    printf("TIMELINE:\n"
           "  new = %lu\n"
           "  delete = %lu\n"
           "  unneeded = %lu\n"
           "  mem_bytes = %lu\n"
           "  unneeded_bytes = %lu\n"
           "BACKUP:\n"
           "  nr_entries = %u\n",
           tl_stat.new, tl_stat.delete, tl_stat.unneeded,
           tl_stat.mem_bytes, tl_stat.unneeded_bytes,
           rblist__nr_entries(&ctx.backup));
}

static int monitor_ctx_init(struct env *env)
{
    int i, j, stacks = 0;
    struct tep_handle *tep;
    struct two_event_options options = {
        .keytype = monitor_instance_oncpu() ? K_CPU : K_THREAD,
        .perins = env->perins,
        .only_print_greater_than = env->only_print_greater_than,
        .greater_than = env->greater_than,
        .heatmap = env->heatmap,
        .first_n = 10,
        .sort_print = ctx.nested ? false : true,
    };
    bool key_attr = false;
    bool untraced = false;

    if (env->nr_events < (ctx.nested ? 1 : 2))
        return -1;

    base_profiler = current_base_profiler();

    tep = tep__ref();

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
            if (tp->untraced && !tp->trigger)
                untraced = true;
            if (tp->untraced)
                continue;
            if (env->key && !tp->key) {
                struct tep_event *event = tep_find_event_by_name(tep, tp->sys, tp->name);
                if (!tep_find_any_field(event, env->key)) {
                    fprintf(stderr, "Cannot find %s field at %s:%s\n", env->key, tp->sys, tp->name);
                    return -1;
                }
            }
            if (tp->key)
                key_attr = true;
        }
    }

    if (stacks) {
        ctx.cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
        base_profiler->pages *= 2;
    } else
        ctx.cc = NULL;

    if (env->key || key_attr) {
        options.keytype = K_CUSTOM;
        if (!current_is_order()) {
            fprintf(stderr, "WARN: Enable the --key parameter, it is recommended to enable the "
                            "--order parameter to order events.\n");
        }
    }

    if (env->before_event1 &&
        ctx.nr_ins > 1 &&
        !using_order(base_profiler)) {
        fprintf(stderr, "Enable --detail=-N, also need to enable --order.\n");
        return -1;
    }

    if (env->impl && impl_based_on_call(env->impl))
        ctx.impl_based_on_call = true;
    if (ctx.impl_based_on_call && !ctx.nested) {
        fprintf(stderr, "Only nested-trace can enable --impl %s.\n", env->impl);
        return -1;
    }

    ctx.impl = impl_get(env->impl ?: TWO_EVENT_DELAY_IMPL);
    if (!ctx.impl) {
        fprintf(stderr, "--impl %s not implemented\n", env->impl);
        return -1;
    }
    ctx.class = ctx.impl->class_new(ctx.impl, &options);

    rblist__init(&ctx.backup);
    ctx.backup.node_cmp = perf_event_backup_node_cmp;
    ctx.backup.node_new = perf_event_backup_node_new;
    ctx.backup.node_delete = perf_event_backup_node_delete;

    rblist__init(&ctx.timeline);
    ctx.timeline.node_cmp = timeline_node_cmp;
    ctx.timeline.node_new = timeline_node_new;
    ctx.timeline.node_delete = timeline_node_delete;

    INIT_LIST_HEAD(&ctx.needed_list);

    ctx.need_timeline = env->detail;

    if (untraced && !env->detail) {
        fprintf(stderr, "WARN: --detail parameter is not enabled. No need to add untrace events.\n");
    }
    if (!env->greater_than && env->detail) {
        fprintf(stderr, "WARN: --than parameter is not enabled. No need to enable the "
                        "--detail parameter.\n");
    }

    ctx.env = env;
    return 0;
}

static void monitor_ctx_exit(void)
{
    int i;

    rblist__exit(&ctx.backup);

    rblist__exit(&ctx.timeline);

    ctx.impl->class_delete(ctx.class);
    callchain_ctx_free(ctx.cc);

    for (i = 0; i < ctx.nr_list; i++)
        tp_list_free(ctx.tp_list[i]);
    free(ctx.tp_list);

    tep__unref();
}

static int __multi_trace_init(struct perf_evlist *evlist, struct env *env)
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
    int i, j;

    if (monitor_ctx_init(env) < 0)
        return -1;

    if (using_order(base_profiler)) {
        base_profiler->dup = true;
    }

    reduce_wakeup_times(base_profiler, &attr);

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
    ctx.evlist = evlist;

    return 0;
}

static int multi_trace_init(struct perf_evlist *evlist, struct env *env)
{
    int i, j, k;

    ctx.nested = 0;
    if (__multi_trace_init(evlist, env) < 0)
        return -1;

    for (k = 0; k < ctx.nr_list - 1; k++) {
        for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
            struct tp *tp1 = &ctx.tp_list[k]->tp[i];
            if (tp1->untraced)
                continue;
            // for handle remaining
            if (!ctx.impl->object_new(ctx.class, tp1, NULL))
                return -1;
            for (j = 0; j < ctx.tp_list[k+1]->nr_tp; j++) {
                struct tp *tp2 = &ctx.tp_list[k+1]->tp[j];
                if (tp2->untraced)
                    continue;
                if (!ctx.impl->object_new(ctx.class, tp1, tp2))
                    return -1;
            }
        }
    }
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

static void multi_trace_handle_remaining(void)
{
    struct rb_node *next = rb_first_cached(&ctx.backup.entries);
    struct timeline_node *left;
    struct two_event *two;

    while (next) {
        left = rb_entry(next, struct timeline_node, key_node);
        two = ctx.impl->object_find(ctx.class, left->tp, NULL);
        if (two) {
            if (ctx.class->remaining(two, left->event, left->key) == REMAINING_BREAK)
                break;
        }
        next = rb_next(next);
    }
}

static void multi_trace_interval(void)
{
    int i, j, k;
    int header = 0;
    struct two_event *two;

    multi_trace_handle_remaining();

    for (k = 0; k < ctx.nr_list - 1; k++) {
        for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
            struct tp *tp1 = &ctx.tp_list[k]->tp[i];
            if (tp1->untraced)
                continue;
            // for print remaining
            two = ctx.impl->object_find(ctx.class, tp1, NULL);
            if (!header) {
                header = ctx.class->print_header(two);
            }
            ctx.class->print(two);
            for (j = 0; j < ctx.tp_list[k+1]->nr_tp; j++) {
                struct tp *tp2 = &ctx.tp_list[k+1]->tp[j];

                if (tp2->untraced)
                    continue;
                two = ctx.impl->object_find(ctx.class, tp1, tp2);
                if (!header) {
                    header = ctx.class->print_header(two);
                }
                ctx.class->print(two);
            }
        }
    }
}

static void multi_trace_exit(struct perf_evlist *evlist)
{
    multi_trace_interval();
    monitor_ctx_exit();
}

static void multi_trace_sigusr1(int signum)
{
    if (ctx.need_timeline)
        timeline_stat();
    else {
        if (base_profiler->dup)
            printf("DUP STAT:\n"
                   "  nr_samples = %lu\n"
                   "  nr_free = %lu\n"
                   "  nr_unfree = %lu\n",
                   dup_stat.nr_samples, dup_stat.nr_free + backup_stat.delete,
                   dup_stat.nr_samples - dup_stat.nr_free - backup_stat.delete);
        printf("BACKUP:\n"
               "  new = %lu\n"
               "  delete = %lu\n"
               "  nr_entries = %u\n"
               "  mem_bytes = %lu\n",
               backup_stat.new, backup_stat.delete, rblist__nr_entries(&ctx.backup),
               backup_stat.mem_bytes);
    }
}

static void multi_trace_lost(union perf_event *event, int ins)
{
    print_lost_fn(event, ins);
    if (ctx.need_timeline)
        timeline_free_unneeded(true);
}

void multi_trace_raw_size(union perf_event *event, void **praw, int *psize, struct tp *tp)
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

void multi_trace_print_title(union perf_event *event, struct tp *tp, const char *title)
{
    struct multi_trace_type_callchain *data = (void *)event->sample.array;
    void *raw;
    int size;

    multi_trace_raw_size(event, &raw, &size, tp);

    if (title)
        printf("%-27s", title);
    else
        print_time(stdout);
    tep__update_comm(NULL, data->h.tid_entry.tid);
    tep__print_event(data->h.time/1000, data->h.cpu_entry.cpu, raw, size);

    if (tp->stack) {
        print_callchain_common(ctx.cc, &data->callchain, 0/*only kernel stack*/);
    }
}

bool event_need_to_print(union perf_event *event, union perf_event *event1, union perf_event *event2)
{
    struct multi_trace_type_header *e  = (void *)event ->sample.array;
    struct multi_trace_type_header *e1 = (void *)event1->sample.array;
    struct multi_trace_type_header *e2 = (void *)event2->sample.array;

    if (!(ctx.env->samecpu || ctx.env->samepid))
        return true;

    if (ctx.env->samecpu)
    if (e->cpu_entry.cpu == e1->cpu_entry.cpu ||
        e->cpu_entry.cpu == e2->cpu_entry.cpu)
        return true;

    if (ctx.env->samepid)
    if (e->tid_entry.pid == e1->tid_entry.pid ||
        e->tid_entry.pid == e2->tid_entry.pid)
        return true;

    return false;
}

int event_iter_cmd(struct event_iter *iter, enum event_iter_cmd cmd)
{
    struct timeline_node *curr;
    struct rb_node *rbn;

    if (!iter || cmd >= CMD_MAX)
        return 0;

    switch (cmd) {
        case CMD_RESET:
            curr = iter->curr = iter->start;
            if (curr) {
                iter->event = curr->event;
                iter->tp = curr->tp;
            }
            break;
        case CMD_EVENT1:
            curr = iter->curr = iter->event1;
            iter->event = curr->event;
            iter->tp = curr->tp;
            break;
        case CMD_PREV:
        case CMD_NEXT:
            if (iter->curr == NULL)
                return 0;

            curr = iter->curr;
            rbn = (cmd == CMD_PREV ? rb_prev : rb_next)(&curr->timeline_node);
            iter->curr = rb_entry_safe(rbn, struct timeline_node, timeline_node);
            if (!iter->curr)
                return 0;

            curr = iter->curr;
            iter->event = curr->event;
            iter->tp = curr->tp;
            break;
        case CMD_MAX:
        default:
            return 0;
    }
    return 1;
}

static struct rb_node *multi_trace_find_prev(struct timeline_node *backup)
{
    struct rb_node *rbn;
    rb_for_each(rbn, backup, &ctx.backup.entries.rb_root, perf_event_backup_node_find) {
        if (!backup->tp)
            return rbn;
        else {
            struct timeline_node *prev;
            prev = container_of(rbn, struct timeline_node, key_node);
            if (prev->tp == backup->tp)
                return rbn;
        }
    }
    return NULL;
}

static void multi_trace_sample(union perf_event *event, int instance)
{
    struct multi_trace_type_header *hdr = (void *)event->sample.array;
    struct tp *tp = NULL, *tp1 = NULL;
    struct timeline_node *tl_event = NULL;
    struct perf_evsel *evsel;
    int i, j;
    bool need_find_prev, need_backup, need_remove_from_backup;
    __u64 key;

    if (base_profiler->dup)
        dup_stat.nr_samples ++;

    evsel = perf_evlist__id_to_evsel(ctx.evlist, hdr->stream_id, NULL);
    if (!evsel)
        goto free_dup_event;

    for (i = 0; i < ctx.nr_list; i++) {
        tp1 = NULL;
        for (j = 0; j < ctx.tp_list[i]->nr_tp; j++) {
            tp = &ctx.tp_list[i]->tp[j];
            if (tp->evsel == evsel)
                goto found;
            if (!tp->untraced)
                tp1 = tp;
        }
    }

free_dup_event:
    if (base_profiler->dup) {
        free(event);
        dup_stat.nr_free ++;
    }
    return;

found:

    if (ctx.env->verbose >= VERBOSE_EVENT || tp->trigger) {
        multi_trace_print_title(event, tp, tp->trigger ? "trigger" : NULL);
    }
    if (tp->trigger) {
        multi_trace_interval();
    }

    if (!ctx.nested) {
        need_find_prev = i != 0;
        need_backup = i != ctx.nr_list - 1;
        need_remove_from_backup = 1;
        // no need to use tp1
        tp1 = NULL;
    } else {
        need_find_prev = ctx.impl_based_on_call || tp1 != NULL;
        need_backup = tp1 == NULL;
        need_remove_from_backup = tp1 != NULL;
    }

    // get key, include untraced events.
    key = monitor_instance_oncpu() ? monitor_instance_cpu(instance) : monitor_instance_thread(instance);
    // !untraced: tp->key || ctx.env->key
    //  untraced: tp->key
    if (tp->key || (!tp->untraced && ctx.env->key)) {
        struct tep_record record;
        struct tep_handle *tep = tep__ref();
        struct tep_event *e;
        void *raw;
        int size;

        multi_trace_raw_size(event, &raw, &size, tp);
        memset(&record, 0, sizeof(record));
        record.ts = hdr->time/1000;
        record.cpu = hdr->cpu_entry.cpu;
        record.size = size;
        record.data = raw;

        e = tep_find_event_by_record(tep, &record);
        if (tep_get_field_val(NULL, e, tp->key ?: ctx.env->key, &record, &key, 0) < 0) {
            if (tep_get_common_field_val(NULL, e, tp->key ?: ctx.env->key, &record, &key, 0) < 0) {
                tep__unref();
                goto free_dup_event;
            }
        }
        tep__unref();
    }

    if (tp->untraced)
        goto untraced_processing;

    // find prev event, not include untraced
    if (need_find_prev) {
        struct timeline_node backup = {
            .key = key,
            .tp = tp1,
        };
        struct two_event *two;
        struct rb_node *rbn = multi_trace_find_prev(&backup);
        if (rbn) {
            struct timeline_node *prev;
            prev = container_of(rbn, struct timeline_node, key_node);
            two = ctx.impl->object_find(ctx.class, prev->tp, tp);
            if (two) {
                struct event_info info;
                info.tp1 = prev->tp;
                info.tp2 = tp;
                info.key = key;
                if (ctx.need_timeline) {
                    struct event_iter iter;
                    if (ctx.env->before_event1) {
                        backup.time = prev->time - ctx.env->before_event1;
                        iter.start = rb_entry_safe(rblist__find_first(&ctx.timeline, &backup),
                                                    struct timeline_node, timeline_node);
                    } else
                        iter.start = prev;
                    iter.event1 = prev;
                    iter.curr = iter.start;
                    ctx.class->two(two, prev->event, event, &info, &iter);
                } else
                    ctx.class->two(two, prev->event, event, &info, NULL);
            }

            if (need_remove_from_backup) {
                rblist__remove_node(&ctx.backup, rbn);

                // ctx.backup no longer references an event, prev.unneeded = 1,
                // releasing unneeded events on the timeline in time.
                if (ctx.need_timeline)
                    timeline_free_unneeded(false);
            }
        } else if (ctx.impl_based_on_call) {
            two = ctx.impl->object_find(ctx.class, tp, NULL);
            if (two) {
                // two(A, NULL), first call A.
                struct event_info info;
                info.tp1 = tp;
                info.tp2 = NULL;
                info.key = key;
                ctx.class->two(two, event, NULL, &info, NULL);
            }
        }
    }

untraced_processing:

    // backup events to Timeline, include untraced events.
    if (ctx.need_timeline) {
        struct timeline_node backup = {
            .time = hdr->time,
            .key = key,
            .tp = tp,
            .unneeded = (!need_backup) || tp->untraced, // untraced means unneeded
            .event = event,
        };
        struct rb_node *rbn;
        bool need_free = false;

        if (rblist__empty(&ctx.timeline) && backup.unneeded && ctx.env->before_event1 == 0)
            rbn = NULL;
        else
            rbn = rblist__findnew(&ctx.timeline, &backup);

        if (rbn) {
            tl_event = rb_entry(rbn, struct timeline_node, timeline_node);
        } else
            goto free_dup_event;

        // backup events, exclude untraced events.
        if (need_backup && !tp->untraced) {
        retry:
            rbn = rblist__findnew(&ctx.backup, tl_event);
            if (rbn) {
                struct timeline_node *new;
                new = rb_entry(rbn, struct timeline_node, key_node);
                if (new != tl_event) {
                    /*
                     * The same event occurs multiple times, only the last event is backed up.
                     * Previous events will be marked as unneeded and released on the timeline in time.
                    **/
                    if (ctx.env->verbose >= VERBOSE_NOTICE)
                        multi_trace_print_title(new->event, new->tp, "EEXIST");
                    rblist__remove_node(&ctx.backup, rbn);
                    need_free = true;

                    /*
                     * tl_event->unneeded is equal to 0, but not added to ctx.backup, tl_event->key_node
                     * is empty, `timeline_free_unneeded' cannot be called immediately.
                    **/
                    goto retry;
                }
            } else {
                tl_event->unneeded = 1;
                need_free = true;
            }
        } else
            // Events at the last level are unneeded.
            need_free = true;

        if (need_free)
            timeline_free_unneeded(false);
    }
    else
    {
        // backup events, exclude untraced events.
        if (need_backup && !tp->untraced) {
            struct timeline_node backup = {
                .time = hdr->time,
                .key = key,
                .tp = tp,
                .event = event,
            };

            if (base_profiler->dup) {
                struct rb_node *rbn = rblist__findnew(&ctx.backup, &backup);
                if (rbn) {
                    struct timeline_node *new;
                    new = rb_entry(rbn, struct timeline_node, key_node);
                    if (new->event != event) {
                        if (ctx.env->verbose >= VERBOSE_NOTICE)
                            multi_trace_print_title(new->event, new->tp, "EEXIST");
                        backup_stat.mem_bytes -= new->event->header.size;
                        dup_stat.nr_free ++;
                        free(new->event);
                        new->event = event;
                        new->time = backup.time;
                        backup_stat.mem_bytes += event->header.size;
                    }
                    new->tp = tp;
                } else
                    goto free_dup_event;
            } else {
                int err = rblist__add_node(&ctx.backup, &backup);
                if (err == -EEXIST) {
                    struct rb_node *rbn = rblist__find(&ctx.backup, &backup);
                    struct timeline_node *new = rb_entry(rbn, struct timeline_node, key_node);
                    if (ctx.env->verbose >= VERBOSE_NOTICE)
                        multi_trace_print_title(new->event, new->tp, "EEXIST");
                    backup_stat.mem_bytes -= new->event->header.size;
                    free(new->event);
                    new->event = memdup(event, event->header.size);
                    new->time = backup.time;
                    new->tp = tp;
                    backup_stat.mem_bytes += event->header.size;
                } else if (err != 0)
                    goto free_dup_event;
            }
        } else
            goto free_dup_event;
    }
}

static void __help_events(struct help_ctx *hctx, const char *impl, bool *has_key)
{
    int i, j;
    struct env *env = hctx->env;

    if (strcmp(impl, TWO_EVENT_SYSCALLS_IMPL) == 0) {
        printf("-e raw_syscalls:sys_enter/./ -e raw_syscalls:sys_exit/./ ");
        return;
    }

    for (i = 0; i < hctx->nr_list; i++) {
        printf("-e \"");
        for (j = 0; j < hctx->tp_list[i]->nr_tp; j++) {
            struct tp *tp = &hctx->tp_list[i]->tp[j];
            printf("%s:%s/%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".");
            if (!env->key || tp->key)
                printf("key=%s/", tp->key?:".");
            if (tp->key)
                *has_key = true;
            if (strcmp(impl, TWO_EVENT_MEM_PROFILE) == 0)
                printf("ptr=%s/size=%s/", tp->mem_ptr?:".", tp->mem_size?:".");
            if (strcmp(impl, TWO_EVENT_PAIR_IMPL) != 0)
                printf("stack/");
            if (tp->untraced)
                printf("untraced/");
            if (tp->trigger)
                printf("trigger/");
            if (tp->alias)
                printf("alias=%s/", tp->alias);
            if (!tp->untraced)
                printf("[untraced/]");
            if (!tp->trigger)
                printf("[trigger/]");
            if (!tp->alias)
                printf("[alias=./]");
            if (j != hctx->tp_list[i]->nr_tp - 1)
                printf(",");
        }
        printf("\" ");
    }
}

static void __multi_trece_help(struct help_ctx *hctx, const char *common, const char *impl, bool impl_default)
{
    struct env *env = hctx->env;
    bool has_key = false;

    if (!ctx.nested && strcmp(impl, TWO_EVENT_SYSCALLS_IMPL) && hctx->nr_list < 2)
        return;
    if (env->impl && strcmp(env->impl, impl))
        return;

    printf("%s ", common);
    __help_events(hctx, impl, &has_key);

    if (env->key)
        printf("-k %s --order --order-mem . ", env->key);
    else if (has_key)
        printf("--order --order-mem . ");
    if (!impl_default)
        printf("--impl %s ", impl);
    if (strcmp(impl, TWO_EVENT_DELAY_IMPL) == 0 ||
        strcmp(impl, TWO_EVENT_SYSCALLS_IMPL) == 0 ||
        strcmp(impl, TWO_EVENT_CALL_DELAY_IMPL) == 0) {
        if (env->perins)
            printf("--perins ");
        if (env->greater_than)
            printf("--than %lu ", env->greater_than);
        if (env->detail) {
            if (env->before_event1 || env->samecpu || env->samepid) {
                int len = 0;
                printf("--detail=");
                if (env->before_event1)
                    len += printf("-%lu", env->before_event1);
                if (env->samecpu)
                    len += printf("%ssamecpu", len > 0 ? "," : "");
                if (env->samepid)
                    len += printf("%ssamepid", len > 0 ? "," : "");
                printf(" ");
            } else
                printf("--detail ");
        }
        if (env->heatmap)
            printf("--heatmap %s ", env->heatmap);
    }
    common_help(hctx, true, true, true, true, false, true, true);

    if (!env->key && !has_key)
        printf("[-k . --order --order-mem .] ");
    else if (!env->key)
        printf("[-k .] ");
    if (strcmp(impl, TWO_EVENT_DELAY_IMPL) == 0 ||
        strcmp(impl, TWO_EVENT_SYSCALLS_IMPL) == 0 ||
        strcmp(impl, TWO_EVENT_CALL_DELAY_IMPL) == 0) {
        if (!env->perins)
            printf("[--perins] ");
        if (!env->greater_than)
            printf("[--than .] ");
        if (!env->detail)
            printf("[--detail[=-N,+N,samecpu,samepid]] ");
        if (!env->heatmap)
            printf("[--heatmap .] ");
    }
    common_help(hctx, false, true, true, true, false, true, true);

    printf("\n");
}

#define NUM(ary) (sizeof(ary)/sizeof(ary[0]))
static void multi_trece_help(struct help_ctx *hctx)
{
    const char *common = PROGRAME " multi-trace";
    const char *impl_str[] = {TWO_EVENT_DELAY_IMPL, TWO_EVENT_PAIR_IMPL, TWO_EVENT_MEM_PROFILE, TWO_EVENT_SYSCALLS_IMPL};
    int impl;

    for (impl = 0; impl < NUM(impl_str); impl++)
        __multi_trece_help(hctx, common, impl_str[impl], false);
}

static const char *multi_trace_desc[] = PROFILER_DESC("multi-trace",
    "[OPTION...] -e EVENT [-e ...] [-k key] [--impl impl] [--than|--only-than ns] [--detail] [--perins] [--heatmap file]",
    "Multipurpose trace: delay, pair, kmemprof, syscalls.", "",
    "SYNOPSIS", "",
    "    Multiple events are associated by key and finally converted into two-event analysis.", "",
    "TWO-EVENT", "",
    "    delay - latency analysis",
    "    pair - event pair, alloc and free, open and close, etc.",
    "    kmemprof - mem profile, alloc and free bytes",
    "    syscalls - syscalls latency analysis", "",
    "EXAMPLES", "",
    "    "PROGRAME" multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000",
    "    "PROGRAME" multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000 --impl pair",
    "    "PROGRAME" multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000 --than 100us",
    "    "PROGRAME" multi-trace -e irq:softirq_entry/vec==1/ -e irq:softirq_exit/vec==1/ -i 1000 --than 100us --order --detail=-1ms");
static const char *multi_trace_argv[] = PROFILER_ARGV("multi-trace",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "key", "impl", "than", "only-than", "detail", "perins", "heatmap");
static profiler multi_trace = {
    .name = "multi-trace",
    .desc = multi_trace_desc,
    .argv = multi_trace_argv,
    .pages = 64,
    .help = multi_trece_help,
    .init = multi_trace_init,
    .filter = multi_trace_filter,
    .deinit = multi_trace_exit,
    .sigusr1 = multi_trace_sigusr1,
    .interval = multi_trace_interval,
    .lost = multi_trace_lost,
    .sample = multi_trace_sample,
};
PROFILER_REGISTER(multi_trace);


static int kmemprof_init(struct perf_evlist *evlist, struct env *env)
{
    if (env->impl)
        free(env->impl);
    env->impl = strdup(TWO_EVENT_MEM_PROFILE);
    return multi_trace_init(evlist, env);
}

static void kmemprof_help(struct help_ctx *hctx)
{
    struct env *env = hctx->env;
    const char *common = PROGRAME " kmemprof";
    char *oldimpl = env->impl;
    env->impl = strdup(TWO_EVENT_MEM_PROFILE);
    __multi_trece_help(hctx, common, TWO_EVENT_MEM_PROFILE, true);
    free(env->impl);
    env->impl = oldimpl;
}

static const char *kmemprof_desc[] = PROFILER_DESC("kmemprof",
    "[OPTION...] -e alloc -e free [-k str]",
    "Memory allocation profile. Both user and kernel allocators are supported.", "",
    "SYNOPSIS", "",
    "    Profile alloc and free bytes, as well as the alloc stack.",
    "    Based on multi-trace. See '"PROGRAME" multi-trace -h' for more information.", "",
    "EXAMPLES", "",
    "    "PROGRAME" kmemprof -e kmem:kmalloc//ptr=ptr/size=bytes_alloc/stack/ -e kmem:kfree//ptr=ptr/ -m 128 --order -k ptr",
    "    "PROGRAME" kmemprof -e kmem:kmalloc//ptr=ptr/size=bytes_alloc/stack/,kmem:kmalloc_node//ptr=ptr/size=bytes_alloc/stack/ -e kmem:kfree//ptr=ptr/ --order -k ptr");
static const char *kmemprof_argv[] = PROFILER_ARGV("kmemprof",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "key");
static profiler kmemprof = {
    .name = "kmemprof",
    .desc = kmemprof_desc,
    .argv = kmemprof_argv,
    .pages = 64,
    .help = kmemprof_help,
    .init = kmemprof_init,
    .filter = multi_trace_filter,
    .deinit = multi_trace_exit,
    .sigusr1 = multi_trace_sigusr1,
    .interval = multi_trace_interval,
    .lost = multi_trace_lost,
    .sample = multi_trace_sample,
};
PROFILER_REGISTER(kmemprof);


static int syscalls_init(struct perf_evlist *evlist, struct env *env)
{
    if (env->impl)
        free(env->impl);
    env->impl = strdup(TWO_EVENT_SYSCALLS_IMPL);
    return multi_trace_init(evlist, env);
}

static void syscalls_help(struct help_ctx *hctx)
{
    struct env *env = hctx->env;
    const char *common = PROGRAME " syscalls";
    char *oldimpl = env->impl;
    env->impl = strdup(TWO_EVENT_SYSCALLS_IMPL);
    __multi_trece_help(hctx, common, TWO_EVENT_SYSCALLS_IMPL, true);
    free(env->impl);
    env->impl = oldimpl;
}

static const char *syscalls_desc[] = PROFILER_DESC("syscalls",
    "[OPTION...] -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit [-k common_pid] [--than ns] [--perins] [--heatmap file]",
    "Syscalls latency analysis.", "",
    "SYNOPSIS", "",
    "    Based on multi-trace. See '"PROGRAME" multi-trace -h' for more information.", "",
    "EXAMPLES", "",
    "    "PROGRAME" syscalls -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit -p 1561",
    "    "PROGRAME" syscalls -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit -k common_pid --order -C 0");
static const char *syscalls_argv[] = PROFILER_ARGV("syscalls",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "key", "than", "perins", "heatmap");
static profiler syscalls = {
    .name = "syscalls",
    .desc = syscalls_desc,
    .argv = syscalls_argv,
    .pages = 64,
    .help = syscalls_help,
    .init = syscalls_init,
    .filter = multi_trace_filter,
    .deinit = multi_trace_exit,
    .sigusr1 = multi_trace_sigusr1,
    .interval = multi_trace_interval,
    .lost = multi_trace_lost,
    .sample = multi_trace_sample,
};
PROFILER_REGISTER(syscalls);


/* nested-trace
 *
 * perf-prof nested-trace -e A,A_ret -e B,B_ret -e C,C_ret [--impl call|call-delay]
 *
 * A call B, B call C.
 *
 * timeline: A, B, C, C_ret, B_ret, A_ret
 *
 *  pid1 | pid2  | pid3
 * ______|_C_B_A_|______
 *       |
 *       `stack-like. A comes first, B next, and C last.
 *
 * pid2 events:
 *     two(A, NULL),  A comes first.   A is the root node.
 *     two(A, B),     B next.          A call B, B is a descendant of A.
 *     two(B, C),     C last.          B call C, C is a descendant of B.
 *     two(C, C_ret), first remove C.  C return, get the execution time of C.
 *     two(B, B_ret), then remove B.   B return, get the execution time of B.
 *     two(A, A_ret), last remove A.   A return, get the execution time of A.
**/
static int nested_perf_event_backup_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct timeline_node *b = container_of(rbn, struct timeline_node, key_node);
    const struct timeline_node *e = entry;

    if (b->key > e->key)
        return 1;
    else if (b->key < e->key)
        return -1;

    //time reverse order
    if (b->time > e->time)
        return -1;
    else if (b->time < e->time)
        return 1;

    return 0;
}

static int nested_trace_init(struct perf_evlist *evlist, struct env *env)
{
    int i, k;

    ctx.nested = 1;
    if (__multi_trace_init(evlist, env) < 0)
        return -1;

    ctx.backup.node_cmp = nested_perf_event_backup_node_cmp;

    for (k = 0; k < ctx.nr_list; k++) {
        struct tp *tp1 = NULL;
        struct tp *tp2 = NULL;

        /*
         * f1 --------> f1_ret
         *    f2 -> f2_ret
         *       ..
         *
         * -e f1,f1_ret -e f2,f2_ret ..
        **/
        if (ctx.tp_list[k]->nr_tp - ctx.tp_list[k]->nr_untraced != 2) {
            fprintf(stderr, "-e ");
            for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
                struct tp *tp = &ctx.tp_list[k]->tp[i];
                fprintf(stderr, "%s%s:%s%s", i == 0 ? "" : ",", tp->sys, tp->name, tp->untraced ? "//untraced/" : "");
            }
            fprintf(stderr, " are unpaired\n");
            return -1;
        }

        for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list[k]->tp[i];
            if (tp->untraced)
                continue;
            if (!tp1)
                tp1 = tp;
            else if (!tp2)
                tp2 = tp;
        }

        if (!ctx.impl->object_new(ctx.class, tp1, tp2))
            return -1;
    }
    return 0;
}

static void nested_trace_interval(void)
{
    int i, k;
    int header = 0;

    multi_trace_handle_remaining();

    for (k = 0; k < ctx.nr_list; k++) {
        struct tp *tp1 = NULL;
        struct tp *tp2 = NULL;
        struct two_event *two;

        for (i = 0; i < ctx.tp_list[k]->nr_tp; i++) {
            struct tp *tp = &ctx.tp_list[k]->tp[i];
            if (tp->untraced)
                continue;
            if (!tp1)
                tp1 = tp;
            else if (!tp2)
                tp2 = tp;
        }
        two = ctx.impl->object_find(ctx.class, tp1, tp2);
        if (!header) {
            header = ctx.class->print_header(two);
        }
        ctx.class->print(two);
    }
}

static void nested_trace_exit(struct perf_evlist *evlist)
{
    nested_trace_interval();
    monitor_ctx_exit();
}

static void nested_trace_help(struct help_ctx *hctx)
{
    const char *common = PROGRAME " nested-trace";
    const char *impl_str[] = {TWO_EVENT_DELAY_IMPL, TWO_EVENT_CALL_IMPL, TWO_EVENT_CALL_DELAY_IMPL};
    int impl;

    ctx.nested = 1;
    for (impl = 0; impl < NUM(impl_str); impl++)
        __multi_trece_help(hctx, common, impl_str[impl], false);
}

static const char *nested_trace_desc[] = PROFILER_DESC("nested-trace",
    "[OPTION...] -e E,E_ret [-e ...] [-k str] [--impl impl] [--than ns] [--detail] [--perins] [--heatmap file]",
    "Nested-event trace: delay, call, call-delay.", "",
    "SYNOPSIS", "",
    "    Function calls, interrupts, etc. are possible nested events.",
    "    Based on multi-trace. See '"PROGRAME" multi-trace -h' for more information.", "",
    "TWO-EVENT", "",
    "    delay - analyze function time",
    "    call - analyze function calls",
    "    call-delay - Analyze function calls. Also analyze function time.", "",
    "EXAMPLES", "",
    "    "PROGRAME" nested-trace -e irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/ -i 1000",
    "    "PROGRAME" nested-trace -e irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/ -i 1000 --impl call-delay",
    "    "PROGRAME" nested-trace -e irq:softirq_entry/vec==1/,irq:softirq_exit/vec==1/ -e "
                                   "timer:timer_expire_entry,timer:timer_expire_exit -i 1000 --impl call-delay");
static const char *nested_trace_argv[] = PROFILER_ARGV("nested-trace",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event", "key", "impl", "than", "detail", "perins", "heatmap");
static profiler nested_trace = {
    .name = "nested-trace",
    .desc = nested_trace_desc,
    .argv = nested_trace_argv,
    .pages = 64,
    .help = nested_trace_help,
    .init = nested_trace_init,
    .filter = multi_trace_filter,
    .deinit = nested_trace_exit,
    .sigusr1 = multi_trace_sigusr1,
    .interval = nested_trace_interval,
    .lost = multi_trace_lost,
    .sample = multi_trace_sample,
};
PROFILER_REGISTER(nested_trace);

