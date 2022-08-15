#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/zalloc.h>
#include <linux/rblist.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
#include <latency_helpers.h>
#include <two-event.h>

static int two_event_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct two_event *two = container_of(rbn, struct two_event, rbnode);
    const struct two_event *e = entry;

    if (two->tp1 > e->tp1)
        return 1;
    else if (two->tp1 < e->tp1)
        return -1;
    else {
        // tp2 can be NULL
        if (e->tp2) {
            if (two->tp2 > e->tp2)
                return 1;
            else if (two->tp2 < e->tp2)
                return -1;
        }
        return 0;
    }
}

static struct rb_node *two_event_node_new(struct rblist *rlist, const void *new_entry)
{
    struct two_event_class *class = container_of(rlist, struct two_event_class, two_events);
    const struct two_event *e = new_entry;
    struct two_event *two = malloc(class->impl->instance_size);
    if (two) {
        memset(two, 0, class->impl->instance_size);
        RB_CLEAR_NODE(&two->rbnode);
        two->class = class;
        two->tp1 = e->tp1;
        two->tp2 = e->tp2;
        return &two->rbnode;
    } else
        return NULL;
}

static void two_event_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct two_event_class *class = container_of(rblist, struct two_event_class, two_events);
    struct two_event *two = container_of(rb_node, struct two_event, rbnode);
    if (!two->deleting) {
        two->deleting = true;
        /*
         * In the two_event_class_delete function, all two_event objects are deleted.
         * Therefore, the derived object is deleted here.
         */
        class->impl->object_delete(class, two);
    }
    free(two);
}

static struct two_event *two_event_new(struct two_event_class *class, struct tp *tp1, struct tp *tp2)
{
    struct two_event entry = {
        .tp1 = tp1,
        .tp2 = tp2,
    };
    struct rb_node *rbn = rblist__findnew(&class->two_events, &entry);
    struct two_event *two = NULL;

    if (rbn) {
        two = container_of(rbn, struct two_event, rbnode);
    }
    return two;
}

static void two_event_delete(struct two_event_class *class, struct two_event *two)
{
    if (two && !two->deleting) {
        two->deleting = true;
        rblist__remove_node(&class->two_events, &two->rbnode);
    }
}

static struct two_event *two_event_find(struct two_event_class *class, struct tp *tp1, struct tp *tp2)
{
    struct two_event entry = {
        .tp1 = tp1,
        .tp2 = tp2,
    };
    struct rb_node *rbn = rblist__find(&class->two_events, &entry);
    struct two_event *two = NULL;

    if (rbn) {
        two = container_of(rbn, struct two_event, rbnode);
    }
    return two;
}

static void dummy_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key, struct event_iter *iter) {}
static void dummy_remaining(struct two_event *two, union perf_event *event, u64 key) {}
static int dummy_print_header(struct two_event *two) {return 0;}
static void dummy_print(struct two_event *two) {}

static struct two_event_class *two_event_class_new(struct two_event_impl *impl, struct two_event_options *options)
{
    struct two_event_class *class = malloc(impl->class_size);

    if (!class)
        return NULL;

    memset(class, 0, impl->class_size);

    class->impl = impl;
    class->opts = *options;
    rblist__init(&class->two_events);
    class->two_events.node_cmp = two_event_node_cmp;
    class->two_events.node_new = two_event_node_new;
    class->two_events.node_delete = two_event_node_delete;

    class->two = dummy_two;
    class->remaining = dummy_remaining;
    class->print_header = dummy_print_header;
    class->print = dummy_print;

    return class;
}

static void two_event_class_delete(struct two_event_class *class)
{
    rblist__exit(&class->two_events);
    free(class);
}

static void impl_init(struct two_event_impl *impl)
{
    /* class */
    if (!impl->class_size)
        impl->class_size = sizeof(struct two_event_class);
    if (!impl->class_new)
        impl->class_new = two_event_class_new;
    if (!impl->class_delete)
        impl->class_delete = two_event_class_delete;

    /* object */
    if (!impl->instance_size)
        impl->instance_size = sizeof(struct two_event);
    if (!impl->object_new)
        impl->object_new = two_event_new;
    if (!impl->object_delete)
        impl->object_delete = two_event_delete;
    if (!impl->object_find)
        impl->object_find = two_event_find;
}


/*
 * Delay between two events
 *
 * Count the maximum, minimum, and average values of each instance.
 * And can output delay heatmap.
**/

struct delay {
    struct two_event base;
    struct heatmap *heatmap;
};

struct delay_class {
    struct two_event_class base;
    int max_len1;
    int max_len2;
    struct latency_dist *lat_dist;
};

static struct two_event *delay_new(struct two_event_class *class, struct tp *tp1, struct tp *tp2)
{
    struct two_event *two = two_event_new(class, tp1, tp2);
    struct delay *delay = NULL;
    struct delay_class *delay_class = NULL;

    if (two) {
        delay = container_of(two, struct delay, base);
        delay_class = container_of(two->class, struct delay_class, base);

        if (strlen(tp1->name) > delay_class->max_len1)
            delay_class->max_len1 = strlen(tp1->name);
        if (strlen(tp2->name) > delay_class->max_len2)
            delay_class->max_len2 = strlen(tp2->name);
        if (class->opts.heatmap) {
            char buff[1024];
            snprintf(buff, sizeof(buff), "%s-%s-%s", class->opts.heatmap, tp1->name, tp2->name);
            delay->heatmap = heatmap_open("ns", "ns", buff);
        }
    }
    return two;
}

static void delay_delete(struct two_event_class *class, struct two_event *two)
{
    struct delay *delay = NULL;

    if (two) {
        delay = container_of(two, struct delay, base);
        heatmap_close(delay->heatmap);
        two_event_delete(class, two);
    }
}

static void delay_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key, struct event_iter *iter)
{
    struct delay *delay = NULL;
    struct delay_class *delay_class = NULL;
    struct two_event_options *opts;
    struct multi_trace_type_header *e1 = (void *)event1->sample.array;
    struct multi_trace_type_header *e2 = (void *)event2->sample.array;
    u64 delta = 0;

    if (two) {
        delay = container_of(two, struct delay, base);
        delay_class = container_of(two->class, struct delay_class, base);
        opts = &two->class->opts;

        if (e2->time > e1->time) {
            delta = e2->time - e1->time;

            latency_dist_input(delay_class->lat_dist, key, (u64)two, delta);

            if (delay->heatmap)
                heatmap_write(delay->heatmap, e2->time, delta);

            if (opts->greater_than && delta > opts->greater_than) {

                // print events before event1
                if (iter && iter->start && iter->start != iter->event1) {
                    struct multi_trace_type_header *e;
                    bool first = true;
                    char buff[32];
                    s64  neg;

                    event_iter_cmd(iter, CMD_RESET);

                    e = (void *)iter->event->sample.array;
                    neg = e->time - e1->time;
                    snprintf(buff, sizeof(buff), "Previous %.3f us", neg/1000.0);
                    printf("\n");

                    do {
                        multi_trace_print_title(iter->event, iter->tp, first ? buff : "|");
                        first = false;
                        if (!event_iter_cmd(iter, CMD_NEXT))
                            break;
                    } while (iter->curr != iter->event1);
                }

                // print event1
                multi_trace_print(event1, two->tp1);

                // print event1 to event2
                if (iter) {
                    bool first = true;
                    char buff[32];
                    snprintf(buff, sizeof(buff), "| %12.3f us", delta/1000.0);
                    event_iter_cmd(iter, CMD_EVENT1);
                    while (event_iter_cmd(iter, CMD_NEXT)) {
                        multi_trace_print_title(iter->event, iter->tp, first ? buff : "|");
                        first = false;
                    }
                }

                // print event2
                multi_trace_print(event2, two->tp2);
            }
        }
    }
}

static void delay_print_node(void *opaque, struct latency_node *node)
{
    struct delay_class *delay_class = opaque;
    struct two_event_options *opts = &delay_class->base.opts;
    struct two_event *two = (struct two_event *)node->key;

    if (opts->perins) {
        printf("[%*lu] ", opts->keytype == K_CPU ? 3 : 6, node->instance);
    }
    printf("%*s", delay_class->max_len1, two->tp1->name);
    printf(" => %-*s", delay_class->max_len2, two->tp2->name);
    printf(" %8lu %16.3f %9.3f %9.3f %12.3f\n",
        node->n, node->sum/1000.0, node->min/1000.0, node->sum/node->n/1000.0, node->max/1000.0);
}

static int delay_print_header(struct two_event *two)
{
    struct delay_class *delay_class = NULL;
    struct two_event_options *opts;
    const char *str_keytype[] = {
        [K_CPU] = "CPU",
        [K_THREAD] = "THREAD",
        [K_CUSTOM] = "CUSTOM"
    };
    int i;

    if (two) {
        delay_class = container_of(two->class, struct delay_class, base);
        opts = &two->class->opts;

        if (latency_dist_empty(delay_class->lat_dist))
            return 1;

        print_time(stdout);
        printf("\n");

        if (opts->perins)
            printf("[%s] ", str_keytype[opts->keytype]);

        printf("%*s => %-*s", delay_class->max_len1, "start", delay_class->max_len2, "end");
        printf(" %8s %16s %9s %9s %12s\n", "calls", "total(us)", "min(us)", "avg(us)", "max(us)");

        if (opts->perins)
            printf(opts->keytype == K_CPU ? "----- " : "-------- ");
        for (i=0; i<delay_class->max_len1; i++) printf("-");
        printf("    ");
        for (i=0; i<delay_class->max_len2; i++) printf("-");
        printf(" %8s %16s %9s %9s %12s\n",
                        "--------", "----------------", "---------", "---------", "------------");

        latency_dist_print(delay_class->lat_dist, delay_print_node, delay_class);
        return 1;
    }
    return 0;
}

static void delay_print(struct two_event *two)
{
}

static struct two_event_class *delay_class_new(struct two_event_impl *impl, struct two_event_options *options)
{
    struct two_event_class *class = two_event_class_new(impl, options);
    struct delay_class *delay_class;

    if (class) {
        class->two = delay_two;
        class->print_header = delay_print_header;
        class->print = delay_print;

        delay_class = container_of(class, struct delay_class, base);
        delay_class->lat_dist = latency_dist_new(options->perins, true, 0);
    }
    return class;
}

static void delay_class_delete(struct two_event_class *class)
{
    struct delay_class *delay_class;
    if (class) {
        delay_class = container_of(class, struct delay_class, base);
        latency_dist_free(delay_class->lat_dist);
        two_event_class_delete(class);
    }
}

static struct two_event_impl delay_impl = {
    .name = TWO_EVENT_DELAY_IMPL,
    .class_size = sizeof(struct delay_class),
    .class_new = delay_class_new,
    .class_delete = delay_class_delete,

    .instance_size = sizeof(struct delay),
    .object_new = delay_new,
    .object_delete = delay_delete,
};


/*
 * syscall delay
 *
 * Count the maximum, minimum, and average values of each instance.
 * Number of syscall errors
 * And can output delay heatmap.
 *
**/

struct sys_enter {
    unsigned short common_type;//       offset:0;       size:2; signed:0;
    unsigned char common_flags;//       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//       offset:3;       size:1; signed:0;
    int common_pid;//   offset:4;       size:4; signed:1;

    long id;//  offset:8;       size:8; signed:1;
    unsigned long args[6];//    offset:16;      size:48;        signed:0;
};

struct sys_exit {
    unsigned short common_type;//       offset:0;       size:2; signed:0;
    unsigned char common_flags;//       offset:2;       size:1; signed:0;
    unsigned char common_preempt_count;//       offset:3;       size:1; signed:0;
    int common_pid;//   offset:4;       size:4; signed:1;

    long id;//  offset:8;       size:8; signed:1;
    long ret;// offset:16;      size:8; signed:1;
};


#undef __SYSCALL
#undef __SYSCALL_WITH_COMPAT
#define __SYSCALL(nr, sym) [nr] = #sym,
#define __SYSCALL_WITH_COMPAT(nr, sym, compat) [nr] = #sym,
const char *syscalls_table[] = {
#if defined(__i386__)
#include <asm/syscalls_32.h>
#elif defined(__x86_64__)
#include <asm/syscalls_64.h>
#else
#include <asm-generic/unistd.h>
#endif
};

static struct two_event *syscalls_new(struct two_event_class *class, struct tp *tp1, struct tp *tp2)
{
    if (strcmp(tp1->sys, "raw_syscalls") ||
        strcmp(tp1->name, "sys_enter") ||
        strcmp(tp2->sys, "raw_syscalls") ||
        strcmp(tp2->name, "sys_exit")) {
        fprintf(stderr, "Please use -e raw_syscalls:sys_enter -e raw_syscalls:sys_exit\n");
        return NULL;
    }
    return delay_new(class, tp1, tp2);
}

static void syscalls_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key, struct event_iter *iter)
{
    struct delay *delay = NULL;
    struct delay_class *delay_class = NULL;
    struct two_event_options *opts;
    struct multi_trace_type_header *e1 = (void *)event1->sample.array;
    struct multi_trace_type_header *e2 = (void *)event2->sample.array;
    struct sys_enter *sys_enter;
    int enter_size;
    struct sys_exit *sys_exit;
    int exit_size;
    u64 delta = 0;
    struct latency_node *node;

    if (two) {
        delay = container_of(two, struct delay, base);
        delay_class = container_of(two->class, struct delay_class, base);
        opts = &two->class->opts;

        if (e2->time > e1->time) {
            delta = e2->time - e1->time;

            multi_trace_raw_size(event1, (void **)&sys_enter, &enter_size, two->tp1);
            multi_trace_raw_size(event2, (void **)&sys_exit, &exit_size, two->tp2);

            if (sys_enter->common_pid != sys_exit->common_pid ||
                sys_enter->id != sys_exit->id)
                return ;

            node = latency_dist_input(delay_class->lat_dist, sys_enter->common_pid, sys_enter->id, delta);
            node->extra[0] += IS_ERR_VALUE((unsigned long)sys_exit->ret); //error

            if (delay->heatmap)
                heatmap_write(delay->heatmap, e2->time, delta);

            if (opts->greater_than && delta > opts->greater_than) {
                multi_trace_print(event1, two->tp1);
                multi_trace_print(event2, two->tp2);
            }
        }
    }
}

static void syscalls_print_node(void *opaque, struct latency_node *node)
{
    struct delay_class *delay_class = opaque;
    struct two_event_options *opts = &delay_class->base.opts;
    char buf[64];

    if (opts->perins) {
        printf("[%6lu] ", node->instance);
    }
    if (node->key < sizeof(syscalls_table)/sizeof(syscalls_table[0])
        && syscalls_table[node->key]) {
        snprintf(buf, sizeof(buf), "%s(%lu)", syscalls_table[node->key], node->key);
        printf("%-20s", buf);
    } else
        printf("%-20lu", node->key);
    printf(" %8lu %16.3f %12.3f %12.3f %12.3f %6lu\n",
        node->n, node->sum/1000.0, node->min/1000.0, node->sum/node->n/1000.0, node->max/1000.0, node->extra[0]);
}

static int syscalls_print_header(struct two_event *two)
{
    struct delay_class *delay_class = NULL;
    struct two_event_options *opts;
    int i;

    if (two) {
        delay_class = container_of(two->class, struct delay_class, base);
        opts = &two->class->opts;

        if (latency_dist_empty(delay_class->lat_dist))
            return 1;

        print_time(stdout);
        printf("\n");

        if (opts->perins)
            printf("[THREAD] ");

        printf("%-20s", "syscalls");
        printf(" %8s %16s %12s %12s %12s %6s\n", "calls", "total(us)", "min(us)", "avg(us)", "max(us)", "err");

        if (opts->perins)
            printf("-------- ");
        for (i=0; i<20; i++) printf("-");
        printf(" %8s %16s %12s %12s %12s %6s\n",
                        "--------", "----------------", "------------", "------------", "------------", "------");

        latency_dist_print(delay_class->lat_dist, syscalls_print_node, delay_class);
        return 1;
    }
    return 0;
}


static struct two_event_class *syscalls_class_new(struct two_event_impl *impl, struct two_event_options *options)
{
    struct two_event_class *class = two_event_class_new(impl, options);
    struct delay_class *delay_class;

    if (class) {
        class->two = syscalls_two;
        class->print_header = syscalls_print_header;
        class->print = delay_print;

        delay_class = container_of(class, struct delay_class, base);
        delay_class->lat_dist = latency_dist_new(options->perins, true, sizeof(u64));
    }
    return class;
}


static struct two_event_impl syscalls_impl = {
    .name = TWO_EVENT_SYSCALLS_IMPL,
    .class_size = sizeof(struct delay_class),
    .class_new = syscalls_class_new,
    .class_delete = delay_class_delete,

    .instance_size = sizeof(struct delay),
    .object_new = syscalls_new,
    .object_delete = delay_delete,
};


/*
 * Determine if two events are paired
 *
 * Print unpaired events.
 * Report the number of paired and unpaired events.
**/

struct pair {
    struct two_event base;
    u64 paired;
    u64 unpaired;
};

struct pair_class {
    struct two_event_class base;
};

static void pair_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key, struct event_iter *iter)
{
    struct pair *pair;

    if (two) {
        pair = container_of(two, struct pair, base);
        pair->paired ++;
    }
}

static void pair_remaining(struct two_event *two, union perf_event *event, u64 key)
{
    struct pair *pair;

    if (two) {
        pair = container_of(two, struct pair, base);
        pair->unpaired ++;
        multi_trace_print(event, two->tp1);
    }
}

static void pair_print(struct two_event *two)
{
    struct pair *pair;

    if (two) {
        pair = container_of(two, struct pair, base);
        printf("%s:%s %s:%s paired %lu unpaired %lu\n", two->tp1->sys, two->tp1->name, two->tp2->sys, two->tp2->name,
                pair->paired, pair->unpaired);
    }
}

static struct two_event_class *pair_class_new(struct two_event_impl *impl, struct two_event_options *options)
{
    struct two_event_class *class = two_event_class_new(impl, options);

    if (class) {
        class->two = pair_two;
        class->remaining = pair_remaining;
        class->print = pair_print;
    }
    return class;
}

static struct two_event_impl pair_impl = {
    .name = TWO_EVENT_PAIR_IMPL,
    .class_size = sizeof(struct pair_class),
    .class_new = pair_class_new,

    .instance_size = sizeof(struct pair),
};




/*
 * Profile memory allocated and freed bytes.
 *
**/

struct mem_profile {
    struct two_event base;
    struct key_value_paires *alloc;
    struct key_value_paires *free;
    unsigned int nr_alloc;
    u64 alloc_bytes;
    unsigned int nr_free;
    u64 free_bytes;
};

struct mem_profile_class {
    struct two_event_class base;
    struct callchain_ctx *cc;
};

static struct two_event *mem_profile_new(struct two_event_class *class, struct tp *tp1, struct tp *tp2)
{
    struct two_event *two = NULL;
    struct mem_profile *profile = NULL;

    if (!tp1->mem_size) {
        fprintf(stderr, "%s:%s//size=?/ size attribute is not set\n", tp1->sys, tp1->name);
        return NULL;
    }
    if (!tp1->stack) {
        fprintf(stderr, "WARN: %s:%s//stack/ without stack attribute, memory allocations "
                        "cannot be profiled based on the stack.\n", tp1->sys, tp1->name);
    }
    if (!tp2->stack) {
        fprintf(stderr, "WARN: %s:%s//stack/ without stack attribute, memory deallocation "
                        "cannot be profiled based on the stack.\n", tp2->sys, tp2->name);
    }

    two = two_event_new(class, tp1, tp2);
    if (two) {
        profile = container_of(two, struct mem_profile, base);
        profile->alloc = keyvalue_pairs_new(sizeof(u64));
        profile->free = keyvalue_pairs_new(sizeof(u64));
    }
    return two;
}

static void mem_profile_delete(struct two_event_class *class, struct two_event *two)
{
    struct mem_profile *profile = NULL;

    if (two) {
        profile = container_of(two, struct mem_profile, base);
        keyvalue_pairs_free(profile->alloc);
        keyvalue_pairs_free(profile->free);
        two_event_delete(class, two);
    }
}

static void mem_profile_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key, struct event_iter *iter)
{
    struct mem_profile *profile = NULL;
    struct multi_trace_type_callchain *data;

    if (!two)
        return ;

    if (two) {
        struct tep_handle *tep;
        struct tep_record record;
        struct tep_event *e;
        unsigned long long bytes_alloc = 0;
        u64 *bytes;
        void *raw;
        int size;

        profile = container_of(two, struct mem_profile, base);

        tep = tep__ref();

        multi_trace_raw_size(event1, &raw, &size, two->tp1);
        memset(&record, 0, sizeof(record));
        record.size = size;
        record.data = raw;

        e = tep_find_event_by_record(tep, &record);
        if (tep_get_field_val(NULL, e, two->tp1->mem_size, &record, &bytes_alloc, 0) < 0) {
            bytes_alloc = 1;
        }

        profile->nr_alloc ++;
        profile->alloc_bytes += bytes_alloc;
        if (two->tp1->stack) {
            data = (void *)event1->sample.array;
            bytes = keyvalue_pairs_add_key(profile->alloc, (struct_key *)&data->callchain);
            *bytes += bytes_alloc;
        }

        if (event2) {
            profile->nr_free ++;
            profile->free_bytes += bytes_alloc;
            if (two->tp2->stack) {
                data = (void *)event2->sample.array;
                bytes = keyvalue_pairs_add_key(profile->free, (struct_key *)&data->callchain);
                *bytes += bytes_alloc;
            }
        }

        tep__unref();
    }
}

static void mem_profile_remaining(struct two_event *two, union perf_event *event, u64 key)
{
    mem_profile_two(two, event, NULL, key, NULL);
}

static int mem_profile_print_header(struct two_event *two)
{
    return 1;
}

static int __cmp(void **value1, void **value2)
{
    u64 *b1 = *(u64 **)value1;
    u64 *b2 = *(u64 **)value2;

    if (*b1 < *b2)
        return 1;
    else if (*b1 > *b2)
        return -1;
    else
        return 0;
}

static void __print_alloc(void *opaque, struct_key *key, void *value, unsigned int n)
{
    struct mem_profile *profile = opaque;
    struct mem_profile_class *mpclass = container_of(profile->base.class, struct mem_profile_class, base);
    u64 *bytes = value;
    printf("Allocate %lu (%.1f%%) bytes on %u (%.1f%%) objects:\n", *bytes, *bytes * 100.0 / profile->alloc_bytes,
                                                                     n, n * 100.0 / profile->nr_alloc);
    print_callchain_common(mpclass->cc, key, 0);
}

static void __print_free(void *opaque, struct_key *key, void *value, unsigned int n)
{
    struct mem_profile *profile = opaque;
    struct mem_profile_class *mpclass = container_of(profile->base.class, struct mem_profile_class, base);
    u64 *bytes = value;
    printf("Free %lu (%.1f%%) bytes on %u (%.1f%%) objects:\n", *bytes, *bytes * 100.0 / profile->free_bytes,
                                                                 n, n * 100.0 / profile->nr_free);
    print_callchain_common(mpclass->cc, key, 0);
}

static void mem_profile_print(struct two_event *two)
{
    struct mem_profile *profile = NULL;

    if (two) {
        profile = container_of(two, struct mem_profile, base);

        print_time(stdout);
        printf("\n%s:%s => %s:%s\n", two->tp1->sys, two->tp1->name, two->tp2->sys, two->tp2->name);

        printf("%s:%s total alloc %lu bytes on %u objects\n", two->tp1->sys, two->tp1->name, profile->alloc_bytes, profile->nr_alloc);
        keyvalue_pairs_sorted_firstn(profile->alloc, __cmp, __print_alloc, profile, two->class->opts.first_n);

        printf("%s:%s total free %lu bytes on %u objects\n", two->tp2->sys, two->tp2->name, profile->free_bytes, profile->nr_free);
        keyvalue_pairs_sorted_firstn(profile->free, __cmp, __print_free, profile, two->class->opts.first_n);
        printf("\n");

        //reset
        profile->nr_alloc = 0;
        profile->nr_free = 0;
        profile->alloc_bytes = 0;
        profile->free_bytes = 0;
        keyvalue_pairs_reinit(profile->alloc);
        keyvalue_pairs_reinit(profile->free);
    }
}

static struct two_event_class *mem_profile_class_new(struct two_event_impl *impl, struct two_event_options *options)
{
    struct two_event_class *class = two_event_class_new(impl, options);
    struct mem_profile_class *mpclass;

    if (class) {
        mpclass = container_of(class, struct mem_profile_class, base);
        class->two = mem_profile_two;
        class->remaining = mem_profile_remaining;
        class->print_header = mem_profile_print_header;
        class->print = mem_profile_print;
        mpclass->cc = callchain_ctx_new(CALLCHAIN_KERNEL, stdout);
    }
    return class;
}

static void mem_profile_class_delete(struct two_event_class *class)
{
    struct mem_profile_class *mpclass;
    if (class) {
        mpclass = container_of(class, struct mem_profile_class, base);
        callchain_ctx_free(mpclass->cc);
        two_event_class_delete(class);
    }
}


static struct two_event_impl mem_profile_impl = {
    .name = TWO_EVENT_MEM_PROFILE,
    .class_size = sizeof(struct mem_profile_class),
    .class_new = mem_profile_class_new,
    .class_delete = mem_profile_class_delete,

    .instance_size = sizeof(struct mem_profile),
    .object_new = mem_profile_new,
    .object_delete = mem_profile_delete,
};


struct two_event_impl *impl_get(const char *name)
{
    struct two_event_impl *impl = NULL;

    if (strcmp(name, delay_impl.name) == 0)
        impl = &delay_impl;
    else if (strcmp(name, pair_impl.name) == 0)
        impl = &pair_impl;
    else if (strcmp(name, mem_profile_impl.name) == 0)
        impl = &mem_profile_impl;
    else if (strcmp(name, syscalls_impl.name) == 0)
        impl = &syscalls_impl;

    if (impl)
        impl_init(impl);
    return impl;
}

