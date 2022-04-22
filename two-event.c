#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/zalloc.h>
#include <linux/rblist.h>
#include <monitor.h>
#include <tep.h>
#include <trace_helpers.h>
#include <stack_helpers.h>
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

static void dummy_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key) {}
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

struct delay_stat {
    struct rb_node rbnode;
    u64 key;
    u64 min;
    u64 max;
    u64 n;
    u64 sum;
};

struct delay {
    struct two_event base;
    struct rblist perins_stat;
    struct delay_stat totins_stat;
    struct heatmap *heatmap;
};

struct delay_class {
    struct two_event_class base;
    int max_len1;
    int max_len2;
};

static int delay_stat_node_cmp(struct rb_node *rbn, const void *entry)
{
    struct delay_stat *d = container_of(rbn, struct delay_stat, rbnode);
    const u64 *key = entry;

    if (d->key > *key)
        return 1;
    else if (d->key < *key)
        return -1;
    else
        return 0;
}

static struct rb_node *delay_stat_node_new(struct rblist *rlist, const void *new_entry)
{
    const u64 *key = new_entry;
    struct delay_stat *d = malloc(sizeof(*d));
    if (d) {
        RB_CLEAR_NODE(&d->rbnode);
        d->key = *key;
        d->min = ~0UL;
        d->max = d->n = d->sum = 0;
        return &d->rbnode;
    } else
        return NULL;
}

static void delay_stat_node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct delay_stat *d = container_of(rb_node, struct delay_stat, rbnode);
    free(d);
}


static struct two_event *delay_new(struct two_event_class *class, struct tp *tp1, struct tp *tp2)
{
    struct two_event *two = two_event_new(class, tp1, tp2);
    struct delay *delay = NULL;
    struct delay_class *delay_class = NULL;

    if (two) {
        delay = container_of(two, struct delay, base);
        delay_class = container_of(two->class, struct delay_class, base);

        rblist__init(&delay->perins_stat);
        delay->perins_stat.node_cmp = delay_stat_node_cmp;
        delay->perins_stat.node_new = delay_stat_node_new;
        delay->perins_stat.node_delete = delay_stat_node_delete;

        delay->totins_stat.min = ~0UL;
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
        rblist__exit(&delay->perins_stat);
        two_event_delete(class, two);
    }
}

static void delay_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key)
{
    struct delay *delay = NULL;
    struct rb_node *rbn = NULL;
    struct two_event_options *opts;
    struct delay_stat *stat = NULL;
    struct multi_trace_type_header *e1 = (void *)event1->sample.array;
    struct multi_trace_type_header *e2 = (void *)event2->sample.array;
    u64 delta = 0;

    if (two) {
        delay = container_of(two, struct delay, base);
        opts = &two->class->opts;

        if (e2->time > e1->time) {
            delta = e2->time - e1->time;
            if (opts->perins) {
                rbn = rblist__findnew(&delay->perins_stat, &key);
                if (rbn) {
                    stat = container_of(rbn, struct delay_stat, rbnode);

                    if (delta < stat->min)
                        stat->min = delta;
                    if (delta > stat->max)
                        stat->max = delta;
                    stat->n ++;
                    stat->sum += delta;
                }
            }
            stat = &delay->totins_stat;
            if (delta < stat->min)
                stat->min = delta;
            if (delta > stat->max)
                stat->max = delta;
            stat->n ++;
            stat->sum += delta;

            if (delay->heatmap)
                heatmap_write(delay->heatmap, e2->time, delta);

            if (opts->greater_than && delta > opts->greater_than) {
                multi_trace_print(event1, two->tp1);
                multi_trace_print(event2, two->tp2);
            }
        }
    }
}

static int delay_print_header(struct two_event *two)
{
    struct delay *delay = NULL;
    struct delay_class *delay_class = NULL;
    struct two_event_options *opts;
    const char *str_keytype[] = {
        [K_CPU] = "CPU",
        [K_THREAD] = "THREAD",
        [K_CUSTOM] = "CUSTOM"
    };
    int i;

    if (two) {
        delay = container_of(two, struct delay, base);
        delay_class = container_of(two->class, struct delay_class, base);
        opts = &two->class->opts;

        if (opts->perins) {
            if (rblist__nr_entries(&delay->perins_stat) == 0)
                return 0;
        } else {
            struct delay_stat *stat = &delay->totins_stat;
            if (stat->n == 0)
                return 0;
        }

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
        return 1;
    }
    return 0;
}

static void delay_print(struct two_event *two)
{
    struct delay *delay = NULL;
    struct delay_class *delay_class = NULL;
    struct two_event_options *opts;
    struct delay_stat *stat;
    struct rb_node *node = NULL, *next = NULL;

    if (two) {
        delay = container_of(two, struct delay, base);
        delay_class = container_of(two->class, struct delay_class, base);
        opts = &two->class->opts;
        if (!opts->perins) {
            stat = &delay->totins_stat;
            goto print_stat;
        }
        for (node = rb_first_cached(&delay->perins_stat.entries); node;
	         node = next) {
            next = rb_next(node);
		    stat = container_of(node, struct delay_stat, rbnode);
        print_stat:
            if (stat->n) {
                if (opts->perins) {
                    printf("[%*lu] ", opts->keytype == K_CPU ? 3 : 6, stat->key);
                }
                printf("%*s", delay_class->max_len1, two->tp1->name);
                printf(" => %-*s", delay_class->max_len2, two->tp2->name);
                printf(" %8lu %16.3f %9.3f %9.3f %12.3f\n",
                    stat->n, stat->sum/1000.0, stat->min/1000.0, stat->sum/stat->n/1000.0, stat->max/1000.0);

                stat->min = ~0UL;
                stat->max = stat->n = stat->sum = 0;
            } else {
                if (opts->perins) {
                    rblist__remove_node(&delay->perins_stat, node);
                }
            }
        }
    }
}

static struct two_event_class *delay_class_new(struct two_event_impl *impl, struct two_event_options *options)
{
    struct two_event_class *class = two_event_class_new(impl, options);

    if (class) {
        class->two = delay_two;
        class->print_header = delay_print_header;
        class->print = delay_print;
    }
    return class;
}

static struct two_event_impl delay_impl = {
    .name = TWO_EVENT_DELAY_IMPL,
    .class_size = sizeof(struct delay_class),
    .class_new = delay_class_new,

    .instance_size = sizeof(struct delay),
    .object_new = delay_new,
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

static void pair_two(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key)
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

struct two_event_impl *impl_get(const char *name)
{
    struct two_event_impl *impl = NULL;

    if (strcmp(name, delay_impl.name) == 0)
        impl = &delay_impl;
    else if (strcmp(name, pair_impl.name) == 0)
        impl = &pair_impl;

    if (impl)
        impl_init(impl);
    return impl;
}

