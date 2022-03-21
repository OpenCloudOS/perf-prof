#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/kernel.h>
#include <monitor.h>
#include <linux/ordered-events.h>


static struct order_ctx {
    profiler *base;
    profiler order;
    struct ordered_events oe;
    struct env *env;
} ctx;

/* in linux/perf_event.h
*  { u64           id;   } && PERF_SAMPLE_IDENTIFIER
*  { u64           ip;   } && PERF_SAMPLE_IP
*  { u32           pid, tid; } && PERF_SAMPLE_TID
*  { u64           time;     } && PERF_SAMPLE_TIME
*/
#define ORDER_SAMPLE_TYPE_MASK (PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME )
#define ORDER_SAMPLE_TYPE (PERF_SAMPLE_TID | PERF_SAMPLE_TIME)
struct order_event_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
};

static int ordered_events__deliver(struct ordered_events *oe,
					 struct ordered_event *event)
{
    ctx.base->sample(event->event, event->instance);
    return 0;
}

static void order_deinit(struct perf_evlist *evlist)
{
    ordered_events__flush(&ctx.oe, OE_FLUSH__FINAL);
    ctx.base->deinit(evlist);
    ordered_events__free(&ctx.oe);
}

static void order_interval(void)
{
    ordered_events__flush(&ctx.oe, OE_FLUSH__ROUND);
    ctx.base->interval();
}

static void order_sample(union perf_event *event, int instance)
{
    struct order_event_header *h = (void *)event->sample.array;
    ordered_events__queue(&ctx.oe, event, h->time, instance);
}

static int order_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    int err;

    ctx.env = env;
    ctx.base->reinit = ctx.order.reinit;
    ctx.base->pages = ctx.order.pages;
    ctx.base->cpus  = ctx.order.cpus;
    ctx.base->threads = ctx.order.threads;

    err = ctx.base->init(evlist, env);
    if (err) return err;
    perf_evlist__for_each_evsel(evlist, evsel) {
        struct perf_event_attr *attr = perf_evsel__attr(evsel);
        if (attr->sample_period != 0 &&
            (attr->sample_type & ORDER_SAMPLE_TYPE_MASK) != ORDER_SAMPLE_TYPE) {
            fprintf(stderr, "--order cannot be enabled\n");
            return -1;
        }
    }

    ctx.order = *ctx.base;
    ctx.order.init = order_init;
    ctx.order.deinit = order_deinit;
    ctx.order.sample = order_sample;
    if (env->interval && ctx.base->interval)
        ctx.order.interval = order_interval;

    ordered_events__init(&ctx.oe, ordered_events__deliver, NULL);
    ordered_events__set_copy_on_queue(&ctx.oe, true);
    if (env->order_mem)
        ordered_events__set_alloc_size(&ctx.oe, env->order_mem);
    return 0;
}

profiler *order(profiler *p)
{
    if (p != &ctx.order) {
        ctx.base = p;
        ctx.order = *p;
        ctx.order.init = order_init;
    }
    return &ctx.order;
}

bool using_order(profiler *p)
{
    if (p != NULL)
        return ctx.base == p;
    else
        return ctx.base != NULL;
}

void reduce_wakeup_times(profiler *p, struct perf_event_attr *attr)
{
    u32 order_watermark = UINT_MAX;
    u32 pages_watermark = UINT_MAX;

    if (!p->pages)
        return;

    if (attr->sample_period == 0)
        return;

    if (!using_order(p)) {
        attr->watermark = 0;
        attr->wakeup_events = 1;
        return;
    }

    pages_watermark = (p->pages << 12) / 4;
    /*
     * When order-mem is enabled and perf-prof is woken up, all perf_events must be
     * read, so order-mem needs enough space to store perf_events.
     */
    if (ctx.env->order_mem)
        order_watermark = (u32)(ctx.env->order_mem / monitor_nr_instance() / 2);

    attr->watermark = 1;
    attr->wakeup_watermark = min(pages_watermark, order_watermark);
}

