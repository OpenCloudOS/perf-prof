#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/kernel.h>
#include <monitor.h>
#include <linux/ordered-events.h>

static int ordered_events__deliver(struct ordered_events *oe,
					 struct ordered_event *event)
{
    struct prof_dev *dev = container_of(oe, struct prof_dev, order.oe);
    profiler *base = dev->order.base;

    base->sample(dev, event->event, event->instance);

    // The base profiler is responsible for releasing the dup event.
    if (dev->dup)
        event->event = NULL;
    else
        perf_event_put(event->event);

    return 0;
}

static void print_nr_unordered_events(struct prof_dev *dev, bool sample)
{
    unsigned int nr_events = dev->order.oe.nr_events;
    u32 nr_unordered_events = dev->order.oe.nr_unordered_events;
    u64 max_timestamp = dev->order.oe.max_timestamp;

    if (nr_events > 0 && nr_unordered_events != dev->order.nr_unordered_events &&
        (!sample || max_timestamp != dev->order.max_timestamp)) {
        dev->order.nr_unordered_events = nr_unordered_events;
        dev->order.max_timestamp = max_timestamp;
        print_time(stderr);
        fprintf(stderr, "%s: Out of order %u, use a larger --order-mem parameter.\n",
                dev->prof->name, nr_unordered_events);
    }
}

static void order_flush(struct prof_dev *dev, enum profdev_flush how)
{
    profiler *base = dev->order.base;
    enum oe_flush oe_how;

    switch (how) {
        default:
        case PROF_DEV_FLUSH_NORMAL:
            return;
        case PROF_DEV_FLUSH_FINAL:
            oe_how = OE_FLUSH__FINAL;
            break;
        case PROF_DEV_FLUSH_ROUND:
            oe_how = OE_FLUSH__ROUND;
            break;
    }

    print_nr_unordered_events(dev, false);
    ordered_events__flush(&dev->order.oe, oe_how);

    if (how == PROF_DEV_FLUSH_FINAL) {
        ordered_events__reinit(&dev->order.oe);
        ordered_events__set_copy_on_queue(&dev->order.oe, true);
        if (dev->env->order_mem)
            ordered_events__set_alloc_size(&dev->order.oe, dev->env->order_mem);
    }

    if (base->flush)
        base->flush(dev, how);
}

static void order_deinit(struct prof_dev *dev)
{
    profiler *base = dev->order.base;
    base->deinit(dev);
    ordered_events__free(&dev->order.oe);
    if (base->lost)
        free(dev->order.lost_records);
}

static void order_interval(struct prof_dev *dev)
{
    profiler *base = dev->order.base;
    print_nr_unordered_events(dev, false);
    ordered_events__flush(&dev->order.oe, OE_FLUSH__ROUND);
    if (base->interval)
        base->interval(dev);
}

static void order_lost(struct prof_dev *dev, union perf_event *event, int ins, u64 lost_start, u64 lost_end)
{
    profiler *base = dev->order.base;
    if (base->lost) {
        dev->order.lost_records[ins].lost = event->lost;
        dev->order.lost_records[ins].ins = ins;
    }
}

static void order_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    profiler *base = dev->order.base;
    void *data = (void *)event->sample.array;
    u64 time = *(u64 *)(data + dev->time_ctx.time_pos);

    if (base->lost) {
        struct lost_record *lost_rec = &dev->order.lost_records[instance];
        if (unlikely(lost_rec->lost.lost)) {
            base->lost(dev, (union perf_event *)&lost_rec->lost, instance,
                            lost_rec->lost_start_time, time);
            lost_rec->lost.lost = 0;
        }
        lost_rec->lost_start_time = time;
    }
    ordered_events__queue(&dev->order.oe, perf_event_get(event), time, instance);

    if (dev->order.flush_in_time)
        ordered_events__flush_time(&dev->order.oe, time);

    /*
     * Use this command:
     *   perf-prof multi-trace -e XX:YYY -e XX:ZZZ,task-state//untraced/ -p 1234 --order \
     *             --than 10ms --detail=sametid
     *
     * multi-trace uses task-state as an event source, and the events it generates will be
     * forwarded to mult-trace. And task-state will enable order by default, its
     * order.flush_in_time = true.
     *
     * The task-state events of pid 1234 will be cached inside multi-trace. When printing
     * events that exceed 10ms from XX:YYY -> XX:ZZZ, the task-state events within these
     * 10ms are in order. The order_sample() of task-state will be flushed in time.
     *
     * The task-state events of the next 10ms and the previous 10ms may not be ordered.
     * Here, an "Out of order" warning will be printed.
     */
    print_nr_unordered_events(dev, true);
}

static int order_init(struct prof_dev *dev)
{
    profiler *base = dev->order.base;
    profiler *order = &dev->order.order;
    int err;

    err = base->init(dev);
    if (err) return err;

    if (perf_sample_time_init(dev) < 0)
        return -1;
    if (!(dev->time_ctx.sample_type & PERF_SAMPLE_TIME)) {
        fprintf(stderr, "--order cannot be enabled\n");
        return -1;
    }

    *order = *base;
    order->init = order_init;
    order->deinit = order_deinit;
    order->flush = order_flush;
    order->sample = order_sample;
    if (base->lost)
        order->lost = order_lost;
    order->interval = order_interval;

    if (base->lost) {
        dev->order.lost_records = calloc(prof_dev_nr_ins(dev), sizeof(*dev->order.lost_records));
        if (!dev->order.lost_records)
            return -1;
    }

    ordered_events__init(&dev->order.oe, ordered_events__deliver, NULL);
    ordered_events__set_copy_on_queue(&dev->order.oe, true);
    if (dev->env->order_mem)
        ordered_events__set_alloc_size(&dev->order.oe, dev->env->order_mem);
    return 0;
}

void order(struct prof_dev *dev)
{
    if (dev->prof != &dev->order.order) {
        dev->order.base = dev->prof;
        dev->order.order = *dev->prof;
        dev->order.order.init = order_init;
        dev->prof = &dev->order.order;
    }
}

bool using_order(struct prof_dev *dev)
{
    return dev->prof == &dev->order.order;
}

void ordered_events(struct prof_dev *dev)
{
    if (using_order(dev))
        dev->order.flush_in_time = true;
}

void reduce_wakeup_times(struct prof_dev *dev, struct perf_event_attr *attr)
{
    struct env *env = dev->env;
    u32 wakeup_watermark = 0;
    u32 wakeup_events = 0;
    int watermark;

    if (!dev->pages)
        return;

    if (attr->sample_period == 0)
        return;

    if (env->watermark_set)
        watermark = env->watermark;
    else {
        if (!attr->watermark) {
            /*
             * Enable watermark to reduce the number of wake-ups.
             * For device wakeup_events = 1, when used as a child-device, adjust to use watermark.
             *
             * In principle, it should be the forwarding source device, which will be flushed by
             * the parent device. However, when reduce_wakeup_times() is called, the device cannot
             * yet be marked as a forwarding source, so prof_dev_has_parent() is used.
             */
            if (prof_dev_has_parent(dev))
                watermark = 50;
            else {
                watermark = 0;
                wakeup_events = attr->wakeup_events;
            }
        } else {
            watermark = 50;
            wakeup_watermark = attr->wakeup_watermark;
        }
    }

    if (watermark == 0) {
        attr->watermark = 0;
        attr->wakeup_events = wakeup_events ? : 1;
    } else {
        if (wakeup_watermark == 0) {
            u32 order_watermark = UINT_MAX;
            u32 pages_watermark = (dev->pages << 12);

            /*
             * When order-mem is enabled and perf-prof is woken up, all perf_events must be
             * read, so order-mem needs enough space to store perf_events.
             */
            if (using_order(dev) && env->order_mem)
                order_watermark = (u32)(env->order_mem / prof_dev_nr_ins(dev));

            wakeup_watermark = min(pages_watermark, order_watermark) * watermark / 100;
        }
        attr->watermark = 1;
        attr->wakeup_watermark = wakeup_watermark;
    }
}

