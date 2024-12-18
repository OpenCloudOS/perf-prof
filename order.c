#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/kernel.h>
#include <monitor.h>
#include <internal/mmap.h>


// heap sort element
struct heap_event {
    struct list_head link;
    struct prof_dev *dev;
    union perf_event *event;
    u64 time;
    int ins;
    bool writable;
};

struct perf_mmap_event {
    struct heap_event base;
    struct perf_mmap *map;
    /*
     * A monotonically increasing timestamp for
     * each perf_map event.
     */
    u64 event_mono_time;
};

static bool less_than(const void *lhs, const void *rhs, void __maybe_unused *args)
{
    struct heap_event *a = *(struct heap_event **)lhs;
    struct heap_event *b = *(struct heap_event **)rhs;
    return a->time < b->time;
}

int order_init(struct prof_dev *dev)
{
    struct perf_mmap *map;
    int nr_mmaps = 0, heap_size = 0;
    struct perf_mmap_event *mmap_event;

    if (dev->order.enabled)
        return 0;

    if (perf_sample_time_init(dev) < 0)
        return -1;
    if (!(dev->pos.sample_type & PERF_SAMPLE_TIME)) {
        fprintf(stderr, "--order cannot be enabled\n");
        return -1;
    }

    perf_evlist__for_each_mmap(dev->evlist, map, dev->env->overwrite)
        nr_mmaps++;
    heap_size += nr_mmaps;

    dev->order.heap_size = heap_size;
    dev->order.data = calloc(heap_size, sizeof(*dev->order.data));
    if (!dev->order.data)
        return -1;
    min_heap_init(&dev->order.heapsort, dev->order.data, heap_size);

    dev->order.nr_mmaps = nr_mmaps;
    dev->order.permap_event = calloc(nr_mmaps, sizeof(struct perf_mmap_event));
    dev->order.heap_popped_time = 0;

    if (!dev->order.permap_event)
        goto failed;

    perf_evlist__for_each_mmap(dev->evlist, map, dev->env->overwrite) {
        int idx = perf_mmap__idx(map);

        mmap_event = (struct perf_mmap_event *)dev->order.permap_event + idx;
        mmap_event->base.dev = dev;
        mmap_event->base.ins = idx;
        mmap_event->map = map;

        list_add(&mmap_event->base.link, &dev->order.heap_event_list);
    }

    dev->order.enabled = 1;
    return 0;

failed:
    order_deinit(dev);
    return -1;
}

void order_deinit(struct prof_dev *dev)
{
    struct heap_event *heap_event, *tmp;
    struct perf_mmap_event *mmap_event;
    int i;

    for (i = 0; i < dev->order.nr_mmaps; i++) {
        mmap_event = (struct perf_mmap_event *)dev->order.permap_event + i;
        list_del(&mmap_event->base.link);
    }
    list_for_each_entry_safe(heap_event, tmp, &dev->order.heap_event_list, link)
        list_del(&heap_event->link);

    if (dev->order.data)
        free(dev->order.data);
    if (dev->order.permap_event)
        free(dev->order.permap_event);
}

static int perf_mmap_event_init(struct heap_event *heap_event)
{
    struct perf_mmap_event *mmap_event = (struct perf_mmap_event *)heap_event;
    struct prof_dev *dev = heap_event->dev;
    struct perf_mmap *map = mmap_event->map;
    int ins = heap_event->ins;
    union perf_event *event;
    bool writable;

    if (perf_mmap__read_init(map) < 0)
        return -1;

retry:
    event = perf_mmap__read_event(map, &writable);
    if (event) {
        /* Only the PERF_RECORD_SAMPLE event can sample time. */
        if (event->header.type != PERF_RECORD_SAMPLE) {
            perf_event_process_record(dev, event, ins, writable, false);
            perf_mmap__consume(map);
            goto retry;
        }

        heap_event->event = event;
        heap_event->time = *(u64 *)((void *)event->sample.array + dev->pos.time_pos);
        heap_event->writable = writable;

        return 0;
    } else
        perf_mmap__read_done(map);

    return -1;
}

void order_process(struct prof_dev *dev, struct perf_mmap *target_map)
{
    struct perf_mmap *map;
    union perf_event *event;
    u64 time;
    int ins;
    bool writable;
    u64 target_end;

    // heap sort
    struct perf_mmap_event *mmap_event;
    struct heap_event *heap_event;
    DEFINE_MIN_HEAP(struct heap_event *, ) *heap;
    struct min_heap_callbacks funcs = {
        .less = less_than,
        .swp = NULL,
    };

    if (perf_mmap__read_init(target_map) < 0)
        return;
    if (perf_mmap__empty(target_map))
        return;

    /*
     * Get the latest event of ringbuffer(perf_mmap). According to the causal
     * relationship, when I see the latest event, events that occurred before
     * the latest on other ringbuffers must have been written.
     *
     * Therefore, if any ringbuffer is empty, there is no need to pay attention
     * to it until the latest event of `target_map' is processed. `target_map->
     * end' points to the end of the latest event.
     */
    target_end = target_map->end;

    heap = (void *)&dev->order.heapsort;
    heap->nr = 0;

    list_for_each_entry(heap_event, &dev->order.heap_event_list, link) {
        if (perf_mmap_event_init(heap_event) == 0) {
            heap->data[heap->nr++] = heap_event;
        }
    }

    // heap sort start
    min_heapify_all(heap, &funcs, NULL);
    while (1) {
        struct heap_event **data = min_heap_peek(heap);
        bool need_break = 0;
        union perf_event *tmp = NULL;

        if (!data)
            break;

        heap_event = data[0];
        mmap_event = (struct perf_mmap_event *)heap_event;

        dev = heap_event->dev;
        map = mmap_event->map;
        event = heap_event->event;
        time = heap_event->time;
        ins = heap_event->ins;
        writable = heap_event->writable;


        /* Keep order in perf_mmap. Why do this?
         *
         *       sh  99330 .... [036] 341318.491172: sched:sched_process_free
         *    ffffffff81086437 delayed_put_task_struct+0x87 ([kernel.kallsyms])
         *    ...
         *    ffffffff81089a45 irq_exit+0xd5 ([kernel.kallsyms])
         *    ffffffff81c024f3 smp_apic_timer_interrupt+0x83 ([kernel.kallsyms])
         *    ffffffff81c01a7f apic_timer_interrupt+0xf ([kernel.kallsyms])
         *    ffffffff811cfe6b __perf_event_header__init_id+0x9b ([kernel.kallsyms])
         *    ffffffff811dd5d7 perf_prepare_sample+0x67 ([kernel.kallsyms])
         *    ffffffff811ddaaf perf_event_output_forward+0x2f ([kernel.kallsyms])
         *    ffffffff811d1f77 __perf_event_overflow+0x57 ([kernel.kallsyms])
         *    ffffffff811d2053 perf_swevent_overflow+0x43 ([kernel.kallsyms])
         *    ffffffff811d212d perf_swevent_event+0x5d ([kernel.kallsyms])
         *    ffffffff811d2492 perf_tp_event+0xe2 ([kernel.kallsyms])
         *    ...
         *
         * After the time is obtained in __perf_event_header__init_id(), but before
         * it is output, an interrupt occurs, and the events later in time are output
         * first.
         */
        if (unlikely(time < mmap_event->event_mono_time)) {
            if (dev->env->verbose)
                printf("%s: fix out-of-order event %lu < %lu\n", dev->prof->name,
                                                time, mmap_event->event_mono_time);
            tmp = memdup(event, event->header.size);
            time = mmap_event->event_mono_time;
            *(u64 *)((void *)tmp->sample.array + dev->pos.time_pos) = time;
            writable = 1;
            dev->order.nr_fixed_events++;
        } else
            mmap_event->event_mono_time = time;

        if (unlikely(time < dev->order.heap_popped_time)) {
            dev->order.nr_unordered_events++;
            fprintf(stderr, "%s: out-of-order event %lu %lu %d\n", dev->prof->name, time, dev->order.heap_popped_time, dev->pos.time_pos);
        } else
            dev->order.heap_popped_time = time;


    process:
        perf_event_process_record(dev, tmp ?: event, ins, writable, false);
        perf_mmap__consume(map);

        if (tmp) {
            free(tmp);
            tmp = NULL;
        }

        if (map == target_map && map->start == target_end)
            need_break = 1;

        event = perf_mmap__read_event(map, &writable);
        if (event) {
            if (event->header.type != PERF_RECORD_SAMPLE) {
                goto process;
            }

            heap_event->event = event;
            heap_event->time = *(u64 *)((void *)event->sample.array + dev->pos.time_pos);
            heap_event->writable = writable;
            min_heap_sift_down(heap, 0, &funcs, NULL);
        } else {
            perf_mmap__read_done(map);
            min_heap_pop(heap, &funcs, NULL);
        }

        if (need_break)
            break;
    }


    while (heap->nr) {
        heap_event = heap->data[--heap->nr];
        mmap_event = (struct perf_mmap_event *)heap_event;
        perf_mmap__unread_event(mmap_event->map, heap_event->event);
    }
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

