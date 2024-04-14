#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>

#include <monitor.h>
#include <tep.h>
#include <linux/thread_map.h>


/*
 *  { u64           id;   } && PERF_SAMPLE_IDENTIFIER
 *  { u64           ip;   } && PERF_SAMPLE_IP
 *  { u32           pid, tid; } && PERF_SAMPLE_TID
 *  { u64           time;     } && PERF_SAMPLE_TIME
 */
#define SAMPLE_TYPE_MASK (PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME)

u64 rdtsc(void)
{
#if defined(__i386__) || defined(__x86_64__)
	unsigned int low, high;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((u64)high) << 32;
#else
    return 0;
#endif
}

static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift)
{
	u32 ah, al;
	u64 ret;

	al = a;
	ah = a >> 32;

	ret = ((u64)al * mul) >> shift;
	if (ah)
		ret += ((u64)ah * mul) << (32 - shift);

	return ret;
}

static inline u64 perf_tsc_to_ns(struct prof_dev *dev, u64 tsc)
{
    struct perf_tsc_conversion *tc = &dev->convert.tsc_conv;
    u64 ns;

    tsc -= dev->env->tsc_offset;
    ns = mul_u64_u32_shr(tsc, tc->time_mult, tc->time_shift);
    return ns + tc->time_zero;
}

u64 perf_time_to_ns(struct prof_dev *dev, u64 time)
{
    if (likely(!dev->convert.need_tsc_conv))
        return time;
    else
        return perf_tsc_to_ns(dev, time);
}

static inline u64 __perf_time_to_tsc(struct prof_dev *dev, u64 ns)
{
    struct perf_tsc_conversion *tc = &dev->convert.tsc_conv;
    u64 t, quot, rem;

    t = ns - tc->time_zero;
    quot = t / tc->time_mult;
    rem  = t % tc->time_mult;
    return (quot << tc->time_shift) +
           (rem << tc->time_shift) / tc->time_mult +
           dev->env->tsc_offset;
}

u64 perf_time_to_tsc(struct prof_dev *dev, u64 time)
{
    if (likely(!dev->convert.need_tsc_conv))
        return time;
    else
        return __perf_time_to_tsc(dev, time);
}

static inline bool is_sampling_event(struct perf_event_attr *attr)
{
	return attr->sample_period != 0;
}

int perf_sample_forward_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_evsel *evsel;
    u64 mask = PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
               PERF_SAMPLE_ADDR | PERF_SAMPLE_ID | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU;
    u64 sample_type_mask = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU;
    u64 sample_type = 0;
    int pos = 0;

    perf_evlist__for_each_evsel(evlist, evsel) {
        struct perf_event_attr *attr = perf_evsel__attr(evsel);
        if (is_sampling_event(attr)) {
            if (sample_type == 0) {
                sample_type = attr->sample_type & mask;
            } else if (sample_type != (attr->sample_type & mask)) {
                fprintf(stderr, "Could not init forward: sample_type mismatch.\n");
                return -1;
            }
        }
    }

    if ((sample_type & sample_type_mask) != sample_type_mask) {
        fprintf(stderr, "Could not init forward: sample_type mismatch.\n");
        return -1;
    }

    dev->forward.id_pos = -1;

    if (sample_type & PERF_SAMPLE_IDENTIFIER)
        pos += sizeof(u64);
    if (sample_type & PERF_SAMPLE_IP)
        pos += sizeof(u64);
    if (sample_type & PERF_SAMPLE_TID) {
        dev->forward.tid_pos = pos;
        pos += sizeof(u32) + sizeof(u32);
    }
    if (sample_type & PERF_SAMPLE_TIME) {
        dev->forward.time_pos = pos;
        pos += sizeof(u64);
    }
    if (sample_type & PERF_SAMPLE_ADDR)
        pos += sizeof(u64);
    if (sample_type & PERF_SAMPLE_ID) {
        dev->forward.id_pos = pos;
        pos += sizeof(u64);
    }
    if (sample_type & PERF_SAMPLE_STREAM_ID)
        pos += sizeof(u64);
    if (sample_type & PERF_SAMPLE_CPU) {
        dev->forward.cpu_pos = pos;
        pos += sizeof(u32) + sizeof(u32);
    }

    dev->forward.forwarded_time_pos = sizeof(u32) + sizeof(u32); // PERF_SAMPLE_TID

    return 0;
}

int perf_sample_time_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_evsel *evsel;
    u64 sample_type = 0;

    perf_evlist__for_each_evsel(evlist, evsel) {
        struct perf_event_attr *attr = perf_evsel__attr(evsel);
        if (is_sampling_event(attr)) {
            if (sample_type == 0) {
                sample_type = attr->sample_type & SAMPLE_TYPE_MASK;
            } else if (sample_type != (attr->sample_type & SAMPLE_TYPE_MASK)) {
                fprintf(stderr, "Could not init time_ctx: sample_type mismatch.\n");
                return -1;
            }
        }
    }

    dev->time_ctx.sample_type = sample_type;
    dev->time_ctx.time_pos = 0;
    dev->time_ctx.last_evtime = ULLONG_MAX;

    if (sample_type & PERF_SAMPLE_TIME) {
        if (sample_type & PERF_SAMPLE_IDENTIFIER)
            dev->time_ctx.time_pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_IP)
            dev->time_ctx.time_pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_TID)
            dev->time_ctx.time_pos += sizeof(u32) + sizeof(u32);
    }
    return 0;
}

int perf_event_convert_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    u64 sample_type = 0;
    int err;

    err = perf_sample_time_init(dev);

    if (!env->tsc && !env->tsc_offset) {
        dev->convert.need_tsc_conv = false;
        return 0;
    }

    if (err < 0)
        return -1;

    sample_type = dev->time_ctx.sample_type;
    if (sample_type & PERF_SAMPLE_TIME) {
        env->tsc = true;
        dev->convert.need_tsc_conv = true;

        dev->convert.event_copy = malloc(PERF_SAMPLE_MAX_SIZE);
        if (!dev->convert.event_copy) {
            fprintf(stderr, "Could not alloc event_copy.\n");
            return -1;
        }
    } else {
        env->tsc = false;
        env->tsc_offset = 0;
        dev->convert.need_tsc_conv = false;
    }

    return 0;
}

void perf_event_convert_deinit(struct prof_dev *dev)
{
    if (dev->convert.event_copy)
        free(dev->convert.event_copy);
    dev->convert.need_tsc_conv = false;
}

void perf_event_convert_read_tsc_conversion(struct prof_dev *dev, struct perf_mmap *map)
{
    if (unlikely(dev->convert.need_tsc_conv)) {
        if (perf_mmap__read_tsc_conversion(map, &dev->convert.tsc_conv) == -EOPNOTSUPP) {
            fprintf(stderr, "TSC conversion is not supported.\n");
            dev->env->tsc = false;
            dev->env->tsc_offset = 0;
            dev->convert.need_tsc_conv = false;
        }
    }
}

union perf_event *perf_event_convert(struct prof_dev *dev, union perf_event *event, bool writable)
{
    void *data;
    u64 *time;

    if (likely(!dev->convert.need_tsc_conv))
        return event;

    if (likely(!writable)) {
        memcpy(dev->convert.event_copy, event, event->header.size);
        event = (union perf_event *)dev->convert.event_copy;
    }

    data = (void *)event->sample.array;

    time = (u64 *)(data + dev->time_ctx.time_pos);
    *time = __perf_time_to_tsc(dev, *time);

    return event;
}


static int evtime_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TIME,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 0,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int id = tep__event_id("syscalls", "sys_enter_getpid");

    if (id < 0) goto failed;

    dev->private = NULL;
    dev->type = PROF_DEV_TYPE_SERVICE;

    attr.config = id;
    evsel = perf_evsel__new(&attr);
    if (!evsel)  goto failed;
    perf_evlist__add(evlist, evsel);

    return 0;
failed:
    return -1;
}

static void evtime_deinit(struct prof_dev *dev)
{
}

static void evtime_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct prof_dev *pdev = dev->private;
    // PERF_SAMPLE_TIME
    struct sample_type_header {
        __u64   time;
    } *data = (void *)event->sample.array;

    pdev->time_ctx.base_evtime = data->time;
}

static profiler evtime = {
    .name = "event-basetime",
    .pages = 1,
    .init = evtime_init,
    .deinit = evtime_deinit,
    .sample = evtime_sample,
};

int perf_timespec_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct perf_mmap *map;
    struct perf_thread_map *tidmap;
    struct env *e = NULL;
    struct prof_dev *evt;

    if (!dev->pages || dev->prof == &evtime)
        return 0;

    if (!(dev->time_ctx.sample_type & PERF_SAMPLE_TIME))
        return 0;

    perf_evlist__for_each_mmap(evlist, map, dev->env->overwrite) {
        int err = 0;
        perf_event_convert_read_tsc_conversion(dev, map);
        if (dev->convert.need_tsc_conv ||
            (err = perf_mmap__read_tsc_conversion(map, &dev->convert.tsc_conv)) == 0) {
            clock_gettime(CLOCK_REALTIME, &dev->time_ctx.base_timespec);
            dev->time_ctx.base_evtime = rdtsc();
            if (dev->time_ctx.base_evtime > 0) {
                dev->time_ctx.base_evtime += dev->env->tsc_offset;
                if (!dev->convert.need_tsc_conv)
                    dev->time_ctx.base_evtime = perf_tsc_to_ns(dev, dev->time_ctx.base_evtime);
                return 0;
            }
        }
        if (err == -EOPNOTSUPP)
            break;
    }

    tidmap = thread_map__new_by_tid(getpid());
    if (!tidmap) goto NULL_tidmap;

    e = zalloc(sizeof(*e)); // free in prof_dev_close()
    if (!e) goto NULL_e;
    e->tsc = dev->env->tsc;
    e->tsc_offset = dev->env->tsc_offset;

    evt = prof_dev_open_cpu_thread_map(&evtime, e, NULL, tidmap, NULL);
    e = NULL;
    if (!evt) goto NULL_e;

    evt->private = dev;

    // trigger getpid syscall
    clock_gettime(CLOCK_REALTIME, &dev->time_ctx.base_timespec);
    syscall(SYS_getpid); // syscall does not necessarily occur with getpid().

    prof_dev_flush(evt, PROF_DEV_FLUSH_NORMAL);
    prof_dev_close(evt);

    if (dev->time_ctx.base_evtime == 0) {
        dev->time_ctx.base_timespec.tv_sec = 0;
        dev->time_ctx.base_timespec.tv_nsec = 0;
    }

NULL_e:
    perf_thread_map__put(tidmap);
NULL_tidmap:
    return dev->time_ctx.base_evtime > 0 ? 0 : -1;
}
