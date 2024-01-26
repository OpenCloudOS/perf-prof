#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <monitor.h>
#include <tep.h>

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

