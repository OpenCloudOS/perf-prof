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
#define CONVERT_SAMPLE_TYPE_MASK (PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME)

static struct perf_event_convert_ctx {
    struct env *env;
    u64 sample_type;

    // tsc convert
    bool need_tsc_conv;
    int time_offset;
    struct perf_tsc_conversion tsc_conv;

    char __aligned(8) event_copy[PERF_SAMPLE_MAX_SIZE];
} convert_ctx;


u64 rdtsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((u64)high) << 32;
}

static inline u64 perf_time_to_tsc(u64 ns)
{
    struct perf_tsc_conversion *tc = &convert_ctx.tsc_conv;
    u64 t, quot, rem;

    t = ns - tc->time_zero;
    quot = t / tc->time_mult;
    rem  = t % tc->time_mult;
    return (quot << tc->time_shift) +
           (rem << tc->time_shift) / tc->time_mult +
           convert_ctx.env->tsc_offset;
}

static inline bool is_sampling_event(struct perf_event_attr *attr)
{
	return attr->sample_period != 0;
}

int perf_event_convert_init(struct perf_evlist *evlist, struct env *env)
{
    struct perf_evsel *evsel;
    u64 sample_type = 0;

    if (!env->tsc && !env->tsc_offset) {
        convert_ctx.need_tsc_conv = false;
        return 0;
    }

    perf_evlist__for_each_evsel(evlist, evsel) {
        struct perf_event_attr *attr = perf_evsel__attr(evsel);
        if (is_sampling_event(attr)) {
            if (sample_type == 0) {
                sample_type = attr->sample_type & CONVERT_SAMPLE_TYPE_MASK;
            } else if (sample_type != (attr->sample_type & CONVERT_SAMPLE_TYPE_MASK)) {
                fprintf(stderr, "Could not convert: sample_type mismatch.\n");
                return -1;
            }
        }
    }

    convert_ctx.env = env;
    convert_ctx.sample_type = sample_type;

    if (sample_type & PERF_SAMPLE_TIME) {
        convert_ctx.env->tsc = true;
        convert_ctx.need_tsc_conv = true;
        convert_ctx.time_offset = 0;
        if (sample_type & PERF_SAMPLE_IDENTIFIER)
            convert_ctx.time_offset += sizeof(u64);
        if (sample_type & PERF_SAMPLE_IP)
            convert_ctx.time_offset += sizeof(u64);
        if (sample_type & PERF_SAMPLE_TID)
            convert_ctx.time_offset += sizeof(u32) + sizeof(u32);
    } else {
        convert_ctx.env->tsc = false;
        convert_ctx.env->tsc_offset = 0;
        convert_ctx.need_tsc_conv = false;
    }

    return 0;
}

void perf_event_convert_read_tsc_conversion(struct perf_mmap *map)
{
    if (unlikely(convert_ctx.need_tsc_conv)) {
        if (perf_mmap__read_tsc_conversion(map, &convert_ctx.tsc_conv) == -EOPNOTSUPP) {
            fprintf(stderr, "TSC conversion is not supported.\n");
            convert_ctx.env->tsc = false;
            convert_ctx.env->tsc_offset = 0;
            convert_ctx.need_tsc_conv = false;
        }
    }
}

union perf_event *perf_event_convert(union perf_event *event, bool writable)
{
    void *data;
    u64 *time;

    if (likely(!convert_ctx.need_tsc_conv))
        return event;

    if (likely(!writable)) {
        memcpy(convert_ctx.event_copy, event, event->header.size);
        event = (union perf_event *)convert_ctx.event_copy;
    }

    data = (void *)event->sample.array;

    time = (u64 *)(data + convert_ctx.time_offset);
    *time = perf_time_to_tsc(*time);

    return event;
}

