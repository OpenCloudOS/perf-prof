#ifndef __BPF_PERF_OUTPUT_H
#define __BPF_PERF_OUTPUT_H

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} perf_events SEC(".maps");


#define perf_output(ctx, event, size) \
        bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, \
                          (event), (size))

#endif
