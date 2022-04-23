#ifndef __TWO_EVENT_H
#define __TWO_EVENT_H

#include <stack_helpers.h>

struct two_event_class;
struct two_event_impl;

enum keytype {
    K_CPU,
    K_THREAD,
    K_CUSTOM,
};
struct two_event_options {
    enum keytype keytype;
    bool perins;
    unsigned long greater_than;
    char *heatmap;
    unsigned int first_n;
};

struct two_event {
    /* object */
    struct two_event_class *class;
    struct rb_node rbnode;
    struct tp *tp1;
    struct tp *tp2;
    bool deleting;
};

struct two_event_class {
    /* class object */
    struct two_event_impl *impl;
    struct two_event_options opts;
    struct rblist two_events;

    /* object function */
    void (*two)(struct two_event *two, union perf_event *event1, union perf_event *event2, u64 key);
    void (*remaining)(struct two_event *two, union perf_event *event, u64 key);
    int (*print_header)(struct two_event *two);
    void (*print)(struct two_event *two);
};

struct two_event_impl {
    /* impl object */
    const char *name;
    int class_size;
    struct two_event_class *(*class_new)(struct two_event_impl *impl, struct two_event_options *options);
    void (*class_delete)(struct two_event_class *class);

    /* class function */
    int instance_size;
    struct two_event *(*object_new)(struct two_event_class *class, struct tp *tp1, struct tp *tp2);
    void (*object_delete)(struct two_event_class *class, struct two_event *two);
    struct two_event *(*object_find)(struct two_event_class *class, struct tp *tp1, struct tp *tp2);
};

/* delay analysis:
 * syscall delay
 * kvm_exit to kvm_entry delay
 * hrtimer_start to hrtimer_expire_entry delay
 * and many more
 */
#define TWO_EVENT_DELAY_IMPL "delay"
/*
 * event pair:
 * kmemleak, alloc and free
 * fdleak, open and close
 */
#define TWO_EVENT_PAIR_IMPL "pair"

/*
 * mem profile:
 * mem-profile, alloc and free bytes
 */
#define TWO_EVENT_MEM_PROFILE "mem-prof"


struct two_event_impl *impl_get(const char *name);


// in linux/perf_event.h
// PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
struct multi_trace_type_header {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    __u64   stream_id;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    __u64		period;
};
struct multi_trace_type_callchain {
    struct multi_trace_type_header h;
    struct callchain callchain;
};
struct multi_trace_type_raw {
    struct multi_trace_type_header h;
    struct {
        __u32   size;
        __u8    data[0];
    } raw;
};

void multi_trace_raw_size(union perf_event *event, void **praw, int *psize, struct tp *tp);
void multi_trace_print(union perf_event *event, struct tp *tp);


#endif

