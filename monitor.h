#ifndef __MONITOR_H
#define __MONITOR_H

#include <stdio.h>
#include <perf/core.h>
#include <perf/cpumap.h>
#include <perf/threadmap.h>
#include <perf/evlist.h>
#include <perf/evsel.h>
#include <perf/mmap.h>
#include <perf/event.h>
#include <tep.h>

struct monitor;
void monitor_register(struct monitor *m);
struct monitor * monitor_find(char *name);
struct monitor *monitor_next(struct monitor *m);
int monitor_nr_instance(void);
int monitor_instance_cpu(int ins);
int monitor_instance_thread(int ins);
int monitor_instance_oncpu(void);
struct monitor *current_monitor(void);

int get_present_cpus(void);
void print_time(FILE *fp);
int get_tsc_khz(void);

#define X86_VENDOR_INTEL	0
#define X86_VENDOR_AMD		1
#define X86_VENDOR_HYGON	2
struct cpuinfo_x86 {
    int vendor;
    int family;
    int model;
    int stepping;
};
int get_cpuinfo(struct cpuinfo_x86 *info);
static inline int get_cpu_vendor(void) {
    return get_cpuinfo(NULL);
};
int in_guest(void);


#define PROFILER_REGISTER_NAME(p, name) \
__attribute__((constructor)) static void __monitor_register_##name(void) \
{ \
    monitor_register(p); \
}
#define PROFILER_REGISTER(p) PROFILER_REGISTER_NAME((&p), p)
#define MONITOR_REGISTER(m)  PROFILER_REGISTER(m)

#define PROGRAME "perf-prof"

#define MAX_SLOTS 26
struct hist {
    unsigned int slots[MAX_SLOTS];
};

struct env {
    int trigger_freq;
    bool guest;
    char *cpumask;
    int interval;
    int latency;  // unit: us
    int freq;
    char *pids;
    char *tids;
    char *event;
    char **events;
    int nr_events;
    char *filter;
    char *key;
    char *impl;
    bool interruptible;
    bool uninterruptible;
    unsigned long greater_than; // unit: ns, percent
    bool callchain;
    int mmap_pages;
    bool exclude_user;
    bool exclude_kernel;
    bool exclude_guest;
    char *tp_alloc;
    char *tp_free;
    char *symbols;
    char *flame_graph;
    char *heatmap;
    bool syscalls;
    bool perins;
    bool test;
    bool precise;
    bool detail;
    char *device;
    int ldlat;
    bool overwrite;

    /* order */
    bool order;
    unsigned long order_mem;

    /* help */
    struct monitor *help_monitor;

    int verbose;
};

struct help_ctx {
    int nr_list;
    struct tp_list **tp_list;
    struct env *env;
};

typedef struct monitor {
    struct monitor *next;
    const char *name;
    int pages;
    int reinit;
    bool dup; //dup event
    bool order; // default enable order
    struct perf_cpu_map *cpus;
    struct perf_thread_map *threads;

    void (*help)(struct help_ctx *ctx);

    int (*init)(struct perf_evlist *evlist, struct env *env);
    int (*filter)(struct perf_evlist *evlist, struct env *env);
    void (*deinit)(struct perf_evlist *evlist);
    void (*sigusr1)(int signum);
    void (*interval)(void);
    void (*read)(struct perf_evsel *evsel, struct perf_counts_values *count, int instance);

    /* PERF_RECORD_* */

    //PERF_RECORD_LOST			= 2,
    void (*lost)(union perf_event *event, int instance);

    //PERF_RECORD_COMM			= 3,
    void (*comm)(union perf_event *event, int instance);

    //PERF_RECORD_EXIT			= 4,
    void (*exit)(union perf_event *event, int instance);

    //PERF_RECORD_THROTTLE			= 5,
	//PERF_RECORD_UNTHROTTLE			= 6,
    void (*throttle)(union perf_event *event, int instance);
    void (*unthrottle)(union perf_event *event, int instance);

    //PERF_RECORD_FORK			= 7,
    void (*fork)(union perf_event *event, int instance);

    //PERF_RECORD_SAMPLE			= 9,
    void (*sample)(union perf_event *event, int instance);

    //PERF_RECORD_SWITCH			= 14,
    //PERF_RECORD_SWITCH_CPU_WIDE		= 15,
    void (*context_switch)(union perf_event *event, int instance);
    void (*context_switch_cpu)(union perf_event *event, int instance);

    //PERF_RECORD_NAMESPACES			= 16,
    void (*namespace)(union perf_event *event, int instance);
}profiler;

profiler *order(profiler *p);
bool current_is_order(void);
bool using_order(profiler *p);
void reduce_wakeup_times(profiler *p, struct perf_event_attr *attr);

//help.c
void common_help(struct help_ctx *ctx, bool enabled, bool cpus, bool pids, bool interval, bool order, bool pages, bool verbose);


#endif
