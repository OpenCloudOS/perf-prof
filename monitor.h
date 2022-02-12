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

struct monitor;
void monitor_register(struct monitor *m);
struct monitor * monitor_find(char *name);
int monitor_nr_instance(void);
int monitor_instance_cpu(int ins);
int monitor_instance_thread(int ins);
int monitor_instance_oncpu(void);

int get_possible_cpus(void);
void print_time(FILE *fp);
int get_tsc_khz(void);

#define X86_VENDOR_INTEL	0
#define X86_VENDOR_AMD		1
#define X86_VENDOR_HYGON	2
int get_cpu_vendor(void);
int in_guest(void);

#define MONITOR_REGISTER(m) \
__attribute__((constructor)) static void __monitor_register_##m(void) \
{ \
    monitor_register(&m); \
}

#define PROFILER_REGISTER(p) MONITOR_REGISTER(p)

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
    char *event;
    char *filter;
    bool interruptible;
    bool uninterruptible;
    int greater_than;
    bool callchain;
    int mmap_pages;
    bool exclude_user;
    bool exclude_kernel;
    bool exclude_guest;
    char *tp_alloc;
    char *tp_free;
    char *symbols;
    char *flame_graph;
    bool syscalls;
    bool perins;
    bool test;
    bool precise;
    int verbose;
};

typedef struct monitor {
    struct monitor *next;
    const char *name;
    int pages;
    int reinit;
    struct perf_cpu_map *cpus;
    struct perf_thread_map *threads;

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

#endif