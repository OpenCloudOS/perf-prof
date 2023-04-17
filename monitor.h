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
#include <parse-options.h>
#include <tep.h>
#include <localtime.h>
#include <linux/epoll.h>

/* perf sample has 16 bits size limit */
#define PERF_SAMPLE_MAX_SIZE (1 << 16)


struct monitor;
void monitor_register(struct monitor *m);
struct monitor * monitor_find(char *name);
struct monitor *monitor_next(struct monitor *m);
int monitor_nr_instance(void);
int monitor_instance_cpu(int ins);
int monitor_instance_thread(int ins);
int monitor_instance_oncpu(void);
struct monitor *current_monitor(void);

int main_epoll_add(int fd, unsigned int events, void *ptr, handle_event handle);
int main_epoll_del(int fd);

void help(void);

int get_present_cpus(void);
void print_time(FILE *fp);
int get_tsc_khz(void);

#define X86_VENDOR_INTEL    0
#define X86_VENDOR_AMD      1
#define X86_VENDOR_HYGON    2
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

void print_lost_fn(union perf_event *event, int ins);

int perf_event_process_record(union perf_event *event, int instance, bool writable, bool converted);


#define PROFILER_REGISTER_NAME(p, name) \
__attribute__((constructor)) static void __monitor_register_##name(void) \
{ \
    monitor_register(p); \
}
#define PROFILER_REGISTER(p) PROFILER_REGISTER_NAME((&p), p)
#define MONITOR_REGISTER(m)  PROFILER_REGISTER(m)

#define PROGRAME "perf-prof"

#define VERBOSE_NOTICE 1 // -v
#define VERBOSE_EVENT  2 // -vv
#define VERBOSE_ALL    3 // -vvv


#define MAX_SLOTS 26
struct hist {
    unsigned int slots[MAX_SLOTS];
};

struct env {
    int trigger_freq;
    char *cpumask;
    int interval;
    int freq;
    long exit_n;
    char *pids;
    char *tids;
    char *cgroups;
    char *event;
    char **events;
    int nr_events;
    char *filter;
    char *key;
    char *impl;
    char *output;
    bool interruptible;
    bool uninterruptible;
    bool only_print_greater_than;
    unsigned long greater_than; // unit: ns, percent
    bool callchain;
    int mmap_pages;
    bool exclude_user;
    bool exclude_kernel;
    bool exclude_guest;
    bool exclude_host;
    // ebpf
    int  irqs_disabled;
    int  tif_need_resched;
    int  exclude_pid;
    int  nr_running_min;
    int  nr_running_max;
    // ebpf end
    char *tp_alloc;
    char *tp_free;
    char *symbols;
    char *flame_graph;
    char *heatmap;
    bool syscalls;
    bool perins;
    bool test;
    bool detail;
    // detail_arg
        unsigned long before_event1;// unit: ns
        unsigned long after_event2; // unit: ns
        bool samecpu;
        bool samepid;
        bool samekey;
    char *device;
    int ldlat;
    bool overwrite;
    unsigned long sample_period;
    bool only_comm;
    bool cycle;
    bool tsc;
    u64  tsc_offset;

    /* kvmmmu */
    bool spte;
    bool mmio;

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
    const char **desc;
    const char **argv;
    int pages;
    int reinit;
    bool dup; //dup event
    bool order; // default enable order
    struct perf_cpu_map *cpus;
    struct perf_thread_map *threads;

    void (*help)(struct help_ctx *ctx);

    int (*argc_init)(int argc, char *argv[]);

    int (*init)(struct perf_evlist *evlist, struct env *env);
    int (*filter)(struct perf_evlist *evlist, struct env *env);
    void (*deinit)(struct perf_evlist *evlist);
    void (*sigusr1)(int signum);
    void (*interval)(void);
    void (*read)(struct perf_evsel *evsel, struct perf_counts_values *count, int instance);

    /* PERF_RECORD_* */

    //PERF_RECORD_LOST          = 2,
    void (*lost)(union perf_event *event, int instance);

    //PERF_RECORD_COMM          = 3,
    void (*comm)(union perf_event *event, int instance);

    //PERF_RECORD_EXIT          = 4,
    void (*exit)(union perf_event *event, int instance);

    //PERF_RECORD_THROTTLE          = 5,
    //PERF_RECORD_UNTHROTTLE            = 6,
    void (*throttle)(union perf_event *event, int instance);
    void (*unthrottle)(union perf_event *event, int instance);

    //PERF_RECORD_FORK          = 7,
    void (*fork)(union perf_event *event, int instance);

    //PERF_RECORD_SAMPLE            = 9,
    void (*sample)(union perf_event *event, int instance);

    //PERF_RECORD_SWITCH            = 14,
    //PERF_RECORD_SWITCH_CPU_WIDE       = 15,
    void (*context_switch)(union perf_event *event, int instance);
    void (*context_switch_cpu)(union perf_event *event, int instance);

    //PERF_RECORD_NAMESPACES            = 16,
    void (*namespace)(union perf_event *event, int instance);
}profiler;

#define PROFILER_DESC(name, arg, ...) \
    {PROGRAME " " name " " arg, "", __VA_ARGS__, NULL}
#define PROFILER_ARGV(name, ...) \
    {PROGRAME, "-h", __VA_ARGS__, NULL}
#define PROFILER_ARGV_OPTION \
    "OPTION:", \
    "cpus", "pids", "tids", "cgroups", \
    "interval", "output", "order", "order-mem", "mmap-pages", "exit-N", "tsc", "tsc-offset", \
    "version", "verbose", "quiet", "help"
#define PROFILER_ARGV_FILTER \
    "FILTER OPTION:", \
    "exclude-host", "exclude-guest", "exclude-user", "exclude-kernel", \
    "irqs_disabled", "tif_need_resched", "exclude_pid", "nr_running_min", "nr_running_max"
#define PROFILER_ARGV_PROFILER \
    "PROFILER OPTION:" \


profiler *order(profiler *p);
bool current_is_order(void);
profiler *current_base_profiler(void);
bool using_order(profiler *p);
void reduce_wakeup_times(profiler *p, struct perf_event_attr *attr);

//help.c
void common_help(struct help_ctx *ctx, bool enabled, bool cpus, bool pids, bool interval, bool order, bool pages, bool verbose);

#include <filter/filter.h>


//convert.c
u64 rdtsc(void);
int perf_event_convert_init(struct perf_evlist *evlist, struct env *env);
void perf_event_convert_read_tsc_conversion(struct perf_mmap *map);
union perf_event *perf_event_convert(union perf_event *event, bool writable);


#endif
