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
#include <timer.h>
#include <limits.h>
#include <signal.h>
#include <localtime.h>
#include <linux/list.h>
#include <linux/epoll.h>
#include <linux/zalloc.h>
#include <linux/time64.h>
#include <linux/refcount.h>
#include <linux/ordered-events.h>

/* perf sample has 16 bits size limit */
#define PERF_SAMPLE_MAX_SIZE (1 << 16)

#define START_OF_KERNEL 0xffff000000000000UL


struct monitor;
struct prof_dev;

void monitor_register(struct monitor *m);
struct monitor * monitor_find(const char *name);
struct monitor *monitor_next(struct monitor *m);
int prof_dev_nr_ins(struct prof_dev *dev);
int prof_dev_ins_cpu(struct prof_dev *dev, int ins);
int prof_dev_ins_thread(struct prof_dev *dev, int ins);
int prof_dev_ins_oncpu(struct prof_dev *dev);

int main_epoll_add(int fd, unsigned int events, void *ptr, handle_event handle);
int main_epoll_del(int fd);

void help(void);

int get_present_cpus(void);
void print_time(FILE *fp);
int get_tsc_khz(void);

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif
int kernel_release(void);


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

int callchain_flags(struct prof_dev *dev, int default_flags);
int exclude_callchain_user(struct prof_dev *dev, int dflt_flags);
int exclude_callchain_kernel(struct prof_dev *dev, int dflt_flags);

void print_lost_fn(struct prof_dev *dev, union perf_event *event, int ins);

int perf_event_process_record(struct prof_dev *dev, union perf_event *event, int instance, bool writable, bool converted);


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

struct workload {
    int cork_fd;
    pid_t pid;
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
    int watermark;
    bool watermark_set;
    bool inherit;
    bool interruptible, interruptible_set;
    bool uninterruptible;
    bool only_print_greater_than;
    unsigned long greater_than; // unit: ns, percent
    unsigned long lower_than; // unit: ns
    bool callchain;
    int mmap_pages;
    bool exclude_user;
    bool exclude_kernel;
    bool exclude_guest;
    bool exclude_host;
    bool user_callchain, user_callchain_set;
    bool kernel_callchain, kernel_callchain_set;
    // ebpf
    bool irqs_disabled_set, tif_need_resched_set, exclude_pid_set;
    bool nr_running_min_set, nr_running_max_set;
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
        bool sametid;
        bool samekey;
    char *device;
    int ldlat;
    bool overwrite;
    unsigned long sample_period;
    bool only_comm;
    bool cycle;
    bool tsc;
    u64  tsc_offset;
    int usage_self;

    /* workload */
    struct workload workload;

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
    const char *compgen;
    int pages;
    bool order; // default enable order

    void (*help)(struct help_ctx *ctx);

    int (*argc_init)(int argc, char *argv[]);

    int (*init)(struct prof_dev *dev);
    int (*filter)(struct prof_dev *dev);
    void (*enabled)(struct prof_dev *dev);
    void (*deinit)(struct prof_dev *dev);
    void (*sigusr)(struct prof_dev *dev, int signum);
    void (*interval)(struct prof_dev *dev);

    // Profiler minimum event time. tsc or ns.
    u64 (*minevtime)(struct prof_dev *dev);

    // return 0:continue; 1:break;
    int (*read)(struct prof_dev *dev, struct perf_evsel *evsel, struct perf_counts_values *count, int instance);

    /* PERF_RECORD_* */

    //PERF_RECORD_LOST          = 2,
    void (*lost)(struct prof_dev *dev, union perf_event *event, int instance, u64 lost_start, u64 lost_end);

    //PERF_RECORD_COMM          = 3,
    void (*comm)(struct prof_dev *dev, union perf_event *event, int instance);

    //PERF_RECORD_EXIT          = 4,
    void (*exit)(struct prof_dev *dev, union perf_event *event, int instance);

    //PERF_RECORD_THROTTLE          = 5,
    //PERF_RECORD_UNTHROTTLE            = 6,
    void (*throttle)(struct prof_dev *dev, union perf_event *event, int instance);
    void (*unthrottle)(struct prof_dev *dev, union perf_event *event, int instance);

    //PERF_RECORD_FORK          = 7,
    void (*fork)(struct prof_dev *dev, union perf_event *event, int instance);

    //PERF_RECORD_SAMPLE            = 9,
    void (*sample)(struct prof_dev *dev, union perf_event *event, int instance);

    //PERF_RECORD_SWITCH            = 14,
    //PERF_RECORD_SWITCH_CPU_WIDE       = 15,
    void (*context_switch)(struct prof_dev *dev, union perf_event *event, int instance);
    void (*context_switch_cpu)(struct prof_dev *dev, union perf_event *event, int instance);

    //PERF_RECORD_NAMESPACES            = 16,
    void (*namespace)(struct prof_dev *dev, union perf_event *event, int instance);
}profiler;

enum prof_dev_state {
	PROF_DEV_STATE_OFF       = -1,
	PROF_DEV_STATE_INACTIVE  =  0,
	PROF_DEV_STATE_ACTIVE    =  1,
};

enum prof_dev_type {
    PROF_DEV_TYPE_NORMAL     = 0,
    PROF_DEV_TYPE_SERVICE    = 1,
};

/*
 * Profiler device
 * Contains sampling ringbuffer, environment, timer, profiler-specific memory, convert, order, etc.
**/
struct prof_dev {
    profiler *prof;
    struct list_head dev_link;
    struct perf_cpu_map *cpus;
    struct perf_thread_map *threads;
    struct perf_evlist *evlist;
    struct timer timer;  // interval
    struct env *env;
    void *private;
    enum prof_dev_type type;
    enum prof_dev_state state; // It can be set off and active again by calling prof_dev_enable.
    int pages;
    int nr_pollfd;
    bool dup; // dup event, order
    // | title                        | detail                                                                       |
    // | 2023-11-28 09:32:36.901715 G |           bash 197260 [000] 751890.944308: page-fault: addr 00007fb3c89d6170 |
    bool print_title;
    int max_read_size;
    struct perf_counts_values *values;
    long sampled_events;
    struct perf_sample_time_ctx { // PERF_SAMPLE_TIME
        u64 sample_type;
        int time_pos;
        u64 last_evtime; // ns, tsc
        u64 enabled_after; // ns, tsc
    } time_ctx;
    struct perf_event_convert {
        // tsc convert
        bool need_tsc_conv;
        struct perf_tsc_conversion tsc_conv;

        char *event_copy; //[PERF_SAMPLE_MAX_SIZE];
    } convert;
    struct order_ctx {
        profiler *base;
        profiler order;
        struct ordered_events oe;
        bool flush_in_time;
        u32 nr_unordered_events;
        u64 max_timestamp;
        struct lost_record {
            struct perf_record_lost lost;
            int ins;
            u64 lost_start_time;
        } *lost_records;
    } order;
    struct tty_ctx {
        bool istty;
        bool shared;
        int row; // TIOCGWINSZ
        int col; // TIOCGWINSZ
    } tty;
    struct prof_dev_links {
        /*
         * profiler[/option/ATTR/ATTR/.../] opens the device as a child prof_dev.
         * Will be linked to the parent device.
         * The child prof_dev is in the PROF_DEV_STATE_OFF state by default. It
         * will enter the PROF_DEV_STATE_ACTIVE state after the parent prof_dev
         * is enabled.
         */
        struct prof_dev *parent;
        struct list_head child_list;
        struct list_head link_to_parent;
    } links;
    struct perf_event_forward_to {
        struct prof_dev *target;
        struct list_head source_list;
        struct list_head link_to_target;
        struct perf_record_dev *event_dev; // PERF_SAMPLE_MAX_SIZE
        short tid_pos, time_pos, id_pos, cpu_pos;
        short forwarded_time_pos; // perf_record_dev.time
        bool ins_reset;
        // Whether the events generated by the source device match the pid/tid.
        // Currently only used within 'task-state' profiler.
        bool (*samepid)(struct prof_dev *dev, union perf_event *event, int pid, int tid);
    } forward;
};

#define for_each_child_dev(dev, parent) \
    if (!list_empty(&parent->links.child_list)) \
        list_for_each_entry(dev, &parent->links.child_list, links.link_to_parent)

#define for_each_child_dev_safe(dev, next, parent) \
    if (!list_empty(&parent->links.child_list)) \
        list_for_each_entry_safe(dev, next, &parent->links.child_list, links.link_to_parent)

#define for_each_source_dev_safe(dev, next, target) \
    if (!list_empty(&target->forward.source_list)) \
        list_for_each_entry_safe(dev, next, &target->forward.source_list, forward.link_to_target)

struct prof_dev *prof_dev_open_cpu_thread_map(profiler *prof, struct env *env,
                 struct perf_cpu_map *cpu_map, struct perf_thread_map *thread_map, struct prof_dev *parent);
struct prof_dev *prof_dev_open(profiler *prof, struct env *env);
int prof_dev_enable(struct prof_dev *dev);
int prof_dev_disable(struct prof_dev *dev);
int prof_dev_forward(struct prof_dev *dev, struct prof_dev *target);
void prof_dev_flush(struct prof_dev *dev);
void prof_dev_close(struct prof_dev *dev);
/*
 * The final prof_dev refers to the device that finally handles the event and will no
 * longer forward the event.
 */
static inline bool prof_dev_is_final(struct prof_dev *dev) {return !dev->forward.target;}
struct env *parse_string_options(char *str);

u64 prof_dev_list_minevtime(void);


#define PROFILER_DESC(name, arg, ...) \
    {PROGRAME " " name " " arg, "", __VA_ARGS__, NULL}
#define PROFILER_ARGV(name, ...) \
    {PROGRAME, "-h", __VA_ARGS__, NULL}
#define PROFILER_ARGV_OPTION \
    "OPTION:", \
    "cpus", "pids", "tids", "cgroups", "watermark", \
    "interval", "output", "order", "order-mem", "mmap-pages", "exit-N", "tsc", "tsc-offset", \
    "usage-self", "version", "verbose", "quiet", "help"
#define PROFILER_ARGV_FILTER \
    "FILTER OPTION:", \
    "exclude-host", "exclude-guest", "exclude-user", "exclude-kernel", \
    "user-callchain", "kernel-callchain", \
    "irqs_disabled", "tif_need_resched", "exclude_pid", "nr_running_min", "nr_running_max"
#define PROFILER_ARGV_CALLCHAIN_FILTER \
        "FILTER OPTION:", "user-callchain", "kernel-callchain"
#define PROFILER_ARGV_PROFILER \
    "PROFILER OPTION:" \

// order.c
void order(struct prof_dev *dev);
bool using_order(struct prof_dev *dev);
void ordered_events(struct prof_dev *dev);
void reduce_wakeup_times(struct prof_dev *dev, struct perf_event_attr *attr);

//help.c
void common_help(struct help_ctx *ctx, bool enabled, bool cpus, bool pids, bool interval, bool order, bool pages, bool verbose);

#include <filter/filter.h>


//convert.c
u64 rdtsc(void);
u64 perf_time_to_ns(struct prof_dev *dev, u64 time);
u64 perf_time_to_tsc(struct prof_dev *dev, u64 time);
int perf_sample_forward_init(struct prof_dev *dev);
int perf_sample_time_init(struct prof_dev *dev);
int perf_event_convert_init(struct prof_dev *dev);
void perf_event_convert_deinit(struct prof_dev *dev);
void perf_event_convert_read_tsc_conversion(struct prof_dev *dev, struct perf_mmap *map);
union perf_event *perf_event_convert(struct prof_dev *dev, union perf_event *event, bool writable);


//comm.c
int global_comm_ref(void);
void global_comm_unref(void);
char *global_comm_get(int pid);
void global_comm_flush(int pid);
#define NOTIFY_COMM_DELETE 1
struct comm_notify {
    struct list_head link;
    int (*notify)(struct comm_notify *notify, int pid, int state, u64 free_time);
};
void global_comm_register_notify(struct comm_notify *node);
void global_comm_unregister_notify(struct comm_notify *node);


//sched.c
int sched_init(int nr_list, struct tp_list **tp_list);
void sched_event(int level, void *raw, int size, int cpu);
bool sched_wakeup_unnecessary(int level, void *raw, int size);


#endif
