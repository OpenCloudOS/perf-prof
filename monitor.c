#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <argp.h>
#include <signal.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/time.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>

#include <monitor.h>
#include <tep.h>

struct monitor *monitors_list = NULL;
struct monitor *monitor = NULL;

void monitor_register(struct monitor *m)
{
    m->next = monitors_list;
    monitors_list = m;
}

struct monitor * monitor_find(char *name)
{
    struct monitor *m = monitors_list;
    while(m) {
        if (!strcmp(m->name, name))
            return m;
        m = m->next;
    }
    return NULL;
}

/******************************************************
perf-monitor argc argv
******************************************************/

struct env env = {
    .trigger_freq = 1000,
    .guest = 0,
    .latency = 20000,
    .freq = 10,
    .verbose = 0,
};

static volatile bool exiting;

const char *argp_program_version = "perf-monitor 0.1";
const char *argp_program_bug_address = "<corcpp@foxmail.com>";
const char argp_program_doc[] =
"Monitor based on perf_event\n"
"\n"
"USAGE:\n"
"    perf-monitor split-lock [-T trigger] [-C cpu] [-G] [-i INT] [--test]\n"
"    perf-monitor irq-off [-L lat] [-C cpu] [-g] [--precise]\n"
"    perf-monitor profile [-F freq] [-C cpu] [-g] [--exclude-*] [--than PCT]\n"
"    perf-monitor trace -e event [--filter filter] [-C cpu]\n"
"    perf-monitor signal [--filter comm] [-C cpu] [-g]\n"
"    perf-monitor task-state [-S] [-D] [--than ms] [--filter comm] [-C cpu] [-g]\n"
"    perf-monitor watchdog [-F freq] [-g] [-C cpu] [-v]\n"
"\n"
"EXAMPLES:\n"
"    perf-monitor split-lock -T 1000 -C 1-21,25-46 -g  # Monitor split-lock\n"
"    perf-monitor irq-off -L 10000 -C 1-21,25-46  # Monitor irq-off\n";


static const struct argp_option opts[] = {
    { "trigger", 'T', "T", 0, "Trigger Threshold, Dflt: 1000" },
    { "cpu", 'C', "CPU", 0, "Monitor the specified CPU, Dflt: all cpu" },
    { "guest", 'G', NULL, 0, "Monitor GUEST, Dflt: false" },
    { "interval", 'i', "INT", 0, "Interval, ms" },
    { "test", 500, NULL, 0, "Test verification" },
    { "latency", 'L', "LAT", 0, "Interrupt off latency, unit: us, Dflt: 20ms" },
    { "freq", 'F', "n", 0, "profile at this frequency, Dflt: 10" },
    { "event", 'e', "event", 0, "event selector. use 'perf list tracepoint' to list available tp events" },
    { "filter", 502, "filter", 0, "event filter/comm filter" },
    { "interruptible", 'S', NULL, 0, "TASK_INTERRUPTIBLE" },
    { "uninterruptible", 'D', NULL, 0, "TASK_UNINTERRUPTIBLE" },
    { "exclude-user", 504, NULL, 0, "exclude user" },
    { "exclude-kernel", 505, NULL, 0, "exclude kernel" },
    { "than", 503, "ms", 0, "Greater than specified time, ms/percent" },
    { "call-graph", 'g', NULL, 0, "Enable call-graph recording" },
    { "mmap-pages", 'm', "pages", 0, "number of mmap data pages and AUX area tracing mmap pages" },
    { "precise", 501, NULL, 0, "Generate precise interrupt" },
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "", 'h', NULL, OPTION_HIDDEN, "" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    int latency;

    switch (key) {
    case 'h':
        argp_help((const struct argp *__restrict)state->root_argp, stderr, ARGP_HELP_STD_HELP, (char *__restrict)"perf-monitor");
        exit(0);
    case 'T':
        env.trigger_freq = strtol(arg, NULL, 10);
        break;
    case 'C':
        env.cpumask = strdup(arg);
        break;
    case 'G':
        env.guest = 1;
        break;
    case 'i':
        env.interval = strtol(arg, NULL, 10);
        break;
    case 500:
        env.test = 1;
        break;
    case 'L':
        latency = strtol(arg, NULL, 10);
        if (latency > 1)
            env.latency = latency;
        break;
    case 'F':
        env.freq = strtol(arg, NULL, 10);
        break;
    case 'e':
        env.event = strdup(arg);
        break;
    case 502:
        env.filter = strdup(arg);
        break;
    case 'S':
        env.interruptible = 1;
        break;
    case 'D':
        env.uninterruptible = 1;
        break;
    case 504:
        env.exclude_user = 1;
        break;
    case 505:
        env.exclude_kernel = 1;
        break;
    case 503:
        env.greater_than = strtol(arg, NULL, 10);
        break;
    case 'g':
        env.callchain = 1;
        break;
    case 'm':
        env.mmap_pages = strtol(arg, NULL, 10);
        break;
    case 501:
        env.precise = 1;
        break;
    case 'v':
        env.verbose++;
        break;
    case ARGP_KEY_ARG:
        switch (state->arg_num) {
            case 0:
                monitor = monitor_find(arg);
                if (monitor == NULL)
                    argp_usage (state);
                break;
            default:
                argp_usage (state);
        };
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 1)
            argp_usage (state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static void sig_handler(int sig)
{
	exiting = 1;
}

int get_possible_cpus(void)
{
    struct perf_cpu_map *cpumap = NULL;
	FILE *f;
    int cpus;

	f = fopen("/sys/devices/system/cpu/possible", "r");
	if (!f)
		f = fopen("/sys/devices/system/cpu/online", "r");
	cpumap = perf_cpu_map__read(f);
	fclose(f);

    cpus = perf_cpu_map__max(cpumap);
    perf_cpu_map__put(cpumap);
    return cpus + 1;
}

int get_tsc_khz(void)
{
    int kvm, vm, vcpu;
    int tsc_khz = 0;

    kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) {
        fprintf(stderr, "open kvm failed\n");
        return 0;
    }
    vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (kvm < 0) {
        fprintf(stderr, "create vm failed\n");
        close(kvm);
        return 0;
    }
    vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    if (vcpu < 0) {
        fprintf(stderr, "create vm failed\n");
        close(vm);
        close(kvm);
        return 0;
    }
    if (ioctl(vm, KVM_CHECK_EXTENSION, KVM_CAP_GET_TSC_KHZ) == 1) {
        tsc_khz = ioctl(vcpu, KVM_GET_TSC_KHZ, 0);
        if (tsc_khz < 0)
            tsc_khz = 0;
    }
    close(vcpu);
    close(vm);
    close(kvm);
    return tsc_khz;
}


void print_time(FILE *fp)
{
    char timebuff[64];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
    fprintf(fp, "%s.%06u ", timebuff, (unsigned int)tv.tv_usec);
}

static void print_lost_fn(union perf_event *event, int cpu)
{
    print_time(stderr);
    fprintf(stderr, "lost %llu events on CPU #%d\n", event->lost.lost, cpu);
}

static void print_fork_exit_fn(union perf_event *event, int cpu, int exit)
{
    if (env.verbose >= 2) {
        print_time(stderr);
        fprintf(stderr, "%s ppid %u ptid %u pid %u tid %u on CPU #%d - %d\n",
                        exit ? "exit" : "fork",
                        event->fork.ppid, event->fork.ptid,
                        event->fork.pid,  event->fork.tid,
                        cpu, env.verbose);
    }
}

static void print_comm_fn(union perf_event *event, int cpu)
{
    if (env.verbose >= 2) {
        print_time(stderr);
        fprintf(stderr, "comm pid %u tid %u %s on CPU #%d\n",
                        event->comm.pid,  event->comm.tid,
                        event->comm.comm, cpu);
    }
}

static void print_context_switch_fn(union perf_event *event, int cpu)
{
    if (env.verbose >= 2) {
        print_time(stderr);
        fprintf(stderr, "switch on CPU #%d\n", cpu);
    }
}

static void print_context_switch_cpu_fn(union perf_event *event, int cpu)
{
    if (env.verbose >= 2) {
        print_time(stderr);
        fprintf(stderr, "switch next pid %u tid %u on CPU #%d\n",
                        event->context_switch.next_prev_pid, event->context_switch.next_prev_tid,
                        cpu);
    }
}

static int perf_event_process_record(union perf_event *event, int cpu)
{
    switch (event->header.type) {
    case PERF_RECORD_LOST:
        if (monitor->lost)
            monitor->lost(event);
        else
            print_lost_fn(event, cpu);
        break;
    case PERF_RECORD_FORK:
        if (monitor->fork)
            monitor->fork(event);
        else
            print_fork_exit_fn(event, cpu, 0);
        break;
    case PERF_RECORD_COMM:
        if (monitor->comm)
            monitor->comm(event);
        else
            print_comm_fn(event, cpu);
        break;
    case PERF_RECORD_EXIT:
        if (monitor->exit)
            monitor->exit(event);
        else
            print_fork_exit_fn(event, cpu, 1);
        break;
    case PERF_RECORD_THROTTLE:
        if (monitor->throttle)
            monitor->throttle(event);
        break;
    case PERF_RECORD_UNTHROTTLE:
        if (monitor->unthrottle)
            monitor->unthrottle(event);
        break;
    case PERF_RECORD_SAMPLE:
        if (monitor->sample)
            monitor->sample(event);
        break;
    case PERF_RECORD_SWITCH:
        if (monitor->context_switch)
            monitor->context_switch(event);
        else
            print_context_switch_fn(event, cpu);
        break;
    case PERF_RECORD_SWITCH_CPU_WIDE:
        if (monitor->context_switch_cpu)
            monitor->context_switch_cpu(event);
        else
            print_context_switch_cpu_fn(event, cpu);
        break;
    default:
        fprintf(stderr, "unknown perf sample type %d\n", event->header.type);
        return -1;
    }
    return 0;
}

static int libperf_print(enum libperf_print_level level,
                         const char *fmt, va_list ap)
{
    return vfprintf(stderr, fmt, ap);
}

int main(int argc, char *argv[])
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    int err;
    struct perf_evlist *evlist = NULL;
    struct perf_cpu_map *cpus = NULL, *online;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.mmap_pages)
        monitor->pages = env.mmap_pages;

    setlinebuf(stdout);
    libperf_init(libperf_print);

reinit:
    monitor->reinit = 0;

    evlist = perf_evlist__new();
    if (!evlist) {
        fprintf(stderr, "failed to create evlist\n");
        return -1;
    }

    if(monitor->init(evlist, &env) < 0) {
        fprintf(stderr, "monitor(%s) init failed\n", monitor->name);
        goto out_delete;
    }

    cpus = perf_cpu_map__new(env.cpumask);
    if (!cpus) {
        fprintf(stderr, "failed to create cpus\n");
        goto out_exit;
    }
    online = perf_cpu_map__new(NULL);
    if (!online) {
        fprintf(stderr, "failed to create online\n");
        goto out_exit;
    }
    cpus = perf_cpu_map__and(cpus, online);
    if (!cpus) {
        fprintf(stderr, "failed to create cpus\n");
        goto out_exit;
    }
    perf_cpu_map__put(online);

    perf_evlist__set_maps(evlist, cpus, NULL);

    err = perf_evlist__open(evlist);
    if (err) {
        fprintf(stderr, "failed to open evlist\n");
        goto out_exit;
    }

    if (monitor->filter && monitor->filter(evlist, &env) < 0) {
        fprintf(stderr, "monitor(%s) filter failed\n", monitor->name);
        goto out_close;
    }

    err = perf_evlist__mmap(evlist, monitor->pages);
    if (err) {
        fprintf(stderr, "failed to mmap evlist\n");
        goto out_close;
    }

    perf_evlist__enable(evlist);

    signal(SIGINT, sig_handler);

    while (!exiting && !monitor->reinit) {
        struct perf_mmap *map;
        union perf_event *event;
        int fds;

        fds = perf_evlist__poll(evlist, env.interval ? : 1000);

        if (fds)
        perf_evlist__for_each_mmap(evlist, map, false) {
            if (perf_mmap__read_init(map) < 0)
                continue;
            while ((event = perf_mmap__read_event(map)) != NULL) {
                /* process event */
                perf_event_process_record(event, perf_mmap__cpu(map));
                perf_mmap__consume(map);
            }
            perf_mmap__read_done(map);
        }

        if (monitor->read) {
            struct perf_evsel *evsel;
            perf_evlist__for_each_evsel(evlist, evsel) {
                int cpu, idx;
                struct perf_cpu_map *cpus = perf_evsel__cpus(evsel);
                perf_cpu_map__for_each_cpu(cpu, idx, cpus) {
                    struct perf_counts_values count;
                    if (perf_evsel__read(evsel, idx, 0, &count) == 0)
                        monitor->read(&count, cpu);
                }
            }
        }
    }

    perf_evlist__disable(evlist);
    perf_evlist__munmap(evlist);
out_close:
    perf_evlist__close(evlist);
out_exit:
    monitor->deinit(evlist);
out_delete:
    perf_evlist__delete(evlist);
    perf_cpu_map__put(cpus);

    if (monitor->reinit)
        goto reinit;

    return err;
}

