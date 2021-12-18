#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <monitor.h>
#include <tep.h>

static struct tep_handle *tep = NULL;
static struct tep_plugin_list *plugins = NULL;

struct tep_handle *tep__ref(void)
{
    if (tep != NULL) {
        tep_ref(tep);
        return tep;
    }
    tep = tep_alloc();
    plugins = tep_load_plugins(tep);
    return tep;
}

void tep__unref(void)
{
    if (tep == NULL)
        return;

    if (tep_get_ref(tep) == 1) {
        tep_unload_plugins(plugins, tep);
        tep_free(tep);
        tep = NULL;
    } else
        tep_unref(tep);
}

int tep__event_id(const char *sys, const char *name)
{
    char format[256];
    struct stat st;
    struct tep_event *event;
    int id = -1;

    tep__ref();
    event = tep_find_event_by_name(tep, sys, name);
    if (event) {
        id = event->id;
        goto unref;
    }
    snprintf(format, sizeof(format), "/sys/kernel/debug/tracing/events/%s/%s/format", sys, name);
    if (stat(format, &st) == 0) {
        FILE *fp;
        size_t size = 65536;
        char *buff = malloc(size);

        fp = fopen(format, "r");
        size = fread(buff, 1, size, fp);
        fclose(fp);

        tep_parse_format(tep, &event, buff, size, sys);

        free(buff);

        id = event->id;
    }
unref:
    tep__unref();
    return id;
}

void tep__update_comm(const char *comm, int pid)
{
    char buff[16];

    if (comm == NULL) {
        char path[64];
        int fd, len;

        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return;
        len = (int)read(fd, buff, sizeof(buff));
        close(fd);
        if (len <= 0)
            return;
        len--;
        if (buff[len] == '\n' || len == sizeof(buff)-1)
            buff[len] = '\0';
        comm = buff;
    }
    tep__ref();
    tep_override_comm(tep, comm, pid);
    tep__unref();
}

const char *tep__pid_to_comm(int pid)
{
    const char *comm;
    tep__ref();
    comm = tep_data_comm_from_pid(tep, pid);
    tep__unref();
    return comm;
}

void tep__print_event(unsigned long long ts, int cpu, void *data, int size)
{
    struct tep_record record;
	struct trace_seq s;
    struct tep_event *e;

	memset(&record, 0, sizeof(record));
    record.ts = ts;
	record.cpu = cpu;
	record.size = size;
	record.data = data;

    tep__ref();
    e = tep_find_event_by_record(tep, &record);

    trace_seq_init(&s);
    tep_print_event(tep, &s, &record, "%16s %6u %s [%03d] %6d: ", TEP_PRINT_COMM, TEP_PRINT_PID,
                TEP_PRINT_LATENCY, TEP_PRINT_CPU, TEP_PRINT_TIME);
    if (e) trace_seq_printf(&s, "%s:", e->system);
    tep_print_event(tep, &s, &record, "%s: %s\n", TEP_PRINT_NAME, TEP_PRINT_INFO);
    tep__unref();
	trace_seq_do_fprintf(&s, stdout);
	trace_seq_destroy(&s);
}


void monitor_tep__comm(union perf_event *event, int instance)
{
    tep__update_comm(event->comm.comm, event->comm.tid);
}


