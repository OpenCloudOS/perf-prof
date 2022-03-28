#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <monitor.h>
#include <tep.h>

#define PLUGINS_DIR "/usr/lib64/perf-prof-traceevent/plugins"

static struct tep_handle *tep = NULL;
static struct tep_plugin_list *plugins = NULL;

struct tep_handle *tep__ref(void)
{
    if (tep != NULL) {
        tep_ref(tep);
        return tep;
    }
    tep = tep_alloc();
    tep_add_plugin_path(tep, (char *)PLUGINS_DIR, TEP_PLUGIN_FIRST);
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


struct tp_list *tp_list_new(char *event)
{
    char *s = event;
    char *sep;
    int i;
    int nr_tp = 0;
    struct tp_list *tp_list = NULL;

    if (!s)
        return NULL;

    while ((sep = strchr(s, ',')) != NULL) {
        nr_tp ++;
        s = sep + 1;
    }
    if (*s)
        nr_tp ++;

    if (nr_tp == 0)
        return NULL;

    tp_list = calloc(1, sizeof(struct tp_list) + nr_tp * sizeof(struct tp));
    if (!tp_list)
        return NULL;

    tp_list->nr_tp = nr_tp;
    s = event;
    i = 0;
    while ((sep = strchr(s, ',')) != NULL) {
        tp_list->tp[i++].name = s;
        *sep = '\0';
        s = sep + 1;
    }
    if (*s)
        tp_list->tp[i++].name = s;

    tep__ref();
    /*
     * Event syntax:
     *    EVENT,EVENT,...
     * EVENT:
     *    sys:name[/filter/ATTR/ATTR/.../]
     * ATTR:
     *    stack : sample_type PERF_SAMPLE_CALLCHAIN
     *    max-stack=int : sample_max_stack
     *    top-by=field : top add and sort by this field
     *    top-add=field: top add this field
     *    ...
    **/
    for (i = 0; i < nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];
        struct tep_event *event = NULL;
        char *sys = NULL;
        char *name = NULL;
        char *filter = NULL;
        int stack = 0;
        int max_stack = 0;
        bool top_by;
        char *alias = NULL;
        int id;

        sys = s = tp->name;
        sep = strchr(s, ':');
        if (!sep)
            goto err_out;
        *sep = '\0';

        name = s = sep + 1;
        sep = strchr(s, '/');
        if (sep)
            *sep = '\0';

        id = tep__event_id(sys, name);
        if (id < 0)
            goto err_out;
        event = tep_find_event_by_name(tep, sys, name);
        if (!event)
            goto err_out;

        if (sep) {
            filter = s = sep + 1;
            sep = strchr(s, '/');
            if (!sep)
                goto err_out;
            *sep = '\0';

            s = sep + 1;
            while ((sep = strchr(s, '/')) != NULL) {
                char *attr = s;
                char *value = NULL;
                *sep = '\0';
                s = sep + 1;
                if ((sep = strchr(attr, '=')) != NULL) {
                    *sep = '\0';
                    value = sep + 1;
                }
                top_by = false;
                if (strcmp(attr, "stack") == 0)
                    stack = 1;
                else if (strcmp(attr, "max-stack") == 0) {
                    stack = 1;
                    max_stack = value ? atoi(value) : 0;
                    if (max_stack > PERF_MAX_STACK_DEPTH)
                        max_stack = PERF_MAX_STACK_DEPTH;
                } else if (strcmp(attr, "top-by") == 0 ||
                           strcmp(attr, "top_by") == 0) {
                    top_by = true;
                    goto top_add;
                } else if (strcmp(attr, "top-add") == 0 ||
                           strcmp(attr, "top_add") == 0) {
                    top_add:
                    if (!tep_find_any_field(event, value)) {
                        fprintf(stderr, "Attr top-add: cannot find %s field at %s:%s\n", value, sys, name);
                        goto err_out;
                    }
                    tp->nr_top ++;
                    tp->top_add = realloc(tp->top_add, tp->nr_top * sizeof(*tp->top_add));
                    tp->top_add[tp->nr_top-1].field = value;
                    tp->top_add[tp->nr_top-1].top_by = top_by;
                } else if (strcmp(attr, "alias") == 0) {
                    alias = value;
                } else if (strcmp(attr, "ptr") == 0) {
                    if (!tep_find_any_field(event, value)) {
                        fprintf(stderr, "Attr ptr: cannot find %s field at %s:%s\n", value, sys, name);
                        goto err_out;
                    }
                    tp->mem_ptr = value;
                } else if (strcmp(attr, "size") == 0) {
                    if (!tep_find_any_field(event, value)) {
                        fprintf(stderr, "Attr size: cannot find %s field at %s:%s\n", value, sys, name);
                        goto err_out;
                    }
                    tp->mem_size = value;
                }
            }
        }

        tp->evsel = NULL;
        tp->id = id;
        tp->sys = sys;
        tp->name = name;
        tp->filter = filter;
        tp->stack = stack;
        tp->max_stack = max_stack;
        tp->alias = alias;
        if (tp->nr_top == 0) {
            tp->nr_top = 1;
            tp->top_add = realloc(tp->top_add, tp->nr_top * sizeof(*tp->top_add));
            tp->top_add[0].field = alias ? : name;
            tp->top_add[0].event = true;
            tp->top_add[0].top_by = false;
        }
        if (!tp->mem_ptr && tep_find_any_field(event, "ptr"))
            tp->mem_ptr = "ptr";
        if (!tp->mem_size && tep_find_any_field(event, "bytes_alloc"))
            tp->mem_size = "bytes_alloc";

        tp_list->nr_need_stack += stack;
        tp_list->nr_top += tp->nr_top;
        tp_list->nr_mem_size += !!tp->mem_size;
    }

    tp_list->need_stream_id = (tp_list->nr_need_stack && tp_list->nr_need_stack != tp_list->nr_tp);

    tep__unref();
    return tp_list;

err_out:
    tep__unref();
    tp_list_free(tp_list);
    return NULL;
}

void tp_list_free(struct tp_list *tp_list)
{
    int i;
    if (!tp_list)
        return ;
    for (i = 0; i < tp_list->nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];
        if (tp->top_add)
            free(tp->top_add);
    }
    free(tp_list);
}

