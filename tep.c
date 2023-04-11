#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <monitor.h>
#include <tep.h>
#include <stack_helpers.h>

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
    function_resolver_ref();
    tep_set_function_resolver(tep, function_resolver, NULL);
    return tep;
}

void tep__unref(void)
{
    if (tep == NULL)
        return;

    if (tep_get_ref(tep) == 1) {
        tep_reset_function_resolver(tep);
        function_resolver_unref();
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

bool tep__event_has_field(int id, const char *field)
{
    bool has_field = false;
    struct tep_event *event;

    tep__ref();
    event = tep_find_event(tep, id);
    if (event) {
        has_field = !!tep_find_any_field(event, field);
    }
    tep__unref();

    return has_field;
}

bool tep__event_field_size(int id, const char *field)
{
    struct tep_event *event;
    struct tep_format_field *format;
    int size = -1;

    tep__ref();
    event = tep_find_event(tep, id);
    if (event) {
        format = tep_find_any_field(event, field);
        if (format)
            size = format->size;
    }
    tep__unref();

    return size;
}

int tep__event_size(int id)
{
    struct tep_event *event;
    struct tep_format_field **fields;
    int size = -1;

    tep__ref();
    event = tep_find_event(tep, id);
    if (event) {
        fields = tep_event_fields(event);
        if (fields) {
            int i = 0;
            while (fields[i]) {
                if (fields[i]->offset + fields[i]->size > size)
                    size = fields[i]->offset + fields[i]->size;
                i++;
            }
            free(fields);
        }
    }
    tep__unref();
    return size;
}

event_fields *tep__event_fields(int id)
{
    struct tep_event *event;
    struct tep_format_field **common_fields;
    struct tep_format_field **fields;
    int nr_common = 0, nr_fields = 0, nr_dynamic = 0;
    event_fields *ef = NULL;
    int i = 0, f = 0;

    tep__ref();
    event = tep_find_event(tep, id);
    if (!event)
        goto _return;

    common_fields = tep_event_common_fields(event);
    fields = tep_event_fields(event);
    if (!common_fields || !fields)
        goto _return;

    while (common_fields[nr_common]) nr_common++;
    while (fields[nr_fields]) {
        if (fields[nr_fields]->flags & TEP_FIELD_IS_DYNAMIC)
            nr_dynamic++;
        nr_fields++;
    }

    ef = calloc(nr_common + nr_fields + nr_dynamic + 1, sizeof(*ef));
    if (!ef)
        goto _free;

    f = 0;
    while (common_fields[f]) {
        ef[i].name = common_fields[f]->name;
        ef[i].offset = common_fields[f]->offset;
        ef[i].size = common_fields[f]->size;
        ef[i].elementsize = common_fields[f]->elementsize;
        i++;
        f++;
    }
    f = 0;
    while (fields[f]) {
        if (fields[f]->flags & TEP_FIELD_IS_DYNAMIC) {
            int len = strlen(fields[f]->name);
            ef[i].name = malloc(len + sizeof("_offset")); //TODO need free
            sprintf((char *)ef[i].name, "%s_offset", fields[f]->name);
            ef[i].offset = fields[f]->offset;
            ef[i].size = 2;
            ef[i].elementsize = 2;
            i++;

            ef[i].name = malloc(len + sizeof("_len")); //TODO need free
            sprintf((char *)ef[i].name, "%s_len", fields[f]->name);
            ef[i].offset = fields[f]->offset + 2;
            ef[i].size = 2;
            ef[i].elementsize = 2;
        } else {
            ef[i].name = fields[f]->name;
            ef[i].offset = fields[f]->offset;
            ef[i].size = fields[f]->size;
            ef[i].elementsize = fields[f]->elementsize;
        }
        i++;
        f++;
    }
    ef[i].name = NULL;

_free:
    if (common_fields) free(common_fields);
    if (fields) free(fields);
_return:
    tep__unref();
    return ef;
}

void monitor_tep__comm(union perf_event *event, int instance)
{
    tep__update_comm(event->comm.comm, event->comm.tid);
}

static char *next_sep(char *s, int c)
{
    while (*s) {
        if (*s == (char)c)
            return (char *)s;
        if (*s == '\'' || *s == '"') {
            int quote = *s++;
            while (*s && *s++ != quote);
        } else
            s++;
    }
    return NULL;
}

struct tp_list *tp_list_new(char *event_str)
{
    char *s = event_str;
    char *sep;
    int i;
    int nr_tp = 0;
    struct tp_list *tp_list = NULL;

    if (!s)
        return NULL;

    while ((sep = next_sep(s, ',')) != NULL) {
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
    s = event_str;
    i = 0;
    while ((sep = next_sep(s, ',')) != NULL) {
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
        event_fields *fields = NULL;
        struct expr_prog *prog = NULL;

        sys = s = tp->name;
        sep = strchr(s, ':');
        if (!sep)
            goto err_out;
        *sep = '\0';

        name = s = sep + 1;
        sep = next_sep(s, '/');
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
            sep = next_sep(s, '/');
            if (!sep)
                goto err_out;
            *sep = '\0';

            s = sep + 1;
            while ((sep = next_sep(s, '/')) != NULL) {
                char *attr = s;
                char *value = NULL;
                *sep = '\0';
                s = sep + 1;
                if ((sep = strchr(attr, '=')) != NULL) {
                    *sep = '\0';
                    value = sep + 1;
                }
                // Remove single and double quotes around value
                if (value && (value[0] == '\'' || value[0] == '"')) {
                    int len = strlen(value);
                    if (value[len-1] == value[0]) {
                        value[len-1] = '\0';
                        value ++;
                    }
                }
                top_by = false;
                prog = NULL;
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
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->nr_top ++;
                    tp->top_add = realloc(tp->top_add, tp->nr_top * sizeof(*tp->top_add));
                    tp->top_add[tp->nr_top-1].field_prog = prog;
                    tp->top_add[tp->nr_top-1].field = value;
                    tp->top_add[tp->nr_top-1].event = false;
                    tp->top_add[tp->nr_top-1].top_by = top_by;
                } else if (strcmp(attr, "comm") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->comm_prog = prog;
                    tp->comm = value;
                } else if (strcmp(attr, "alias") == 0) {
                    alias = value;
                } else if (strcmp(attr, "ptr") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->mem_ptr_prog = prog;
                    tp->mem_ptr = value;
                } else if (strcmp(attr, "size") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->mem_size_prog = prog;
                    tp->mem_size = value;
                } else if (strcmp(attr, "num") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->num_prog = prog;
                    tp->num = value;
                } else if (strcmp(attr, "key") == 0) {
                    if (!fields) fields = tep__event_fields(id);
                    if (fields)  prog = expr_compile(value, fields);
                    if (!prog) { free(fields); goto err_out; }

                    tp->key_prog = prog;
                    tp->key = value;
                } else if (strcmp(attr, "untraced") == 0) {
                    tp->untraced = true;
                } else if (strcmp(attr, "trigger") == 0) {
                    tp->trigger = true;
                } else if (strcmp(attr, "push") == 0) {
                    if (tp_broadcast_new(tp, value) < 0) goto err_out;
                } else if (strcmp(attr, "pull") == 0) {
                    if (tp_receive_new(tp, value) < 0) goto err_out;
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
        tp->kernel = !tp->receive;
        if (tp->nr_top == 0) {
            tp->nr_top = 1;
            tp->top_add = realloc(tp->top_add, tp->nr_top * sizeof(*tp->top_add));
            tp->top_add[0].field_prog = NULL;
            tp->top_add[0].field = alias ? : name;
            tp->top_add[0].event = true;
            tp->top_add[0].top_by = false;
        }

        if (!tp->mem_ptr && tep_find_any_field(event, "ptr")) {
            if (!fields) fields = tep__event_fields(id);
            if (fields)  prog = expr_compile((char *)"ptr", fields);
            if (!prog) { free(fields); goto err_out; }

            tp->mem_ptr_prog = prog;
            tp->mem_ptr = "ptr";
        }
        if (!tp->mem_size && tep_find_any_field(event, "bytes_alloc")) {
            if (!fields) fields = tep__event_fields(id);
            if (fields)  prog = expr_compile((char *)"bytes_alloc", fields);
            if (!prog) { free(fields); goto err_out; }

            tp->mem_size_prog = prog;
            tp->mem_size = "bytes_alloc";
        }

        tp_list->nr_need_stack += stack;
        tp_list->nr_top += tp->nr_top;
        tp_list->nr_comm += !!tp->comm_prog;
        tp_list->nr_mem_size += !!tp->mem_size_prog;
        tp_list->nr_num += !!tp->num_prog;
        tp_list->nr_untraced += !!tp->untraced;
        tp_list->nr_push_to += !!tp->broadcast;
        tp_list->nr_pull_from += !!tp->receive;

        if (fields)
            free(fields);
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
    int i, j;
    if (!tp_list)
        return ;
    for (i = 0; i < tp_list->nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];
        for (j = 0; j < tp->nr_top; j++) {
            if (tp->top_add[j].field_prog)
                expr_destroy(tp->top_add[j].field_prog);
        }
        if (tp->top_add)
            free(tp->top_add);
        if (tp->comm_prog)
            expr_destroy(tp->comm_prog);
        if (tp->mem_ptr_prog)
            expr_destroy(tp->mem_ptr_prog);
        if (tp->mem_size_prog)
            expr_destroy(tp->mem_size_prog);
        if (tp->num_prog)
            expr_destroy(tp->num_prog);
        if (tp->key_prog)
            expr_destroy(tp->key_prog);
        tp_broadcast_free(tp);
        tp_receive_free(tp);
    }
    free(tp_list);
}

struct expr_prog *tp_new_prog(struct tp *tp, char *expr_str)
{
    event_fields *fields = tep__event_fields(tp->id);
    struct expr_prog *prog = NULL;
    if (fields) {
        prog = expr_compile(expr_str, fields);
        free(fields);
    }
    return prog;
}

long tp_prog_run(struct tp *tp, struct expr_prog *prog, void *data, int size)
{
    if (expr_load_data(prog, data, size) != 0) {
        expr_dump(prog);
        fprintf(stderr, "tp %s:%s prog load data failed!\n", tp->sys, tp->name);
        return -1;
    }
    return expr_run(prog);
}

char *tp_get_comm(struct tp *tp, void *data, int size)
{
    long comm = tp_prog_run(tp, tp->comm_prog, data, size);
    return comm == -1 ? (char *)"Error" : (char *)(unsigned long)comm;
}

unsigned long tp_get_key(struct tp *tp, void *data, int size)
{
    long key = tp_prog_run(tp, tp->key_prog, data, size);
    return key == -1 ? 0 : (unsigned long)key;
}

unsigned long tp_get_num(struct tp *tp, void *data, int size)
{
    long num = tp_prog_run(tp, tp->num_prog, data, size);
    return num == -1 ? 0 : (unsigned long)num;
}

void *tp_get_mem_ptr(struct tp *tp, void *data, int size)
{
    long mem_ptr = tp_prog_run(tp, tp->mem_ptr_prog, data, size);
    return mem_ptr == -1 ? NULL : (void *)mem_ptr;
}

unsigned long tp_get_mem_size(struct tp *tp, void *data, int size)
{
    long mem_size = tp_prog_run(tp, tp->mem_size_prog, data, size);
    return mem_size == -1 ? 1 : (unsigned long)mem_size;
}

