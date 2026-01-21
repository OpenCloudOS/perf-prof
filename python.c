// SPDX-License-Identifier: GPL-2.0
/*
 * python - Python scripting profiler for perf-prof
 *
 * Convert perf events to Python objects and process them with Python scripts.
 *
 * Usage: perf-prof python -e EVENT script.py
 */

/* Python.h must be included first */
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <monitor.h>
#include <dlfcn.h>
#include <tep.h>
#include <trace_helpers.h>

/* Global script path, set by argc_init before init */
static char *script_path = NULL;

/*
 * Sample type for Python profiler (no callchain support in initial version)
 * PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU |
 * PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
 *
 * Same layout as struct sql_sample_type in sqlite/ext.h
 */
struct python_sample_type {
    struct {
        u32    pid;
        u32    tid;
    }    tid_entry;
    u64   time;
    u64   id;
    struct {
        u32    cpu;
        u32    reserved;
    }    cpu_entry;
    u64   period;
    struct {
        u32   size;
        union {
            u8    data[0];
            struct trace_entry common;
        };
    } raw;
};

struct python_ctx {
    struct tp_list *tp_list;
    char *script_path;
    PyObject *module;
    PyObject *func_init;
    PyObject *func_exit;
    PyObject *func_print_stat;
    PyObject *func_interval;
    PyObject *func_lost;
    PyObject *func_sample;  /* default __sample__ handler */
    /* Per-event handlers: sys__event_name */
    PyObject **event_handlers;
    /* Event fields cache */
    struct tep_format_field ***event_fields;
    int nr_events;
};

static void python_exit(struct prof_dev *dev);

/*
 * Get Python function from module, returns NULL if not found (not an error)
 * Only returns user-defined functions, not built-in module attributes like __init__.
 */
static PyObject *get_python_func(PyObject *module, const char *name)
{
    PyObject *func = PyObject_GetAttrString(module, name);
    if (func) {
        /* Must be a user-defined function, not built-in or other callable */
        if (!PyFunction_Check(func)) {
            Py_DECREF(func);
            func = NULL;
        }
    }
    if (!func)
        PyErr_Clear();
    return func;
}

/*
 * Build event handler function name: sys__event_name
 * e.g., "sched:sched_wakeup" -> "sched__sched_wakeup"
 * e.g., "sched:sched-wakeup" -> "sched__sched_wakeup"
 * Convert invalid characters (like '-') to '_' for valid Python function names.
 */
static char *build_handler_name(const char *sys, const char *name)
{
    char *handler_name;
    size_t len = strlen(sys) + 2 + strlen(name) + 1;
    char *p;

    handler_name = malloc(len);
    if (handler_name) {
        snprintf(handler_name, len, "%s__%s", sys, name);
        /* Convert invalid characters to underscore */
        for (p = handler_name; *p; p++) {
            if (*p == '-' || *p == '.' || *p == ':')
                *p = '_';
        }
    }
    return handler_name;
}

/*
 * Convert raw event data to Python dict
 * Fields are extracted based on tep_format_field
 */
static PyObject *event_to_dict(struct python_ctx *ctx, struct tp *tp,
                               struct python_sample_type *data, int tp_index)
{
    PyObject *dict, *val;
    struct tep_format_field **fields;
    void *base;
    int i;

    dict = PyDict_New();
    if (!dict)
        return NULL;

    /* Add common sample fields - must Py_DECREF after PyDict_SetItemString */
#define SET_DICT_ITEM(dict, key, value) do { \
        val = (value); \
        PyDict_SetItemString(dict, key, val); \
        Py_DECREF(val); \
    } while (0)

    SET_DICT_ITEM(dict, "_pid", PyLong_FromLong(data->tid_entry.pid));
    SET_DICT_ITEM(dict, "_tid", PyLong_FromLong(data->tid_entry.tid));
    SET_DICT_ITEM(dict, "_time", PyLong_FromUnsignedLongLong(data->time));
    SET_DICT_ITEM(dict, "_cpu", PyLong_FromLong(data->cpu_entry.cpu));
    SET_DICT_ITEM(dict, "_period", PyLong_FromUnsignedLongLong(data->period));

    /* Add common_* fields from trace_entry */
    SET_DICT_ITEM(dict, "common_flags", PyLong_FromLong(data->raw.common.common_flags));
    SET_DICT_ITEM(dict, "common_preempt_count", PyLong_FromLong(data->raw.common.common_preempt_count));
    SET_DICT_ITEM(dict, "common_pid", PyLong_FromLong(data->raw.common.common_pid));

#undef SET_DICT_ITEM

    /* Get cached fields for this event */
    if (tp_index < 0 || tp_index >= ctx->nr_events || !ctx->event_fields[tp_index]) {
        return dict;
    }

    fields = ctx->event_fields[tp_index];
    base = data->raw.data;

    /* Parse event-specific fields (similar to sql_tp_file_sample) */
    for (i = 0; fields[i]; i++) {
        struct tep_format_field *field = fields[i];
        PyObject *value = NULL;
        void *ptr;
        int len;

        if (field->flags & TEP_FIELD_IS_STRING) {
            /* String field */
            if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                ptr = base + *(unsigned short *)(base + field->offset);
                len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
                if (len > 0)
                    value = PyUnicode_FromStringAndSize((char *)ptr, len - 1); /* exclude null */
                else
                    value = PyUnicode_FromString("");
            } else {
                ptr = base + field->offset;
                value = PyUnicode_FromString((char *)ptr);
            }
        } else if (field->flags & TEP_FIELD_IS_ARRAY) {
            /* Array field -> bytes */
            if (field->flags & TEP_FIELD_IS_DYNAMIC) {
                ptr = base + *(unsigned short *)(base + field->offset);
                len = *(unsigned short *)(base + field->offset + sizeof(unsigned short));
            } else {
                ptr = base + field->offset;
                len = field->size;
            }
            value = PyBytes_FromStringAndSize((char *)ptr, len);
        } else {
            /* Numeric field */
            bool is_signed = field->flags & TEP_FIELD_IS_SIGNED;
            long long val = 0;

            if (field->size == 1)
                val = is_signed ? *(char *)(base + field->offset)
                                : *(unsigned char *)(base + field->offset);
            else if (field->size == 2)
                val = is_signed ? *(short *)(base + field->offset)
                                : *(unsigned short *)(base + field->offset);
            else if (field->size == 4)
                val = is_signed ? *(int *)(base + field->offset)
                                : *(unsigned int *)(base + field->offset);
            else if (field->size == 8)
                val = is_signed ? *(long long *)(base + field->offset)
                                : *(unsigned long long *)(base + field->offset);

            if (field->size <= 8)
                value = PyLong_FromLongLong(val);
        }

        if (value) {
            PyDict_SetItemString(dict, field->name, value);
            Py_DECREF(value);
        }
    }

    return dict;
}

/*
 * Cache event fields for faster lookup during sampling.
 * After tep__ref(), tep_find_event() returns pointers that remain valid.
 */
static int cache_event_fields(struct python_ctx *ctx)
{
    struct tep_handle *tep;
    struct tp *tp;
    int i, ret = -1;

    ctx->nr_events = ctx->tp_list->nr_tp;
    ctx->event_fields = calloc(ctx->nr_events, sizeof(struct tep_format_field **));
    ctx->event_handlers = calloc(ctx->nr_events, sizeof(PyObject *));

    if (!ctx->event_fields || !ctx->event_handlers)
        return -1;

    tep = tep__ref();

    for_each_real_tp(ctx->tp_list, tp, i) {
        struct tep_event *event = tep_find_event(tep, tp->id);
        char *handler_name;

        if (event) {
            ctx->event_fields[i] = tep_event_fields(event);
            if (!ctx->event_fields[i])
                goto failed;
        }

        /* Look for event-specific handler */
        handler_name = build_handler_name(tp->sys, tp->name);
        if (handler_name) {
            ctx->event_handlers[i] = get_python_func(ctx->module, handler_name);
            free(handler_name);
        }
    }
    ret = 0;

failed:
    tep__unref();
    return ret;
}

/*
 * Initialize Python interpreter and load script
 */
static int python_script_init(struct python_ctx *ctx)
{
    PyObject *sys_path, *path;
    char *script_dir, *script_name, *base, *dot;
    char *script_path_copy;

    /* Initialize Python */
    Py_Initialize();
    if (!Py_IsInitialized()) {
        fprintf(stderr, "Failed to initialize Python interpreter\n");
        return -1;
    }

    /* Add script directory to sys.path */
    script_path_copy = strdup(ctx->script_path);
    if (!script_path_copy)
        return -1;

    script_dir = dirname(script_path_copy);
    sys_path = PySys_GetObject("path");
    if (sys_path) {
        path = PyUnicode_FromString(script_dir);
        if (path) {
            PyList_Insert(sys_path, 0, path);
            Py_DECREF(path);
        }
    }

    /* Get module name (script filename without .py) */
    script_name = strdup(ctx->script_path);
    if (!script_name) {
        free(script_path_copy);
        return -1;
    }

    /* Remove directory path */
    base = strrchr(script_name, '/');
    if (base)
        base++;
    else
        base = script_name;

    /* Remove .py extension */
    dot = strrchr(base, '.');
    if (dot && strcmp(dot, ".py") == 0)
        *dot = '\0';

    /* Import the module */
    ctx->module = PyImport_ImportModule(base);
    free(script_name);
    free(script_path_copy);

    if (!ctx->module) {
        PyErr_Print();
        fprintf(stderr, "Failed to load Python script: %s\n", ctx->script_path);
        return -1;
    }

    /* Get callback functions */
    ctx->func_init = get_python_func(ctx->module, "__init__");
    ctx->func_exit = get_python_func(ctx->module, "__exit__");
    ctx->func_print_stat = get_python_func(ctx->module, "__print_stat__");
    ctx->func_interval = get_python_func(ctx->module, "__interval__");
    ctx->func_lost = get_python_func(ctx->module, "__lost__");
    ctx->func_sample = get_python_func(ctx->module, "__sample__");

    return 0;
}

static void python_script_exit(struct python_ctx *ctx)
{
    int i;

    if (ctx->func_init) Py_DECREF(ctx->func_init);
    if (ctx->func_exit) Py_DECREF(ctx->func_exit);
    if (ctx->func_print_stat) Py_DECREF(ctx->func_print_stat);
    if (ctx->func_interval) Py_DECREF(ctx->func_interval);
    if (ctx->func_lost) Py_DECREF(ctx->func_lost);
    if (ctx->func_sample) Py_DECREF(ctx->func_sample);

    if (ctx->event_handlers) {
        for (i = 0; i < ctx->nr_events; i++) {
            if (ctx->event_handlers[i])
                Py_DECREF(ctx->event_handlers[i]);
        }
        free(ctx->event_handlers);
    }

    if (ctx->event_fields) {
        for (i = 0; i < ctx->nr_events; i++) {
            if (ctx->event_fields[i])
                free(ctx->event_fields[i]);
        }
        free(ctx->event_fields);
    }

    if (ctx->module) Py_DECREF(ctx->module);

    if (Py_IsInitialized())
        Py_Finalize();
}

/*
 * Call Python __init__() function
 */
static int python_call_init(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_init)
        return 0;

    result = PyObject_CallObject(ctx->func_init, NULL);
    if (!result) {
        PyErr_Print();
        return -1;
    }
    Py_DECREF(result);
    return 0;
}

/*
 * Call Python __exit__() function
 */
static void python_call_exit(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_exit)
        return;

    result = PyObject_CallObject(ctx->func_exit, NULL);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * Call Python __print_stat__(indent) function
 */
static void python_call_print_stat(struct python_ctx *ctx, int indent)
{
    PyObject *result;

    if (!ctx->func_print_stat)
        return;

    result = PyObject_CallFunction(ctx->func_print_stat, "i", indent);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * Call Python __interval__() function
 */
static void python_call_interval(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_interval)
        return;

    result = PyObject_CallObject(ctx->func_interval, NULL);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * Call Python __lost__() function
 */
static void python_call_lost(struct python_ctx *ctx)
{
    PyObject *result;

    if (!ctx->func_lost)
        return;

    result = PyObject_CallObject(ctx->func_lost, NULL);
    if (!result) {
        PyErr_Print();
        return;
    }
    Py_DECREF(result);
}

/*
 * python_argc_init - Parse extra command line arguments (script.py)
 * Called before init() to capture the script path from remaining arguments.
 */
static int python_argc_init(int argc, char *argv[])
{
    if (script_path) {
        free(script_path);
        script_path = NULL;
    }

    if (argc >= 1) {
        script_path = strdup(argv[0]);
        if (!script_path)
            return -1;
    }
    return 0;
}

/*
 * monitor_ctx_init - Initialize the Python profiler context
 */
static int monitor_ctx_init(struct prof_dev *dev)
{
    struct env *env = dev->env;
    struct python_ctx *ctx;

    if (!env->event) {
        fprintf(stderr, "Error: -e EVENT is required\n");
        return -1;
    }

    if (!script_path) {
        fprintf(stderr, "Error: Python script path is required\n");
        fprintf(stderr, "Usage: perf-prof python -e EVENT script.py\n");
        return -1;
    }

    /* Verify script exists */
    if (access(script_path, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot read script: %s\n", script_path);
        return -1;
    }

    ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;

    tep__ref();

    ctx->script_path = strdup(script_path);
    if (!ctx->script_path)
        goto failed;

    ctx->tp_list = tp_list_new(dev, env->event);
    if (!ctx->tp_list)
        goto failed;

    /* Initialize Python and load script */
    if (python_script_init(ctx) < 0)
        goto failed;

    /* Cache event fields */
    if (cache_event_fields(ctx) < 0)
        goto failed;

    dev->private = ctx;
    return 0;

failed:
    python_script_exit(ctx);
    if (ctx->tp_list)
        tp_list_free(ctx->tp_list);
    if (ctx->script_path)
        free(ctx->script_path);
    tep__unref();
    free(ctx);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct python_ctx *ctx = dev->private;

    python_call_exit(ctx);
    python_script_exit(ctx);

    tp_list_free(ctx->tp_list);
    free(ctx->script_path);
    tep__unref();
    free(ctx);
}

static int python_init(struct prof_dev *dev)
{
    struct perf_evlist *evlist = dev->evlist;
    struct env *env = dev->env;
    struct python_ctx *ctx;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID |
                         PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW,
        .read_format   = PERF_FORMAT_ID,
        .pinned        = 1,
        .disabled      = 1,
        .inherit       = env->inherit,
        .watermark     = 1,
    };
    struct perf_evsel *evsel;
    struct tp *tp;
    int i;

    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;

    reduce_wakeup_times(dev, &attr);

    for_each_real_tp(ctx->tp_list, tp, i) {
        evsel = tp_evsel_new(tp, &attr);
        if (!evsel)
            goto failed;
        perf_evlist__add(evlist, evsel);
    }

    /* Call Python __init__ */
    if (python_call_init(ctx) < 0)
        goto failed;

    return 0;

failed:
    monitor_ctx_exit(dev);
    return -1;
}

static int python_filter(struct prof_dev *dev)
{
    struct python_ctx *ctx = dev->private;
    return tp_list_apply_filter(dev, ctx->tp_list);
}

static void python_exit(struct prof_dev *dev)
{
    monitor_ctx_exit(dev);
}

static void python_lost(struct prof_dev *dev, union perf_event *event,
                        int instance, u64 lost_start, u64 lost_end)
{
    struct python_ctx *ctx = dev->private;
    print_lost_fn(dev, event, instance);
    python_call_lost(ctx);
}

static void python_sample(struct prof_dev *dev, union perf_event *event, int instance)
{
    struct python_ctx *ctx = dev->private;
    struct python_sample_type *data = (void *)event->sample.array;
    struct perf_evsel *evsel;
    struct tp *tp;
    PyObject *dict, *result;
    int i;

    /* Find the matching tp */
    evsel = perf_evlist__id_to_evsel(dev->evlist, data->id, NULL);
    for_each_real_tp(ctx->tp_list, tp, i) {
        if (tp->evsel == evsel)
            break;
    }

    if (i >= ctx->tp_list->nr_tp)
        return;

    /* Convert event to Python dict */
    dict = event_to_dict(ctx, tp, data, i);
    if (!dict)
        return;

    /* Call event-specific handler or default __sample__ */
    if (ctx->event_handlers[i]) {
        result = PyObject_CallFunction(ctx->event_handlers[i], "O", dict);
        if (!result)
            PyErr_Print();
        else
            Py_DECREF(result);
    } else if (ctx->func_sample) {
        /* Add _event field for default handler */
        char event_name[256];
        PyObject *event_str;
        snprintf(event_name, sizeof(event_name), "%s:%s", tp->sys, tp->name);
        event_str = PyUnicode_FromString(event_name);
        PyDict_SetItemString(dict, "_event", event_str);
        Py_DECREF(event_str);

        result = PyObject_CallFunction(ctx->func_sample, "O", dict);
        if (!result)
            PyErr_Print();
        else
            Py_DECREF(result);
    }

    Py_DECREF(dict);
}

static void python_interval(struct prof_dev *dev)
{
    struct python_ctx *ctx = dev->private;
    python_call_interval(ctx);
}

static void python_print_dev(struct prof_dev *dev, int indent)
{
    struct python_ctx *ctx = dev->private;
    python_call_print_stat(ctx, indent);
}

static void python_help(struct help_ctx *hctx)
{
    int i, j;

    printf(PROGRAME " python ");
    printf("-e \"");
    for (i = 0; i < hctx->nr_list; i++) {
        struct tp *tp;
        for_each_real_tp(hctx->tp_list[i], tp, j) {
            printf("%s:%s/%s/", tp->sys, tp->name,
                   tp->filter && tp->filter[0] ? tp->filter : ".");
            if (i != hctx->nr_list - 1 ||
                j != hctx->tp_list[i]->nr_tp - 1)
                printf(",");
        }
    }
    printf("\" ");
    printf("script.py ");

    common_help(hctx, true, true, true, true, true, true, false);
    printf("\n");
}

static const char *python_desc[] = PROFILER_DESC("python",
    "[OPTION...] -e EVENT[,EVENT...] script.py",
    "Process perf events with Python scripts.",
    "",
    "SYNOPSIS",
    "    Convert perf events to Python dict objects and process them with custom",
    "    Python scripts. Provides a flexible way to analyze events using Python.",
    "",
    "SCRIPT SYNTAX",
    "  CALLBACK FUNCTIONS",
    "    __init__()              - Called once before event processing",
    "    __exit__()              - Called once before program exit",
    "    __print_stat__(indent)  - Called on SIGUSR2 signal",
    "    __interval__()          - Called at each -i interval",
    "    __lost__()              - Called when events are lost",
    "",
    "  EVENT HANDLERS (priority: specific > default)",
    "    sys__event_name(event)  - Event-specific handler",
    "                              e.g., sched__sched_wakeup for sched:sched_wakeup",
    "                              Characters '-', '.', ':' converted to '_'",
    "    __sample__(event)       - Default handler (dict includes _event field)",
    "",
    "  EVENT DICT FIELDS",
    "    _pid, _tid              - Process/thread ID",
    "    _time                   - Event timestamp (ns)",
    "    _cpu                    - CPU number",
    "    _period                 - Sample period",
    "    _event                  - Event name (only in __sample__)",
    "    common_flags            - Trace event flags",
    "    common_preempt_count    - Preemption count",
    "    common_pid              - Thread ID from trace event",
    "    <field>                 - Event-specific fields (int/str/bytes)",
    "",
    "EXAMPLES",
    "    "PROGRAME" python -e sched:sched_wakeup counter.py",
    "    "PROGRAME" python -e sched:sched_wakeup,sched:sched_switch -i 1000 analyzer.py",
    "    "PROGRAME" python -e 'sched:sched_wakeup/pid>1000/' -C 0-3 filter.py");

static const char *python_argv[] = PROFILER_ARGV("python",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "event");

static profiler python = {
    .name = "python",
    .desc = python_desc,
    .argv = python_argv,
    .pages = 2,
    .help = python_help,
    .argc_init = python_argc_init,
    .init = python_init,
    .filter = python_filter,
    .deinit = python_exit,
    .print_dev = python_print_dev,
    .interval = python_interval,
    .lost = python_lost,
    .sample = python_sample,
};
PROFILER_REGISTER(python);
