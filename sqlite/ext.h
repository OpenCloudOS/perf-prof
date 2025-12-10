/*
 * ext.h - SQLite extension interface for perf tracepoint events
 * Defines data structures shared between sql.c and sqlite/perf_tp.c:
 */
#ifndef __SQLITE_EXT_H
#define __SQLITE_EXT_H

#include <monitor.h>
#include <tep.h>
#include <linux/rblist.h>

#include <sqlite3.h>
/*
 * SQLite compatibility mode:
 * Define SQLITE_COMPAT to force using sqlite3_prepare_v2 instead of v3.
 * This is useful for old systems where sqlite3_prepare_v3 is not available.
 *
 * Usage: export CFLAGS=-DSQLITE_COMPAT; make
 */
#if defined(SQLITE_PREPARE_PERSISTENT) && !defined(SQLITE_COMPAT)
#define USE_SQLITE_PREPARE_V3 1
#endif


/*
 * Perf event sample layout matching the sample_type configuration:
 * PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ID | PERF_SAMPLE_CPU |
 * PERF_SAMPLE_PERIOD | PERF_SAMPLE_RAW
 */
struct sql_sample_type {
    struct {
        __u32    pid;
        __u32    tid;
    }    tid_entry;
    __u64   time;
    __u64   id;
    struct {
        __u32    cpu;
        __u32    reserved;
    }    cpu_entry;
    __u64        period;
    struct {
        __u32   size;
        union {
            __u8    data[0];
            struct trace_entry common;
        };
    } raw;
};

/* Event node for memory mode linked list */
struct tp_event {
    struct list_head link;
    uint64_t rowid;
    union perf_event event;
};

struct tp_private {
    /* Common fields */
    struct tep_format_field **fields;
    int nr_fields;
    const char *table_name;
    char *function_list;  /* Comma-separated list of available SQL functions for this event */
    time_t created_time;

    /* Memory mode: events stored in linked list */
    uint64_t rowid;
    struct list_head event_list; // struct tp_event;

    /* File mode: events inserted via prepared statement */
    sqlite3_stmt *insert_stmt;

    /* Event statistics */
    uint64_t sample_count;
    uint64_t first_sample_time;
    uint64_t last_sample_time;
};

struct sql_tp_ctx {
    sqlite3 *sql;
    struct tp_list *tp_list;
    struct tep_handle *tep;
    struct rblist symbolic_table;
    struct sqlite_func {
        int data_type; // SQLITE_INTEGER, SQLITE_BLOB
        const char *func_name;
    } *sqlite_funcs;
    int ksymbol;

    int (*sample)(struct sql_tp_ctx *ctx, struct tp *tp, union perf_event *event);
    void (*reset)(struct sql_tp_ctx *ctx);
};

struct sql_tp_ctx *sql_tp_file(sqlite3 *sql, struct tp_list *tp_list);
struct sql_tp_ctx *sql_tp_mem(sqlite3 *sql, struct tp_list *tp_list);
void sql_tp_free(struct sql_tp_ctx *ctx);

#endif