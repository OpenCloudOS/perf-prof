#ifndef __TEP_H
#define __TEP_H

#include <event-parse.h>
#include <expr.h>
#include <net.h>

struct tep_handle *tep__ref(void);
void tep__unref(void);
int tep__event_id(const char *sys, const char *name);
void tep__update_comm(const char *comm, int pid);
const char *tep__pid_to_comm(int pid);
void tep__print_event(unsigned long long ts, int cpu, void *data, int size);
bool tep__event_has_field(int id, const char *field);
bool tep__event_field_size(int id, const char *field);
int tep__event_size(int id);

typedef struct global_var_declare event_fields;
event_fields *tep__event_fields(int id);

void monitor_tep__comm(union perf_event *event, int instance);

struct tp {
    struct perf_evsel *evsel;
    int id;
    char *sys;
    char *name;
    char *filter;
    int stack;
    int max_stack;
    char *alias;
    unsigned long *counters; // Counter per instance

    // top profiler
    struct {
        // long tp_prog_run(struct tp *tp, ...)
        struct expr_prog *field_prog;
        char *field;
        bool event;
        bool top_by;
    } *top_add;
    int nr_top;

    // char *tp_get_comm(struct tp *tp, ...)
    struct expr_prog *comm_prog;
    const char *comm;

    // kmemleak profiler
    struct expr_prog *mem_ptr_prog;
    const char *mem_ptr;
    struct expr_prog *mem_size_prog;
    const char *mem_size;

    // num-dist profiler
    struct expr_prog *num_prog;
    const char *num;

    //multi-trace profiler
    // unsigned long tp_get_key(struct tp *tp, ...)
    struct expr_prog *key_prog;
    const char *key;
    bool untraced;
    bool trigger;

    // net event
    void *push_to;
    struct tcp_socket_ops push_ops;
    const char *server_ip;
    const char *server_port;

    void *pull_from;
    struct tcp_socket_ops pull_ops;
    const char *ip;
    const char *port;
    int remote_id;
    int cpu_pos;
    int stream_id_pos;
    int common_type_pos;
};

struct tp_list {
    int nr_tp;
    int nr_need_stack;
    bool need_stream_id;
    int nr_top;
    int nr_comm;
    int nr_mem_size;
    int nr_num;
    int nr_untraced;
    int nr_push_to;
    int nr_pull_from;
    struct tp tp[0];
};

struct perf_record_tp {
    struct perf_event_header header;
    u32 id;
    u16 sys_offset;
    u16 name_offset;
    u64 sample_period;
    u64 sample_type;
    u32 event_size;
    u32 unused;
    char str[];
};

enum tp_event_type {
    PERF_RECORD_TP = PERF_RECORD_HEADER_MAX + 1,
};

struct tp_list *tp_list_new(char *event_str);
void tp_list_free(struct tp_list *tp_list);
bool tp_local(struct tp *tp);
int tp_broadcast_event(struct tp *tp, union perf_event *event);

struct expr_prog *tp_new_prog(struct tp *tp, char *expr_str);
long tp_prog_run(struct tp *tp, struct expr_prog *prog, void *data, int size);
char *tp_get_comm(struct tp *tp, void *data, int size);
void *tp_get_mem_ptr(struct tp *tp, void *data, int size);
unsigned long tp_get_mem_size(struct tp *tp, void *data, int size);
unsigned long tp_get_key(struct tp *tp, void *data, int size);
unsigned long tp_get_num(struct tp *tp, void *data, int size);


#endif

