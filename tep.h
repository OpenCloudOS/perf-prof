#ifndef __TEP_H
#define __TEP_H

#include <event-parse.h>

struct tep_handle *tep__ref(void);
void tep__unref(void);
int tep__event_id(const char *sys, const char *name);
void tep__update_comm(const char *comm, int pid);
const char *tep__pid_to_comm(int pid);
void tep__print_event(unsigned long long ts, int cpu, void *data, int size);


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
    struct {
        char *field;
        bool event;
        bool top_by;
    } *top_add;
    int nr_top;
};

struct tp_list {
    int nr_tp;
    int nr_need_stack;
    bool need_stream_id;
    int nr_top;
    struct tp tp[0];
};

struct tp_list *tp_list_new(char *event);
void tp_list_free(struct tp_list *tp_list);




#endif

