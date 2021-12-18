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


#endif

