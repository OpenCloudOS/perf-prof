#ifndef __EVENT_SPREAD
#define __EVENT_SPREAD


int tp_broadcast_new(struct tp *tp, char *s);
void tp_broadcast_free(struct tp *tp);
int tp_broadcast_event(struct tp *tp, union perf_event *event);

int tp_receive_new(struct tp *tp, char *s);
void tp_receive_free(struct tp *tp);

#endif
