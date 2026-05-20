#ifndef __TIMER_H__
#define __TIMER_H__

#include <sys/timerfd.h>

struct timer {
    int fd;
    int started;
    int max_exp_once;
    struct itimerspec it;
    void (*function)(struct timer *);
};

int timer_init(struct timer *timer, int max_exp_once, void (*func)(struct timer *));
long timer_start(struct timer *timer, unsigned long expires, bool oneshot);
long timer_cancel(struct timer *timer);
void timer_destroy(struct timer *timer);
static inline bool timer_started(struct timer *timer) {return timer->started;}

#endif
