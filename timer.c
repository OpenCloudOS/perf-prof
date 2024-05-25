#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <monitor.h>
#include <timer.h>

static void timer_expire(int fd, unsigned int revents, void *ptr)
{
    struct timer *timer = ptr;
    uint64_t exp;
    int s;

    s = read(fd, &exp, sizeof(uint64_t));
    if (s < 0) {
        if (errno != EAGAIN)
            timer_cancel(timer);
        return;
    }

    if (timer->max_exp_once > 0 && exp > timer->max_exp_once)
        exp = timer->max_exp_once;

    while (exp--)
        timer->function(timer);
}

int timer_init(struct timer *timer, int max_exp_once, void (*func)(struct timer *))
{
    int fd;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0)
        return -errno;

    timer->fd = fd;
    timer->started = 0;
    timer->max_exp_once = max_exp_once;
    timer->function = func;
    return 0;
}

long timer_start(struct timer *timer, unsigned long expires, bool oneshot)
{
    struct itimerspec it;
    struct itimerspec old;

    it.it_value.tv_sec = expires / 1000000000UL;
    it.it_value.tv_nsec = expires % 1000000000UL;
    it.it_interval = oneshot ? (struct timespec){0, 0} : it.it_value;
    if (timerfd_settime(timer->fd, 0, &it, &old) < 0)
        return -1;

    timer->it = it;

    if (main_epoll_add(timer->fd, EPOLLIN, timer, timer_expire) < 0)
        return -1;

    timer->started = 1;
    return old.it_value.tv_sec * 1000000000UL + it.it_value.tv_nsec;
}

long timer_cancel(struct timer *timer)
{
    struct itimerspec it;
    struct itimerspec old;

    if (!timer->started)
        return 0;

    it.it_value = (struct timespec){0, 0};
    it.it_interval = (struct timespec){0, 0};
    if (timerfd_settime(timer->fd, 0, &it, &old) < 0)
        old.it_value = (struct timespec){0, 0};

    main_epoll_del(timer->fd);

    timer->started = 0;
    return old.it_value.tv_sec * 1000000000UL + it.it_value.tv_nsec;
}

void timer_destroy(struct timer *timer)
{
    timer_cancel(timer);
    close(timer->fd);
    timer->fd = -1;
}

