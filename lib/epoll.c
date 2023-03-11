#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/zalloc.h>
#include <linux/epoll.h>

typedef int (*keycmp)(const void *key, const struct rb_node *rbn);

static int fdcmp(struct rb_node *rb1, const struct rb_node *rb2)
{
    struct event_poll_data *d1 = rb_entry(rb1, struct event_poll_data, rbn);
    struct event_poll_data *d2 = rb_entry(rb2, struct event_poll_data, rbn);
    return d1->fd - d2->fd;
}

struct event_poll *event_poll__alloc(int maxevents)
{
    struct event_poll *ep;

    ep = malloc(sizeof(*ep));
    if (!ep)
        return NULL;

    memset(ep, 0, sizeof(*ep));

    ep->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ep->epfd < 0)
        goto err;
    ep->maxevents = maxevents;
    ep->events = zalloc(ep->maxevents * sizeof(*ep->events));
    if (ep->events == NULL)
        goto err;

    ep->root = RB_ROOT;
    return ep;
err:
    event_poll__free(ep);
    return NULL;
}

void event_poll__free(struct event_poll *ep)
{
    if (ep->nr) {
        struct rb_node *node, *next;
        struct event_poll_data *data;

        for (node = rb_first(&ep->root); node; node = next) {
            next = rb_next(node);
            rb_erase(node, &ep->root);
            data = rb_entry(node, struct event_poll_data, rbn);
            epoll_ctl(ep->epfd, EPOLL_CTL_DEL, data->fd, NULL);
            free(data);
        }
    }
    if (ep->events)
        free(ep->events);
    if (ep->epfd >= 0)
        close(ep->epfd);
    free(ep);
}

int event_poll__add(struct event_poll *ep, int fd, unsigned int events, void *ptr, handle_event handle)
{
    struct event_poll_data *data;
    struct rb_node *rbn = NULL;
    struct epoll_event event;

    data = malloc(sizeof(*data));
    if (!data)
        return -ENOMEM;

    data->fd = fd;
    RB_CLEAR_NODE(&data->rbn);
    rbn = rb_find_add(&data->rbn, &ep->root, fdcmp);
    if (rbn) {
        free(data);
        data = rb_entry(rbn, struct event_poll_data, rbn);
    } else {
        fcntl(fd, F_SETFL, O_NONBLOCK);
        ep->nr ++;
    }

    /*
     * There is no need to check whether data is being used in ep->events, and new
     * values can be safely assigned.
     *
     * For the new fd, there can be no reference to data in ep->events.
     *
     * For the old fd, there may be a reference to data in ep->events. Regardless
     * of whether data->handle is executing or not, it is safe to assign a new value
     * to data.
    **/
    data->ptr = ptr;
    data->events = events;
    data->handle = handle;

    event.events = events;
    event.data.ptr = data;
    return epoll_ctl(ep->epfd, rbn ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &event);
}

int event_poll__del(struct event_poll *ep, int fd)
{
    struct event_poll_data *data;
    struct event_poll_data key;
    struct rb_node *rbn;
    int i;

    key.fd = fd;
    rbn = rb_find(&key, &ep->root, (keycmp)fdcmp);
    if (rbn) {
        data = rb_entry(rbn, struct event_poll_data, rbn);
        /*
         * Check if data is being used in ep->events, if so, clear it.
        **/
        for (i = ep->i + 1; i < ep->cnt; i++) {
            if (ep->events[i].data.ptr == data) {
                ep->events[i].data.ptr = NULL;
            }
        }

        rb_erase(rbn, &ep->root);
        free(data);
        ep->nr --;
        return epoll_ctl(ep->epfd, EPOLL_CTL_DEL, fd, NULL);
    } else
        return -ENOENT;
}

int event_poll__poll(struct event_poll *ep, int timeout)
{
    int i, cnt;
    unsigned int revents;
    struct event_poll_data *data;

    cnt = epoll_wait(ep->epfd, ep->events, ep->maxevents, timeout);
    if (cnt < 0)
        return -errno;

    ep->cnt = cnt;
    for (i = 0; i < cnt; i++) {
        revents = ep->events[i].events;
        data = ep->events[i].data.ptr;
        if (data) {
            ep->i = i;
            data->handle(data->fd, revents, data->ptr);
        }
    }
    ep->i = ep->cnt = 0;

    return ep->nr ? cnt : -ENOENT;
}

