/*
 * Clone the new prof_dev under the control of ptrace.
 *
 * For prof_dev, after it is attached to a process (-p <pid>), there is no way to
 * track the newly forked child process. However, we can use ptrace to control the
 * forked child process(tracee), which is initially in a STOP state, and can notify
 * it to CONTINUE at the appropriate time.
 *
 * The main idea is:
 *    When in the STOP state, clone a new prof_dev for the tracee.
 *    Then, notify it to CONTINUE.
 *
 *    When tracee exits, close its prof_dev.
 *
 * Initially, ptrace is used to trace the fork, vfork, and clone syscalls.
 * And re-inject all delivered signals.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <linux/rblist.h>
#include <linux/thread_map.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <monitor.h>

struct pid_node {
    struct rb_node rbnode;
    int pid, ppid;
    bool initial, detach;
    int ptrace_request;
    struct prof_dev *dev;
    struct list_head link_to_dev;
};

static int __ptrace_link(struct pid_node *node, struct prof_dev *dev)
{
    if (dev && prof_dev_use(dev)) {
        node->dev = dev;
        list_add(&node->link_to_dev, &dev->ptrace_list);
        return 1;
    }
    return 0;
}

static void __ptrace_unlink(struct pid_node *node)
{
    if (node->dev) {
        list_del(&node->link_to_dev);
        prof_dev_unuse(node->dev);
    }
}

static int __node_cmp(struct rb_node *rbn, const void *entry)
{
    struct pid_node *b = container_of(rbn, struct pid_node, rbnode);
    const struct pid_node *e = entry;

    return b->pid - e->pid;
}
static struct rb_node *__node_new(struct rblist *rlist, const void *new_entry)
{
    struct pid_node *b = malloc(sizeof(*b));
    const struct pid_node *e = new_entry;
    if (b) {
        memset(b, 0, sizeof(*b));
        RB_CLEAR_NODE(&b->rbnode);
        b->pid = e->pid;
        INIT_LIST_HEAD(&b->link_to_dev);
        if (!e->dev || __ptrace_link(b, e->dev))
            return &b->rbnode;
    }
    return NULL;
}
static void __node_delete(struct rblist *rblist, struct rb_node *rb_node)
{
    struct pid_node *b = container_of(rb_node, struct pid_node, rbnode);
    __ptrace_unlink(b);
    free(b);
}

struct rblist pid_list = {
    .entries = RB_ROOT_CACHED,
    .node_cmp = __node_cmp,
    .node_new = __node_new,
    .node_delete = __node_delete,
};

int ptrace_attach(struct perf_thread_map *thread_map, struct prof_dev *dev)
{
    struct pid_node node = {.dev = dev};
    int pid;
    int idx;
    bool workload;
    int succ = 0;

    if (prof_dev_is_cloned(dev))
        return 0;
    if (!prof_dev_use(dev))
        return 0;

    workload = dev->env->workload.pid > 0;
    perf_thread_map__for_each_thread(pid, idx, thread_map) {
        /*
         * The pid can only be attached to one tracer. If this pid is attached
         * to gdb, or strace, or other perf-prof, etc. PTRACE_SEIZE returns -1.
         */
        int ret = ptrace(PTRACE_SEIZE, pid, 0,
                         (workload ? PTRACE_O_EXITKILL : 0) | // tracer exits, SIGKILL workload(every tracee).
                         PTRACE_O_TRACEFORK |  // trace fork
                         PTRACE_O_TRACEVFORK | // trace vfork
                         PTRACE_O_TRACECLONE | // trace clone
                         //PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT |
                         PTRACE_O_TRACESYSGOOD);

        if (ret == 0) {
            node.pid = pid;
            ret = rblist__add_node(&pid_list, &node);
            succ ++;
        }
        if (ret < 0) {
            // On failure, skip it and continue with other pids.
            // Don't return -1.
        }
    }
    if (!succ)
        fprintf(stderr, "ptrace fails for all pids.\n");

    // If all ptrace returns fail, prof_dev will be closed.
    prof_dev_unuse(dev);
    return 0;
}

void ptrace_detach(struct prof_dev *dev)
{
    struct pid_node *node, *n;
    struct prof_dev *child, *tmp;
    struct prof_dev *top = prof_dev_top_cloned(dev);
    bool workload = top->env->workload.pid > 0;

    /*
     * When prof_dev is closed in advance(i.e. -N 10), ptrace_list is not
     * empty and detach is performed.
     * But for daemonize, its parent process will exit normally and
     * ptrace_list is empty.
     */
    if (list_empty(&dev->ptrace_list))
        return;

    prof_dev_get(dev);

    list_for_each_entry_safe(node, n, &dev->ptrace_list, link_to_dev) {
        if (!node->detach) {
            node->detach = 1;
            node->ptrace_request = workload ? PTRACE_KILL : PTRACE_DETACH;
            if (ptrace(PTRACE_INTERRUPT, node->pid, 0, 0) < 0)
                rblist__remove_node(&pid_list, &node->rbnode);
            else
                d_printf("PTRACE_INTERRUPT %d\n", node->pid);
        }
    }

    // Also close all prof_dev cloned from 'dev'.
    for_each_child_dev_get(child, tmp, dev) {
        if (child->clone && !list_empty(&child->ptrace_list))
            ptrace_detach(child);
    }

    prof_dev_put(dev);
}

bool ptrace_detach_done(void)
{
    return rblist__empty(&pid_list);
}

enum {
    CONT = 0,
    SKIP_CONT = 1,
    KEEP_STOP = 1,
};

static struct prof_dev *__clone_dev(int ppid, int pid)
{
    struct pid_node node = {.pid = ppid, .dev = NULL};
    struct pid_node *parent;

    parent = rb_entry_safe(rblist__find(&pid_list, &node), struct pid_node, rbnode);
    if (parent && parent->dev) {
        struct prof_dev *dev;
        struct perf_thread_map *map;

        map = thread_map__new_by_tid(pid);
        if (!map) return NULL;

        dev = prof_dev_clone(parent->dev, NULL, map);
        perf_thread_map__put(map);
        return dev;
    }
    return NULL;
}

static int __fork(int ppid, int pid)
{
    struct pid_node node = {.pid = pid, .dev = NULL};
    struct pid_node *new;

    ptrace(PTRACE_CONT, ppid, 0, 0);
    d_printf("        CONT %d signo 0\n", ppid);

    new = rb_entry_safe(rblist__findnew(&pid_list, &node), struct pid_node, rbnode);
    if (new) {
        new->ppid = ppid;
        if (new->initial) {
            struct prof_dev *dev = __clone_dev(new->ppid, new->pid);
            __ptrace_link(new, dev);
            new->initial = 0;
            ptrace(PTRACE_CONT, new->pid, 0, 0);
            d_printf("        CONT %d signo 0\n", new->pid);
        }
    }
    return SKIP_CONT;
}

static int __new_or_interrupt(int pid)
{
    struct pid_node node = {.pid = pid, .dev = NULL};
    struct pid_node *new;

    new = rb_entry_safe(rblist__findnew(&pid_list, &node), struct pid_node, rbnode);
    if (new) {
        if (new->detach)
            goto detach;

        if (new->ppid) {
            if (!new->dev) {
                struct prof_dev *dev = __clone_dev(new->ppid, new->pid);
                __ptrace_link(new, dev);
            }
        } else
            new->initial = 1;
        return new->initial ? KEEP_STOP : CONT;
    }
    return CONT;

detach:
    ptrace(new->ptrace_request, new->pid, 0, 0);
    if (new->ptrace_request == PTRACE_KILL)
        d_printf("        KILL %d\n", pid);
    if (new->ptrace_request == PTRACE_DETACH)
        d_printf("        DETACH %d\n", pid);
    rblist__remove_node(&pid_list, &new->rbnode);
    return SKIP_CONT;
}

int ptrace_exited(int pid)
{
    struct pid_node node = {.pid = pid};
    struct rb_node *rbn = rblist__find(&pid_list, &node);
    if (rbn)
        rblist__remove_node(&pid_list, rbn);
    return 0;
}

int ptrace_stop(int pid, int status)
{
    unsigned long pid_forked, pid_oldns, exit_code, syscall;
    const char * __maybe_unused str = NULL;
    int signo = 0;
    int ret = CONT;
    int cont = PTRACE_CONT;

    switch (status) {
    // PTRACE_EVENT stops
    case SIGTRAP | (PTRACE_EVENT_FORK  << 8): str = "FORK";  goto FORK;
    case SIGTRAP | (PTRACE_EVENT_VFORK << 8): str = "VFORK"; goto FORK;
    case SIGTRAP | (PTRACE_EVENT_CLONE << 8): str = "CLONE"; FORK:
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &pid_forked);
        d_printf("PTRACE %d %s %ld\n", pid, str, pid_forked);
        ret = __fork(pid, pid_forked);
        break;
    case SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8):
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &pid_forked);
        d_printf("PTRACE %d VFORK_DONE %ld\n", pid, pid_forked);
        break;
    case SIGTRAP | (PTRACE_EVENT_EXEC << 8):
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &pid_oldns);
        d_printf("PTRACE %d EXEC NSPID %ld\n", pid, pid_oldns);
        break;
    case SIGTRAP | (PTRACE_EVENT_EXIT << 8):
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &exit_code);
        d_printf("PTRACE %d EXIT CODE %ld\n", pid, exit_code);
        break;
    case SIGTRAP | (PTRACE_EVENT_STOP << 8):
        d_printf("PTRACE %d PTRACE_INTERRUPT | SIGCONT | initial new\n", pid);
        ret = __new_or_interrupt(pid);
        break;

    // Syscall-stops
    case SIGTRAP | 0x80 /* PTRACE_O_TRACESYSGOOD */:
        // new kernel
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &syscall);
        d_printf("PTRACE %d SYSCALL %s\n", pid, syscall == PTRACE_EVENTMSG_SYSCALL_ENTRY ? "ENTRY" : "EXIT");
        break;

    // Group-stop
    case SIGSTOP | (PTRACE_EVENT_STOP << 8): str = "SIGSTOP"; goto STOP;
    case SIGTSTP | (PTRACE_EVENT_STOP << 8): str = "SIGTSTP"; goto STOP;
    case SIGTTIN | (PTRACE_EVENT_STOP << 8): str = "SIGTTIN"; goto STOP;
    case SIGTTOU | (PTRACE_EVENT_STOP << 8): str = "SIGTTOU"; STOP:
        d_printf("PTRACE %d %s stop\n", pid, str);
        /*
         * If cont is PTRACE_CONT, pid cannot be STOP.
         * Only PTRACE_LISTEN, `kill -SIGCONT pid` can actually wake it up.
         */
        cont = PTRACE_LISTEN;
        break;

    // Signal-delivery-stop
    default:
        signo = status;
        if (unlikely(signo & (PTRACE_EVENT_STOP << 8))) {
            d_printf("PTRACE %d unknown STOP\n", pid);
            signo = 0;
            break;
        }
        d_printf("PTRACE %d == inject %d == \n", pid, signo);
        signo &= 0xff;
        break;
    }

    if (ret == CONT) {
        ptrace(cont, pid, 0, signo);
        d_printf("        %s %d signo %d\n", cont == PTRACE_CONT ? "CONT" : "LISTEN", pid, signo);
    }
    return 0;
}

