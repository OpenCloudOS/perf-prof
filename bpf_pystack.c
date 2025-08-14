#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <monitor.h>
#include <internal/xyarray.h>
#include <internal/evsel.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stack_helpers.h>
#include <latency_helpers.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf-skel/bpf_pystack.h>
#include <bpf-skel/bpf_pystack.skel.h>
#include "trace_helpers.h"

struct bpf_pystack_ctx {
    struct bpf_pystack_bpf *obj;
    void *fixed_event;
    struct perf_evsel *evsel;
    //char binary_path[BINARY_PATH_SIZE];
};
static const char *object;
static int monitor_ctx_init(struct prof_dev *dev)
{
    struct bpf_pystack_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    ctx->obj = bpf_pystack_bpf__open();
    if (!ctx->obj) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        goto free_ctx;
    }
    return 0;
free_ctx:
    free(ctx);
    return -1;
}

static void monitor_ctx_exit(struct prof_dev *dev)
{
    struct bpf_pystack_ctx *ctx = dev->private;
    bpf_pystack_bpf__destroy(ctx->obj);
    free(ctx->fixed_event);
    free(ctx);
}

static int bpf_pystack_init(struct prof_dev *dev)
{
    struct bpf_pystack_ctx *ctx;
    struct env *env = dev->env;
    struct perf_evlist *evlist = dev->evlist;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_BPF_OUTPUT, 
        .size          = sizeof(struct perf_event_attr),
        .sample_type   = PERF_SAMPLE_TIME, 
        .sample_period = 1,
        .pinned        = 1,
        .disabled      = 1,
        .watermark     = 1,
    };
    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;
    prof_dev_env2attr(dev, &attr);

    ctx->evsel = perf_evsel__new(&attr);
    if (!ctx->evsel)
        goto failed;

    perf_evlist__add(evlist, ctx->evsel);
    if (bpf_pystack_bpf__load(ctx->obj))
        goto failed;

    ctx->fixed_event = malloc(PERF_SAMPLE_MAX_SIZE);
    if (!ctx->fixed_event){
        printf("Failed to allocate fixed_event buffer\n");
        goto deinit;
    }
    object = env->bpf_python_callchain;
    printf("bpf_pystack object: %s\n", object);
    return 0;

failed:
    monitor_ctx_exit(dev);
deinit:
    monitor_ctx_exit(dev);
    return -1;
}

static int bpf_pystack_filter(struct prof_dev *dev)
{
    struct bpf_pystack_ctx *ctx = dev->private;
    int err;

    ctx->obj->links.probe_function_entry = bpf_program__attach_usdt(ctx->obj->progs.probe_function_entry, -1,
								object, "python", "function__entry", NULL);
	if (!ctx->obj->links.probe_function_entry) {
		err = errno;
		fprintf(stderr, "attach usdt probe_function_entry failed: %s\n", strerror(err));
	}

    ctx->obj->links.probe_function_return = bpf_program__attach_usdt(ctx->obj->progs.probe_function_return, -1,
								object, "python", "function__return", NULL);   
	if (!ctx->obj->links.probe_function_return) {
		err = errno;
		fprintf(stderr, "attach usdt probe_function__return failed: %s\n", strerror(err));
	}                             
    return 1;
}

struct monitor bpf_pystack = {
    .name = "bpf-pystack",
    .pages = 4,
    .init = bpf_pystack_init,
    .filter = bpf_pystack_filter,
    .deinit = monitor_ctx_exit,
};
MONITOR_REGISTER(bpf_pystack)

int bpf_pystack_link(struct prof_dev *main_dev)
{
    struct prof_dev *bpf_pydev;
    struct env *e;
    if (main_dev->prof == &bpf_pystack)
        return 0;
    e = clone_env(main_dev->env);
    if (!e)
        return -1;

    // Specifies the parent of pydev so that the real main_dev can be found
    // when heap-sorting pydev events. See order_main_dev().
    bpf_pydev = prof_dev_open_cpu_thread_map(&bpf_pystack, e, NULL, NULL, main_dev);
    if (!bpf_pydev){
        printf("fail to open bpf_pystack device\n");
        return -1;
    }
        
    if (order_together(main_dev, bpf_pydev) < 0) {
        prof_dev_close(bpf_pydev);
        return -1;
    }
    main_dev->links.pystack = bpf_pydev;
    return 0;
}

void bpf_pystack_unlink(struct prof_dev *main_dev)
{
    if (main_dev->links.pystack) {
        prof_dev_close(main_dev->links.pystack);
        main_dev->links.pystack = NULL;
    }
}
