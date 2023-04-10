#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <linux/list.h>
#include <monitor.h>
#include <tep.h>
#include <net.h>

enum block_type {
    TYPE_TCP,
    TYPE_FILE,
};

struct event_block_list {
    struct list_head block_list;
    struct tp *tp;
    bool broadcast;
    bool freeing;
};

struct event_block {
    struct list_head link;
    struct event_block_list *eb_list;
    enum block_type type;
    union {
        struct tcp_block {
            void *tcp; // broadcast or receive
            struct tcp_socket_ops ops;
            const char *ip;
            const char *port;
        } tcp;
        struct file_block {
            FILE *file; // broadcast or receive
            size_t pos;
            const char *filename;
            int notifyfd;
        } file;
    } u;
    // receive
    int remote_id;
    int cpu_pos;
    int stream_id_pos;
    int common_type_pos;
};

static inline void block_free(struct event_block *block);

static int block_event_convert(struct event_block *block, union perf_event *event)
{
    struct tp *tp = block->eb_list->tp;
    struct perf_event_attr *attr;
    void *data;
    u64 sample_type;
    int cpuidx = 0;
    int pos = 0;
    int common_type_pos = 0;

    if (unlikely(!tp->evsel))
        return -1;

    attr = perf_evsel__attr(tp->evsel);
    if (unlikely(attr->sample_period == 0))
        return -1;

   /*
    *  { u64           id;   } && PERF_SAMPLE_IDENTIFIER
    *  { u64           ip;   } && PERF_SAMPLE_IP
    *  { u32           pid, tid; } && PERF_SAMPLE_TID
    *  { u64           time;     } && PERF_SAMPLE_TIME
    *  { u64           addr;     } && PERF_SAMPLE_ADDR
    *  { u64           id;   } && PERF_SAMPLE_ID
    *  { u64           stream_id;} && PERF_SAMPLE_STREAM_ID
    *  { u32           cpu, res; } && PERF_SAMPLE_CPU
    *  { u64           period;   } && PERF_SAMPLE_PERIOD
    *  { struct read_format    values;   } && PERF_SAMPLE_READ
    *  { u64           nr,
    *    u64           ips[nr];  } && PERF_SAMPLE_CALLCHAIN
    *  { u32			size;
    *    char                  data[size];}&& PERF_SAMPLE_RAW
    */
    data = (void *)event->sample.array;
    sample_type = attr->sample_type;

    if (block->cpu_pos == -1 && block->stream_id_pos == -1 && block->common_type_pos == -1) {
        if (sample_type & PERF_SAMPLE_IDENTIFIER)
            pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_IP)
            pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_TID)
            pos += sizeof(u32) + sizeof(u32);
        if (sample_type & PERF_SAMPLE_TIME)
            pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_ADDR)
            pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_ID)
            pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_STREAM_ID) {
            block->stream_id_pos = pos;
            pos += sizeof(u64);
        }
        if (sample_type & PERF_SAMPLE_CPU) {
            block->cpu_pos = pos;
            pos += sizeof(u32) + sizeof(u32);
        }
        if (sample_type & PERF_SAMPLE_PERIOD)
            pos += sizeof(u64);
        if (sample_type & PERF_SAMPLE_READ)
            pos += perf_evsel__read_size(tp->evsel);
        block->common_type_pos = pos;
    }

    if (block->cpu_pos != -1) {
        cpuidx = perf_cpu_map__idx(perf_evsel__cpus(tp->evsel), *(u32 *)(data + block->cpu_pos));
        if (cpuidx < 0)
            cpuidx = 0;
    }

    if (sample_type & PERF_SAMPLE_STREAM_ID) {
        //u64           stream_id;
        *(u64 *)(data + block->stream_id_pos) = perf_evsel__get_id(tp->evsel, cpuidx, 0);
    }

    if (tp->id != block->remote_id) {
        common_type_pos = block->common_type_pos;
        if (sample_type & PERF_SAMPLE_CALLCHAIN) {
            struct {
                u64 nr;
                u64 ips[];
            } *callchain = data + common_type_pos;
            common_type_pos += (callchain->nr + 1) * sizeof(u64);
        }
        if (sample_type & PERF_SAMPLE_RAW) {
            common_type_pos += sizeof(u32);
            //unsigned short common_type;
            *(unsigned short *)(data + common_type_pos) = tp->id;
        }
    }
    return cpuidx;
}

static int block_process_event(struct event_block *block, union perf_event *event)
{
    struct tp *tp = block->eb_list->tp;
    int ins = 0;

    switch (event->header.type) {
        case PERF_RECORD_TP: {
                struct perf_record_tp *record = (void *)event;
                struct perf_event_attr *attr = tp->evsel ? perf_evsel__attr(tp->evsel) : NULL;

                if (strcmp((char *)record + record->sys_offset, tp->sys) ||
                    strcmp((char *)record + record->name_offset, tp->name)) {
                    fprintf(stderr, "tp sys:name mismatch, unable to receive pull-events.\n");
                    goto failed;
                }
                if (!attr || attr->sample_period == 0 || record->sample_period == 0) {
                    fprintf(stderr, "tp is non-sampling, unable to receive pull-events.\n");
                    goto failed;
                }
                if (attr->sample_type != record->sample_type) {
                    fprintf(stderr, "tp sample_type(%llu) mismatch, unable to receive pull-events.\n",
                                    attr->sample_type ^ record->sample_type);
                    goto failed;
                }
                if (record->sample_type & PERF_SAMPLE_CALLCHAIN) {
                    fprintf(stderr, "tp has PERF_SAMPLE_CALLCHAIN enabled, unable to receive pull-events.\n");
                    goto failed;
                }
                if (tep__event_size(tp->id) != record->event_size) {
                    fprintf(stderr, "tp event_size mismatch, unable to receive pull-events.\n");
                    goto failed;
                }

                block->remote_id = record->id;
                return 0;

            failed:
                block_free(block);
                return -1;
            }
        case PERF_RECORD_SAMPLE:
            ins = block_event_convert(block, event);
            if (ins < 0) return 0;
            else break;
        default:
            break;
    }

    perf_event_process_record(event, ins, true, true);
    return 0;
}

static int tcp_process_event(union perf_event *event, struct tcp_socket_ops *ops)
{
    struct event_block *block = container_of(ops, struct event_block, u.tcp.ops);
    return block_process_event(block, event);
}

static int tcp_disconnect(struct tcp_socket_ops *ops)
{
    struct event_block *block = container_of(ops, struct event_block, u.tcp.ops);
    block_free(block);
    return 0;
}

static int perf_record_tp_init(struct tp *tp, struct perf_record_tp *record)
{
    struct perf_event_attr *attr;

    if (!tp->evsel)
        return -1;

    attr = perf_evsel__attr(tp->evsel);

    // send sys:name, perf_event_attr, /FILTER/ATTR/

    record->header.size = sizeof(*record) + strlen(tp->sys) + strlen(tp->name) + 2;
    record->header.type = PERF_RECORD_TP;
    record->header.misc = 0;

    record->id = tp->id;
    record->sys_offset = sizeof(*record);
    record->name_offset = sizeof(*record) + strlen(tp->sys) + 1;
    record->sample_period = attr->sample_period;
    record->sample_type = attr->sample_type;
    record->event_size = tep__event_size(tp->id);
    record->unused = 0;

    return 0;
}

static int tcp_new_client(struct tcp_socket_ops *ops)
{
    struct event_block *block = NULL;
    struct tp *tp = NULL;
    struct perf_record_tp record;

    if (!ops->server_ops)
        return 0;

    block = container_of(ops->server_ops, struct event_block, u.tcp.ops);
    tp = block->eb_list->tp;
    if (perf_record_tp_init(tp, &record) < 0)
        return 0;

    if (tcp_send(ops->client, &record, sizeof(record), MSG_MORE) == 0 &&
        tcp_send(ops->client, tp->sys, strlen(tp->sys)+1, MSG_MORE) == 0 &&
        tcp_send(ops->client, tp->name, strlen(tp->name)+1, 0) == 0)
        return 0;
    else
        return -1;
}

static int file_write_header(struct event_block *block)
{
    struct tp *tp = block->eb_list->tp;
    struct perf_record_tp record;
    FILE *file = block->u.file.file;
    size_t pos = 0;

    if (perf_record_tp_init(tp, &record) < 0)
        return 0;

    pos += fwrite(&record, 1, sizeof(record), file);
    pos += fwrite(tp->sys, 1, strlen(tp->sys)+1, file);
    pos += fwrite(tp->name, 1, strlen(tp->name)+1, file);
    block->u.file.pos = pos;
    fflush(file);
    return 0;
}

static void handle_file_event(int fd, unsigned int revents, void *ptr)
{
    struct event_block *block = ptr;
    FILE *file = block->u.file.file;
    char event_copy[PERF_SAMPLE_MAX_SIZE];
    union perf_event *event = (void *)event_copy;
    int len, i;

    for (i = 0; i < 64; i++) {
        len = fread(event_copy, 1, sizeof(struct perf_event_header), file);
        if (len == sizeof(struct perf_event_header))
            len += fread(event_copy+len, 1, event->header.size-len, file);
        if (len != event->header.size)
            goto err;
        if (block_process_event(block, event) < 0)
            break;
    }
    return ;

err:
    block_free(block);
    return;
}

static int block_new(struct event_block_list *eb_list, char *value)
{
    struct event_block *block = NULL;
    char *ip = NULL;
    char *port;
    FILE *file = NULL;

    port = strchr(value, ':');
    if (port) {
        *port ++ = '\0';
        if (*value) ip = value;
    } else
        port = value;
    if (!*port) goto err_return;

    if (!(block = malloc(sizeof(*block)))) return -1;
    memset(block, 0, sizeof(*block));

    block->eb_list = eb_list;
    list_add_tail(&block->link, &eb_list->block_list);

    block->cpu_pos = -1;
    block->stream_id_pos = -1;
    block->common_type_pos = -1;

    block->u.tcp.ip = ip;
    block->u.tcp.port = port;
    block->u.tcp.ops.process_event = tcp_process_event;
    block->u.tcp.ops.disconnect = tcp_disconnect;
    block->u.tcp.ops.new_client = tcp_new_client;
    block->u.tcp.tcp = (eb_list->broadcast ? tcp_server : tcp_connect)(ip, port, &block->u.tcp.ops);
    if (block->u.tcp.tcp) {
        block->type = TYPE_TCP;
        return 0;
    }
    if ((file = fopen(port, eb_list->broadcast ? "w+" : "r"))) {
        block->u.file.file = file;
        block->u.file.pos = 0;
        block->u.file.filename = port;
        block->type = TYPE_FILE;
        if (!eb_list->broadcast) {
            block->u.file.notifyfd = eventfd(1, EFD_NONBLOCK);
            if (block->u.file.notifyfd < 0)
                goto failed;
            main_epoll_add(block->u.file.notifyfd, EPOLLIN, block, handle_file_event);
        } else
            block->u.file.notifyfd = -1;
        printf("Open file %s\n", block->u.file.filename);
        return 0;
    }

failed:
    // failed
    list_del(&block->link);
    if (file) fclose(file);
    free(block);
err_return:
    fprintf(stderr, "The pull=%s attribute is incorrect.\n", value);
    return -1;
}

static void block_free(struct event_block *block)
{
    struct event_block_list *eb_list = block->eb_list;

    switch (block->type) {
        case TYPE_TCP:
            tcp_close(block->u.tcp.tcp);
            break;
        case TYPE_FILE:
            if (block->u.file.notifyfd >= 0)
                main_epoll_del(block->u.file.notifyfd);
            fclose(block->u.file.file);
            printf("Close file %s\n", block->u.file.filename);
            break;
        default:
            break;
    }
    list_del(&block->link);
    free(block);

    if (!eb_list->freeing &&
        !eb_list->broadcast && list_empty(&eb_list->block_list)) {
        struct tp *tp = eb_list->tp;
        printf("%s:%s re-enable kernel events\n", tp->sys, tp->name);
        if (tp->evsel) {
            perf_evsel__keep_disable(tp->evsel, false);
            perf_evsel__enable(tp->evsel);
        }
    }
}

static inline void block_broadcast(struct event_block *block, const void *buf, size_t len, int flags)
{
    switch (block->type) {
        case TYPE_TCP:
            tcp_server_broadcast(block->u.tcp.tcp, buf, len, flags);
            break;
        case TYPE_FILE:
            if (block->u.file.pos == 0)
                file_write_header(block);
            block->u.file.pos += fwrite(buf, 1, len, block->u.file.file);
            break;
        default:
            break;
    }
}

static void block_list_free(struct tp *tp, bool broadcast)
{
    struct event_block_list *eb_list = (broadcast ? tp->broadcast : tp->receive);
    struct event_block *block, *next;

    if (!eb_list)
        return ;

    eb_list->freeing = 1;
    list_for_each_entry_safe(block, next, &eb_list->block_list, link) {
        block_free(block);
    }
    free(eb_list);

    if (broadcast) tp->broadcast = NULL;
    else tp->receive = NULL;
}

static int block_list_new(struct tp *tp, char *s, bool broadcast)
{
    struct event_block_list *eb_list = (broadcast ? tp->broadcast : tp->receive);
    char *sep;

    if (eb_list == NULL) {
        if (!(eb_list = malloc(sizeof(*eb_list)))) return -1;
        memset(eb_list, 0, sizeof(*eb_list));

        INIT_LIST_HEAD(&eb_list->block_list);
        eb_list->tp = tp;
        eb_list->broadcast = broadcast;
        eb_list->freeing = 0;

        if (broadcast) tp->broadcast = eb_list;
        else tp->receive = eb_list;
    }

    while ((sep = strchr(s, ',')) != NULL) {
        *sep = '\0';
        if (block_new(eb_list, s) < 0) goto err;
        s = sep + 1;
    }
    if (block_new(eb_list, s) < 0) goto err;

    return 0;

err:
    block_list_free(tp, broadcast);
    return -1;
}


int tp_broadcast_new(struct tp *tp, char *s)
{
    return block_list_new(tp, s, true);
}

void tp_broadcast_free(struct tp *tp)
{
    block_list_free(tp, true);
}

int tp_broadcast_event(struct tp *tp, union perf_event *event)
{
    struct event_block_list *eb_list = tp->broadcast;
    struct event_block *block;

    if (!eb_list)
        return 0;

    list_for_each_entry(block, &eb_list->block_list, link) {
        block_broadcast(block, event, event->header.size, 0);
    }
    return 1;
}

int tp_receive_new(struct tp *tp, char *s)
{
    return block_list_new(tp, s, false);
}

void tp_receive_free(struct tp *tp)
{
    block_list_free(tp, false);
}

