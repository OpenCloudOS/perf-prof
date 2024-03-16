#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/circ_buf.h>
#include <monitor.h>
#include <net.h>

#define BUF_LEN (1 << 16)

enum socket_type {
    LISTEN_SERVER,
    ACCEPT_CLIENT,
    CONNECT_CLIENT,
};

struct tcp_socket_header {
    int fd;
    refcount_t ref;
    enum socket_type type;
    struct tcp_socket_ops *ops;
};

struct tcp_client_socket {
    struct tcp_socket_header header;

    unsigned int events;
    struct list_head srvlink;
    struct tcp_socket_ops inline_ops;
    struct sockaddr peer_addr;
    socklen_t peer_addrlen;

    // EPOLLOUT
    struct perf_record_lost lost_event;
    char buf[BUF_LEN];
    int send; // head
    int write; // tail

    // EPOLLIN
    int read;
    char event_copy[PERF_SAMPLE_MAX_SIZE];
};

struct tcp_server_socket {
    struct tcp_socket_header header;

    struct sockaddr bind_addr;
    socklen_t bind_addrlen;
    struct list_head clilist;
};

static inline int buf_cnt(struct tcp_client_socket *cli)
{
    return CIRC_CNT(cli->write, cli->send, BUF_LEN);
}

static inline int buf_idle(struct tcp_client_socket *cli)
{
    return CIRC_SPACE(cli->write, cli->send, BUF_LEN);
}

static inline int buf_is_empty(struct tcp_client_socket *cli)
{
    return buf_cnt(cli) == 0;
}

static inline int buf_is_full(struct tcp_client_socket *cli)
{
    return buf_idle(cli) == 0;
}

static inline int buf_write(struct tcp_client_socket *cli, const void *buf, size_t len)
{
    if (cli->write + len >= BUF_LEN) {
        int n = BUF_LEN - cli->write;
        memcpy(&cli->buf[cli->write], buf, n);
        buf += n;
        len -= n;
        cli->write = 0;
    }

    if (len) {
        memcpy(&cli->buf[cli->write], buf, len);
        cli->write += len;
    }
    return 0;
}

static inline int buf_send(struct tcp_client_socket *cli)
{
    int len = buf_cnt(cli);

    if (cli->send + len >= BUF_LEN) {
        int n = BUF_LEN - cli->send;
        int ret = send(cli->header.fd, &cli->buf[cli->send], n, n != len ? MSG_MORE|MSG_NOSIGNAL : MSG_NOSIGNAL);
        if (ret <= 0)
            return ret;
        cli->send = (cli->send + ret) % BUF_LEN;
        if (ret != n)
            return 0;
        len -= ret;
    }

    if (len) {
        int ret = send(cli->header.fd, &cli->buf[cli->send], len, MSG_NOSIGNAL);
        if (ret <= 0)
            return ret;
        cli->send = (cli->send + ret) % BUF_LEN;
    }

    // write lost event
    if (cli->lost_event.lost > 0 && buf_idle(cli) > sizeof(struct perf_record_lost)) {
        buf_write(cli, &cli->lost_event, sizeof(struct perf_record_lost));
        cli->lost_event.lost = 0;
    }

    return 0;
}

static int set_reuse_addr(int fd)
{
    int opt = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static int set_nonblocking_flag(int fd, bool value)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;

    if (((flags & O_NONBLOCK) != 0) == value)
        return 0;

    if (value) flags |= O_NONBLOCK;
    else       flags &= ~O_NONBLOCK;
    return fcntl (fd, F_SETFL, flags);
}

static int set_close_on_exec(int fd, bool value)
{
    int flags;

    flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        return -1;

    if (((flags & FD_CLOEXEC) != 0) == value)
        return 0;

    if (value) flags |= FD_CLOEXEC;
    else       flags &= ~FD_CLOEXEC;
    return fcntl(fd, F_SETFD, flags);
}

static void print_sockaddr_to(const char *prefix, struct sockaddr *addr, socklen_t len, FILE *to)
{
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

    if (getnameinfo(addr, len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
            NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        fprintf(to, "%s %s:%s\n", prefix, hbuf, sbuf);
}

static inline void print_sockaddr(const char *prefix, struct sockaddr *addr, socklen_t len)
{
    print_sockaddr_to(prefix, addr, len, stdout);
}

static inline void tcp_client_init(struct tcp_client_socket *tcp)
{
    tcp->header.fd = -1;
    refcount_set(&tcp->header.ref, 1);
    tcp->header.type = 0;
    tcp->header.ops = NULL;

    tcp->events = 0;
    INIT_LIST_HEAD(&tcp->srvlink);
    memset(&tcp->peer_addr, 0, sizeof(tcp->peer_addr));
    tcp->peer_addrlen = 0;

    memset(&tcp->lost_event, 0, sizeof(tcp->lost_event));
    tcp->send = 0;
    tcp->write = 0;

    tcp->read = 0;
}

static inline void tcp_server_init(struct tcp_server_socket *srv)
{
    srv->header.fd = -1;
    refcount_set(&srv->header.ref, 1);
    srv->header.type = LISTEN_SERVER;
    srv->header.ops = NULL;

    INIT_LIST_HEAD(&srv->clilist);
}

static inline void tcp_ref(void *tcp)
{
    struct tcp_socket_header *header = tcp;
    refcount_inc_not_zero(&header->ref);
}

static inline void tcp_unref(void *tcp)
{
    struct tcp_socket_header *header = tcp;
    if (refcount_dec_and_test(&header->ref)) {
        if (header->type == ACCEPT_CLIENT)
            tcp_unref(header->ops->server);
        free(header);
    }
}

static int handle_errhup(int fd, unsigned int revents, void *ptr)
{
    struct tcp_client_socket *client = ptr;

    if (unlikely(revents & (EPOLLERR | EPOLLHUP)) &&
        client->header.fd >= 0) {
        int by_connect = client->header.type == CONNECT_CLIENT;
        struct tcp_socket_ops *ops = client->header.ops;

        print_sockaddr(by_connect ? "Disconnect from" : "Client hangs up", &client->peer_addr, client->peer_addrlen);
        main_epoll_del(client->header.fd);
        // Closing a file descriptor is automatically removed from all epoll set.
        close(client->header.fd);
        client->header.fd = -1;

        if (by_connect) {
            if (ops) {
                ops->client = NULL;
                if (ops->disconnect)
                    ops->disconnect(ops);
            }
        } else
            list_del(&client->srvlink);

        tcp_unref(client);
        return 1;
    }
    return 0;
}

static void handle_inout(int fd, unsigned int revents, void *ptr)
{
    struct tcp_client_socket *client = ptr;
    struct tcp_socket_ops *ops = client->header.ops;
    int (*process_event)(union perf_event *event, struct tcp_socket_ops *ops);

    if (handle_errhup(fd, revents, ptr))
        return;

    if (revents & EPOLLOUT) {
        int ret = buf_send(ptr);
        if (unlikely(ret < 0)) {
            if (errno != EAGAIN) {
                if (errno != ECONNRESET && errno != EPIPE)
                    fprintf(stderr, "Unable to send: %s\n", strerror(errno));
                handle_errhup(client->header.fd, EPOLLHUP, client);
                return;
            }
        } else if (buf_is_empty(client)) {
            client->events &= ~EPOLLOUT;
            main_epoll_add(client->header.fd, client->events, client, handle_inout);
        }
    }

    if (revents & EPOLLIN) {
        union perf_event *event;
        int ret;

        process_event = (ops && ops->process_event) ? ops->process_event : NULL;

        while (true) {
            ret = recv(client->header.fd, client->event_copy+client->read, sizeof(client->event_copy)-client->read, 0);
            if (unlikely(ret <= 0)) {
                // The return value will be 0 when the peer has performed an orderly shutdown.
                if (ret == 0) {
                    handle_errhup(client->header.fd, EPOLLHUP, client);
                    return;
                }
                if (errno != EAGAIN)
                    fprintf(stderr, "Unable to recv: %s\n", strerror(errno));
                break;
            }
            if (unlikely(!process_event))
                continue;

            client->read += ret;
            event = (void *)client->event_copy;
            while (client->read >= sizeof(struct perf_event_header) &&
                client->read >= event->header.size) {
                client->read -= event->header.size;
                if (unlikely(process_event(event, ops) < 0))
                    return;
                event = (void *)event + event->header.size;
            }
            if (client->read) {
                memcpy(client->event_copy, event, client->read);
            }
        }
    }
}

static void handle_accept(int fd, unsigned int revents, void *ptr)
{
    struct tcp_server_socket *srv = ptr;
    struct tcp_client_socket *client;
    struct tcp_socket_ops *ops;
    int cfd;

    if (!(client = malloc(sizeof(*client)))) return;
    tcp_client_init(client);

    client->peer_addrlen = sizeof(client->peer_addr);
    cfd = accept(srv->header.fd, &client->peer_addr, &client->peer_addrlen);
    if (cfd < 0) {
        if (errno == ECONNABORTED ||
            errno == EAGAIN) {
            goto err;
        }
        fprintf(stderr, "Unable to accept client: %s\n", strerror(errno));
        goto err;
    }

    print_sockaddr("Accept client", &client->peer_addr, client->peer_addrlen);

    if (set_nonblocking_flag(cfd, true) < 0) goto err;
    if (set_close_on_exec(cfd, true) < 0) goto err;

    ops = &client->inline_ops;
    memset(ops, 0, sizeof(*ops));
    if (srv->header.ops) {
        *ops = *srv->header.ops;
        ops->server_ops = srv->header.ops;
    }
    ops->client = client;
    ops->server = srv;
    tcp_ref(srv);

    client->header.fd = cfd;
    client->header.type = ACCEPT_CLIENT;
    client->header.ops = ops;

    list_add_tail(&client->srvlink, &srv->clilist);
    client->events = EPOLLIN | EPOLLERR | EPOLLHUP;
    main_epoll_add(cfd, client->events, client, handle_inout);

    if (client->header.ops->new_client)
        client->header.ops->new_client(client->header.ops);

    return;
err:
    free(client);
    return;
}

void *tcp_server(const char *node, const char *service, struct tcp_socket_ops *ops)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    struct tcp_server_socket *srv;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV; /* For wildcard IP address */
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Stream socket */
    hints.ai_protocol = 0;           /* Any protocol */

    s = getaddrinfo(node, service, &hints, &result);
    if (s != 0)
        return NULL;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0)
            continue;

        if (set_reuse_addr(sfd) < 0)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        print_sockaddr_to(strerror(errno), rp->ai_addr, rp->ai_addrlen, stderr);
        close(sfd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        return NULL;

    if (set_nonblocking_flag(sfd, true) < 0) goto err;
    if (set_close_on_exec(sfd, true) < 0) goto err;
    if (listen(sfd, 32) < 0) goto err;
    if (!(srv = malloc(sizeof(*srv)))) goto err;
    tcp_server_init(srv);

    srv->bind_addrlen = sizeof(srv->bind_addr);
    if (getsockname(sfd, &srv->bind_addr, &srv->bind_addrlen) == 0) {
        print_sockaddr("Listen at", &srv->bind_addr, srv->bind_addrlen);
    }

    if (ops) {
        ops->client = NULL;
        ops->server = srv;
        ops->server_ops = NULL;
    }

    srv->header.fd = sfd;
    srv->header.type = LISTEN_SERVER;
    srv->header.ops = ops;
    tcp_ref(srv);
    main_epoll_add(sfd, EPOLLIN, srv, handle_accept);

    return srv;

err:
    close(sfd);
    return NULL;
}

int tcp_send(void *cli, const void *buf, size_t len, int flags)
{
    struct tcp_client_socket *client = cli;
    int add = 0;

    if (!client)
        return -1;

    if (buf_idle(client) < len) {
        int ret = buf_send(client);
        if (unlikely(ret < 0)) {
            if (errno != EAGAIN) {
                //ECONNRESET Connection reset by peer.
                //EPIPE  The local end has been shut down on a connection oriented socket.
                if (errno != EPIPE && errno != ECONNRESET)
                    fprintf(stderr, "Unable to send: %s\n", strerror(errno));
                list_del_init(&client->srvlink);
                return -1;
            }
        }
    }

    add = buf_is_empty(client);
    if (likely(buf_idle(client) >= len)) {
        buf_write(client, buf, len);
        if (add && !(client->events & EPOLLOUT)) {
            client->events |= EPOLLOUT;
            main_epoll_add(client->header.fd, client->events, client, handle_inout);
        }
    } else {
        // lost event
        client->lost_event.header.size = sizeof(struct perf_record_lost);
        client->lost_event.header.type = PERF_RECORD_LOST;
        client->lost_event.header.misc = 0;
        client->lost_event.id          = 0;
        client->lost_event.lost        ++ ;
    }

    return 0;
}

int tcp_server_broadcast(void *server, const void *buf, size_t len, int flags)
{
    struct tcp_server_socket *srv = server;
    struct tcp_client_socket *client, *next;

    // Non-tcp server, tcp_send directly.
    if (unlikely(srv->header.type != LISTEN_SERVER)) {
        tcp_send(srv, buf, len, flags);
        return 0;
    }

    list_for_each_entry_safe(client, next, &srv->clilist, srvlink) {
        tcp_send(client, buf, len, flags);
    }
    return 0;
}

static void handle_connect(int fd, unsigned int revents, void *ptr)
{
    struct tcp_client_socket *conn = ptr;
    int err = 0;

    if (revents & EPOLLOUT) {
        socklen_t len = sizeof(err);
        int ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (ret == 0 && err == 0) {
            conn->peer_addrlen = sizeof(conn->peer_addr);
            if (getpeername(fd, &conn->peer_addr, &conn->peer_addrlen) == 0) {
                print_sockaddr("Connected to", &conn->peer_addr, conn->peer_addrlen);
            }
            conn->events = EPOLLIN | EPOLLERR | EPOLLHUP;
            main_epoll_add(fd, conn->events, conn, handle_inout);
            return;
        }
        fprintf(stderr, "Unable to connect: %s\n", strerror(ret<0 ? errno : err));
    }
    handle_errhup(fd, revents, ptr);
}

void *tcp_connect(const char *node, const char *service, struct tcp_socket_ops *ops)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int cfd, s;
    struct tcp_client_socket *conn = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* For wildcard IP address */
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Stream socket */
    hints.ai_protocol = 0;           /* Any protocol */

    s = getaddrinfo(node, service, &hints, &result);
    if (s != 0)
        return NULL;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        cfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (cfd >= 0)
            break;
    }

    if (rp == NULL) {
        freeaddrinfo(result);
        return NULL;
    }

    if (set_nonblocking_flag(cfd, true) < 0) goto err;
    if (set_close_on_exec(cfd, true) < 0) goto err;
    if (!(conn = malloc(sizeof(*conn)))) goto err;
    tcp_client_init(conn);
    if (connect(cfd, rp->ai_addr, rp->ai_addrlen) < 0) {
        if (errno == EINPROGRESS) {
            tcp_ref(conn);
            main_epoll_add(cfd, EPOLLOUT, conn, handle_connect);
        } else
            goto err;
    } else {
        conn->peer_addrlen = sizeof(conn->peer_addr);
        if (getpeername(cfd, &conn->peer_addr, &conn->peer_addrlen) == 0) {
            print_sockaddr("Connected to", &conn->peer_addr, conn->peer_addrlen);
        }
        tcp_ref(conn);
        conn->events = EPOLLIN | EPOLLERR | EPOLLHUP;
        main_epoll_add(cfd, conn->events, conn, handle_inout);
    }

    if (ops) {
        ops->client = conn;
        ops->server = NULL;
        ops->server_ops = NULL;
    }

    conn->header.fd = cfd;
    conn->header.type = CONNECT_CLIENT;
    conn->header.ops = ops;

    freeaddrinfo(result);
    return conn;

err:
    freeaddrinfo(result);
    if (conn) free(conn);
    close(cfd);
    return NULL;
}

static void tcp_close_flush(void *tcp)
{
    struct tcp_socket_header *header = tcp;
    struct tcp_server_socket *srv;
    struct tcp_client_socket *client, *next;

    switch (header->type) {
        case LISTEN_SERVER:
            srv = tcp;
            list_for_each_entry_safe(client, next, &srv->clilist, srvlink) {
                set_nonblocking_flag(client->header.fd, false);
                handle_inout(client->header.fd, EPOLLOUT, client);
            }
            break;
        case CONNECT_CLIENT:
            client = tcp;
            set_nonblocking_flag(client->header.fd, false);
            handle_inout(client->header.fd, EPOLLOUT, client);
            break;
        case ACCEPT_CLIENT: /* Can't be closed */
        default:
            return;
    }
}

void tcp_close(void *tcp)
{
    struct tcp_socket_header *header = tcp;

    tcp_close_flush(tcp);

    switch (header->type) {
        case LISTEN_SERVER:
            main_epoll_del(header->fd);
            close(header->fd);
            tcp_unref(tcp);
            break;
        case CONNECT_CLIENT:
            /*
             * Calling tcp_close externally prohibits calling the disconnect callback to avoid
             * repeated execution of the disconnect callback. handle_errhup, tcp_close, and
             * disconnect callback can only be executed once.
             * Therefore, the external call to tcp_close also needs to include the disconnect
             * callback function.
             */
            if (header->ops)
                header->ops->disconnect = NULL;
            handle_errhup(header->fd, EPOLLHUP, tcp);
            break;
        case ACCEPT_CLIENT: /* Can't be closed */
        default:
            return;
    }

    tcp_unref(tcp);
}

