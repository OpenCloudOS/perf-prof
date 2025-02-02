#ifndef __NET_H
#define __NET_H

#include <sys/types.h>
#include <sys/socket.h>

struct tcp_socket_ops {
    void *client; // by tcp_connect() or accepted by tcp_server().
    void *server;
    struct tcp_socket_ops *server_ops;

    void (*notify_to_recv)(struct tcp_socket_ops *ops);
    int (*process_event)(char *event_buf, int size, struct tcp_socket_ops *ops);
    int (*disconnect)(struct tcp_socket_ops *ops);

    int (*new_client)(struct tcp_socket_ops *ops);
};

void *tcp_server(const char *node, const char *service, struct tcp_socket_ops *ops);

int tcp_send(void *client, const void *buf, size_t len, int flags);
int tcp_recv(void *client, void *buf, size_t len, int flags);
int tcp_server_broadcast(void *server, const void *buf, size_t len, int flags);

void *tcp_connect(const char *node, const char *service, struct tcp_socket_ops *ops);

void tcp_close(void *tcp);


#endif
