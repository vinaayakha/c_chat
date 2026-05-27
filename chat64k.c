/* chat64k.c — TCP chat server, <64 KB app state, 512 concurrent users.
 *
 * Build:  gcc -O2 -Wall -Wextra -o chat64k chat64k.c
 * Run:    ./chat64k [port]            (default 5555)
 * Test:   nc 127.0.0.1 5555           (type a nickname, then chat)
 *
 * Design:
 *   - Single thread, Linux epoll, level-triggered.
 *   - Static `clients[512]`, 64 bytes per slot (no malloc anywhere).
 *   - Shared 1 KB recv buffer + 512 B broadcast buffer (not per-client).
 *   - epoll_data.u32 carries the slot index so lookups are O(1).
 *   - Sends are non-blocking with MSG_DONTWAIT; if a peer can't keep up,
 *     we drop them rather than grow a per-client send queue (that's how
 *     we stay flat at 64 B/client).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define MAX_CLIENTS    512
#define NAME_MAX_LEN   15           /* +1 NUL = 16 bytes in struct */
#define LINE_BUF_LEN   40           /* per-client partial-line buffer  */
#define EPOLL_BATCH    64
#define MSG_MAX        512
#define READ_BUF_LEN   1024
#define PORT_DEFAULT   5555
#define LISTEN_SLOT    0xFFFFFFFFu  /* sentinel in epoll_data.u32 */

enum { ST_NAMING = 0, ST_CHATTING = 1 };

struct client {
    int      fd;                          /* 4  */
    uint8_t  name_len;                    /* 1  */
    uint8_t  buf_len;                     /* 1  */
    uint8_t  state;                       /* 1  */
    uint8_t  _pad;                        /* 1  */
    char     name[NAME_MAX_LEN + 1];      /* 16 */
    char     buf[LINE_BUF_LEN];           /* 40 */
};                                        /* = 64 bytes */

static struct client clients[MAX_CLIENTS];          /* 32 KB */
static char          readbuf[READ_BUF_LEN];         /*  1 KB */
static char          msgbuf[MSG_MAX];               /* 512 B */
static int           epfd;
static int           listen_fd;

/* ---------- helpers ---------- */

static int find_free_slot(void) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd < 0) return i;
    return -1;
}

static void drop(int i) {                        /* hard close, no announce */
    if (clients[i].fd < 0) return;
    epoll_ctl(epfd, EPOLL_CTL_DEL, clients[i].fd, NULL);
    close(clients[i].fd);
    memset(&clients[i], 0, sizeof clients[i]);
    clients[i].fd = -1;
}

static void broadcast_except(int from, const char *s, int n) {
    for (int j = 0; j < MAX_CLIENTS; j++) {
        if (j == from) continue;
        if (clients[j].fd < 0 || clients[j].state != ST_CHATTING) continue;
        if (send(clients[j].fd, s, n, MSG_NOSIGNAL | MSG_DONTWAIT) < 0
            && errno != EAGAIN && errno != EWOULDBLOCK) {
            drop(j);                             /* slow/dead peer */
        }
    }
}

static void send_to(int i, const char *s, int n) {
    if (clients[i].fd < 0) return;
    if (send(clients[i].fd, s, n, MSG_NOSIGNAL | MSG_DONTWAIT) < 0
        && errno != EAGAIN && errno != EWOULDBLOCK) {
        drop(i);
    }
}

static void close_client(int i, const char *reason) {
    if (clients[i].fd < 0) return;
    if (clients[i].state == ST_CHATTING) {
        int n = snprintf(msgbuf, sizeof msgbuf,
                         "* %s left (%s)\n", clients[i].name, reason);
        if (n > (int)sizeof msgbuf) n = sizeof msgbuf;
        /* broadcast_except scans the table — do it before we wipe the slot */
        broadcast_except(i, msgbuf, n);
    }
    drop(i);
}

/* ---------- protocol ---------- */

static void handle_line(int i, const char *line, int len) {
    while (len > 0 && (line[len-1] == '\r' || line[len-1] == '\n')) len--;

    if (clients[i].state == ST_NAMING) {
        if (len == 0) { send_to(i, "name? ", 6); return; }
        if (len > NAME_MAX_LEN) len = NAME_MAX_LEN;
        memcpy(clients[i].name, line, len);
        clients[i].name[len] = 0;
        clients[i].name_len  = (uint8_t)len;
        clients[i].state     = ST_CHATTING;

        int n = snprintf(msgbuf, sizeof msgbuf,
                         "* %s joined\n", clients[i].name);
        if (n > (int)sizeof msgbuf) n = sizeof msgbuf;
        broadcast_except(i, msgbuf, n);
        send_to(i, "welcome\n", 8);
        return;
    }

    if (len == 0) return;
    int n = snprintf(msgbuf, sizeof msgbuf,
                     "<%s> %.*s\n", clients[i].name, len, line);
    if (n < 0) return;
    if (n > (int)sizeof msgbuf) n = sizeof msgbuf;
    broadcast_except(i, msgbuf, n);
}

static void on_readable(int i) {
    for (;;) {
        ssize_t r = recv(clients[i].fd, readbuf, sizeof readbuf, 0);
        if (r == 0) { close_client(i, "eof");      return; }
        if (r <  0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            close_client(i, "recv");               return;
        }
        for (ssize_t p = 0; p < r; p++) {
            char c = readbuf[p];
            if (c == '\n') {
                handle_line(i, clients[i].buf, clients[i].buf_len);
                clients[i].buf_len = 0;
            } else if (clients[i].buf_len < LINE_BUF_LEN) {
                clients[i].buf[clients[i].buf_len++] = c;
            } else {                              /* line too long: flush */
                handle_line(i, clients[i].buf, clients[i].buf_len);
                clients[i].buf_len = 0;
                if (c != '\r') clients[i].buf[clients[i].buf_len++] = c;
            }
        }
    }
}

/* ---------- accept ---------- */

static void accept_new(void) {
    for (;;) {
        struct sockaddr_in sa;
        socklen_t sl = sizeof sa;
        int fd = accept4(listen_fd, (struct sockaddr*)&sa, &sl, SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        int slot = find_free_slot();
        if (slot < 0) {
            const char *m = "server full\n";
            send(fd, m, 12, MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        clients[slot].fd       = fd;
        clients[slot].state    = ST_NAMING;
        clients[slot].name_len = 0;
        clients[slot].buf_len  = 0;

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLRDHUP,
            .data   = { .u32 = (uint32_t)slot },
        };
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            close(fd);
            memset(&clients[slot], 0, sizeof clients[slot]);
            clients[slot].fd = -1;
            continue;
        }
        send(fd, "name? ", 6, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : PORT_DEFAULT;
    signal(SIGPIPE, SIG_IGN);

    for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;

    listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons((uint16_t)port);
    if (bind(listen_fd, (struct sockaddr*)&sa, sizeof sa) < 0) {
        perror("bind"); return 1;
    }
    if (listen(listen_fd, 128) < 0) { perror("listen"); return 1; }

    epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); return 1; }

    struct epoll_event lev = {
        .events = EPOLLIN,
        .data   = { .u32 = LISTEN_SLOT },
    };
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &lev);

    fprintf(stderr, "chat64k: listening on :%d (max %d clients)\n",
            port, MAX_CLIENTS);

    struct epoll_event evs[EPOLL_BATCH];
    for (;;) {
        int n = epoll_wait(epfd, evs, EPOLL_BATCH, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); return 1;
        }
        for (int k = 0; k < n; k++) {
            uint32_t slot = evs[k].data.u32;
            if (slot == LISTEN_SLOT) { accept_new(); continue; }

            if (evs[k].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
                close_client((int)slot, "hup");
                continue;
            }
            if (evs[k].events & EPOLLIN)
                on_readable((int)slot);
        }
    }
}
