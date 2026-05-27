/* ws_chat64k.c — WebSocket chat server, <64 KiB app state, 512 users.
 *
 * Wire:  RFC 6455 WebSocket over TCP. Browsers connect with
 *          const ws = new WebSocket("ws://host:5555");
 *
 * App protocol (server is JSON-aware on the way out):
 *   - First text frame from a client = nickname (UTF-8, up to 15 bytes).
 *   - Each subsequent text frame = the chat message payload (any UTF-8;
 *     clients typically send JSON, but the server doesn't care).
 *   - Server broadcasts each chat message to all other clients as a
 *     JSON envelope:
 *         {"from":"alice","msg":"...payload, JSON-string-escaped..."}
 *     so JS clients can `JSON.parse(event.data)` directly.
 *   - Join / leave notices are also JSON envelopes:
 *         {"event":"join","name":"alice"}
 *         {"event":"leave","name":"alice"}
 *
 * Memory:  per-client = 64 B (compile-time asserted). 512 clients = 32 KiB.
 *          Shared readbuf + msgbuf = 2 KiB. Epoll batch = ~768 B. Total
 *          BSS ≈ 35 KiB (verify with `size`).
 *
 * Frame size:  payload capped at MAX_PAYLOAD bytes. Frames that arrive
 *              whole in one recv() are processed inline. Frames split
 *              across multiple recv() calls are tolerated up to 16 bytes
 *              of partial payload (per-client buffer); larger split
 *              frames drop the client.
 *
 * Build: gcc -O2 -Wall -Wextra -o ws_chat64k ws_chat64k.c
 * Run:   ./ws_chat64k [port]            (default 5555)
 * Test:  open the bundled wsclient.html in two browser tabs.
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
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include "db.h"

#define MAX_CLIENTS    512
#define EPOLL_BATCH    64
#define READ_BUF_LEN   1024
#define MSG_BUF_LEN    1024
#define NAME_MAX_LEN   15
#define MAX_PAYLOAD    900
#define LISTEN_SLOT    0xFFFFFFFFu
#define PORT_DEFAULT   5555
#define WS_MAGIC       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

enum { ST_HS = 0, ST_NAMING = 1, ST_OPEN = 2 };

/* HTTP handshake sub-states */
enum {
    HS_LOL = 0,       /* at start of a line */
    HS_NAME_MATCH,    /* matching "sec-websocket-key:" */
    HS_SKIP_TO_LF,    /* skipping rest of current line */
    HS_PRE_VAL,       /* skipping whitespace before value */
    HS_IN_VAL,        /* collecting value */
    HS_AFTER_VAL,     /* skipping rest of value line */
    HS_FINAL_CR,      /* saw \r at start of line, expect \n => done */
};

struct ws_client {
    int      fd;                   /* 4 */
    uint8_t  state;                /* 1 */
    uint8_t  hs_state;             /* 1 */
    uint8_t  hs_match_pos;         /* 1  position in "sec-websocket-key:" */
    uint8_t  hs_key_len;           /* 1  chars of WS-Key value collected */
    uint8_t  name_len;             /* 1 */
    uint8_t  fr_hdr_bytes;         /* 1  0..8 (incremental header parser) */
    uint8_t  fr_opcode;            /* 1 */
    uint8_t  _pad;                 /* 1 */
    uint16_t fr_payload_total;     /* 2 */
    uint16_t fr_payload_seen;      /* 2 */
    uint8_t  mask[4];              /* 4 */
    union {                        /* 24 */
        char hs_keybuf[24];        /*    during ST_HS */
        char name[24];             /*    during ST_NAMING / ST_OPEN */
    };
    uint8_t  partial[20];          /* 20 */
};
_Static_assert(sizeof(struct ws_client) == 64, "ws_client must be 64 bytes");

static struct ws_client clients[MAX_CLIENTS];   /* 32 KiB */
static char  readbuf[READ_BUF_LEN];             /*  1 KiB */
static char  msgbuf[MSG_BUF_LEN];               /*  1 KiB */
static int   epfd, listen_fd;

static const char NEEDLE[] = "sec-websocket-key:"; /* 18 chars */

/* =====================================================================
 * SHA-1  (compact, RFC 3174)
 * =================================================================== */
static void sha1_block(uint32_t h[5], const uint8_t *blk) {
    uint32_t w[80], a, b, c, d, e, f, k, t;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[4*i]   << 24) | ((uint32_t)blk[4*i+1] << 16)
             | ((uint32_t)blk[4*i+2] <<  8) |  (uint32_t)blk[4*i+3];
    for (int i = 16; i < 80; i++) {
        uint32_t v = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (v << 1) | (v >> 31);
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (int i = 0; i < 80; i++) {
        if      (i < 20) { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = t;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
}

static void sha1(const uint8_t *msg, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                     0x10325476, 0xC3D2E1F0};
    size_t i = 0;
    while (i + 64 <= len) { sha1_block(h, msg + i); i += 64; }
    uint8_t blk[64] = {0};
    size_t rem = len - i;
    memcpy(blk, msg + i, rem);
    blk[rem] = 0x80;
    if (rem >= 56) {
        sha1_block(h, blk);
        memset(blk, 0, 64);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++)
        blk[56 + j] = (uint8_t)(bits >> (56 - 8*j));
    sha1_block(h, blk);
    for (int j = 0; j < 5; j++) {
        out[4*j  ] = (uint8_t)(h[j] >> 24);
        out[4*j+1] = (uint8_t)(h[j] >> 16);
        out[4*j+2] = (uint8_t)(h[j] >>  8);
        out[4*j+3] = (uint8_t) h[j];
    }
}

/* =====================================================================
 * Base64 encode (no line wrap)
 * =================================================================== */
static const char B64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const uint8_t *in, int n, char *out) {
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        v |= (i + 1 < n) ? ((uint32_t)in[i+1] << 8) : 0;
        v |= (i + 2 < n) ?  (uint32_t)in[i+2]       : 0;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? B64[v & 63]        : '=';
    }
    return o;
}

/* =====================================================================
 * Slot helpers + drop / broadcast
 * =================================================================== */
static int find_free_slot(void) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd < 0) return i;
    return -1;
}

static void drop(int i) {
    if (clients[i].fd < 0) return;
    epoll_ctl(epfd, EPOLL_CTL_DEL, clients[i].fd, NULL);
    close(clients[i].fd);
    memset(&clients[i], 0, sizeof clients[i]);
    clients[i].fd = -1;
}

static void ws_send_text(int i, const char *payload, int n);

static void broadcast_except(int from, const char *payload, int n) {
    for (int j = 0; j < MAX_CLIENTS; j++) {
        if (j == from) continue;
        if (clients[j].fd < 0 || clients[j].state != ST_OPEN) continue;
        ws_send_text(j, payload, n);
    }
}

/* =====================================================================
 * JSON string escape — append \"...\" to dst, return chars written or -1
 * Escapes the minimum required for valid JSON strings.
 * =================================================================== */
static int json_quote(char *dst, int cap, const char *s, int n) {
    if (cap < 2) return -1;
    int o = 0;
    dst[o++] = '"';
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            if (o + 2 + 1 > cap) return -1;
            dst[o++] = '\\'; dst[o++] = (char)c;
        } else if (c == '\n') {
            if (o + 2 + 1 > cap) return -1;
            dst[o++] = '\\'; dst[o++] = 'n';
        } else if (c == '\r') {
            if (o + 2 + 1 > cap) return -1;
            dst[o++] = '\\'; dst[o++] = 'r';
        } else if (c == '\t') {
            if (o + 2 + 1 > cap) return -1;
            dst[o++] = '\\'; dst[o++] = 't';
        } else if (c < 0x20) {
            if (o + 6 + 1 > cap) return -1;
            static const char H[] = "0123456789abcdef";
            dst[o++] = '\\'; dst[o++] = 'u';
            dst[o++] = '0';  dst[o++] = '0';
            dst[o++] = H[c >> 4]; dst[o++] = H[c & 15];
        } else {
            if (o + 1 + 1 > cap) return -1;
            dst[o++] = (char)c;
        }
    }
    dst[o++] = '"';
    return o;
}

/* =====================================================================
 * Handshake response
 * =================================================================== */
static void send_handshake_response(int i) {
    /* compute Sec-WebSocket-Accept = base64(SHA1(key || GUID)) */
    char concat[24 + 36 + 1];
    int kl = clients[i].hs_key_len;
    if (kl > 24) kl = 24;
    memcpy(concat, clients[i].hs_keybuf, kl);
    memcpy(concat + kl, WS_MAGIC, 36);
    uint8_t hash[20];
    sha1((const uint8_t*)concat, kl + 36, hash);
    char accept[40];
    int al = b64_encode(hash, 20, accept);
    accept[al] = 0;

    int n = snprintf(msgbuf, sizeof msgbuf,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", accept);
    if (n < 0 || n >= (int)sizeof msgbuf) { drop(i); return; }
    if (send(clients[i].fd, msgbuf, n, MSG_NOSIGNAL | MSG_DONTWAIT) < 0) {
        drop(i); return;
    }
    clients[i].state         = ST_NAMING;
    clients[i].hs_state      = 0;
    clients[i].hs_match_pos  = 0;
    clients[i].hs_key_len    = 0;
    clients[i].fr_hdr_bytes  = 0;
    /* clear the union so name[] starts empty */
    memset(clients[i].name, 0, 24);
}

/* =====================================================================
 * WebSocket frame send (server -> client, opcode 0x1 text, no mask)
 * =================================================================== */
static void ws_send_text(int i, const char *payload, int n) {
    if (clients[i].fd < 0) return;
    if (n < 0) return;
    uint8_t hdr[4];
    int hl;
    if (n < 126) {
        hdr[0] = 0x81;            /* FIN | text */
        hdr[1] = (uint8_t)n;
        hl = 2;
    } else if (n <= 0xFFFF) {
        hdr[0] = 0x81;
        hdr[1] = 126;
        hdr[2] = (uint8_t)(n >> 8);
        hdr[3] = (uint8_t)(n & 0xFF);
        hl = 4;
    } else {
        return; /* we never send frames this big */
    }
    struct iovec iov[2] = {
        { .iov_base = hdr,            .iov_len = (size_t)hl },
        { .iov_base = (void*)payload, .iov_len = (size_t)n  }
    };
    struct msghdr mh = { 0 };
    mh.msg_iov    = iov;
    mh.msg_iovlen = 2;
    if (sendmsg(clients[i].fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT) < 0
        && errno != EAGAIN && errno != EWOULDBLOCK) {
        drop(i);
    }
}

/* =====================================================================
 * Application-layer message handling — runs on a fully-unmasked payload
 * =================================================================== */
static void on_text_message(int i, const char *p, int n) {
    /* strip trailing whitespace some clients send */
    while (n > 0 && (p[n-1] == '\r' || p[n-1] == '\n' || p[n-1] == ' ')) n--;
    while (n > 0 && (p[0] == ' ')) { p++; n--; }

    if (clients[i].state == ST_NAMING) {
        if (n == 0) return;
        if (n > NAME_MAX_LEN) n = NAME_MAX_LEN;
        memcpy(clients[i].name, p, n);
        clients[i].name[n] = 0;
        clients[i].name_len = (uint8_t)n;
        clients[i].state = ST_OPEN;

        /* announce join: {"event":"join","name":"<name>"} */
        int off = snprintf(msgbuf, sizeof msgbuf,
                           "{\"event\":\"join\",\"name\":");
        int qn = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 1,
                            clients[i].name, n);
        if (qn < 0) return;
        off += qn;
        msgbuf[off++] = '}';
        broadcast_except(i, msgbuf, off);
        db_log_event("join", clients[i].name, n);

        /* welcome the new user */
        const char *w = "{\"event\":\"welcome\"}";
        ws_send_text(i, w, (int)strlen(w));
        return;
    }

    if (n == 0) return;

    /* build {"from":"<name>","msg":<quoted-payload>} */
    int off = snprintf(msgbuf, sizeof msgbuf, "{\"from\":");
    int q1 = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 16,
                        clients[i].name, clients[i].name_len);
    if (q1 < 0) return;
    off += q1;
    int hdr2 = snprintf(msgbuf + off, sizeof msgbuf - off, ",\"msg\":");
    off += hdr2;
    int q2 = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 2, p, n);
    if (q2 < 0) return;
    off += q2;
    msgbuf[off++] = '}';
    broadcast_except(i, msgbuf, off);
    db_log_msg(clients[i].name, clients[i].name_len, p, n);
}

static void announce_leave(int i) {
    if (clients[i].state != ST_OPEN) return;
    int off = snprintf(msgbuf, sizeof msgbuf,
                       "{\"event\":\"leave\",\"name\":");
    int qn = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 1,
                        clients[i].name, clients[i].name_len);
    if (qn < 0) return;
    off += qn;
    msgbuf[off++] = '}';
    broadcast_except(i, msgbuf, off);
    db_log_event("leave", clients[i].name, clients[i].name_len);
}

/* =====================================================================
 * Handshake byte parser (streaming, no per-client buffer for the request)
 * =================================================================== */
static int hs_feed(int i, uint8_t b) {
    /* returns 1 once HS_DONE, 0 mid-way, -1 on error */
    struct ws_client *c = &clients[i];
    switch (c->hs_state) {
    case HS_LOL:
        if (b == '\r') { c->hs_state = HS_FINAL_CR; return 0; }
        if (b == '\n') return 0;
        if ((char)tolower(b) == NEEDLE[0]) {
            c->hs_match_pos = 1; c->hs_state = HS_NAME_MATCH;
        } else {
            c->hs_state = HS_SKIP_TO_LF;
        }
        return 0;
    case HS_NAME_MATCH:
        if ((char)tolower(b) == NEEDLE[c->hs_match_pos]) {
            c->hs_match_pos++;
            if (c->hs_match_pos == sizeof NEEDLE - 1) {
                c->hs_state = HS_PRE_VAL;
                c->hs_key_len = 0;
            }
        } else if (b == '\n') {
            c->hs_state = HS_LOL;
        } else {
            c->hs_state = HS_SKIP_TO_LF;
        }
        return 0;
    case HS_SKIP_TO_LF:
        if (b == '\n') c->hs_state = HS_LOL;
        return 0;
    case HS_PRE_VAL:
        if (b == ' ' || b == '\t') return 0;
        if (b == '\r') { c->hs_state = HS_AFTER_VAL; return 0; }
        if (b == '\n') { c->hs_state = HS_LOL; return 0; }
        c->hs_keybuf[c->hs_key_len++] = (char)b;
        c->hs_state = HS_IN_VAL;
        return 0;
    case HS_IN_VAL:
        if (b == '\r') { c->hs_state = HS_AFTER_VAL; return 0; }
        if (b == '\n') { c->hs_state = HS_LOL; return 0; }
        if (c->hs_key_len < 24) c->hs_keybuf[c->hs_key_len++] = (char)b;
        return 0;
    case HS_AFTER_VAL:
        if (b == '\n') c->hs_state = HS_LOL;
        return 0;
    case HS_FINAL_CR:
        if (b == '\n') return (c->hs_key_len > 0) ? 1 : -1;
        c->hs_state = HS_SKIP_TO_LF;
        return 0;
    }
    return -1;
}

/* =====================================================================
 * WebSocket frame parser — fed bytes from readbuf
 *
 * Header-state progression via fr_hdr_bytes:
 *   0 -> 1   first byte (FIN/opcode)
 *   1 -> 2   second byte (mask/len7); if len7==126 collect 2 more
 *   2 -> 3   ext-len hi
 *   3 -> 4   ext-len lo
 *   4..7     mask bytes  (4 -> 5 -> 6 -> 7 -> 8 = header done)
 *
 * Once header done, fr_payload_seen is bumped while we unmask & process.
 * If the whole payload is available in this recv chunk, we process inline;
 * otherwise we buffer up to sizeof(partial) bytes for cross-recv joining.
 * =================================================================== */
static int parse_header_byte(int i, uint8_t b) {
    struct ws_client *c = &clients[i];
    switch (c->fr_hdr_bytes) {
    case 0:
        if (!(b & 0x80)) return -1;          /* require FIN */
        if (b & 0x70)    return -1;          /* RSV must be 0 */
        c->fr_opcode = b & 0x0F;
        c->fr_hdr_bytes = 1;
        return 0;
    case 1: {
        if (!(b & 0x80)) return -1;          /* client must mask */
        uint8_t len = b & 0x7F;
        if (len == 127) return -1;           /* 64-bit lengths unsupported */
        if (len == 126) {
            c->fr_payload_total = 0;
            c->fr_hdr_bytes = 2;
        } else {
            c->fr_payload_total = len;
            c->fr_hdr_bytes = 4;             /* skip ext-len phase */
        }
        return 0;
    }
    case 2:
        c->fr_payload_total = (uint16_t)b << 8;
        c->fr_hdr_bytes = 3;
        return 0;
    case 3:
        c->fr_payload_total |= b;
        if (c->fr_payload_total > MAX_PAYLOAD) return -1;
        c->fr_hdr_bytes = 4;
        return 0;
    case 4: case 5: case 6: case 7:
        c->mask[c->fr_hdr_bytes - 4] = b;
        c->fr_hdr_bytes++;
        if (c->fr_hdr_bytes == 8) {
            c->fr_payload_seen = 0;
            if (c->fr_payload_total > MAX_PAYLOAD) return -1;
            return 1;                        /* header complete */
        }
        return 0;
    }
    return -1;
}

/* dispatch a fully-assembled, already-unmasked payload */
static void dispatch_frame(int i, const char *payload, int n) {
    struct ws_client *c = &clients[i];
    switch (c->fr_opcode) {
    case 0x1: /* text */
        on_text_message(i, payload, n);
        break;
    case 0x8: /* close */
        announce_leave(i);
        drop(i);
        return;
    case 0x9: /* ping -> pong */
    {
        uint8_t hdr[2] = { 0x8A, (uint8_t)n };
        struct iovec iov[2] = {
            { hdr, 2 }, { (void*)payload, (size_t)n }
        };
        struct msghdr mh = { 0 };
        mh.msg_iov = iov; mh.msg_iovlen = 2;
        sendmsg(clients[i].fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
        break;
    }
    case 0xA: /* pong */ break;
    default:  drop(i); return;
    }
    /* reset for next frame */
    c->fr_hdr_bytes = 0;
    c->fr_opcode = 0;
    c->fr_payload_total = 0;
    c->fr_payload_seen = 0;
}

/* feed one recv() chunk worth of data through the frame parser.
 * returns 0 on success, -1 on protocol error (client should be dropped) */
static int feed_frames(int i, const uint8_t *data, int n) {
    struct ws_client *c = &clients[i];
    int p = 0;
    while (p < n) {
        /* header phase */
        while (c->fr_hdr_bytes < 8 && p < n) {
            int r = parse_header_byte(i, data[p++]);
            if (r < 0) return -1;
        }
        if (c->fr_hdr_bytes < 8) return 0;     /* need more bytes */

        /* payload phase */
        int need = (int)c->fr_payload_total - (int)c->fr_payload_seen;
        int have = n - p;
        if (need == 0) {
            /* zero-length frame */
            dispatch_frame(i, NULL, 0);
            continue;
        }
        if (c->fr_payload_seen == 0 && have >= need) {
            /* fast path: whole payload in this recv */
            uint8_t *q = (uint8_t*)readbuf + p;   /* unmask in place */
            for (int k = 0; k < need; k++) q[k] ^= c->mask[k & 3];
            dispatch_frame(i, (char*)q, need);
            p += need;
        } else {
            /* slow path: cross-recv. buffer up to sizeof(partial) bytes */
            int take = have < need ? have : need;
            if (c->fr_payload_seen + take > (int)sizeof c->partial) {
                /* would overflow our partial buffer — bail */
                return -1;
            }
            for (int k = 0; k < take; k++)
                c->partial[c->fr_payload_seen + k] =
                    data[p + k] ^ c->mask[(c->fr_payload_seen + k) & 3];
            c->fr_payload_seen += take;
            p += take;
            if (c->fr_payload_seen == c->fr_payload_total) {
                dispatch_frame(i, (char*)c->partial, c->fr_payload_total);
            } else {
                return 0;  /* wait for more */
            }
        }
    }
    return 0;
}

/* =====================================================================
 * Read handler
 * =================================================================== */
static void on_readable(int i) {
    for (;;) {
        ssize_t r = recv(clients[i].fd, readbuf, sizeof readbuf, 0);
        if (r == 0) { announce_leave(i); drop(i); return; }
        if (r <  0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            announce_leave(i); drop(i); return;
        }
        if (clients[i].state == ST_HS) {
            int p = 0;
            while (p < r && clients[i].state == ST_HS) {
                int rc = hs_feed(i, (uint8_t)readbuf[p++]);
                if (rc < 0) { drop(i); return; }
                if (rc > 0) {
                    send_handshake_response(i);
                    /* remaining bytes after handshake belong to first frame */
                    if (p < r) {
                        if (feed_frames(i, (uint8_t*)readbuf + p, (int)(r - p)) < 0) {
                            announce_leave(i); drop(i); return;
                        }
                    }
                    break;
                }
            }
        } else {
            if (feed_frames(i, (uint8_t*)readbuf, (int)r) < 0) {
                announce_leave(i); drop(i); return;
            }
        }
    }
}

/* =====================================================================
 * Accept
 * =================================================================== */
static void accept_new(void) {
    for (;;) {
        struct sockaddr_in sa; socklen_t sl = sizeof sa;
        int fd = accept4(listen_fd, (struct sockaddr*)&sa, &sl, SOCK_NONBLOCK);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        int slot = find_free_slot();
        if (slot < 0) { close(fd); continue; }

        memset(&clients[slot], 0, sizeof clients[slot]);
        clients[slot].fd    = fd;
        clients[slot].state = ST_HS;

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
    }
}

/* =====================================================================
 * main
 * =================================================================== */
int main(int argc, char **argv) {
    const char *port_env = getenv("PORT");
    int port = (argc > 1) ? atoi(argv[1])
             : (port_env && *port_env) ? atoi(port_env)
             : PORT_DEFAULT;
    signal(SIGPIPE, SIG_IGN);

    db_init();

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

    fprintf(stderr, "ws_chat64k: ws://0.0.0.0:%d  (max %d clients)\n",
            port, MAX_CLIENTS);

    struct epoll_event evs[EPOLL_BATCH];
    for (;;) {
        int n = epoll_wait(epfd, evs, EPOLL_BATCH, -1);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); return 1; }
        for (int k = 0; k < n; k++) {
            uint32_t slot = evs[k].data.u32;
            if (slot == LISTEN_SLOT) { accept_new(); continue; }
            if (evs[k].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
                announce_leave((int)slot);
                drop((int)slot);
                continue;
            }
            if (evs[k].events & EPOLLIN) on_readable((int)slot);
        }
    }
}
