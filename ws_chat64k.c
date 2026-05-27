/* ws_chat64k.c — HTTP + WebSocket chat server with PG-backed auth/history.
 *
 * Single TCP listener. Per-connection request buffer parses HTTP. If the
 * request carries `Upgrade: websocket`, we send the 101 handshake and the
 * connection switches into WebSocket mode (text/broadcast). Otherwise the
 * request is routed:
 *
 *   GET  /                       -> bundled wsclient (public/index.html)
 *   GET  /api/history?limit=N    -> JSON array of recent messages
 *   POST /api/register {u, p}    -> JSON {token, username}
 *   POST /api/login    {u, p}    -> JSON {token, username}
 *   POST /api/logout   {token}   -> JSON {}
 *   OPTIONS *                    -> 204 + permissive CORS
 *
 * WS auth: browser passes the session token via the WebSocket subprotocol
 *   `bearer.<hex-token>`. Server validates the session against PG and uses
 *   the username as the broadcast nick. If no subprotocol is offered the
 *   client must send its nickname as the first text frame (guest mode).
 *
 * Build (static, scratch image): see Dockerfile.
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
#include "bundled.h"

#define MAX_CLIENTS    512
#define EPOLL_BATCH    64
#define READ_BUF_LEN   4096
#define MSG_BUF_LEN    2048
#define NAME_MAX_LEN   32
#define MAX_PAYLOAD    1200
#define REQ_BUF_LEN    4096
#define MAX_BODY_LEN   1024
#define LISTEN_SLOT    0xFFFFFFFFu
#define PORT_DEFAULT   5555
#define WS_MAGIC       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

enum { ST_REQ = 0, ST_NAMING = 1, ST_OPEN = 2, ST_SENDING = 3 };

struct ws_client {
    int       fd;
    uint8_t   state;
    uint8_t   close_after_send;
    uint8_t   name_len;
    uint8_t   has_token;          /* WS upgrade carried valid bearer */

    /* HTTP request buffering */
    uint16_t  req_len;            /* bytes in req_buf */
    int       req_head_end;       /* offset of "\r\n\r\n"+4, or -1 if not yet seen */
    int       req_content_length; /* parsed Content-Length, 0 if absent */
    uint8_t   req_buf[REQ_BUF_LEN];

    /* HTTP response (heap) */
    uint8_t  *resp;
    size_t    resp_len;
    size_t    resp_sent;

    /* WS frame state (after upgrade) */
    uint8_t   fr_hdr_bytes;
    uint8_t   fr_opcode;
    uint16_t  fr_payload_total;
    uint16_t  fr_payload_seen;
    uint8_t   mask[4];
    uint8_t   ws_partial[MAX_PAYLOAD];

    char      name[NAME_MAX_LEN + 1];
};

static struct ws_client clients[MAX_CLIENTS];
static char  readbuf[READ_BUF_LEN];
static char  msgbuf[MSG_BUF_LEN];
static int   epfd, listen_fd;

/* =====================================================================
 * SHA-1 + Base64 (RFC 6455 handshake)
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
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t i = 0;
    while (i + 64 <= len) { sha1_block(h, msg + i); i += 64; }
    uint8_t blk[64] = {0};
    size_t rem = len - i;
    memcpy(blk, msg + i, rem);
    blk[rem] = 0x80;
    if (rem >= 56) { sha1_block(h, blk); memset(blk, 0, 64); }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) blk[56 + j] = (uint8_t)(bits >> (56 - 8*j));
    sha1_block(h, blk);
    for (int j = 0; j < 5; j++) {
        out[4*j  ] = (uint8_t)(h[j] >> 24); out[4*j+1] = (uint8_t)(h[j] >> 16);
        out[4*j+2] = (uint8_t)(h[j] >>  8); out[4*j+3] = (uint8_t) h[j];
    }
}
static const char B64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64_encode(const uint8_t *in, int n, char *out) {
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        v |= (i + 1 < n) ? ((uint32_t)in[i+1] << 8) : 0;
        v |= (i + 2 < n) ?  (uint32_t)in[i+2]       : 0;
        out[o++] = B64[(v >> 18) & 63]; out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? B64[v & 63]        : '=';
    }
    return o;
}

/* =====================================================================
 * JSON helpers
 * =================================================================== */
static int json_quote(char *dst, int cap, const char *s, int n) {
    if (cap < 2) return -1;
    int o = 0; dst[o++] = '"';
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            if (o + 3 > cap) return -1;
            dst[o++] = '\\'; dst[o++] = (char)c;
        } else if (c == '\n') { if (o+3>cap) return -1; dst[o++]='\\'; dst[o++]='n'; }
        else if (c == '\r')   { if (o+3>cap) return -1; dst[o++]='\\'; dst[o++]='r'; }
        else if (c == '\t')   { if (o+3>cap) return -1; dst[o++]='\\'; dst[o++]='t'; }
        else if (c < 0x20) {
            if (o + 7 > cap) return -1;
            static const char H[] = "0123456789abcdef";
            dst[o++]='\\'; dst[o++]='u'; dst[o++]='0'; dst[o++]='0';
            dst[o++]=H[c>>4]; dst[o++]=H[c&15];
        } else { if (o+2>cap) return -1; dst[o++] = (char)c; }
    }
    dst[o++] = '"';
    return o;
}

/* Minimal JSON string-field extractor.
 * Finds: "key" : "value"  in src[0..len). Decodes a small set of escapes.
 * Writes up to out_cap-1 chars + NUL into out. Returns 0 on success. */
static int json_get_string(const char *src, int len, const char *key,
                           char *out, int out_cap) {
    int klen = (int)strlen(key);
    for (int i = 0; i + klen + 2 < len; i++) {
        if (src[i] != '"') continue;
        if (i + 1 + klen + 1 > len) break;
        if (memcmp(src + i + 1, key, klen) != 0) continue;
        if (src[i + 1 + klen] != '"') continue;
        int j = i + 2 + klen;
        while (j < len && (src[j] == ' ' || src[j] == '\t')) j++;
        if (j >= len || src[j] != ':') continue;
        j++;
        while (j < len && (src[j] == ' ' || src[j] == '\t')) j++;
        if (j >= len || src[j] != '"') return -1;
        j++;
        int o = 0;
        while (j < len && src[j] != '"') {
            if (o + 1 >= out_cap) return -1;
            if (src[j] == '\\' && j + 1 < len) {
                char e = src[j+1];
                if      (e == 'n')  out[o++] = '\n';
                else if (e == 'r')  out[o++] = '\r';
                else if (e == 't')  out[o++] = '\t';
                else if (e == '"')  out[o++] = '"';
                else if (e == '\\') out[o++] = '\\';
                else if (e == '/')  out[o++] = '/';
                else                out[o++] = e;
                j += 2;
            } else {
                out[o++] = src[j++];
            }
        }
        out[o] = 0;
        return 0;
    }
    return -1;
}

/* =====================================================================
 * Slot mgmt / drop
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
    free(clients[i].resp);
    memset(&clients[i], 0, sizeof clients[i]);
    clients[i].fd = -1;
    clients[i].req_head_end = -1;
}

/* =====================================================================
 * Epoll event update
 * =================================================================== */
static void epoll_mod(int i, uint32_t events) {
    struct epoll_event ev = { .events = events, .data = { .u32 = (uint32_t)i } };
    epoll_ctl(epfd, EPOLL_CTL_MOD, clients[i].fd, &ev);
}

/* =====================================================================
 * WS send (server -> client)
 * =================================================================== */
static void ws_send_text(int i, const char *payload, int n) {
    if (clients[i].fd < 0 || n < 0) return;
    uint8_t hdr[4]; int hl;
    if (n < 126) { hdr[0]=0x81; hdr[1]=(uint8_t)n; hl=2; }
    else if (n <= 0xFFFF) {
        hdr[0]=0x81; hdr[1]=126;
        hdr[2]=(uint8_t)(n>>8); hdr[3]=(uint8_t)(n&0xFF); hl=4;
    } else return;
    struct iovec iov[2] = { { hdr, (size_t)hl }, { (void*)payload, (size_t)n } };
    struct msghdr mh = { 0 }; mh.msg_iov = iov; mh.msg_iovlen = 2;
    if (sendmsg(clients[i].fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT) < 0
        && errno != EAGAIN && errno != EWOULDBLOCK) drop(i);
}

static void broadcast_except(int from, const char *payload, int n) {
    for (int j = 0; j < MAX_CLIENTS; j++) {
        if (j == from) continue;
        if (clients[j].fd < 0 || clients[j].state != ST_OPEN) continue;
        ws_send_text(j, payload, n);
    }
}

/* =====================================================================
 * Chat broadcast logic
 * =================================================================== */
static void announce_join(int i) {
    int off = snprintf(msgbuf, sizeof msgbuf, "{\"event\":\"join\",\"name\":");
    int qn = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 1,
                        clients[i].name, clients[i].name_len);
    if (qn < 0) return;
    off += qn; msgbuf[off++] = '}';
    broadcast_except(i, msgbuf, off);
    db_log_event("join", clients[i].name, clients[i].name_len);
}
static void announce_leave(int i) {
    if (clients[i].state != ST_OPEN) return;
    int off = snprintf(msgbuf, sizeof msgbuf, "{\"event\":\"leave\",\"name\":");
    int qn = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 1,
                        clients[i].name, clients[i].name_len);
    if (qn < 0) return;
    off += qn; msgbuf[off++] = '}';
    broadcast_except(i, msgbuf, off);
    db_log_event("leave", clients[i].name, clients[i].name_len);
}

static void on_text_message(int i, const char *p, int n) {
    while (n > 0 && (p[n-1]=='\r' || p[n-1]=='\n' || p[n-1]==' ')) n--;
    while (n > 0 && p[0] == ' ') { p++; n--; }

    if (clients[i].state == ST_NAMING) {
        if (n == 0) return;
        if (n > NAME_MAX_LEN) n = NAME_MAX_LEN;
        memcpy(clients[i].name, p, n);
        clients[i].name[n] = 0;
        clients[i].name_len = (uint8_t)n;
        clients[i].state = ST_OPEN;
        announce_join(i);
        const char *w = "{\"event\":\"welcome\"}";
        ws_send_text(i, w, (int)strlen(w));
        return;
    }
    if (n == 0) return;

    int off = snprintf(msgbuf, sizeof msgbuf, "{\"from\":");
    int q1 = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 16,
                        clients[i].name, clients[i].name_len);
    if (q1 < 0) return;
    off += q1;
    off += snprintf(msgbuf + off, sizeof msgbuf - off, ",\"msg\":");
    int q2 = json_quote(msgbuf + off, (int)sizeof msgbuf - off - 2, p, n);
    if (q2 < 0) return;
    off += q2; msgbuf[off++] = '}';
    broadcast_except(i, msgbuf, off);
    db_log_msg(clients[i].name, clients[i].name_len, p, n);
}

/* =====================================================================
 * WS frame parser (post-upgrade)
 * =================================================================== */
static int parse_header_byte(int i, uint8_t b) {
    struct ws_client *c = &clients[i];
    switch (c->fr_hdr_bytes) {
    case 0:
        if (!(b & 0x80)) return -1;
        if (b & 0x70)    return -1;
        c->fr_opcode = b & 0x0F;
        c->fr_hdr_bytes = 1; return 0;
    case 1: {
        if (!(b & 0x80)) return -1;
        uint8_t len = b & 0x7F;
        if (len == 127) return -1;
        if (len == 126) { c->fr_payload_total = 0; c->fr_hdr_bytes = 2; }
        else            { c->fr_payload_total = len; c->fr_hdr_bytes = 4; }
        return 0;
    }
    case 2: c->fr_payload_total = (uint16_t)b << 8; c->fr_hdr_bytes = 3; return 0;
    case 3:
        c->fr_payload_total |= b;
        if (c->fr_payload_total > MAX_PAYLOAD) return -1;
        c->fr_hdr_bytes = 4; return 0;
    case 4: case 5: case 6: case 7:
        c->mask[c->fr_hdr_bytes - 4] = b;
        c->fr_hdr_bytes++;
        if (c->fr_hdr_bytes == 8) {
            c->fr_payload_seen = 0;
            if (c->fr_payload_total > MAX_PAYLOAD) return -1;
            return 1;
        }
        return 0;
    }
    return -1;
}
static void dispatch_frame(int i, const char *payload, int n) {
    struct ws_client *c = &clients[i];
    switch (c->fr_opcode) {
    case 0x1: on_text_message(i, payload, n); break;
    case 0x8: announce_leave(i); drop(i); return;
    case 0x9: {
        uint8_t hdr[2] = { 0x8A, (uint8_t)n };
        struct iovec iov[2] = { { hdr, 2 }, { (void*)payload, (size_t)n } };
        struct msghdr mh = { 0 }; mh.msg_iov = iov; mh.msg_iovlen = 2;
        sendmsg(clients[i].fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
        break;
    }
    case 0xA: break;
    default:  drop(i); return;
    }
    c->fr_hdr_bytes = 0; c->fr_opcode = 0;
    c->fr_payload_total = 0; c->fr_payload_seen = 0;
}
static int feed_frames(int i, const uint8_t *data, int n) {
    struct ws_client *c = &clients[i];
    int p = 0;
    while (p < n) {
        while (c->fr_hdr_bytes < 8 && p < n) {
            int r = parse_header_byte(i, data[p++]);
            if (r < 0) return -1;
        }
        if (c->fr_hdr_bytes < 8) return 0;
        int need = (int)c->fr_payload_total - (int)c->fr_payload_seen;
        int have = n - p;
        if (need == 0) { dispatch_frame(i, NULL, 0); continue; }
        if (c->fr_payload_seen == 0 && have >= need) {
            uint8_t *q = (uint8_t*)data + p;
            for (int k = 0; k < need; k++) q[k] ^= c->mask[k & 3];
            dispatch_frame(i, (char*)q, need);
            p += need;
        } else {
            int take = have < need ? have : need;
            if (c->fr_payload_seen + take > (int)sizeof c->ws_partial) return -1;
            for (int k = 0; k < take; k++)
                c->ws_partial[c->fr_payload_seen + k] =
                    data[p + k] ^ c->mask[(c->fr_payload_seen + k) & 3];
            c->fr_payload_seen += take;
            p += take;
            if (c->fr_payload_seen == c->fr_payload_total)
                dispatch_frame(i, (char*)c->ws_partial, c->fr_payload_total);
            else return 0;
        }
    }
    return 0;
}

/* =====================================================================
 * Response queueing — owns heap memory; caller passes ownership.
 * =================================================================== */
static void queue_response(int i, uint8_t *resp, size_t len, int close_after) {
    clients[i].resp = resp;
    clients[i].resp_len = len;
    clients[i].resp_sent = 0;
    clients[i].close_after_send = (uint8_t)(close_after ? 1 : 0);
    clients[i].state = ST_SENDING;
    epoll_mod(i, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
}

static void flush_response(int i) {
    struct ws_client *c = &clients[i];
    while (c->resp_sent < c->resp_len) {
        ssize_t w = send(c->fd, c->resp + c->resp_sent,
                         c->resp_len - c->resp_sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0) { c->resp_sent += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        drop(i); return;
    }
    /* Fully sent */
    free(c->resp); c->resp = NULL; c->resp_len = 0; c->resp_sent = 0;
    if (c->close_after_send) { drop(i); return; }
    /* Otherwise this was the WS 101 — go back to read-only and become WS. */
    epoll_mod(i, EPOLLIN | EPOLLRDHUP);
}

/* =====================================================================
 * HTTP response builders
 * =================================================================== */
static void send_simple(int i, int status, const char *reason,
                        const char *ctype, const char *body, size_t body_len) {
    /* Build response into heap buffer. */
    size_t hdr_room = 256 + (ctype ? strlen(ctype) : 0) + (reason ? strlen(reason) : 0);
    size_t cap = hdr_room + body_len;
    uint8_t *buf = malloc(cap);
    if (!buf) { drop(i); return; }
    int hl = snprintf((char*)buf, hdr_room,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: content-type\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "\r\n",
        status, reason, ctype, body_len);
    if (hl < 0 || (size_t)hl >= hdr_room) { free(buf); drop(i); return; }
    if (body_len) memcpy(buf + hl, body, body_len);
    queue_response(i, buf, (size_t)hl + body_len, /*close_after=*/1);
}

static void send_json(int i, int status, const char *json) {
    send_simple(i, status, status == 200 ? "OK" : "Error",
                "application/json", json, strlen(json));
}
static void send_error(int i, int status, const char *err_msg) {
    char body[256];
    int n = snprintf(body, sizeof body, "{\"error\":\"%s\"}", err_msg);
    send_simple(i, status, "Error", "application/json", body, (size_t)n);
}
static void send_204_cors(int i) {
    send_simple(i, 204, "No Content", "text/plain", "", 0);
}
static void send_not_found(int i) {
    send_simple(i, 404, "Not Found", "text/plain", "not found\n", 10);
}

/* =====================================================================
 * Header lookup utilities (case-insensitive)
 * =================================================================== */
static int hdr_match(const char *line, int line_len, const char *name) {
    int nl = (int)strlen(name);
    if (line_len < nl + 1) return 0;
    for (int i = 0; i < nl; i++)
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i]))
            return 0;
    return line[nl] == ':';
}
static const char *hdr_value(const char *line, int line_len, const char *name, int *out_len) {
    int nl = (int)strlen(name);
    int j = nl + 1;
    while (j < line_len && (line[j] == ' ' || line[j] == '\t')) j++;
    int end = line_len;
    while (end > j && (line[end-1] == ' ' || line[end-1] == '\t' || line[end-1] == '\r')) end--;
    *out_len = end - j;
    return line + j;
}
static int hdr_value_contains(const char *v, int vlen, const char *needle) {
    int nl = (int)strlen(needle);
    for (int i = 0; i + nl <= vlen; i++) {
        int ok = 1;
        for (int k = 0; k < nl; k++)
            if (tolower((unsigned char)v[i+k]) != tolower((unsigned char)needle[k])) { ok = 0; break; }
        if (ok) return 1;
    }
    return 0;
}

/* =====================================================================
 * Request parsing
 *
 * On entry: req_buf[0..req_len) contains all bytes read so far.
 * If "\r\n\r\n" not present yet, returns 0 (need more).
 * If headers complete but Content-Length body still incoming, returns 0.
 * If full request available, returns 1 and fills out_* refs.
 * On malformed request, returns -1.
 * =================================================================== */
static int parse_request(int i,
                         char **out_method, int *out_method_len,
                         char **out_path,   int *out_path_len,
                         char **out_body,   int *out_body_len,
                         int *out_is_ws_upgrade,
                         char *out_wskey, int wskey_cap,
                         char *out_bearer, int bearer_cap) {
    struct ws_client *c = &clients[i];
    if (c->req_head_end < 0) {
        /* search for "\r\n\r\n" */
        for (int k = 0; k + 3 < c->req_len; k++) {
            if (c->req_buf[k]=='\r' && c->req_buf[k+1]=='\n'
             && c->req_buf[k+2]=='\r' && c->req_buf[k+3]=='\n') {
                c->req_head_end = k + 4;
                break;
            }
        }
        if (c->req_head_end < 0) {
            if (c->req_len >= REQ_BUF_LEN - 1) return -1;
            return 0;
        }
    }
    int head_end = c->req_head_end;
    /* Parse request line */
    char *buf = (char*)c->req_buf;
    int line_end = 0;
    while (line_end < head_end - 1 && !(buf[line_end]=='\r' && buf[line_end+1]=='\n')) line_end++;
    if (line_end >= head_end - 1) return -1;

    /* METHOD SP PATH SP HTTP/x */
    int sp1 = 0; while (sp1 < line_end && buf[sp1] != ' ') sp1++;
    if (sp1 >= line_end) return -1;
    int sp2 = sp1 + 1; while (sp2 < line_end && buf[sp2] != ' ') sp2++;
    if (sp2 >= line_end) return -1;
    *out_method = buf; *out_method_len = sp1;
    *out_path = buf + sp1 + 1; *out_path_len = sp2 - sp1 - 1;

    /* Walk headers */
    int hdr_start = line_end + 2;
    int has_upgrade_ws = 0, has_connection_upgrade = 0;
    if (out_wskey && wskey_cap) out_wskey[0] = 0;
    if (out_bearer && bearer_cap) out_bearer[0] = 0;
    c->req_content_length = 0;

    while (hdr_start < head_end - 2) {
        int le = hdr_start;
        while (le < head_end - 1 && !(buf[le]=='\r' && buf[le+1]=='\n')) le++;
        if (le == hdr_start) break;
        int hl = le - hdr_start;
        char *line = buf + hdr_start;
        if (hdr_match(line, hl, "Upgrade")) {
            int vl; const char *v = hdr_value(line, hl, "Upgrade", &vl);
            if (hdr_value_contains(v, vl, "websocket")) has_upgrade_ws = 1;
        } else if (hdr_match(line, hl, "Connection")) {
            int vl; const char *v = hdr_value(line, hl, "Connection", &vl);
            if (hdr_value_contains(v, vl, "Upgrade")) has_connection_upgrade = 1;
        } else if (hdr_match(line, hl, "Sec-WebSocket-Key") && out_wskey) {
            int vl; const char *v = hdr_value(line, hl, "Sec-WebSocket-Key", &vl);
            if (vl > 0 && vl < wskey_cap) { memcpy(out_wskey, v, vl); out_wskey[vl] = 0; }
        } else if (hdr_match(line, hl, "Sec-WebSocket-Protocol") && out_bearer) {
            int vl; const char *v = hdr_value(line, hl, "Sec-WebSocket-Protocol", &vl);
            /* may be "bearer.<token>" possibly comma-separated */
            for (int k = 0; k + 7 <= vl; k++) {
                if ((k == 0 || v[k-1] == ' ' || v[k-1] == ',')
                    && tolower((unsigned char)v[k])=='b'
                    && memcmp(v+k, "bearer.", 7) == 0) {
                    int q = k + 7;
                    int qe = q;
                    while (qe < vl && v[qe] != ',' && v[qe] != ' ') qe++;
                    int tl = qe - q;
                    if (tl > 0 && tl < bearer_cap) {
                        memcpy(out_bearer, v + q, tl); out_bearer[tl] = 0;
                    }
                    break;
                }
            }
        } else if (hdr_match(line, hl, "Content-Length")) {
            int vl; const char *v = hdr_value(line, hl, "Content-Length", &vl);
            int cl = 0;
            for (int k = 0; k < vl && isdigit((unsigned char)v[k]); k++)
                cl = cl * 10 + (v[k] - '0');
            c->req_content_length = cl;
        }
        hdr_start = le + 2;
    }
    *out_is_ws_upgrade = (has_upgrade_ws && has_connection_upgrade) ? 1 : 0;

    /* Body */
    int body_have = c->req_len - head_end;
    int body_need = c->req_content_length;
    if (body_need > MAX_BODY_LEN) return -1;
    if (body_have < body_need) {
        if (head_end + body_need > REQ_BUF_LEN) return -1;
        return 0;
    }
    *out_body = buf + head_end;
    *out_body_len = body_need;
    return 1;
}

/* =====================================================================
 * Send WS 101 with optional subprotocol echo. Does NOT close after send.
 * =================================================================== */
static void send_ws_handshake(int i, const char *wskey, const char *bearer_echo) {
    char concat[256];
    int kl = (int)strlen(wskey);
    if (kl > 200) { drop(i); return; }
    memcpy(concat, wskey, kl);
    memcpy(concat + kl, WS_MAGIC, 36);
    uint8_t hash[20];
    sha1((const uint8_t*)concat, kl + 36, hash);
    char accept[40];
    int al = b64_encode(hash, 20, accept);
    accept[al] = 0;

    char hdr[512];
    int n;
    if (bearer_echo && *bearer_echo) {
        n = snprintf(hdr, sizeof hdr,
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "Sec-WebSocket-Protocol: bearer.%s\r\n"
            "\r\n", accept, bearer_echo);
    } else {
        n = snprintf(hdr, sizeof hdr,
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n", accept);
    }
    if (n < 0 || n >= (int)sizeof hdr) { drop(i); return; }
    uint8_t *buf = malloc((size_t)n);
    if (!buf) { drop(i); return; }
    memcpy(buf, hdr, (size_t)n);
    queue_response(i, buf, (size_t)n, /*close_after=*/0);
}

/* =====================================================================
 * Route dispatch
 * =================================================================== */
static int path_eq(const char *p, int n, const char *s) {
    int sl = (int)strlen(s);
    return n == sl && memcmp(p, s, sl) == 0;
}
static int path_starts(const char *p, int n, const char *s) {
    int sl = (int)strlen(s);
    return n >= sl && memcmp(p, s, sl) == 0;
}
static int parse_query_int(const char *p, int n, const char *key, int dflt) {
    int kl = (int)strlen(key);
    for (int i = 0; i + kl + 1 < n; i++) {
        if ((i == 0 || p[i-1] == '?' || p[i-1] == '&')
            && memcmp(p + i, key, kl) == 0 && p[i + kl] == '=') {
            int v = 0, j = i + kl + 1;
            while (j < n && isdigit((unsigned char)p[j])) v = v*10 + (p[j++] - '0');
            return v;
        }
    }
    return dflt;
}

static void route_register_or_login(int i, int is_register,
                                    const char *body, int body_len) {
    char user[64], pass[160];
    if (json_get_string(body, body_len, "username", user, sizeof user) < 0
     || json_get_string(body, body_len, "password", pass, sizeof pass) < 0) {
        send_error(i, 400, "username and password required");
        return;
    }
    if (is_register) {
        if (db_user_create(user, pass) < 0) {
            send_error(i, 400, "could not create user (exists or invalid)");
            return;
        }
    } else {
        if (db_user_check(user, pass) < 0) {
            send_error(i, 401, "invalid credentials");
            return;
        }
    }
    char tok[65];
    if (db_session_create(user, tok) < 0) {
        send_error(i, 500, "session create failed");
        return;
    }
    char body_out[256];
    int n = snprintf(body_out, sizeof body_out,
                     "{\"token\":\"%s\",\"username\":\"%s\"}", tok, user);
    send_json(i, 200, body_out);
    (void)n;
}
static void route_logout(int i, const char *body, int body_len) {
    char tok[80];
    if (json_get_string(body, body_len, "token", tok, sizeof tok) == 0)
        db_session_delete(tok);
    send_json(i, 200, "{}");
}
static void route_history(int i, const char *path, int path_len) {
    int limit = parse_query_int(path, path_len, "limit", 100);
    char *js = db_history_json(limit);
    if (!js) { send_json(i, 200, "[]"); return; }
    send_simple(i, 200, "OK", "application/json", js, strlen(js));
    free(js);
}
static void route_index(int i) {
    send_simple(i, 200, "OK", "text/html; charset=utf-8",
                (const char*)INDEX_HTML, (size_t)INDEX_HTML_len);
}

/* =====================================================================
 * Once the full HTTP request is in the buffer, dispatch.
 * =================================================================== */
static void dispatch_request(int i) {
    char *method, *path, *body;
    int method_len, path_len, body_len;
    int is_ws = 0;
    char wskey[64], bearer[80];
    int r = parse_request(i, &method, &method_len, &path, &path_len,
                          &body, &body_len, &is_ws, wskey, sizeof wskey,
                          bearer, sizeof bearer);
    if (r < 0) { send_error(i, 400, "bad request"); return; }
    if (r == 0) return;

    int is_get  = method_len == 3 && memcmp(method, "GET",  3) == 0;
    int is_post = method_len == 4 && memcmp(method, "POST", 4) == 0;
    int is_opts = method_len == 7 && memcmp(method, "OPTIONS", 7) == 0;

    /* Bytes after the request (incl. body) that arrived early — for WS,
     * any extra after head+body belongs to the first frame. */
    struct ws_client *c = &clients[i];
    int consumed = c->req_head_end + c->req_content_length;
    int extra = c->req_len - consumed;

    if (is_ws) {
        if (!wskey[0]) { send_error(i, 400, "missing Sec-WebSocket-Key"); return; }
        char username[NAME_MAX_LEN + 1] = {0};
        const char *echo = NULL;
        if (bearer[0] && db_session_lookup(bearer, username, sizeof username) == 0) {
            int ul = (int)strlen(username);
            if (ul > NAME_MAX_LEN) ul = NAME_MAX_LEN;
            memcpy(c->name, username, ul); c->name[ul] = 0;
            c->name_len = (uint8_t)ul;
            c->has_token = 1;
            echo = bearer;
        }
        send_ws_handshake(i, wskey, echo);
        /* Post-send state will be: ST_OPEN if we have a name, ST_NAMING otherwise.
         * We can't set it until flush completes, but it's simpler to set immediately
         * since flush only changes ST_SENDING -> back; record the post-flush state
         * in close_after_send=0 and use has_token + name_len to decide later. */
        /* Save any extra bytes as the start of the first WS frame, post-flush. */
        if (extra > 0) {
            /* shift remaining bytes to start of req_buf to reuse later */
            memmove(c->req_buf, c->req_buf + consumed, extra);
            c->req_len = (uint16_t)extra;
        } else {
            c->req_len = 0;
        }
        c->req_head_end = -1;
        c->req_content_length = 0;
        return;
    }

    /* Plain HTTP */
    if (is_opts) { send_204_cors(i); return; }
    if (is_get && (path_eq(path, path_len, "/") ||
                   path_eq(path, path_len, "/index.html") ||
                   path_starts(path, path_len, "/?"))) {
        route_index(i); return;
    }
    if (is_get && path_starts(path, path_len, "/api/history")) {
        route_history(i, path, path_len); return;
    }
    if (is_post && path_eq(path, path_len, "/api/register")) {
        route_register_or_login(i, 1, body, body_len); return;
    }
    if (is_post && path_eq(path, path_len, "/api/login")) {
        route_register_or_login(i, 0, body, body_len); return;
    }
    if (is_post && path_eq(path, path_len, "/api/logout")) {
        route_logout(i, body, body_len); return;
    }
    send_not_found(i);
}

/* =====================================================================
 * After 101 handshake send completes, transition the WS client to its
 * post-upgrade state and drain any pre-buffered frame bytes.
 * =================================================================== */
static void after_ws_handshake(int i) {
    struct ws_client *c = &clients[i];
    if (c->has_token && c->name_len > 0) {
        c->state = ST_OPEN;
        announce_join(i);
        const char *w = "{\"event\":\"welcome\"}";
        ws_send_text(i, w, (int)strlen(w));
    } else {
        c->state = ST_NAMING;
    }
    if (c->req_len > 0) {
        if (feed_frames(i, c->req_buf, c->req_len) < 0) {
            announce_leave(i); drop(i); return;
        }
        c->req_len = 0;
    }
}

/* =====================================================================
 * Read handler
 * =================================================================== */
static void on_readable(int i) {
    struct ws_client *c = &clients[i];
    for (;;) {
        if (c->state == ST_REQ) {
            int room = REQ_BUF_LEN - c->req_len;
            if (room <= 0) { send_error(i, 413, "request too large"); return; }
            ssize_t r = recv(c->fd, c->req_buf + c->req_len, (size_t)room, 0);
            if (r == 0) { drop(i); return; }
            if (r <  0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                drop(i); return;
            }
            c->req_len += (uint16_t)r;
            dispatch_request(i);
            return;  /* either queued response or waiting for more data */
        } else if (c->state == ST_OPEN || c->state == ST_NAMING) {
            ssize_t r = recv(c->fd, readbuf, sizeof readbuf, 0);
            if (r == 0) { announce_leave(i); drop(i); return; }
            if (r <  0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                announce_leave(i); drop(i); return;
            }
            if (feed_frames(i, (uint8_t*)readbuf, (int)r) < 0) {
                announce_leave(i); drop(i); return;
            }
        } else {
            /* ST_SENDING — ignore until writable transitions us back. */
            return;
        }
    }
}

/* =====================================================================
 * Write handler
 * =================================================================== */
static void on_writable(int i) {
    struct ws_client *c = &clients[i];
    if (c->state != ST_SENDING) {
        epoll_mod(i, EPOLLIN | EPOLLRDHUP);
        return;
    }
    size_t was_unsent = c->resp_len - c->resp_sent;
    flush_response(i);
    if (c->fd < 0) return;
    if (c->resp == NULL && was_unsent > 0 && !c->close_after_send) {
        /* WS handshake just finished sending — promote to WS. */
        after_ws_handshake(i);
    }
    /* If close_after_send was true, drop() already happened in flush. */
}

/* =====================================================================
 * Accept
 * =================================================================== */
static void accept_new(void) {
    for (;;) {
        struct sockaddr_in sa; socklen_t sl = sizeof sa;
        int fd = accept4(listen_fd, (struct sockaddr*)&sa, &sl, SOCK_NONBLOCK);
        if (fd < 0) return;
        int slot = find_free_slot();
        if (slot < 0) { close(fd); continue; }

        memset(&clients[slot], 0, sizeof clients[slot]);
        clients[slot].fd = fd;
        clients[slot].state = ST_REQ;
        clients[slot].req_head_end = -1;

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

    for (int i = 0; i < MAX_CLIENTS; i++) { clients[i].fd = -1; clients[i].req_head_end = -1; }

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
    struct epoll_event lev = { .events = EPOLLIN, .data = { .u32 = LISTEN_SLOT } };
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &lev);

    fprintf(stderr, "ws_chat64k: http+ws://0.0.0.0:%d  (max %d clients)\n",
            port, MAX_CLIENTS);

    struct epoll_event evs[EPOLL_BATCH];
    for (;;) {
        int n = epoll_wait(epfd, evs, EPOLL_BATCH, -1);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); return 1; }
        for (int k = 0; k < n; k++) {
            uint32_t slot = evs[k].data.u32;
            if (slot == LISTEN_SLOT) { accept_new(); continue; }
            if (evs[k].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) {
                announce_leave((int)slot); drop((int)slot); continue;
            }
            if (evs[k].events & EPOLLOUT) on_writable((int)slot);
            if (clients[slot].fd >= 0 && (evs[k].events & EPOLLIN))
                on_readable((int)slot);
        }
    }
}
