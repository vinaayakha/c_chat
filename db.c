/* Enable GNU extensions (setenv with overwrite=0 semantics, getline, etc).
 * Must precede any system header. */
#define _GNU_SOURCE
#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <libpq-fe.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* PBKDF2-HMAC-SHA256 iteration count for password hashing. OWASP 2023
 * recommends >=600k for SHA-256; 100k chosen as a cheap-server compromise.
 * Raise this on faster hardware. Changing it does NOT invalidate existing
 * hashes only if iters are stored per-row — they aren't here, so a change
 * requires re-registering all users. */
#define PBKDF2_ITERS  100000

/* Per-user random salt length in bytes. 16 (128 bits) is well above the
 * NIST minimum and prevents rainbow-table reuse across users. */
#define PBKDF2_SALT    16

/* Derived key length in bytes. 32 = SHA-256 output size; using the native
 * digest length avoids unnecessary PBKDF2 block iterations. */
#define PBKDF2_HASH    32

/* Session token raw byte length from CSPRNG. Stored hex-encoded, so the
 * DB token column holds 2*SESSION_BYTES chars. 32 bytes = 256 bits of
 * entropy — well beyond brute-force reach. */
#define SESSION_BYTES  32

/* Session lifetime in seconds. Sessions expire absolutely (no sliding
 * renewal); after this the client must re-login. 7 days picked for a
 * chat client UX — short enough to limit stolen-token blast radius. */
#define SESSION_TTL_S  (7 * 24 * 3600)

static PGconn *conn = NULL;

static void load_dotenv(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = p, *v = eq + 1;
        size_t kl = strlen(k);
        while (kl && (k[kl-1] == ' ' || k[kl-1] == '\t')) k[--kl] = 0;
        size_t vl = strlen(v);
        while (vl && (v[vl-1] == '\n' || v[vl-1] == '\r'
                      || v[vl-1] == ' ' || v[vl-1] == '\t')) v[--vl] = 0;
        if (vl >= 2 && ((v[0]=='"' && v[vl-1]=='"') || (v[0]=='\'' && v[vl-1]=='\''))) {
            v[vl-1] = 0; v++;
        }
        if (!getenv(k)) setenv(k, v, 0);
    }
    fclose(f);
}

int db_ready(void) { return conn != NULL; }

void db_init(void) {
    load_dotenv(".env");
    const char *url = getenv("DATABASE_URL");
    if (!url || !*url) {
        fprintf(stderr, "db: DATABASE_URL not set, persistence disabled\n");
        return;
    }
    conn = PQconnectdb(url);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "db: connect failed: %s", PQerrorMessage(conn));
        PQfinish(conn); conn = NULL; return;
    }
    const char *ddl =
        "CREATE TABLE IF NOT EXISTS chat_messages ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  ts TIMESTAMPTZ NOT NULL DEFAULT now(),"
        "  sender TEXT NOT NULL,"
        "  body TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_chat_messages_ts ON chat_messages(ts DESC);"
        "CREATE TABLE IF NOT EXISTS chat_events ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  ts TIMESTAMPTZ NOT NULL DEFAULT now(),"
        "  event TEXT NOT NULL,"
        "  name TEXT);"
        "CREATE TABLE IF NOT EXISTS users ("
        "  username TEXT PRIMARY KEY,"
        "  pw_hash BYTEA NOT NULL,"
        "  pw_salt BYTEA NOT NULL,"
        "  created_at TIMESTAMPTZ NOT NULL DEFAULT now());"
        "CREATE TABLE IF NOT EXISTS sessions ("
        "  token TEXT PRIMARY KEY,"
        "  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,"
        "  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
        "  expires_at TIMESTAMPTZ NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);";
    PGresult *r = PQexec(conn, ddl);
    if (PQresultStatus(r) != PGRES_COMMAND_OK)
        fprintf(stderr, "db: ddl failed: %s", PQerrorMessage(conn));
    PQclear(r);
    fprintf(stderr, "db: connected, persistence enabled\n");
}

void db_close(void) { if (conn) { PQfinish(conn); conn = NULL; } }

static char *dup_n(const char *s, int n) {
    char *o = malloc(n + 1); if (!o) return NULL;
    memcpy(o, s, n); o[n] = 0; return o;
}

static void reset_if_dead(void) {
    if (conn && PQstatus(conn) == CONNECTION_BAD) PQreset(conn);
}

/* ===================================================================== */
/* Chat logging                                                          */
/* ===================================================================== */
void db_log_msg(const char *from, int from_len, const char *msg, int msg_len) {
    if (!conn) return;
    char *f = dup_n(from, from_len), *m = dup_n(msg, msg_len);
    if (!f || !m) { free(f); free(m); return; }
    const char *vals[2] = { f, m };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO chat_messages(sender, body) VALUES($1, $2)",
        2, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "db: insert msg: %s", PQerrorMessage(conn));
        reset_if_dead();
    }
    PQclear(r); free(f); free(m);
}

void db_log_event(const char *event, const char *name, int name_len) {
    if (!conn) return;
    char *n = name_len > 0 ? dup_n(name, name_len) : NULL;
    const char *vals[2] = { event, n };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO chat_events(event, name) VALUES($1, $2)",
        2, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "db: insert event: %s", PQerrorMessage(conn));
        reset_if_dead();
    }
    PQclear(r); free(n);
}

/* ===================================================================== */
/* History -> JSON                                                       */
/* ===================================================================== */
static int json_append_str(char **buf, size_t *cap, size_t *len, const char *s) {
    size_t n = strlen(s);
    /* worst case: every char -> \uXXXX = 6 + quotes */
    size_t need = *len + n * 6 + 3;
    if (need > *cap) {
        size_t nc = *cap ? *cap : 256;
        while (nc < need) nc *= 2;
        char *nb = realloc(*buf, nc);
        if (!nb) return -1;
        *buf = nb; *cap = nc;
    }
    char *o = *buf + *len;
    *o++ = '"';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\')       { *o++='\\'; *o++=c; }
        else if (c == '\n')              { *o++='\\'; *o++='n'; }
        else if (c == '\r')              { *o++='\\'; *o++='r'; }
        else if (c == '\t')              { *o++='\\'; *o++='t'; }
        else if (c < 0x20) {
            static const char H[] = "0123456789abcdef";
            *o++='\\'; *o++='u'; *o++='0'; *o++='0';
            *o++=H[c>>4]; *o++=H[c&15];
        } else *o++ = c;
    }
    *o++ = '"';
    *len = o - *buf;
    return 0;
}

static int json_append_raw(char **buf, size_t *cap, size_t *len, const char *s) {
    size_t n = strlen(s), need = *len + n + 1;
    if (need > *cap) {
        size_t nc = *cap ? *cap : 256;
        while (nc < need) nc *= 2;
        char *nb = realloc(*buf, nc);
        if (!nb) return -1;
        *buf = nb; *cap = nc;
    }
    memcpy(*buf + *len, s, n); *len += n; return 0;
}

char *db_history_json(int limit) {
    if (!conn) return NULL;
    if (limit <= 0 || limit > 1000) limit = 100;
    char lim_s[16]; snprintf(lim_s, sizeof lim_s, "%d", limit);
    const char *vals[1] = { lim_s };
    PGresult *r = PQexecParams(conn,
        "SELECT sender, body, to_char(ts at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') "
        "FROM (SELECT * FROM chat_messages ORDER BY id DESC LIMIT $1::int) t "
        "ORDER BY id ASC",
        1, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_TUPLES_OK) {
        fprintf(stderr, "db: history: %s", PQerrorMessage(conn));
        PQclear(r); reset_if_dead(); return NULL;
    }
    int n = PQntuples(r);
    char *buf = NULL; size_t cap = 0, len = 0;
    if (json_append_raw(&buf, &cap, &len, "[") < 0) goto fail;
    for (int i = 0; i < n; i++) {
        if (i && json_append_raw(&buf, &cap, &len, ",") < 0) goto fail;
        if (json_append_raw(&buf, &cap, &len, "{\"from\":") < 0) goto fail;
        if (json_append_str(&buf, &cap, &len, PQgetvalue(r, i, 0)) < 0) goto fail;
        if (json_append_raw(&buf, &cap, &len, ",\"msg\":") < 0) goto fail;
        if (json_append_str(&buf, &cap, &len, PQgetvalue(r, i, 1)) < 0) goto fail;
        if (json_append_raw(&buf, &cap, &len, ",\"ts\":") < 0) goto fail;
        if (json_append_str(&buf, &cap, &len, PQgetvalue(r, i, 2)) < 0) goto fail;
        if (json_append_raw(&buf, &cap, &len, "}") < 0) goto fail;
    }
    if (json_append_raw(&buf, &cap, &len, "]") < 0) goto fail;
    /* null-terminate */
    if (len + 1 > cap) { char *nb = realloc(buf, len + 1); if (!nb) goto fail; buf = nb; }
    buf[len] = 0;
    PQclear(r); return buf;
fail:
    free(buf); PQclear(r); return NULL;
}

/* ===================================================================== */
/* Auth                                                                   */
/* ===================================================================== */
static const char HEX[] = "0123456789abcdef";

static void to_hex(const unsigned char *in, int n, char *out) {
    for (int i = 0; i < n; i++) {
        out[2*i]   = HEX[in[i] >> 4];
        out[2*i+1] = HEX[in[i] & 15];
    }
    out[2*n] = 0;
}

static int pbkdf2(const char *password, const unsigned char *salt, int salt_len,
                  unsigned char *out, int out_len) {
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                             salt, salt_len, PBKDF2_ITERS, EVP_sha256(),
                             out_len, out) == 1 ? 0 : -1;
}

static int valid_username(const char *u) {
    if (!u || !*u) return 0;
    size_t n = strlen(u);
    if (n < 1 || n > 32) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = u[i];
        if (!(isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.')) return 0;
    }
    return 1;
}

int db_user_create(const char *username, const char *password) {
    if (!conn) return -1;
    if (!valid_username(username)) return -1;
    if (!password || strlen(password) < 4 || strlen(password) > 128) return -1;

    unsigned char salt[PBKDF2_SALT], hash[PBKDF2_HASH];
    if (RAND_bytes(salt, PBKDF2_SALT) != 1) return -1;
    if (pbkdf2(password, salt, PBKDF2_SALT, hash, PBKDF2_HASH) < 0) return -1;

    const char *vals[3] = { username, (const char*)hash, (const char*)salt };
    int      lens[3]    = { 0, PBKDF2_HASH, PBKDF2_SALT };
    int      fmts[3]    = { 0, 1, 1 };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO users(username, pw_hash, pw_salt) VALUES($1, $2, $3)",
        3, NULL, vals, lens, fmts, 0);
    int ok = PQresultStatus(r) == PGRES_COMMAND_OK ? 0 : -1;
    if (!ok) {} else fprintf(stderr, "db: user_create: %s", PQerrorMessage(conn));
    PQclear(r); reset_if_dead();
    return ok;
}

int db_user_check(const char *username, const char *password) {
    if (!conn || !valid_username(username) || !password) return -1;
    const char *vals[1] = { username };
    PGresult *r = PQexecParams(conn,
        "SELECT pw_hash, pw_salt FROM users WHERE username = $1",
        1, NULL, vals, NULL, NULL, 1);
    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1) {
        PQclear(r); reset_if_dead(); return -1;
    }
    int hl = PQgetlength(r, 0, 0), sl = PQgetlength(r, 0, 1);
    if (hl != PBKDF2_HASH || sl != PBKDF2_SALT) { PQclear(r); return -1; }
    unsigned char stored_h[PBKDF2_HASH], salt[PBKDF2_SALT], cmp[PBKDF2_HASH];
    memcpy(stored_h, PQgetvalue(r, 0, 0), PBKDF2_HASH);
    memcpy(salt,     PQgetvalue(r, 0, 1), PBKDF2_SALT);
    PQclear(r);
    if (pbkdf2(password, salt, PBKDF2_SALT, cmp, PBKDF2_HASH) < 0) return -1;
    /* constant-time compare */
    unsigned char d = 0;
    for (int i = 0; i < PBKDF2_HASH; i++) d |= stored_h[i] ^ cmp[i];
    return d == 0 ? 0 : -1;
}

int db_session_create(const char *username, char *out_token) {
    if (!conn || !valid_username(username) || !out_token) return -1;
    unsigned char raw[SESSION_BYTES];
    if (RAND_bytes(raw, SESSION_BYTES) != 1) return -1;
    char tok[2 * SESSION_BYTES + 1];
    to_hex(raw, SESSION_BYTES, tok);

    char ttl[32]; snprintf(ttl, sizeof ttl, "%d seconds", SESSION_TTL_S);
    const char *vals[3] = { tok, username, ttl };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO sessions(token, username, expires_at) "
        "VALUES($1, $2, now() + $3::interval)",
        3, NULL, vals, NULL, NULL, 0);
    int ok = PQresultStatus(r) == PGRES_COMMAND_OK ? 0 : -1;
    PQclear(r); reset_if_dead();
    if (ok == 0) memcpy(out_token, tok, sizeof tok);
    return ok;
}

int db_session_lookup(const char *token, char *out_username, size_t out_cap) {
    if (!conn || !token || !out_username || out_cap == 0) return -1;
    /* basic shape: 64 hex chars */
    size_t n = strlen(token);
    if (n != 2 * SESSION_BYTES) return -1;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)token[i])) return -1;

    const char *vals[1] = { token };
    PGresult *r = PQexecParams(conn,
        "SELECT username FROM sessions WHERE token = $1 AND expires_at > now()",
        1, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1) {
        PQclear(r); reset_if_dead(); return -1;
    }
    const char *u = PQgetvalue(r, 0, 0);
    size_t ul = strlen(u);
    if (ul + 1 > out_cap) { PQclear(r); return -1; }
    memcpy(out_username, u, ul + 1);
    PQclear(r);
    return 0;
}

int db_session_delete(const char *token) {
    if (!conn || !token) return -1;
    const char *vals[1] = { token };
    PGresult *r = PQexecParams(conn,
        "DELETE FROM sessions WHERE token = $1",
        1, NULL, vals, NULL, NULL, 0);
    int ok = PQresultStatus(r) == PGRES_COMMAND_OK ? 0 : -1;
    PQclear(r); reset_if_dead();
    return ok;
}
