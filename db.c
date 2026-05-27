#define _GNU_SOURCE
#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libpq-fe.h>

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
        char *k = p;
        char *v = eq + 1;
        size_t kl = strlen(k);
        while (kl && (k[kl-1] == ' ' || k[kl-1] == '\t')) k[--kl] = 0;
        size_t vl = strlen(v);
        while (vl && (v[vl-1] == '\n' || v[vl-1] == '\r'
                      || v[vl-1] == ' ' || v[vl-1] == '\t')) v[--vl] = 0;
        if (vl >= 2 && ((v[0] == '"' && v[vl-1] == '"')
                       || (v[0] == '\'' && v[vl-1] == '\''))) {
            v[vl-1] = 0; v++;
        }
        if (!getenv(k)) setenv(k, v, 0);
    }
    fclose(f);
}

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
        PQfinish(conn);
        conn = NULL;
        return;
    }
    const char *ddl =
        "CREATE TABLE IF NOT EXISTS chat_messages ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  ts TIMESTAMPTZ NOT NULL DEFAULT now(),"
        "  sender TEXT NOT NULL,"
        "  body TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS chat_events ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  ts TIMESTAMPTZ NOT NULL DEFAULT now(),"
        "  event TEXT NOT NULL,"
        "  name TEXT"
        ");";
    PGresult *r = PQexec(conn, ddl);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "db: ddl failed: %s", PQerrorMessage(conn));
    }
    PQclear(r);
    fprintf(stderr, "db: connected, persistence enabled\n");
}

static char *dup_n(const char *s, int n) {
    char *o = malloc(n + 1);
    if (!o) return NULL;
    memcpy(o, s, n);
    o[n] = 0;
    return o;
}

void db_log_msg(const char *from, int from_len, const char *msg, int msg_len) {
    if (!conn) return;
    char *f = dup_n(from, from_len);
    char *m = dup_n(msg, msg_len);
    if (!f || !m) { free(f); free(m); return; }
    const char *vals[2] = { f, m };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO chat_messages(sender, body) VALUES($1, $2)",
        2, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "db: insert msg failed: %s", PQerrorMessage(conn));
        if (PQstatus(conn) == CONNECTION_BAD) PQreset(conn);
    }
    PQclear(r);
    free(f); free(m);
}

void db_log_event(const char *event, const char *name, int name_len) {
    if (!conn) return;
    char *n = name_len > 0 ? dup_n(name, name_len) : NULL;
    const char *vals[2] = { event, n };
    PGresult *r = PQexecParams(conn,
        "INSERT INTO chat_events(event, name) VALUES($1, $2)",
        2, NULL, vals, NULL, NULL, 0);
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        fprintf(stderr, "db: insert event failed: %s", PQerrorMessage(conn));
        if (PQstatus(conn) == CONNECTION_BAD) PQreset(conn);
    }
    PQclear(r);
    free(n);
}

void db_close(void) {
    if (conn) { PQfinish(conn); conn = NULL; }
}
