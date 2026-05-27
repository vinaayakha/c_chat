#ifndef DB_H
#define DB_H

#include <stddef.h>

void db_init(void);
void db_close(void);
int  db_ready(void);

/* Chat persistence. from/msg NOT null-terminated. */
void db_log_msg(const char *from, int from_len, const char *msg, int msg_len);
void db_log_event(const char *event, const char *name, int name_len);

/* Returns malloc'd JSON array string of recent messages, oldest first.
 * Caller frees. Returns NULL on error or db disabled. */
char *db_history_json(int limit);

/* Auth.
 * username/password: C strings.
 * Returns 0 on success, -1 on error (already exists, db down, bad input). */
int  db_user_create(const char *username, const char *password);

/* Returns 0 if username+password matches, -1 otherwise. */
int  db_user_check(const char *username, const char *password);

/* Creates a session for username with 7-day expiry.
 * Writes hex token (64 chars + NUL) to out_token (must be >=65 bytes).
 * Returns 0 on success. */
int  db_session_create(const char *username, char *out_token);

/* Looks up session; if valid, copies username into out_username (max out_cap).
 * Returns 0 on success, -1 if no such valid session. */
int  db_session_lookup(const char *token, char *out_username, size_t out_cap);

int  db_session_delete(const char *token);

#endif
