#ifndef DB_H
#define DB_H

/* Initialize PG connection from DATABASE_URL env. Loads .env if present.
 * On failure, logs to stderr and disables persistence (calls become no-ops). */
void db_init(void);

/* Persist a chat message. from/msg are NOT null-terminated. */
void db_log_msg(const char *from, int from_len, const char *msg, int msg_len);

/* Persist join/leave/welcome events. event is C string. */
void db_log_event(const char *event, const char *name, int name_len);

void db_close(void);

#endif
