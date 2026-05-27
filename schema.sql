CREATE TABLE IF NOT EXISTS chat_messages (
  id     BIGSERIAL PRIMARY KEY,
  ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender TEXT NOT NULL,
  body   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_ts ON chat_messages(ts DESC);

CREATE TABLE IF NOT EXISTS chat_events (
  id    BIGSERIAL PRIMARY KEY,
  ts    TIMESTAMPTZ NOT NULL DEFAULT now(),
  event TEXT NOT NULL,
  name  TEXT
);

CREATE TABLE IF NOT EXISTS users (
  username   TEXT PRIMARY KEY,
  pw_hash    BYTEA NOT NULL,
  pw_salt    BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
