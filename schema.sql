CREATE TABLE IF NOT EXISTS chat_messages (
  id     BIGSERIAL PRIMARY KEY,
  ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender TEXT NOT NULL,
  body   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_events (
  id    BIGSERIAL PRIMARY KEY,
  ts    TIMESTAMPTZ NOT NULL DEFAULT now(),
  event TEXT NOT NULL,
  name  TEXT
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_ts ON chat_messages(ts DESC);
