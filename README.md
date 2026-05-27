# ws_chat64k

C epoll WebSocket chat server + Postgres persistence + Vercel-hosted static client.

## Layout

- `ws_chat64k.c`, `db.c`, `db.h` — Linux WS server with libpq writes.
- `schema.sql` — PG tables (auto-created on startup too).
- `.env.example` — copy to `.env`, fill `DATABASE_URL`.
- `public/index.html` — static client, deployed to Vercel.
- `vercel.json` — serves `public/` at site root.

## Server (deploy on Fly.io / Railway / VPS — NOT Vercel)

Vercel cannot host persistent WS sockets or C runtimes. Run the C server elsewhere.

Build (Linux):
```
sudo apt-get install -y libpq-dev
make
```

Run:
```
cp .env.example .env   # set DATABASE_URL
./ws_chat64k           # listens on $PORT or 5555
```

DB tables auto-created. If `DATABASE_URL` is unset, server runs without persistence.

Front it with TLS-terminating reverse proxy (Caddy/nginx) for `wss://`.

## Client (Vercel)

```
vercel --prod
```

Static deploy of `public/`. Client picks WS URL from `?ws=wss://host/...` query or localStorage, fallback `wss://<vercel-host>/ws` (proxy that to your server) or `ws://localhost:5555` in dev.

## Schema

`chat_messages(id, ts, sender, body)` — every text frame.
`chat_events(id, ts, event, name)` — join/leave.
