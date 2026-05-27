# Build / Run

**Always use `make`.** Never invoke `gcc`, `cc`, `docker build`, or `docker run` directly. Never suggest one-off compile commands. If a flag or step is missing, add it to the `Makefile` — do not bypass it.

Targets:

- `make` — native build (Linux only, requires `libpq-dev`).
- `make run` — Docker run, foreground, interactive. Reads `.env`, port from `PORT` in `.env` (fallback 5555). **Default for local dev.**
- `make run-detached` — same, backgrounded.
- `make logs` / `make stop` — tail / kill the detached container.
- `make run-native` — native build + run (Linux only).
- `make docker-build` — build image only.
- `make clean` — remove binary.

## Local dev on macOS

`sys/epoll.h` is Linux-only. Do not attempt native builds on macOS. Use `make run`.

## Env

`DATABASE_URL` and `PORT` come from `.env` (see `.env.example`). `.env` is gitignored. Do not hardcode credentials anywhere else.

## Deploy

- C server: Linux host (Fly.io / Railway / VPS). Vercel cannot host it.
- Static client (`public/`): Vercel via `vercel.json`.
