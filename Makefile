CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
PKG     ?= pkg-config
PG_CFLAGS := $(shell $(PKG) --cflags libpq 2>/dev/null)
PG_LIBS   := $(shell $(PKG) --libs   libpq 2>/dev/null)
ifeq ($(strip $(PG_LIBS)),)
  PG_LIBS := -lpq
endif

BIN   := ws_chat64k
SRC   := ws_chat64k.c db.c
UNAME := $(shell uname -s)
IMAGE := ws-chat64k
ENV_PORT := $(shell [ -f .env ] && grep -E '^PORT=' .env | tail -1 | cut -d= -f2)
PORT  ?= $(if $(ENV_PORT),$(ENV_PORT),5555)

$(BIN): $(SRC) db.h
	$(CC) $(CFLAGS) $(PG_CFLAGS) -o $@ $(SRC) $(PG_LIBS)

# Native run (Linux only — uses epoll).
run-native: $(BIN)
	./$(BIN)

# Docker-based run (works on macOS/Linux). Loads .env, host networking on Linux,
# port-mapped on macOS. Use this as the default `make run`.
docker-build:
	docker build -t $(IMAGE) .

run: docker-build
	@test -f .env || { echo "missing .env (copy .env.example)"; exit 1; }
	docker rm -f $(IMAGE) 2>/dev/null || true
	docker run --rm -it --name $(IMAGE) --env-file .env -p $(PORT):$(PORT) $(IMAGE)

run-detached: docker-build
	@test -f .env || { echo "missing .env (copy .env.example)"; exit 1; }
	docker rm -f $(IMAGE) 2>/dev/null || true
	docker run -d --name $(IMAGE) --env-file .env -p $(PORT):$(PORT) $(IMAGE)
	@echo "running on port $(PORT). logs: make logs   stop: make stop"

logs:
	docker logs -f $(IMAGE)

stop:
	docker rm -f $(IMAGE) 2>/dev/null || true

# Integration tests. Boots a container if none is running, then hits HTTP+WS.
test:
	@if ! docker ps --filter name=$(IMAGE) --filter status=running -q | grep -q .; then \
		echo "starting container for tests..."; \
		$(MAKE) -s run-detached; \
		sleep 2; \
	fi
	PORT=$(PORT) bash tests/run.sh

clean:
	rm -f $(BIN)

.PHONY: clean run run-native run-detached docker-build logs stop test
