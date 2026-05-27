#!/usr/bin/env bash
# Integration tests for ws_chat64k. Assumes server is running on $PORT.
# Usage: PORT=34905 ./tests/run.sh   (or via `make test`)

set -u
PORT="${PORT:-5555}"
BASE="http://localhost:$PORT"
PASS=0
FAIL=0
USER="test_$(date +%s)_$$"
PW="hunter2pw"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
ok()    { green "  PASS  $*"; PASS=$((PASS+1)); }
ko()    { red   "  FAIL  $*"; FAIL=$((FAIL+1)); }

assert_eq() {  # name expected actual
    if [ "$2" = "$3" ]; then ok "$1 (=$2)"; else ko "$1: expected '$2' got '$3'"; fi
}
assert_contains() {  # name needle haystack
    case "$3" in *"$2"*) ok "$1 (contains '$2')";;
        *) ko "$1: '$3' missing '$2'";;
    esac
}

echo "== ws_chat64k tests against $BASE =="

# ---------- HTTP ----------

CODE=$(curl -sS -o /tmp/body.html -w "%{http_code}" "$BASE/")
assert_eq "GET / status" 200 "$CODE"
CTYPE=$(curl -sS -D - -o /dev/null "$BASE/" | awk 'tolower($1)=="content-type:"{print $2}' | tr -d '\r')
assert_contains "GET / content-type" "text/html" "$CTYPE"
assert_contains "GET / body" "ws_chat64k" "$(cat /tmp/body.html)"

CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X OPTIONS "$BASE/api/login")
assert_eq "OPTIONS /api/login status" 204 "$CODE"
ACAO=$(curl -sS -D - -o /dev/null -X OPTIONS "$BASE/api/login" | awk 'tolower($1)=="access-control-allow-origin:"{print $2}' | tr -d '\r')
assert_eq "OPTIONS CORS allow-origin" "*" "$ACAO"

CODE=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE/api/does-not-exist")
assert_eq "GET unknown path -> 404" 404 "$CODE"

# ---------- register / login / logout ----------

R=$(curl -sS -X POST -H 'content-type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PW\"}" \
    "$BASE/api/register")
assert_contains "register success body" "\"token\":" "$R"
TOKEN=$(echo "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
[ -n "$TOKEN" ] && ok "register returned token (len=${#TOKEN})" || ko "register returned no token"

CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H 'content-type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PW\"}" \
    "$BASE/api/register")
assert_eq "register duplicate -> 400" 400 "$CODE"

CODE=$(curl -sS -o /tmp/login.json -w "%{http_code}" -X POST -H 'content-type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PW\"}" \
    "$BASE/api/login")
assert_eq "login correct -> 200" 200 "$CODE"
TOKEN2=$(python3 -c 'import json;print(json.load(open("/tmp/login.json"))["token"])' 2>/dev/null)
[ -n "$TOKEN2" ] && ok "login returned token" || ko "login token missing"

CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H 'content-type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"wrong\"}" \
    "$BASE/api/login")
assert_eq "login wrong pw -> 401" 401 "$CODE"

CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST -H 'content-type: application/json' \
    -d '{"bogus":"json"}' "$BASE/api/login")
assert_eq "login missing fields -> 400" 400 "$CODE"

# ---------- history ----------

CODE=$(curl -sS -o /tmp/hist.json -w "%{http_code}" "$BASE/api/history?limit=3")
assert_eq "GET /api/history status" 200 "$CODE"
case "$(head -c1 /tmp/hist.json)" in '[') ok "history is JSON array";;
    *) ko "history is not JSON array: $(head -c40 /tmp/hist.json)";;
esac

# ---------- WS handshake ----------

ws_handshake() {  # extra_headers -> dumps response headers to /tmp/wsresp
    local extra="$1"
    KEY=$(head -c 16 /dev/urandom | base64)
    {
        printf "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n" "$KEY"
        [ -n "$extra" ] && printf "%s\r\n" "$extra"
        printf "\r\n"
        sleep 1.2
    } | nc -w 2 localhost "$PORT" > /tmp/wsresp 2>/dev/null
}

ws_handshake ""
FIRST=$(head -1 /tmp/wsresp | tr -d '\r')
assert_eq "WS guest upgrade status" "HTTP/1.1 101 Switching Protocols" "$FIRST"

ws_handshake "Sec-WebSocket-Protocol: bearer.$TOKEN"
FIRST=$(head -1 /tmp/wsresp | tr -d '\r')
assert_eq "WS bearer upgrade status" "HTTP/1.1 101 Switching Protocols" "$FIRST"
if grep -qai "^sec-websocket-protocol: bearer\.$TOKEN" /tmp/wsresp; then
    ok "WS subprotocol echoed for valid bearer"
else
    ko "WS subprotocol not echoed for valid bearer"
fi
# welcome frame should be appended after the handshake response
if grep -qa 'event":"welcome"' /tmp/wsresp; then
    ok "WS authed: welcome frame received"
else
    ko "WS authed: no welcome frame in response"
fi

ws_handshake "Sec-WebSocket-Protocol: bearer.deadbeef00000000000000000000000000000000000000000000000000000000"
if grep -qai "^sec-websocket-protocol:" /tmp/wsresp; then
    ko "WS invalid bearer should not echo subprotocol"
else
    ok "WS invalid bearer treated as guest (no subprotocol)"
fi

# ---------- logout ----------

CODE=$(curl -sS -o /tmp/lo.json -w "%{http_code}" -X POST -H 'content-type: application/json' \
    -d "{\"token\":\"$TOKEN\"}" "$BASE/api/logout")
assert_eq "logout status" 200 "$CODE"
assert_eq "logout body" "{}" "$(cat /tmp/lo.json)"

# ---------- summary ----------

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ] || exit 1
