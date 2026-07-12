#!/usr/bin/env bash
# Redis: RESP text-ish protocol over TCP. Single-threaded event loop.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

REDIS_ARGS=(
    --bind "$REDIS_HOST"
    --port "$REDIS_PORT"
    --protected-mode no
    --save ""
    --daemonize no
    --loglevel notice
)

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${REDIS_PORT}" 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_client() {
    local out
    out=$(printf '*1\r\n$4\r\nPING\r\n' | timeout 3 nc -q 1 "$REDIS_HOST" "$REDIS_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    grep -q '^+PONG' <<< "$out" || return 1
    out=$(printf '*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nhello\r\n*2\r\n$3\r\nGET\r\n$1\r\nk\r\n' \
            | timeout 3 nc -q 1 "$REDIS_HOST" "$REDIS_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    grep -q '^+OK' <<< "$out" || return 1
    grep -q '^hello' <<< "$out" || return 1
    return 0
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/bin/redis-server "${REDIS_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[redis] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[redis] PASS"; return 0; fi
    echo "[redis] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
