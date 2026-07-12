#!/usr/bin/env bash
# memcached. ASCII protocol over TCP: set/get/version.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
MC_PORT="${MC_PORT:-11211}"
MC_HOST="${MC_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

MC_ARGS=(-l "$MC_HOST" -p "$MC_PORT" -t 1 -u root -v)

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${MC_PORT}" 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_client() {
    local out
    out=$(printf 'version\r\n' | timeout 3 nc -q 1 "$MC_HOST" "$MC_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    grep -qE '^VERSION ' <<< "$out" || return 1
    out=$(printf 'set k 0 0 5\r\nhello\r\nget k\r\n' \
            | timeout 3 nc -q 1 "$MC_HOST" "$MC_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    grep -q '^STORED' <<< "$out" || return 1
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
        exec /usr/bin/memcached "${MC_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[memcached] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[memcached] PASS"; return 0; fi
    echo "[memcached] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
