#!/usr/bin/env bash
# libcoap coap-server-notls: built-in `/time` resource. coap-client GETs
# it. We check we got a non-empty body back.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
COAP_PORT="${COAP_PORT:-5683}"
COAP_HOST="${COAP_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

COAP_ARGS=(-A "$COAP_HOST" -p "$COAP_PORT" -v 4)

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -uln "sport = :${COAP_PORT}" 2>/dev/null | grep -q UNCONN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_client() {
    local out
    out=$(timeout 5 coap-client-notls -m get "coap://${COAP_HOST}:${COAP_PORT}/time" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    [[ -n "$out" ]] || return 1
    return 0
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/bin/coap-server-notls "${COAP_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[libcoap] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[libcoap] PASS"; return 0; fi
    echo "[libcoap] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
