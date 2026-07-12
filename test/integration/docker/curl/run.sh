#!/usr/bin/env bash
# curl as SUT under nfl+bridge-kernel, talking to an unmodified python
# http.server peer in the same container. Verifies the *client*-side
# bridge path: nfl_tcp_connect creates a real kernel socket, nfl_send
# writes the request to it, nfl_receive reads the response back.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
HTTP_PORT="${HTTP_PORT:-8084}"
HTTP_HOST="${HTTP_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${HTTP_PORT}" 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_server() {
    cd /tmp/curl-root || exit 1
    exec python3 -u -m http.server "$HTTP_PORT" --bind "$HTTP_HOST"
}

run_client() {
    # curl IS the SUT here, runs under nfl. The peer is plain python.
    local out rc
    out=$(LD_PRELOAD="$PRELOAD" \
            NFL_BRIDGE_LOG="$BRIDGE_LOG" \
            timeout 5 curl -sS -m 4 \
                "http://${HTTP_HOST}:${HTTP_PORT}/" 2>>"$CLIENT_LOG")
    rc=$?
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    if [[ $rc -ne 0 ]]; then
        echo "[curl] client rc=$rc" >&2
        return 1
    fi
    grep -q '^nfl-curl-ok' <<< "$out" || return 1
    return 0
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    server_pid=""
    trap 'if [[ -n "${server_pid:-}" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi' EXIT

    # Server runs UNMODIFIED, no LD_PRELOAD. Its job is just to be a real
    # peer for curl's bridged socket.
    (run_server) >> "$DAEMON_LOG" 2>&1 &
    server_pid=$!

    if ! wait_for_listener; then
        echo "[curl] FAIL: python http.server did not bind" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[curl] PASS"
        return 0
    fi
    echo "[curl] FAIL: curl client failed or response mismatch" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" 2>/dev/null >&2 || true
    return 1
}
