#!/usr/bin/env bash
# lighttpd: small HTTP server, single-process default.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
HTTP_PORT="${HTTP_PORT:-8081}"
HTTP_HOST="${HTTP_HOST:-127.0.0.1}"
DOC_ROOT="${DOC_ROOT:-/tmp/lighttpd-root}"
CONF="${LIGHTTPD_CONF:-/tmp/lighttpd-nfl.conf}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

write_setup() {
    mkdir -p "$DOC_ROOT"
    echo "nfl-lighttpd-ok" > "$DOC_ROOT/index.html"
    cat > "$CONF" <<EOF
server.document-root = "${DOC_ROOT}"
server.bind          = "${HTTP_HOST}"
server.port          = ${HTTP_PORT}
server.max-worker    = 0
server.errorlog      = "${DAEMON_LOG}"
mimetype.assign      = ( ".html" => "text/html" )
index-file.names     = ( "index.html" )
EOF
}

# -D foreground, -f config.
LIGHTTPD_ARGS=(-D -f "$CONF")

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

run_client() {
    local out
    out=$(timeout 3 curl -sS -m 2 "http://${HTTP_HOST}:${HTTP_PORT}/" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    grep -q '^nfl-lighttpd-ok' <<< "$out" || return 1
    return 0
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    write_setup
    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/sbin/lighttpd "${LIGHTTPD_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[lighttpd] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[lighttpd] PASS"; return 0; fi
    echo "[lighttpd] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
