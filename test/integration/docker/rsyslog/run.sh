#!/usr/bin/env bash
# rsyslog: receive a UDP syslog message and verify it lands in our
# capture file. Logger uses RFC 3164 over UDP by default.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
SYSLOG_PORT="${SYSLOG_PORT:-5140}"
SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
CONF="${RSYSLOG_CONF:-/tmp/rsyslog-nfl.conf}"
CAPTURE="${RSYSLOG_CAPTURE:-/tmp/rsyslog-capture.log}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

write_config() {
    : > "$CAPTURE"
    cat > "$CONF" <<EOF
module(load="imudp")
input(type="imudp" port="${SYSLOG_PORT}" address="${SYSLOG_HOST}")
\$WorkDirectory /tmp
*.* ${CAPTURE}
EOF
}

# -n: foreground, -f: config, -i: pidfile (we want one we control).
RSYSLOG_ARGS=(-n -f "$CONF" -i /tmp/rsyslogd.pid)

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -uln "sport = :${SYSLOG_PORT}" 2>/dev/null | grep -q UNCONN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_client() {
    # Plain RFC 3164 UDP datagram via logger -d (UDP) -n host -P port.
    timeout 3 logger -d -n "$SYSLOG_HOST" -P "$SYSLOG_PORT" \
        -t nfltest "hello-from-nfl-$$" 2>>"$CLIENT_LOG"
    # rsyslog buffers, so give it a moment to flush.
    local deadline=$(( $(date +%s) + 5 ))
    while (( $(date +%s) < deadline )); do
        if grep -q 'hello-from-nfl' "$CAPTURE" 2>/dev/null; then
            cat "$CAPTURE" >> "$CLIENT_LOG"
            return 0
        fi
        sleep 0.2
    done
    cat "$CAPTURE" >> "$CLIENT_LOG" 2>/dev/null || true
    return 1
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    write_config
    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/sbin/rsyslogd "${RSYSLOG_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[rsyslog] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[rsyslog] PASS"; return 0; fi
    echo "[rsyslog] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
