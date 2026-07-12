#!/usr/bin/env bash
#
# Pure-FTPd target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# SUT: pure-ftpd standalone (foreground default) under LD_PRELOAD +
# the kernel-bridge module. Listener parent under nfl forks a child
# per FTP control connection. The child handles the session.
#
# Native client: scripted USER/PASS/QUIT over `nc`.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
FTP_PORT="${FTP_PORT:-2121}"
FTP_HOST="${FTP_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# pure-ftpd flags:
#   -S host,port   bind address+port. Comma separator (not colon!).
#   -e             allow only anonymous logins. Keeps the test
#                  self-contained. No /etc/passwd / /etc/shadow
#                  setup, no pam, no puredb. The package's `ftp`
#                  user (added in the Dockerfile) is what the
#                  anonymous login resolves to.
#   -j             create the home directory if it doesn't exist.
#                  /tmp does, but harmless to set.
#   -dd            stay in foreground (default is foreground unless
#                  -B / --daemonize is set), and emit debug logs to
#                  stderr, useful for diagnostics on failure.
PURE_FTPD_ARGS=(
    -S "${FTP_HOST},${FTP_PORT}"
    -e
    -j
    -dd
)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[pure-ftpd] starting on ${FTP_HOST}:${FTP_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec /usr/sbin/pure-ftpd "${PURE_FTPD_ARGS[@]}"
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${FTP_PORT}" 2>/dev/null \
                | grep -q "LISTEN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[pure-ftpd] daemon never listened on ${FTP_PORT}" >&2
    return 1
}

run_client() {
    echo "[pure-ftpd] running anonymous FTP login transaction" | tee -a "$CLIENT_LOG"
    local out
    out=$(printf 'USER anonymous\r\nPASS test@nfl\r\nQUIT\r\n' \
            | timeout 5 nc -q 1 "$FTP_HOST" "$FTP_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    if ! grep -qE '^220[ -]' <<< "$out"; then
        echo "[pure-ftpd] missing 220 banner" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qE '^230 ' <<< "$out"; then
        echo "[pure-ftpd] missing 230 login-granted" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qE '^221 ' <<< "$out"; then
        echo "[pure-ftpd] missing 221 bye" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[pure-ftpd] FTP login ok (220/230/221 all observed)" >> "$CLIENT_LOG"
    return 0
}

run_test() {
    : > "$DAEMON_LOG"
    : > "$CLIENT_LOG"

    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/sbin/pure-ftpd "${PURE_FTPD_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[pure-ftpd] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[pure-ftpd] PASS"
        return 0
    fi

    echo "[pure-ftpd] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
