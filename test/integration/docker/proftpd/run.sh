#!/usr/bin/env bash
#
# ProFTPD target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# SUT: proftpd standalone under LD_PRELOAD + the kernel-bridge
# module. Listener parent under nfl forks a child per FTP control
# connection. The child handles the session in a single process.
# Native client: a scripted FTP login transaction over `nc`.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
# Non-privileged FTP port. bftpd uses 21 (mapped via NAT in CI), so
# 2121 here also avoids any cross-target collision.
FTP_PORT="${FTP_PORT:-2121}"
FTP_HOST="${FTP_HOST:-127.0.0.1}"
PROFTPD_CONFIG="${PROFTPD_CONFIG:-/opt/nfl-proftpd.conf}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# proftpd flags:
#   -n     foreground (no daemonise), needed so $! tracks the
#          listener parent for trap-kill.
#   -q     suppress stderr noise from -n.
#   -c     config file. proftpd searches /etc/proftpd/proftpd.conf
#          by default. We use our own minimal one in /opt.
PROFTPD_ARGS=(
    -n
    -q
    -c "${PROFTPD_CONFIG}"
)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[proftpd] starting on ${FTP_HOST}:${FTP_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec /usr/sbin/proftpd "${PROFTPD_ARGS[@]}"
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
    echo "[proftpd] daemon never listened on ${FTP_PORT}" >&2
    return 1
}

run_client() {
    echo "[proftpd] running anonymous FTP login transaction" | tee -a "$CLIENT_LOG"
    # Anonymous login flow:
    #   server 220 (banner)
    #   client USER anonymous
    #   server 331 (challenge)
    #   client PASS <anything>
    #   server 230 (granted)
    #   client QUIT
    #   server 221 (bye)
    local out
    out=$(printf 'USER anonymous\r\nPASS test@nfl\r\nQUIT\r\n' \
            | timeout 5 nc -q 1 "$FTP_HOST" "$FTP_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    if ! grep -qE '^220 ' <<< "$out"; then
        echo "[proftpd] missing 220 banner" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qE '^230 ' <<< "$out"; then
        echo "[proftpd] missing 230 login-granted" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qE '^221 ' <<< "$out"; then
        echo "[proftpd] missing 221 bye" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[proftpd] FTP login ok (220/230/221 all observed)" >> "$CLIENT_LOG"
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
        exec /usr/sbin/proftpd "${PROFTPD_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[proftpd] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[proftpd] PASS"
        return 0
    fi

    echo "[proftpd] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
