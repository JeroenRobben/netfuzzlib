#!/usr/bin/env bash
#
# Exim target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# SUT: exim4 daemon under LD_PRELOAD + the kernel-bridge module,
# listening on a non-privileged port. The listener parent runs under
# nfl. It forks a child per accepted connection and the child runs
# the actual SMTP session, same fork-then-handle pattern as bftpd.
#
# Native client: a scripted SMTP transaction over `nc`.
#   server greets with 220 ESMTP Exim …
#   client EHLO
#   server 250-… (multi-line)
#   client QUIT
#   server 221 closing connection
# We assert all three response codes are present in the captured
# stream, which means the bridge moved bytes both directions across a
# multi-step request/response sequence.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
# Non-privileged port. The daemon doesn't need root for this and we
# avoid clashes with anything bound on 25.
SMTP_PORT="${SMTP_PORT:-2525}"
SMTP_HOST="${SMTP_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# exim flags:
#   -bdf                 daemon mode, foreground (no detach). The
#                        plain -bd double-forks into the background,
#                        which means our $! tracks the wrapper not the
#                        listener and trap-kill misses the daemon.
#   -oX HOST.PORT        listen address+port. Exim's -oX syntax uses
#                        '.' as the separator, so 127.0.0.1.2525 means
#                        host=127.0.0.1, port=2525.
#   -oP /tmp/exim.pid    pidfile in /tmp (exim won't start without
#                        the file existing, -oP just sets the path).
EXIM_ARGS=(
    -bdf
    -oX "${SMTP_HOST}.${SMTP_PORT}"
    -oP "/tmp/exim.pid"
)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[exim] starting exim4 -bdf on ${SMTP_HOST}:${SMTP_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec /usr/sbin/exim4 "${EXIM_ARGS[@]}"
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${SMTP_PORT}" 2>/dev/null \
                | grep -q "LISTEN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[exim] daemon never listened on ${SMTP_PORT}" >&2
    return 1
}

run_client() {
    echo "[exim] running SMTP EHLO/QUIT transaction" | tee -a "$CLIENT_LOG"
    # Feed all SMTP commands at once. Exim parses CRLF-delimited
    # lines and replies after each. nc -q 1 keeps reading until 1s
    # of stdin EOF idle, which is plenty for the EHLO + QUIT
    # round-trips on loopback. timeout 5 caps the worst case if the
    # bridge wedges.
    local out
    out=$(printf 'EHLO nfl-test\r\nQUIT\r\n' \
            | timeout 5 nc -q 1 "$SMTP_HOST" "$SMTP_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    # 220 banner on connect, then 250 (EHLO ok), then 221 (QUIT bye).
    if ! grep -qE '^220 .* ESMTP Exim' <<< "$out"; then
        echo "[exim] missing 220 ESMTP banner" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qE '^250[ -]' <<< "$out"; then
        echo "[exim] missing 250 EHLO response" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qE '^221 ' <<< "$out"; then
        echo "[exim] missing 221 QUIT response" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[exim] SMTP transaction ok (220/250/221 all observed)" >> "$CLIENT_LOG"
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
        exec /usr/sbin/exim4 "${EXIM_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[exim] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[exim] PASS"
        return 0
    fi

    echo "[exim] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
