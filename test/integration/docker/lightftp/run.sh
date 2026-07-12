#!/usr/bin/env bash
#
# LightFTP target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# Contract (see nfl-entrypoint.sh): defines run_test, run_daemon, run_client.
#   run_daemon: exec the daemon under LD_PRELOAD. Must NOT return.
#   run_client: drive the protocol from outside, exit 0 on pass.
#   run_test:   orchestrate both: start daemon, wait until ready, run client,
#               capture exit code, kill daemon, exit with that code.
#
# Logs land in $NFL_LOG_DIR/{daemon,client,bridge}.log.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
LIGHTFTP_PORT="${LIGHTFTP_PORT:-2200}"
LIGHTFTP_HOST="${LIGHTFTP_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

run_daemon() {
    # NFL_BRIDGE_LOG goes to the shared bridge.log so accept/recv/send
    # events appear next to the netns snapshot from nfl-entrypoint.
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[lightftp] starting daemon on ${LIGHTFTP_HOST}:${LIGHTFTP_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec lightftp /etc/fftp.conf >> "$DAEMON_LOG" 2>&1
}

wait_for_listener() {
    # Poll until the daemon's listening socket is up. Bounded by 10s. If
    # we're still not listening, something's wrong and the test should
    # fail loud rather than hang.
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${LIGHTFTP_PORT}" 2>/dev/null \
                | grep -q "LISTEN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[lightftp] daemon never listened on ${LIGHTFTP_PORT}" >&2
    return 1
}

run_client() {
    # Anonymous FTP RETR. curl exits non-zero on protocol errors.
    echo "[lightftp] running curl client" | tee -a "$CLIENT_LOG"
    local out
    if ! out=$(curl -sS --connect-timeout 5 --max-time 15 \
                "ftp://${LIGHTFTP_HOST}:${LIGHTFTP_PORT}/hello.txt" \
                2> >(tee -a "$CLIENT_LOG" >&2)); then
        echo "[lightftp] curl FAILED" >> "$CLIENT_LOG"
        return 1
    fi
    if [[ "$out" != "hello from lightftp under nfl" ]]; then
        printf '[lightftp] unexpected payload:\n%s\n' "$out" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[lightftp] curl ok, payload matched" >> "$CLIENT_LOG"
    return 0
}

run_test() {
    : > "$DAEMON_LOG"
    : > "$CLIENT_LOG"

    # daemon_pid is intentionally global (not `local`): the EXIT trap fires
    # in the outer shell where a function-local would already be out of
    # scope, and `set -u` would then trip with "daemon_pid: unbound".
    daemon_pid=""
    # Trap registered before fork so we never miss a window. `${var:-}`
    # tolerates the case where the daemon never started.
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    # Start daemon in background as a child of this script so we can kill
    # it cleanly. exec'ing would replace the script entirely, which we
    # need to avoid in test mode.
    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        # No NFL_BRIDGE_PRELISTEN: the bridge module's nfl_sock_listen
        # callback opens a real kernel listener at the moment the daemon
        # transitions any TCP socket to listening state, which covers the
        # PASV data ports automatically.
        lightftp /etc/fftp.conf
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[lightftp] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[lightftp] PASS"
        return 0
    fi

    echo "[lightftp] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
