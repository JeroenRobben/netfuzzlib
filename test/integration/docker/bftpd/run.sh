#!/usr/bin/env bash
#
# bftpd target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
# Mirrors the lightftp/run.sh contract (run_daemon / run_client / run_test).

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
BFTPD_PORT="${BFTPD_PORT:-2200}"
BFTPD_HOST="${BFTPD_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# `-D` keeps bftpd in single-process daemon mode (no pre-fork). Forking
# would hand each connection to a child process whose bridge state is
# copy-on-write of the parent's. Fine for one connection at a time, but
# it starts to interact with concurrent listener accepts in non-obvious
# ways. -D is enough for our single-curl test and keeps the bridge
# bookkeeping linear.
BFTPD_ARGS=(-D -c /etc/bftpd.conf)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[bftpd] starting daemon on ${BFTPD_HOST}:${BFTPD_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec bftpd "${BFTPD_ARGS[@]}" >> "$DAEMON_LOG" 2>&1
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${BFTPD_PORT}" 2>/dev/null \
                | grep -q "LISTEN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[bftpd] daemon never listened on ${BFTPD_PORT}" >&2
    return 1
}

run_client() {
    echo "[bftpd] running curl client" | tee -a "$CLIENT_LOG"
    local out
    if ! out=$(curl -sS --connect-timeout 5 --max-time 15 \
                "ftp://${BFTPD_HOST}:${BFTPD_PORT}/hello.txt" \
                2> >(tee -a "$CLIENT_LOG" >&2)); then
        echo "[bftpd] curl FAILED" >> "$CLIENT_LOG"
        return 1
    fi
    if [[ "$out" != "hello from bftpd under nfl" ]]; then
        printf '[bftpd] unexpected payload:\n%s\n' "$out" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[bftpd] curl ok, payload matched" >> "$CLIENT_LOG"
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
        bftpd "${BFTPD_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[bftpd] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[bftpd] PASS"
        return 0
    fi

    echo "[bftpd] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
