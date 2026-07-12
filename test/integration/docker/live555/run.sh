#!/usr/bin/env bash
#
# live555 target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# SUT: testOnDemandRTSPServer under LD_PRELOAD + the kernel-bridge
# module. Native client: a shell-driven RTSP OPTIONS probe via nc.
#
# OPTIONS doesn't require any registered stream URL or media file, so
# the test is fully self-contained. We just want to confirm an RTSP
# request can flow from a real client through the bridge into the SUT
# and a well-formed response can flow back.
#
# A v2 that did DESCRIBE → SETUP → PLAY (and asserted on captured RTP
# bytes) was attempted and rolled back. testOnDemandRTSPServer's event
# loop spins under nfl because our select() interceptor ignores the
# caller's timeout argument. live555's BasicTaskScheduler interprets
# the immediate 0-return as "all alarms fired" and re-runs delayed
# tasks that create+destroy sockets, which starves SETUP of UDP
# port allocation. See the Dockerfile header for the full diagnosis.
# Fixing that needs a select/poll interceptor change, not a bridge
# tweak.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
# testOnDemandRTSPServer hardcodes 8554 (no argv override). Keep the
# default so we don't have to patch the binary. Collisions with other
# targets are avoided by this being the only live555 test.
RTSP_PORT="${RTSP_PORT:-8554}"
RTSP_HOST="${RTSP_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    # testOnDemandRTSPServer enumerates streams that resolve to files
    # in cwd at request time. For OPTIONS we never resolve a stream,
    # so cwd doesn't matter. /tmp keeps the binary out of /.
    cd /tmp
    echo "[live555] starting testOnDemandRTSPServer on ${RTSP_HOST}:${RTSP_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec /usr/local/bin/testOnDemandRTSPServer
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${RTSP_PORT}" 2>/dev/null \
                | grep -q "LISTEN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[live555] daemon never listened on ${RTSP_PORT}" >&2
    return 1
}

run_client() {
    echo "[live555] running RTSP OPTIONS probe" | tee -a "$CLIENT_LOG"
    # nc -q 1: after stdin EOFs (request fully sent), wait 1s for the
    # server reply, then close. RTSP server replies immediately upon
    # receiving the blank-line terminator, so 1s is plenty.
    # The outer `timeout 5` is a hard cap if the bridge wedges.
    local out
    out=$(printf 'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: nfl-test\r\n\r\n' \
            | timeout 5 nc -q 1 "$RTSP_HOST" "$RTSP_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    if ! grep -q '^RTSP/1.0 200 OK' <<< "$out"; then
        echo "[live555] OPTIONS not 200 OK" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qiE '^Public:.*DESCRIBE' <<< "$out"; then
        echo "[live555] OPTIONS response missing expected Public: header" \
            >> "$CLIENT_LOG"
        return 1
    fi
    echo "[live555] RTSP OPTIONS ok" >> "$CLIENT_LOG"
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
        cd /tmp
        exec /usr/local/bin/testOnDemandRTSPServer
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[live555] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[live555] PASS"
        return 0
    fi

    echo "[live555] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
