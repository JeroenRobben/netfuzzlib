#!/usr/bin/env bash
#
# tinydtls-client target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# Roles are swapped vs. the `tinydtls` (server-side) target:
#   - The "daemon" we bring up is a NATIVE dtls-server (no LD_PRELOAD).
#     It plays the role of the peer fixture. The client is the SUT.
#   - The "client" we then run is the dtls-CLIENT under LD_PRELOAD,
#     paired with the kernel-bridge module. This exercises the
#     outgoing-UDP path (lazy real-socket creation on first send,
#     recvmsg back to the SUT, source-port preservation) which the
#     server-side test only stresses for the listener direction.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DTLS_PORT="${DTLS_PORT:-20221}"
DTLS_HOST="${DTLS_HOST:-127.0.0.1}"
PAYLOAD="hello from tinydtls-client under nfl"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# Native server (peer fixture), NOT under nfl. -A binds to loopback,
# -p picks a port distinct from the server-side test's 20220 so the
# two targets can't accidentally interfere if both run in parallel
# in CI.
DTLS_SERVER_ARGS=(-A "${DTLS_HOST}" -p "${DTLS_PORT}")

# Client args, see test/integration/docker/tinydtls/run.sh for
# the full rationale on why -p / -i / -k are NOT passed.
DTLS_CLIENT_ARGS=("${DTLS_HOST}" "${DTLS_PORT}")

run_daemon() {
    # In this target, "run_daemon" means "bring up the native peer
    # fixture so a developer can `docker exec` the container and run
    # the SUT manually". It does NOT use LD_PRELOAD. The SERVER is
    # not the SUT here.
    echo "[tinydtls-client] starting NATIVE dtls-server peer on ${DTLS_HOST}:${DTLS_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec dtls-server "${DTLS_SERVER_ARGS[@]}"
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -uln "sport = :${DTLS_PORT}" 2>/dev/null \
                | grep -q "UNCONN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[tinydtls-client] peer never bound UDP ${DTLS_PORT}" >&2
    return 1
}

run_client() {
    echo "[tinydtls-client] running dtls-client under nfl" | tee -a "$CLIENT_LOG"
    # Same stdin choreography as the server-side test: pre-sleep to
    # let the handshake finish, then send the payload, then send
    # `client:exit` so the example client breaks its main loop and
    # flushes stdout before exiting. Increased the post-payload sleep
    # because round-trip through the bridge has more hops than the
    # native-only case.
    local out
    if ! out=$({ sleep 2; printf '%s\nclient:exit\n' "$PAYLOAD"; sleep 2; } \
                | LD_PRELOAD="$PRELOAD" \
                  NFL_BRIDGE_LOG="$BRIDGE_LOG" \
                  timeout 15 dtls-client "${DTLS_CLIENT_ARGS[@]}" \
                2> >(tee -a "$CLIENT_LOG" >&2)); then
        echo "[tinydtls-client] dtls-client FAILED" >> "$CLIENT_LOG"
        return 1
    fi
    if ! grep -qxF "$PAYLOAD" <<< "$out"; then
        printf '[tinydtls-client] payload not in client stdout. Output:\n%s\n' "$out" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[tinydtls-client] dtls-client ok, payload echoed back over DTLS" >> "$CLIENT_LOG"
    return 0
}

run_test() {
    : > "$DAEMON_LOG"
    : > "$CLIENT_LOG"

    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    # Native server, no LD_PRELOAD. This is the peer fixture, not the
    # SUT, so we don't want netfuzzlib in its address space.
    (
        exec dtls-server "${DTLS_SERVER_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[tinydtls-client] FAIL: peer fixture did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[tinydtls-client] PASS"
        return 0
    fi

    echo "[tinydtls-client] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
