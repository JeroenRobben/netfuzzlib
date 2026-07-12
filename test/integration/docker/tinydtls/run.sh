#!/usr/bin/env bash
#
# tinydtls target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# tinydtls's example dtls-server echoes back whatever the client sends
# over the encrypted UDP session. We drive it with the matching
# dtls-client binary (built from the same source so PSK identity/key
# match by default, no key wiring needed).

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DTLS_PORT="${DTLS_PORT:-20220}"
DTLS_HOST="${DTLS_HOST:-127.0.0.1}"
PAYLOAD="hello from tinydtls under nfl"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# dtls-server flags:
#   -A 127.0.0.1   bind to loopback (avoids picking up eth0 by default).
#   -p 20220       listening port, matches what the client connects to.
DTLS_SERVER_ARGS=(-A "${DTLS_HOST}" -p "${DTLS_PORT}")

# dtls-client args:
#   <host> <port>     positional: destination (server) host and port.
# Notes on what we deliberately do NOT pass:
#   -p                 sets the *local* port (default ephemeral). The
#                      example client's "natural" usage on the same host
#                      as the server uses an ephemeral source port. If
#                      we pinned -p to the server's port, both ends bind
#                      127.0.0.1:DTLS_PORT and the kernel routes packets
#                      ambiguously between them, causing the server to
#                      receive its own replies.
#   -i / -k            those are FILE paths in tinydtls (PSK identity/key
#                      read from disk). Both binaries ship with matching
#                      compile-time defaults (Client_identity / secretPSK),
#                      so omitting these uses the matching pair without
#                      needing to drop key files into the image.
DTLS_CLIENT_ARGS=(
    "${DTLS_HOST}"
    "${DTLS_PORT}"
)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[tinydtls] starting dtls-server on ${DTLS_HOST}:${DTLS_PORT}" \
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
    echo "[tinydtls] daemon never bound UDP ${DTLS_PORT}" >&2
    return 1
}

run_client() {
    echo "[tinydtls] running dtls-client" | tee -a "$CLIENT_LOG"
    # Sequence quirks of the tinydtls dtls-client example we have to
    # work around:
    #   - It reads stdin EAGERLY, even before the handshake completes,
    #     and silently drops data fed to dtls_write on a not-yet-
    #     established session. So we sleep BEFORE writing the payload.
    #   - It does NOT exit on stdin EOF (handle_stdin treats fgets-NULL
    #     as a no-op and the main loop spins forever). The clean way
    #     out is to send the literal command "client:exit\n". The
    #     example main loop matches it and `break`s, flushing stdio
    #     on normal exit. Without this, only `timeout` ends the run,
    #     which SIGKILLs before stdout's block buffer flushes and we
    #     lose the echoed payload.
    #
    # Stdin script:
    #   sleep 2                handshake window
    #   printf payload         one line of app data
    #   sleep 1                round-trip echo arrives
    #   printf "client:exit\n" trigger graceful client shutdown
    local out
    if ! out=$({ sleep 2; printf '%s\nclient:exit\n' "$PAYLOAD"; sleep 1; } \
                | timeout 15 dtls-client "${DTLS_CLIENT_ARGS[@]}" \
                2> >(tee -a "$CLIENT_LOG" >&2)); then
        echo "[tinydtls] dtls-client FAILED" >> "$CLIENT_LOG"
        return 1
    fi
    # The client's read_from_peer dumps received bytes raw to stdout
    # AND prints "client: exit" before breaking the loop. Match the
    # payload as a substring rather than equality.
    if ! grep -qxF "$PAYLOAD" <<< "$out"; then
        printf '[tinydtls] payload not in client stdout. Output:\n%s\n' "$out" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[tinydtls] dtls-client ok, payload echoed back over DTLS" >> "$CLIENT_LOG"
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
        exec dtls-server "${DTLS_SERVER_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[tinydtls] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[tinydtls] PASS"
        return 0
    fi

    echo "[tinydtls] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
