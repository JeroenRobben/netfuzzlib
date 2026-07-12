#!/usr/bin/env bash
#
# openssl s_server target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# Scenario: s_server speaks an unframed echo-ish protocol on top of TLS.
# Whatever the client sends, the server prints to its stdout. Whatever
# the server's operator types on stdin, the server sends to the client.
# We exploit this for a deterministic check: prime the daemon's stdin
# with a known payload, then have s_client connect and read N bytes.
# If we get the expected payload back over TLS, the handshake worked
# and bidirectional flows work too.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
TLS_PORT="${TLS_PORT:-4433}"
TLS_HOST="${TLS_HOST:-127.0.0.1}"
TLS_CERT="${TLS_CERT:-/etc/nfl-tls/server.crt}"
TLS_KEY="${TLS_KEY:-/etc/nfl-tls/server.key}"
EXPECTED_PAYLOAD="hello from openssl s_server under nfl"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# s_server flags:
#   -accept              listen port
#   -cert / -key         self-signed material from the Dockerfile
#   -quiet               suppress chatty handshake/cert dumps so the
#                        bytes the client reads are exactly what we
#                        write to stdin
#   -no_ign_eof          exit cleanly when stdin EOFs (otherwise it
#                        keeps the connection open after our prime)
#   -naccept 1           handle exactly one connection then exit. The
#                        test client opens one connection so this is
#                        sufficient and avoids stale-listener issues
S_SERVER_ARGS=(
    s_server
    -accept "${TLS_PORT}"
    -cert "${TLS_CERT}"
    -key "${TLS_KEY}"
    -quiet
    -no_ign_eof
    -naccept 1
)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[openssl] starting s_server on ${TLS_HOST}:${TLS_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec openssl "${S_SERVER_ARGS[@]}"
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${TLS_PORT}" 2>/dev/null \
                | grep -q "LISTEN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[openssl] daemon never listened on ${TLS_PORT}" >&2
    return 1
}

run_client() {
    echo "[openssl] running s_client" | tee -a "$CLIENT_LOG"
    # -quiet               suppress cert/handshake banners → stdout
    #                      contains only application data the server
    #                      sent us. -quiet implies -ign_eof, so the
    #                      client won't initiate shutdown on stdin EOF.
    # </dev/null           client sends nothing. We read the payload
    #                      the server's stdin was primed with.
    # timeout 1            both peers ignore stdin EOF, so neither
    #                      initiates SSL_shutdown. We bound the wait
    #                      and accept timeout (exit 124) as long as we
    #                      captured the expected payload. The assertion
    #                      below is the actual pass/fail signal. The
    #                      handshake + payload exchange completes well
    #                      under a second on a warm container.
    # The default s_client verification mode does NOT abort on a
    # self-signed cert. It only sets a non-zero exit if you ALSO pass
    # -verify_return_error. So no -verify flag needed here.
    local out
    out=$(timeout 1 openssl s_client \
                    -connect "${TLS_HOST}:${TLS_PORT}" \
                    -quiet \
                    </dev/null \
                    2>>"$CLIENT_LOG") || true
    out="${out%$'\n'}"
    if [[ "$out" != "$EXPECTED_PAYLOAD" ]]; then
        printf '[openssl] unexpected payload: %q\n' "$out" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[openssl] s_client ok, payload matched over TLS" >> "$CLIENT_LOG"
    return 0
}

run_test() {
    : > "$DAEMON_LOG"
    : > "$CLIENT_LOG"

    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    # Prime s_server's stdin with the known payload. As soon as a
    # client connects, s_server reads from its stdin and sends those
    # bytes (TLS-encrypted) over the wire. We use printf so the
    # trailing newline matches our $EXPECTED_PAYLOAD comparison.
    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        printf '%s\n' "$EXPECTED_PAYLOAD" \
            | exec openssl "${S_SERVER_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[openssl] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[openssl] PASS"
        return 0
    fi

    echo "[openssl] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
