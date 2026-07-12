#!/usr/bin/env bash
#
# Kamailio target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# SUT: kamailio in single-process mode (fork=no) under LD_PRELOAD +
# the kernel-bridge module. UDP-only: SIP signalling on port 5060.
#
# Native client: hand-rolled SIP OPTIONS over `nc -u`, expects a
# `SIP/2.0 200 OK` reply emitted by the `sl` core module.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
KAMAILIO_PORT="${KAMAILIO_PORT:-5060}"
KAMAILIO_HOST="${KAMAILIO_HOST:-127.0.0.1}"
KAMAILIO_CFG="${KAMAILIO_CFG:-/tmp/kamailio-nfl.cfg}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# Minimal config:
#   fork=no             single-process, no UDP/TCP child processes.
#                       Without this kamailio defaults to fork=yes and
#                       spawns one child per listener. The listener
#                       child never returns to the parent's accept-loop
#                       so nfl's quiescence model and the bridge's per-
#                       process state both go off the rails. fork=no
#                       collapses the entire daemon into one event loop,
#                       same shape as dnsmasq --keep-in-foreground.
#   disable_tcp=yes     we only test UDP signalling. Skip the TCP
#                       listener entirely so there's no second socket
#                       to track.
#   listen=udp:HOST:PORT
#                       single explicit binding. Without this kamailio
#                       enumerates all interfaces and binds to each.
#   request_route       reply 200 OK to anything. Method-conditioned
#                       routing (`is_method("OPTIONS")`) needs the
#                       textops module which the Debian package ships
#                       in `kamailio-extra-modules`, not installed
#                       here. The client only sends OPTIONS so a
#                       blanket 200 is fine for a smoke test.
write_config() {
    cat > "$KAMAILIO_CFG" <<EOF
#!KAMAILIO

debug=2
fork=no
log_stderror=yes
disable_tcp=yes
listen=udp:${KAMAILIO_HOST}:${KAMAILIO_PORT}

loadmodule "sl.so"

request_route {
    sl_send_reply("200", "OK");
    exit;
}
EOF
}

run_daemon() {
    write_config
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[kamailio] starting on ${KAMAILIO_HOST}:${KAMAILIO_PORT} (UDP)" \
        | tee -a "$DAEMON_LOG"
    exec /usr/sbin/kamailio -f "$KAMAILIO_CFG" -E
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -uln "sport = :${KAMAILIO_PORT}" 2>/dev/null \
                | grep -q "UNCONN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[kamailio] daemon never bound UDP ${KAMAILIO_PORT}" >&2
    return 1
}

# Hand-rolled SIP OPTIONS. RFC 3261 §8.1.1 requires Via, From, To,
# Call-ID, CSeq, Max-Forwards, Content-Length. The branch parameter
# must start with the magic cookie z9hG4bK. CRLF line endings are
# mandatory. \n alone is malformed and most stacks silently drop it.
sip_options_request() {
    printf 'OPTIONS sip:test@%s:%s SIP/2.0\r\n' "$KAMAILIO_HOST" "$KAMAILIO_PORT"
    printf 'Via: SIP/2.0/UDP %s:5061;branch=z9hG4bK-nfl-test;rport\r\n' "$KAMAILIO_HOST"
    printf 'Max-Forwards: 70\r\n'
    printf 'From: <sip:nfl@%s>;tag=nfl-tag\r\n' "$KAMAILIO_HOST"
    printf 'To: <sip:test@%s:%s>\r\n' "$KAMAILIO_HOST" "$KAMAILIO_PORT"
    printf 'Call-ID: nfl-test-call@%s\r\n' "$KAMAILIO_HOST"
    printf 'CSeq: 1 OPTIONS\r\n'
    printf 'Content-Length: 0\r\n'
    printf '\r\n'
}

run_client() {
    echo "[kamailio] sending SIP OPTIONS" | tee -a "$CLIENT_LOG"
    local out
    # nc -u: UDP. -w 1: exit 1 s after stdin EOF. Gives kamailio time
    # to reply before nc tears the socket down.
    out=$(sip_options_request \
            | timeout 5 nc -u -w 1 "$KAMAILIO_HOST" "$KAMAILIO_PORT" 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    if ! grep -qE '^SIP/2\.0 200 ' <<< "$out"; then
        echo "[kamailio] missing SIP/2.0 200 reply" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[kamailio] OPTIONS ok (200 received)" >> "$CLIENT_LOG"
    return 0
}

run_test() {
    : > "$DAEMON_LOG"
    : > "$CLIENT_LOG"
    write_config

    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/sbin/kamailio -f "$KAMAILIO_CFG" -E
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[kamailio] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[kamailio] PASS"
        return 0
    fi

    echo "[kamailio] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
