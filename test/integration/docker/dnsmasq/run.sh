#!/usr/bin/env bash
#
# dnsmasq target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
# Mirrors the bftpd/lightftp run.sh contract: run_daemon, run_client,
# run_test.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DNSMASQ_PORT="${DNSMASQ_PORT:-5300}"
DNSMASQ_HOST="${DNSMASQ_HOST:-127.0.0.1}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

# Args, with rationale per flag:
#   --no-daemon            keep dnsmasq in the foreground so we can
#                          supervise its pid from this shell.
#   --keep-in-foreground   defensive: pair with --no-daemon, never fork.
#   --port=$PORT           non-privileged port (avoids CAP_NET_BIND_SERVICE).
#   --listen-address=...   bind to a specific IP. Combined with the
#                          DEFAULT (no --bind-interfaces) dnsmasq binds
#                          INADDR_ANY and uses IP_PKTINFO via recvmsg to
#                          demultiplex per-destination IP. The model's
#                          recvmsg_dgram synthesises the IP_PKTINFO
#                          cmsg from pkt->local_addr. The bridge module
#                          fills that field from the kernel's own
#                          IP_PKTINFO/IPV6_PKTINFO cmsg on the real
#                          socket, so this whole path is now exercised.
#   --address=/hello.test/192.0.2.10
#                          static A record, the only thing the test
#                          query should match. 192.0.2.0/24 is RFC 5737
#                          TEST-NET-1, so the value won't collide with
#                          anything real.
#   --user=root            container runs as root. Default `nobody`
#                          would setuid and drop privs we don't have
#                          since the rootfs has no /etc/shadow.
#   --log-facility=...     route logs to a file rather than syslog so
#                          the test artifact upload can grab them.
#
DNSMASQ_ARGS=(
    --no-daemon
    --keep-in-foreground
    --port="${DNSMASQ_PORT}"
    --listen-address="${DNSMASQ_HOST}"
    --address=/hello.test/192.0.2.10
    --user=root
    --log-facility="${DAEMON_LOG}"
)

run_daemon() {
    export LD_PRELOAD="$PRELOAD"
    export NFL_BRIDGE_LOG="$BRIDGE_LOG"
    echo "[dnsmasq] starting daemon on ${DNSMASQ_HOST}:${DNSMASQ_PORT}" \
        | tee -a "$DAEMON_LOG"
    exec dnsmasq "${DNSMASQ_ARGS[@]}"
}

wait_for_listener() {
    # dnsmasq opens both UDP and TCP listeners on the configured port.
    # Probe UDP since that's the path our test query takes.
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -uln "sport = :${DNSMASQ_PORT}" 2>/dev/null \
                | grep -q "UNCONN"; then
            return 0
        fi
        sleep 0.2
    done
    echo "[dnsmasq] daemon never bound UDP ${DNSMASQ_PORT}" >&2
    return 1
}

run_client() {
    echo "[dnsmasq] running dig client" | tee -a "$CLIENT_LOG"
    local out
    if ! out=$(dig "@${DNSMASQ_HOST}" -p "${DNSMASQ_PORT}" \
                   hello.test +short +tries=1 +time=3 \
                   2> >(tee -a "$CLIENT_LOG" >&2)); then
        echo "[dnsmasq] dig FAILED" >> "$CLIENT_LOG"
        return 1
    fi
    # +short emits one line per A record. We expect exactly the one we
    # configured. Trim trailing whitespace from dig's output.
    out="${out%$'\n'}"
    if [[ "$out" != "192.0.2.10" ]]; then
        printf '[dnsmasq] unexpected answer: %q\n' "$out" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[dnsmasq] dig ok, A record matched" >> "$CLIENT_LOG"
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
        exec dnsmasq "${DNSMASQ_ARGS[@]}"
    ) &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[dnsmasq] FAIL: daemon did not start" >&2
        echo "--- daemon.log tail ---" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        echo "--- bridge.log tail ---" >&2
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi

    if run_client; then
        echo "[dnsmasq] PASS"
        return 0
    fi

    echo "[dnsmasq] FAIL: client check failed" >&2
    echo "--- daemon.log ---" >&2
    cat "$DAEMON_LOG" >&2 || true
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    echo "--- bridge.log ---" >&2
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
