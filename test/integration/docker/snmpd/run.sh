#!/usr/bin/env bash
# Net-SNMP snmpd: UDP, single-process. snmpwalk public-community for
# sysDescr.0 and check we get a non-empty STRING reply.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
SNMP_PORT="${SNMP_PORT:-1161}"
SNMP_HOST="${SNMP_HOST:-127.0.0.1}"
CONF="${SNMPD_CONF:-/tmp/snmpd-nfl.conf}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

write_config() {
    cat > "$CONF" <<EOF
rocommunity public 127.0.0.1
sysLocation "nfl-test"
sysContact "nfl@test"
sysName "nfl-snmpd"
EOF
}

# -f foreground, -Lo log to stderr, -u root keeps us privileged in container,
# -C uses our minimal config (skip /etc/snmp/snmpd.conf), bind UDP only.
SNMP_ARGS=(-f -Lo -u root -C -c "$CONF" "udp:${SNMP_HOST}:${SNMP_PORT}")

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -uln "sport = :${SNMP_PORT}" 2>/dev/null | grep -q UNCONN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_client() {
    local out
    # Numeric OID for sysName.0. Package's MIB downloader is missing,
    # so symbolic names ("sysDescr.0") fail client-side parsing. The
    # daemon itself replies fine. We just check we get a STRING back.
    out=$(timeout 5 snmpget -v2c -c public -On -t 2 -r 0 \
            "${SNMP_HOST}:${SNMP_PORT}" 1.3.6.1.2.1.1.5.0 2>>"$CLIENT_LOG") || true
    printf '%s\n' "$out" >> "$CLIENT_LOG"
    grep -qE 'STRING:.+nfl-snmpd' <<< "$out" || return 1
    return 0
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    write_config
    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/sbin/snmpd "${SNMP_ARGS[@]}"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[snmpd] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[snmpd] PASS"; return 0; fi
    echo "[snmpd] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
