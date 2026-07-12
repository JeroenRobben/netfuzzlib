#!/usr/bin/env bash
# Mosquitto MQTT broker. mosquitto_pub does CONNECT/PUBLISH/DISCONNECT in
# one shot. We just check it returns success.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
MQTT_PORT="${MQTT_PORT:-1883}"
MQTT_HOST="${MQTT_HOST:-127.0.0.1}"
CONF="${MOSQUITTO_CONF:-/tmp/mosquitto-nfl.conf}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-bridge-kernel.so"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"
BRIDGE_LOG="${NFL_LOG_DIR}/bridge.log"

write_config() {
    cat > "$CONF" <<EOF
listener ${MQTT_PORT} ${MQTT_HOST}
allow_anonymous true
persistence false
log_dest stderr
EOF
}

wait_for_listener() {
    local deadline=$(( $(date +%s) + 10 ))
    while (( $(date +%s) < deadline )); do
        if ss -tln "sport = :${MQTT_PORT}" 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

run_client() {
    timeout 5 mosquitto_pub -h "$MQTT_HOST" -p "$MQTT_PORT" \
        -t test/topic -m hello -q 0 2>>"$CLIENT_LOG"
    local rc=$?
    echo "mosquitto_pub rc=$rc" >> "$CLIENT_LOG"
    return "$rc"
}

run_test() {
    : > "$DAEMON_LOG"; : > "$CLIENT_LOG"
    write_config
    daemon_pid=""
    trap 'if [[ -n "${daemon_pid:-}" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi' EXIT

    (
        export LD_PRELOAD="$PRELOAD"
        export NFL_BRIDGE_LOG="$BRIDGE_LOG"
        exec /usr/sbin/mosquitto -c "$CONF"
    ) >> "$DAEMON_LOG" 2>&1 &
    daemon_pid=$!

    if ! wait_for_listener; then
        echo "[mosquitto] FAIL: daemon did not start" >&2
        tail -n 40 "$DAEMON_LOG" >&2 || true
        tail -n 40 "$BRIDGE_LOG" >&2 || true
        return 1
    fi
    if run_client; then echo "[mosquitto] PASS"; return 0; fi
    echo "[mosquitto] FAIL: client failed" >&2
    cat "$DAEMON_LOG" >&2 || true
    cat "$CLIENT_LOG" >&2 || true
    cat "$BRIDGE_LOG" >&2 || true
    return 1
}
