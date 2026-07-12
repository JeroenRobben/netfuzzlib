#!/usr/bin/env bash
# afl-fuzz curl with libnfl-afl in client mode. nfl_tcp_connect
# accepts curl's connect to 127.0.0.1:$PORT synthetically. nfl_receive
# delivers AFL's test case as the HTTP response curl will parse.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
PORT="${HTTP_PORT:-80}"
TIME_BUDGET="${AFL_TIME_BUDGET:-60}"

PRELOAD="${NFL_LIB_DIR}/libnfl-afl.so"

run_test() {
    : > "$DAEMON_LOG"
    local out_dir=/tmp/afl-out
    rm -rf "$out_dir"

    # curl is a TCP client: the module infers that from its connect() to
    # NFL_PORT and delivers the fuzz bytes as the response. -m none / -t 5000
    # same rationale as the daemon AFL targets: keep AFL from clipping the SUT.
    AFL_NO_AFFINITY=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_PRELOAD="$PRELOAD" \
    NFL_PORT="$PORT" \
        afl-fuzz -i /opt/afl-curl/seeds -o "$out_dir" -V "$TIME_BUDGET" \
            -m none -t 5000 \
            -- /opt/curl -sS --max-time 3 "http://127.0.0.1:${PORT}/" \
            >>"$DAEMON_LOG" 2>&1
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "[afl-curl] FAIL: afl-fuzz exited rc=$rc" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    local queue_count seed_count
    queue_count=$(find "$out_dir/default/queue" -maxdepth 1 -type f -name 'id:*' 2>/dev/null | wc -l)
    seed_count=$(find /opt/afl-curl/seeds -maxdepth 1 -type f 2>/dev/null | wc -l)
    if [[ "$queue_count" -le "$seed_count" ]]; then
        echo "[afl-curl] FAIL: corpus did not grow (queue=$queue_count seeds=$seed_count)" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    echo "[afl-curl] PASS: queue=$queue_count, rc=$rc"
    return 0
}
