#!/usr/bin/env bash
# afl-fuzz redis-server. Pass = afl-fuzz exited cleanly + corpus grew.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
PORT="${REDIS_PORT:-6379}"
TIME_BUDGET="${AFL_TIME_BUDGET:-60}"

PRELOAD="${NFL_LIB_DIR}/libnfl-afl.so"

# redis-server flags chosen to keep startup deterministic and small:
#   --port $PORT             non-privileged
#   --bind 127.0.0.1         single bind, no interface scanning
#   --daemonize no           stay in foreground
#   --save ""                disable RDB snapshots (no background fork)
#   --appendonly no          no AOF persistence
#   --logfile ""             stderr only, no file ops
#   --protected-mode no      bind-only safety bypass. We control the
#                            network model, no real exposure
DAEMON_ARGS=(
    --port "$PORT"
    --bind 127.0.0.1
    --daemonize no
    --save ""
    --appendonly no
    --logfile ""
    --protected-mode no
)

run_test() {
    : > "$DAEMON_LOG"
    local out_dir=/tmp/afl-out
    rm -rf "$out_dir"

    # No AFL_DEFER_FORKSRV, same reason as afl-dnsmasq: redis's startup
    # path makes several poll cycles before reaching the first TCP
    # accept on $PORT, and nfl's liveness counter would trip before
    # the deferred fork-server engaged. Auto-init at main is reliable
    # and the per-iteration cost is acceptable for a smoke test.
    AFL_NO_AFFINITY=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_PRELOAD="$PRELOAD" \
    NFL_PORT="$PORT" \
        afl-fuzz -i /opt/afl-redis/seeds -o "$out_dir" -V "$TIME_BUDGET" \
            -m none -t 5000 \
            -- /opt/redis-server "${DAEMON_ARGS[@]}" \
            >>"$DAEMON_LOG" 2>&1
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "[afl-redis] FAIL: afl-fuzz exited rc=$rc" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    local queue_count seed_count
    queue_count=$(find "$out_dir/default/queue" -maxdepth 1 -type f -name 'id:*' 2>/dev/null | wc -l)
    seed_count=$(find /opt/afl-redis/seeds -maxdepth 1 -type f 2>/dev/null | wc -l)
    if [[ "$queue_count" -le "$seed_count" ]]; then
        echo "[afl-redis] FAIL: corpus did not grow (queue=$queue_count seeds=$seed_count)" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    echo "[afl-redis] PASS: queue=$queue_count, rc=$rc"
    return 0
}
