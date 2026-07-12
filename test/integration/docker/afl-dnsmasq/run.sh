#!/usr/bin/env bash
# afl-fuzz dnsmasq through libnfl-afl. Pass condition: afl-fuzz exited
# cleanly and the queue grew past the seed corpus (proves fuzz bytes are
# reaching the SUT and exercising new paths).

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
PORT="${DNSMASQ_PORT:-5300}"
TIME_BUDGET="${AFL_TIME_BUDGET:-60}"

PRELOAD="${NFL_LIB_DIR}/libnfl-afl.so"

# dnsmasq flags chosen to keep startup minimal under fuzzing:
#   --no-daemon / --keep-in-foreground   stay attached, no double-fork
#   --port=$PORT                         non-privileged
#   --listen-address=127.0.0.1           single bind, no interface scanning
#   --no-resolv --no-hosts --cache-size=0
#                                        skip /etc/resolv.conf, /etc/hosts,
#                                        and the in-memory cache. Nothing
#                                        the fuzzer can stumble into that
#                                        depends on host filesystem state
#   --user=root                          container is root, default user
#                                        "nobody" would setuid-drop and
#                                        fail without /etc/passwd entries
DAEMON_ARGS=(
    --no-daemon --keep-in-foreground
    --port="$PORT"
    --listen-address=127.0.0.1
    --no-resolv --no-hosts --cache-size=0
    --user=root
)

run_test() {
    : > "$DAEMON_LOG"
    local out_dir=/tmp/afl-out
    rm -rf "$out_dir"

    # No AFL_DEFER_FORKSRV here: dnsmasq's startup polls rtnetlink and
    # several other fds before it ever reaches the UDP recv on port
    # $PORT, and nfl's idle-poll liveness counter trips before we can
    # engage the deferred fork-server from inside nfl_receive. Auto-init
    # at main entry is per-iteration but works reliably. -m none keeps
    # AFL from clipping dnsmasq's address space, -t bumps the run
    # timeout for slower paths. Coverage map size override unblocks
    # AFL when the SUT's instrumentation reports more edges than the
    # default map can hold.
    AFL_NO_AFFINITY=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_PRELOAD="$PRELOAD" \
    NFL_PORT="$PORT" \
        afl-fuzz -i /opt/afl-dnsmasq/seeds -o "$out_dir" -V "$TIME_BUDGET" \
            -m none -t 5000 \
            -- /opt/dnsmasq "${DAEMON_ARGS[@]}" \
            >>"$DAEMON_LOG" 2>&1
    local rc=$?

    # Pass = afl-fuzz exited 0 (no harness error) AND found new corpus
    # entries. Seeds in /opt/afl-dnsmasq/seeds become entry index 0. Any
    # additional id:* file proves AFL drove the SUT through new edges
    # via fuzz bytes delivered through libnfl-afl.
    if [[ $rc -ne 0 ]]; then
        echo "[afl-dnsmasq] FAIL: afl-fuzz exited rc=$rc" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    local queue_count
    queue_count=$(find "$out_dir/default/queue" -maxdepth 1 -type f -name 'id:*' 2>/dev/null | wc -l)
    if [[ "$queue_count" -le 1 ]]; then
        echo "[afl-dnsmasq] FAIL: corpus did not grow (queue=$queue_count)" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    echo "[afl-dnsmasq] PASS: queue=$queue_count, rc=$rc"
    return 0
}
