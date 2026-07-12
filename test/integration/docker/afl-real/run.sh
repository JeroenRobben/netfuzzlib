#!/usr/bin/env bash
# afl-fuzz the instrumented target under LD_PRELOAD=libnfl +
# libnfl-afl. The module synthesises one accept(), nfl_receive
# delivers AFL's test case as the inbound packet, the target either
# reaches the crash branch or exits cleanly.
#
# Pass = at least one crash file in the AFL output corpus.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
PORT="${TCP_AFL_PORT:-8095}"
# Empirically AFL hits the magic-bytes branch in 10–50 s. Budget set
# well above that so a slow scheduler doesn't flake the test.
TIME_BUDGET="${AFL_TIME_BUDGET:-180}"

PRELOAD="${NFL_LIB_DIR}/libnfl-afl.so"

run_test() {
    : > "$DAEMON_LOG"
    local out_dir=/tmp/afl-out
    rm -rf "$out_dir"

    # AFL_PRELOAD: applied to target child only (not afl-fuzz itself).
    # AFL_BENCH_UNTIL_CRASH: exit AFL the moment a crash is recorded.
    # AFL_NO_AFFINITY / AFL_SKIP_CPUFREQ: container-friendly defaults.
    # AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: skip the host /proc/sys
    #   core_pattern check. We can't change kernel.core_pattern from
    #   inside an unprivileged container.
    # AFL_DEFER_FORKSRV (single underscore): afl-fuzz's own knob,
    #   documented as "enforced deferred forkserver (__AFL_INIT is in a
    #   shared lib)". Two side effects, both required:
    #     1. afl-fuzz advertises shmem fuzzing in the handshake. Without
    #        it, the target's __afl_sharedmem_fuzzing=1 advertisement is
    #        ignored on afl-fuzz's side and fuzz bytes never reach
    #        __afl_fuzz_ptr (verified: 22% coverage, 0 crashes/30s).
    #     2. afl-fuzz `setenv`s __AFL_DEFER_FORKSRV=1 (double underscore)
    #        into the target's env. That's what afl-clang-fast's runtime
    #        reads to bail out of auto-init, and what libnfl-afl
    #        reads as the gate to call __afl_manual_init itself.
    #   Standard env inheritance does the propagation. Both vars
    #   inherit through afl-fuzz to the target and onward to every
    #   child of the SUT.
    AFL_NO_AFFINITY=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_BENCH_UNTIL_CRASH=1 \
    AFL_DEFER_FORKSRV=1 \
    AFL_PRELOAD="$PRELOAD" \
    NFL_PORT="$PORT" \
        afl-fuzz -i /opt/afl-real/seeds -o "$out_dir" -V "$TIME_BUDGET" \
            -- /opt/afl-real/afl_target \
            >>"$DAEMON_LOG" 2>&1
    local rc=$?

    local crash_count
    crash_count=$(find "$out_dir/default/crashes" -maxdepth 1 -type f -name 'id:*' 2>/dev/null | wc -l)
    if [[ "$crash_count" -lt 1 ]]; then
        echo "[afl-real] FAIL: afl-fuzz exited rc=$rc with no crashes after ${TIME_BUDGET}s" >&2
        echo "----- afl-fuzz tail -----" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi

    echo "[afl-real] PASS: AFL found $crash_count crash(es) (rc=$rc)"
    # Show one crash file's bytes for the log (should start with 'BUG!').
    local first_crash
    first_crash=$(find "$out_dir/default/crashes" -maxdepth 1 -type f -name 'id:*' | head -n 1)
    if [[ -n "$first_crash" ]]; then
        printf '[afl-real] first crash bytes: ' ; head -c 8 "$first_crash" | od -An -c | tr -s ' '
    fi
    return 0
}
