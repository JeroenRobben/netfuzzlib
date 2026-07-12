#!/usr/bin/env bash
# LibAFL ForkserverExecutor driving dnsmasq via libnfl-afl. Pass
# condition: fuzzer ran for the time budget AND LibAFL's stats line
# reports more than LIBAFL_MIN_EXECS executions. That proves fuzz bytes
# made it through ForkserverExecutor -> __AFL_SHM_FUZZ_ID -> afl
# -> dnsmasq's recv path.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
PORT="${DNSMASQ_PORT:-5300}"
TIME_BUDGET="${LIBAFL_TIME_BUDGET:-30}"
MIN_EXECS="${LIBAFL_MIN_EXECS:-100}"

run_test() {
    : > "$DAEMON_LOG"
    local out_dir=/tmp/libafl-out
    rm -rf "$out_dir"
    mkdir -p "$out_dir"

    # Use the harness's own --max-time rather than wrapping with `timeout`.
    # External `timeout` would either (a) leave SimpleEventManager with no
    # graceful-shutdown path and lose buffered stats lines on SIGKILL, or
    # (b) re-raise the killing signal at the bash layer and bypass the
    # PASS/FAIL echo below. The Rust sidecar thread just calls
    # process::exit(0) when the deadline hits, so we get a clean rc=0.
    local rc=0
    /opt/libafl-fuzzer \
        --target /opt/dnsmasq \
        --nfl-lib-dir "$NFL_LIB_DIR" \
        --input /opt/libafl-dnsmasq/seeds \
        --output "$out_dir" \
        --port "$PORT" \
        --max-time "$TIME_BUDGET" \
        >>"$DAEMON_LOG" 2>&1 || rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "[libafl-dnsmasq] FAIL: fuzzer exited rc=$rc" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi

    # SimpleMonitor prints lines like
    #   [Stats #0] (GLOBAL) run time: 0h-0m-31s, ..., executions: 28104, exec/sec: ...
    # Take the largest 'executions:' across all stats lines.
    local max_execs
    max_execs=$(grep -oE 'executions: [0-9]+' "$DAEMON_LOG" \
                | awk '{print $2}' | sort -n | tail -1)
    max_execs=${max_execs:-0}

    if (( max_execs < MIN_EXECS )); then
        echo "[libafl-dnsmasq] FAIL: executions=$max_execs < min=$MIN_EXECS" >&2
        tail -n 80 "$DAEMON_LOG" >&2 || true
        return 1
    fi
    echo "[libafl-dnsmasq] PASS: executions=$max_execs, rc=$rc"
    return 0
}
