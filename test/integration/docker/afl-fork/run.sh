#!/usr/bin/env bash
# Drive the AFL module's accept+fork tracker without a real AFL runtime.
# Pass condition: the daemon log contains the tracker's reap line for
# every child the SUT forked.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"

DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"
PORT="${TCP_FORK_PORT:-8090}"

PRELOAD="${NFL_LIB_DIR}/libnfl-afl.so"

run_daemon() {
    : > "$DAEMON_LOG"
    LD_PRELOAD="$PRELOAD" \
        NFL_PORT="$PORT" \
        TCP_FORK_PORT="$PORT" \
        /opt/afl-fork/tcp_fork_server
}

run_test() {
    : > "$DAEMON_LOG"
    # Single-shot run: the AFL module orchestrates the whole lifecycle:
    # fake-accept once, let the SUT fork, then go idle. Nothing external to
    # start. We just exec the daemon and assert on the log.
    run_daemon >>"$DAEMON_LOG" 2>&1
    local rc=$?
    # Once all sockets are idle, nfl_socket_idle() reaps the tracked children
    # and calls exit(0). So a successful run leaves rc=0. Anything else is a
    # regression.
    if [[ $rc -ne 0 ]]; then
        echo "[afl-fork] FAIL: daemon exited with rc=$rc" >&2
        cat "$DAEMON_LOG" >&2 || true
        return 1
    fi
    if ! grep -q "first accept granted" "$DAEMON_LOG"; then
        echo "[afl-fork] FAIL: module did not record a successful first accept" >&2
        cat "$DAEMON_LOG" >&2 || true
        return 1
    fi
    if ! grep -q "afl: all sockets idle, reaping" "$DAEMON_LOG"; then
        echo "[afl-fork] FAIL: module's nfl_socket_idle reaping path did not fire" >&2
        cat "$DAEMON_LOG" >&2 || true
        return 1
    fi
    if ! grep -Eq "afl tracker: reaped pid [0-9]+" "$DAEMON_LOG"; then
        echo "[afl-fork] FAIL: tracker did not reap any child" >&2
        cat "$DAEMON_LOG" >&2 || true
        return 1
    fi
    # Cross-check: every "forked child <pid>" the SUT logged should match
    # a "reaped pid <pid>" line from the tracker.
    local missing=0
    while read -r pid; do
        if ! grep -q "reaped pid ${pid}" "$DAEMON_LOG"; then
            echo "[afl-fork] FAIL: child pid ${pid} forked but not reaped" >&2
            missing=1
        fi
    done < <(grep -oE "forked child [0-9]+" "$DAEMON_LOG" | awk '{print $3}')
    if [[ $missing -ne 0 ]]; then
        cat "$DAEMON_LOG" >&2 || true
        return 1
    fi
    echo "[afl-fork] PASS"
    return 0
}
