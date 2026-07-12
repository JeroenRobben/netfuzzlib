#!/usr/bin/env bash
#
# programs target dispatches to one of the pre-built binaries in
# /opt/programs/. Selected at run time via env vars so we get one
# image and many ctest entries.
#
# Required env (set by the CTest entry):
#   NFL_PROGRAM   binary name under /opt/programs (e.g. libevent_udp_echo)
#   NFL_SCENARIO  scenario filename under /opt/programs/scenarios
#                 (e.g. udp_echo.txt)
# Optional:
#   NFL_BACKEND   passed as argv[1] to the binary (libevent / libev only)

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"

DAEMON_LOG="${NFL_LOG_DIR}/daemon.log"

PROG="/opt/programs/${NFL_PROGRAM:?NFL_PROGRAM not set}"
SCEN="/opt/programs/scenarios/${NFL_SCENARIO:?NFL_SCENARIO not set}"

if [[ ! -x "$PROG" ]]; then
    echo "[programs] missing binary: $PROG" >&2
    return 1
fi
if [[ ! -f "$SCEN" ]]; then
    echo "[programs] missing scenario: $SCEN" >&2
    return 1
fi

# The scripted module is bind-mounted via /opt/nfl/lib alongside libnfl
# (see run-target.sh). We don't need the bridge here. These are SUT-side
# tests where the scripted module replays canned traffic.
PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-test-scripted.so"

run_test() {
    : > "$DAEMON_LOG"
    args=()
    [[ -n "${NFL_BACKEND:-}" ]] && args+=("$NFL_BACKEND")
    LD_PRELOAD="$PRELOAD" \
        NFL_TEST_SCENARIO="$SCEN" \
        "$PROG" "${args[@]}" >> "$DAEMON_LOG" 2>&1
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "[programs/$NFL_PROGRAM${NFL_BACKEND:+/$NFL_BACKEND}] PASS"
        return 0
    fi
    echo "[programs/$NFL_PROGRAM${NFL_BACKEND:+/$NFL_BACKEND}] FAIL (rc=$rc)" >&2
    cat "$DAEMON_LOG" >&2 || true
    return 1
}
