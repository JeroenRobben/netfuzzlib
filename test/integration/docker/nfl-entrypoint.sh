#!/usr/bin/env bash
#
# Multi-mode entrypoint shared by every netfuzzlib docker test image.
# Per-target images set NFL_TARGET_RUN_SH (the test logic) and possibly
# NFL_TARGET_NAME, then exec this script.
#
# Modes:
#   test         - run the target's test scenario, exit non-zero on failure.
#                  This is the CI default.
#   shell        - start an interactive bash with the env preset and a
#                  banner showing how to invoke the daemon and the client
#                  manually. Used for `docker run -it ... shell`.
#   daemon-only  - run just the daemon side under LD_PRELOAD and block
#                  forever. Lets a developer `docker exec -it ... bash`
#                  in another window and poke at the live process.
#   client-only  - run just the client side. Assumes a daemon is already
#                  running (e.g. spawned by another container or
#                  daemon-only).
#   help         - print this list and exit 0.
#
# Note: the netfuzzlib libraries are NOT baked into the image. They're
# bind-mounted from the host's CMake build output by run-target.sh. If
# /opt/nfl/lib is empty, run `cmake --build <build-dir>` on the host
# before re-running the test.
#
# Logs go to $NFL_LOG_DIR (default /var/log/nfl) as daemon.log /
# client.log / bridge.log so a CI artifact upload picks them up
# regardless of which side broke.
#
# Per-target hook contract:
#   $NFL_TARGET_RUN_SH must be a script implementing two functions:
#       run_daemon   - exec the daemon under LD_PRELOAD. Must not return.
#       run_client   - drive the protocol from the client side, exit 0
#                      on success, non-zero on failure.

set -euo pipefail

NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"
NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_TARGET_NAME="${NFL_TARGET_NAME:-unknown}"

mkdir -p "$NFL_LOG_DIR"

print_help() {
    cat <<EOF
nfl-entrypoint — netfuzzlib docker test runner

Modes:
  test          run the target's scenario (CI default)
  shell         interactive shell with NFL_LIB_DIR + helpers preset
  daemon-only   run the daemon under nfl, block forever for inspection
  client-only   run only the client (assumes daemon is up elsewhere)
  help          print this banner

Environment:
  NFL_TARGET_NAME   = ${NFL_TARGET_NAME}
  NFL_LIB_DIR       = ${NFL_LIB_DIR}
  NFL_LOG_DIR       = ${NFL_LOG_DIR}
  NFL_TARGET_RUN_SH = ${NFL_TARGET_RUN_SH:-<unset>}

Logs land in \$NFL_LOG_DIR (daemon.log, client.log, bridge.log).
EOF
}

snapshot_netns() {
    # One-time snapshot of the container's network state, written into
    # bridge.log. When a test fails this is the first thing to look at.
    # It tells you whether the daemon got the IPs/ports it expected.
    {
        echo "=== nfl-entrypoint network snapshot ($(date -u +%FT%TZ)) ==="
        echo "--- ip addr ---"
        ip addr || true
        echo "--- ss -tlnu ---"
        ss -tlnu || true
        echo "--- /etc/resolv.conf ---"
        cat /etc/resolv.conf 2>/dev/null || true
        echo "--- LD_PRELOAD-ready libs in $NFL_LIB_DIR ---"
        ls -l "$NFL_LIB_DIR" || true
        echo "==="
    } >> "$NFL_LOG_DIR/bridge.log" 2>&1
}

mode="${1:-help}"
shift || true

case "$mode" in
    help)
        print_help
        exit 0
        ;;
    shell)
        snapshot_netns
        echo "[nfl] interactive shell — target=${NFL_TARGET_NAME}"
        echo "[nfl] libs available under \$NFL_LIB_DIR=$NFL_LIB_DIR:"
        ls -1 "$NFL_LIB_DIR"
        echo "[nfl] run the daemon manually with:"
        echo "      LD_PRELOAD=\$NFL_LIB_DIR/libnfl.so:\$NFL_LIB_DIR/libmodule-bridge-kernel.so <daemon> <args>"
        echo "[nfl] target run script: ${NFL_TARGET_RUN_SH:-<unset>}"
        export NFL_LIB_DIR NFL_LOG_DIR NFL_TARGET_NAME NFL_TARGET_RUN_SH
        exec /bin/bash
        ;;
    test|daemon-only|client-only)
        # Sanity-check: the libs must be mounted at this point. Fail
        # fast with a clear message rather than getting an opaque
        # ld.so error mid-test.
        if [[ ! -f "$NFL_LIB_DIR/libnfl.so" || \
              ! -f "$NFL_LIB_DIR/libmodule-bridge-kernel.so" ]]; then
            echo "[nfl] error: $NFL_LIB_DIR is empty or missing libs." >&2
            echo "[nfl] run-target.sh bind-mounts the host's CMake lib output here." >&2
            echo "[nfl] If you're invoking docker directly, pass:" >&2
            echo "[nfl]   -v <repo>/cmake-build-debug/lib:/opt/nfl/lib:ro" >&2
            exit 2
        fi
        if [[ -z "${NFL_TARGET_RUN_SH:-}" ]] || [[ ! -x "$NFL_TARGET_RUN_SH" ]]; then
            echo "[nfl] error: NFL_TARGET_RUN_SH is unset or not executable" >&2
            print_help
            exit 2
        fi
        snapshot_netns
        # The per-target script defines run_daemon / run_client. Source it
        # so we can dispatch on the mode.
        # shellcheck disable=SC1090
        source "$NFL_TARGET_RUN_SH"
        case "$mode" in
            test)        run_test "$@" ;;
            daemon-only) run_daemon "$@" ;;
            client-only) run_client "$@" ;;
        esac
        ;;
    *)
        echo "[nfl] unknown mode: $mode" >&2
        print_help
        exit 2
        ;;
esac
