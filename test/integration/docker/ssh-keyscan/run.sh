#!/usr/bin/env bash
#
# ssh-keyscan target driver, sourced by /opt/nfl/bin/nfl-entrypoint.
#
# No live peer: ssh-keyscan runs under LD_PRELOAD + the replay module,
# which streams a prerecorded SSH server handshake (transcript.bin). We
# assert the printed host key matches the ed25519 key baked into that
# transcript (host_ed25519.pub). See Dockerfile / capture.sh for why a
# static transcript is valid and why this replaces the kernel bridge.

set -uo pipefail

NFL_LIB_DIR="${NFL_LIB_DIR:-/opt/nfl/lib}"
NFL_LOG_DIR="${NFL_LOG_DIR:-/var/log/nfl}"

TRANSCRIPT="${NFL_REPLAY_TRANSCRIPT:-/etc/nfl-ssh/transcript.bin}"
EXPECTED_PUB="${SSH_KEYSCAN_EXPECTED_PUB:-/etc/nfl-ssh/host_ed25519.pub}"
# Arbitrary: no real listener, the replay module ignores the address.
SCAN_HOST="${SCAN_HOST:-127.0.0.1}"
SCAN_PORT="${SCAN_PORT:-2223}"

PRELOAD="${NFL_LIB_DIR}/libnfl.so:${NFL_LIB_DIR}/libmodule-replay.so"
CLIENT_LOG="${NFL_LOG_DIR}/client.log"

run_client() {
    echo "[ssh-keyscan] running ssh-keyscan under nfl + replay module" \
        | tee -a "$CLIENT_LOG"
    # ssh-keyscan flags:
    #   -t ed25519   only the algorithm the transcript carries.
    #   -T 5         connect+banner timeout (a bound; replay is immediate).
    #   -p PORT      match the address in the run (cosmetic under replay).
    # Output line shape (stdout): `[127.0.0.1]:2223 ssh-ed25519 AAAA…`
    local out
    if ! out=$(LD_PRELOAD="$PRELOAD" \
               NFL_REPLAY_TRANSCRIPT="$TRANSCRIPT" \
               timeout 10 ssh-keyscan -t ed25519 -T 5 \
                   -p "${SCAN_PORT}" "${SCAN_HOST}" \
                   2>>"$CLIENT_LOG"); then
        echo "[ssh-keyscan] ssh-keyscan FAILED" >> "$CLIENT_LOG"
        return 1
    fi
    local scanned_key
    scanned_key=$(awk '/ ssh-ed25519 /{print $3; exit}' <<< "$out")
    if [[ -z "$scanned_key" ]]; then
        printf '[ssh-keyscan] no ed25519 key in keyscan output:\n%s\n' "$out" \
            >> "$CLIENT_LOG"
        return 1
    fi
    local expected_key
    expected_key=$(awk '{print $2}' "$EXPECTED_PUB")
    if [[ "$scanned_key" != "$expected_key" ]]; then
        printf '[ssh-keyscan] key mismatch.\n  scanned : %s\n  expected: %s\n' \
            "$scanned_key" "$expected_key" >> "$CLIENT_LOG"
        return 1
    fi
    echo "[ssh-keyscan] ok, host key matched" >> "$CLIENT_LOG"
    return 0
}

# daemon-only debug mode has nothing to run: there is no live peer.
run_daemon() {
    echo "[ssh-keyscan] no daemon: this target replays a recorded transcript" >&2
    sleep infinity
}

run_test() {
    : > "$CLIENT_LOG"
    if run_client; then
        echo "[ssh-keyscan] PASS"
        return 0
    fi
    echo "[ssh-keyscan] FAIL: client check failed" >&2
    echo "--- client.log ---" >&2
    cat "$CLIENT_LOG" >&2 || true
    return 1
}
