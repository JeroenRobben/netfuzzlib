#!/usr/bin/env bash
#
# Regenerate the checked-in fixtures for the ssh-keyscan replay test:
#
#   transcript.bin    the server->client bytes of one real SSH transport
#                     handshake (banner, KEXINIT, ECDH reply carrying the
#                     host key), up to where ssh-keyscan bails.
#   host_ed25519.pub  the ed25519 host key baked into that transcript. The
#                     test asserts the scanned key matches this.
#
# Why a static capture is valid: ssh-keyscan registers key_print_wrapper as
# its verify_host_key callback, which grabs the host key and returns -1 to
# ABORT the key exchange before any signature verification, during the ECDH
# reply, before NEWKEYS. So it never checks the signature over the exchange
# hash, and a recorded server side stays valid across runs even though the
# client's ephemeral key and KEXINIT cookie are random each time. No entropy
# control is needed.
#
# The KEX is pinned to curve25519-sha256 so the recorded ECDH reply has a
# fixed, version-independent structure that any modern ssh-keyscan negotiates.
#
# Requires: ssh-keygen, sshd, ssh-keyscan, python3. Runs sshd as a normal
# user on a high port, no root needed.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sshd_port=12222
proxy_port=12223

ssh-keygen -t ed25519 -N '' -C nfl-replay-fixture -f "$work/host" >/dev/null

/usr/bin/sshd -D -e -p "$sshd_port" -f /dev/null \
    -h "$work/host" \
    -o ListenAddress=127.0.0.1 -o PidFile=none -o UsePAM=no \
    -o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 \
    >"$work/sshd.log" 2>&1 &
sshd_pid=$!

python3 "$here/capture_proxy.py" "$proxy_port" "$sshd_port" "$here/transcript.bin" &
proxy_pid=$!
sleep 1

ssh-keyscan -t ed25519 -p "$proxy_port" 127.0.0.1 >/dev/null 2>&1 || true
sleep 0.5

kill "$sshd_pid" "$proxy_pid" 2>/dev/null || true
wait 2>/dev/null || true

cp "$work/host.pub" "$here/host_ed25519.pub"
echo "wrote transcript.bin ($(wc -c < "$here/transcript.bin") bytes) and host_ed25519.pub"
