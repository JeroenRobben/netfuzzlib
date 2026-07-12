# ssh-keyscan under nfl, driven by a prerecorded SSH server handshake.
#
# The SUT is OpenSSH ssh-keyscan under LD_PRELOAD + the replay module
# (module-replay). There is NO live peer: the replay module streams a
# checked-in transcript of one real SSH server's pre-NEWKEYS handshake
# (banner, KEXINIT, ECDH reply with the host key), and ssh-keyscan
# extracts and prints the host key.
#
# Why replay and not the kernel bridge: ssh-keyscan drives a non-blocking
# socket and poll()s for the server's reply. Against the bridge that reply
# is on a real kernel socket a network round-trip away, and nfl's poll does
# a single readiness probe without waiting, so it always reports "nothing"
# and keyscan gives up. The replay module makes the recorded bytes available
# synchronously, so the poll succeeds at once. It is also fully hermetic and
# deterministic: no sshd, no networking.
#
# ssh-keyscan never verifies the server's signature (it aborts the KEX the
# moment it has the host key), so the static transcript stays valid across
# runs with no entropy control. See capture.sh for how the fixtures are made.
#
# Build with: docker build -f test/integration/docker/ssh-keyscan/Dockerfile \
#                          -t netfuzzlib-test-ssh-keyscan .

FROM netfuzzlib-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Recorded server handshake + the host key it carries (the comparison
# source consumed by run.sh).
RUN mkdir -p /etc/nfl-ssh
COPY test/integration/docker/ssh-keyscan/transcript.bin /etc/nfl-ssh/transcript.bin
COPY test/integration/docker/ssh-keyscan/host_ed25519.pub /etc/nfl-ssh/host_ed25519.pub

COPY test/integration/docker/ssh-keyscan/run.sh /opt/nfl/targets/ssh-keyscan/run.sh
RUN chmod +x /opt/nfl/targets/ssh-keyscan/run.sh

ENV NFL_TARGET_NAME=ssh-keyscan \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/ssh-keyscan/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
