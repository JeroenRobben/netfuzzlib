# Kamailio: SIP server. We exercise just the UDP signalling path here:
# a one-shot OPTIONS request gets a 200 OK reply via the `sl` (stateless)
# core module. UDP-based, single-process under `fork=no`, so it sidesteps
# the fork-per-connection blocker that gates sshd / forked-daapd.
#
# Build with: docker build -f test/integration/docker/kamailio/Dockerfile \
#                          -t netfuzzlib-test-kamailio .

FROM netfuzzlib-base

# `kamailio` ships /usr/sbin/kamailio plus the core module set (sl, tm,
# rr, …) under /usr/lib/x86_64-linux-gnu/kamailio/modules/. We only need
# `sl.so` for stateless replies. `netcat-openbsd` is for the client.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        kamailio \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# No config file on disk. run.sh generates a minimal cfg per-run via
# heredoc so the test scenario stays in one place. The package's own
# /etc/kamailio/kamailio.cfg pulls in DB modules we don't need.

COPY test/integration/docker/kamailio/run.sh /opt/nfl/targets/kamailio/run.sh
RUN chmod +x /opt/nfl/targets/kamailio/run.sh

ENV NFL_TARGET_NAME=kamailio \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/kamailio/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
