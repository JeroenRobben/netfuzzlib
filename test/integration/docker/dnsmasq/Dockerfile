# dnsmasq: small DNS/DHCP server. We exercise just the DNS half here:
# UDP port serves a static A record, driven by `dig` over the kernel
# bridge (the daemon's nfl UDP socket forwards to a real kernel UDP
# socket bound on the same address/port via the bridge module).
#
# Build with: docker build -f test/integration/docker/dnsmasq/Dockerfile \
#                          -t netfuzzlib-test-dnsmasq .

FROM netfuzzlib-base

# `dnsmasq-base` ships just the binary (no init scripts, no /etc default
# files we'd have to fight). `dnsutils` provides `dig`. Both are pinned
# implicitly to the Ubuntu 24.04 repository state. The base image is
# rebuilt on apt-cache invalidation, so this matches the base's libc.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dnsmasq-base \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# No config file on disk. Every option lives on the dnsmasq command
# line (see run.sh). That keeps the test scenario obvious from one place
# and avoids dragging in /etc/dnsmasq.conf defaults from the package.

COPY test/integration/docker/dnsmasq/run.sh /opt/nfl/targets/dnsmasq/run.sh
RUN chmod +x /opt/nfl/targets/dnsmasq/run.sh

ENV NFL_TARGET_NAME=dnsmasq \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/dnsmasq/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
