# Pure-FTPd: fork-per-connection FTP server. Same architectural
# shape as bftpd and proftpd already in the suite (listener parent
# under nfl, forks a child per accept, child handles the FTP session
# in a single process). Adds a third forking-FTP daemon to the
# coverage matrix. Same protocol, distinct codebase and config
# style.
#
# Note on capabilities: pure-ftpd calls capset() during startup as
# a hardening step (drops everything except a small useful set). It
# aborts with "421 Unable to switch capabilities" on EPERM, which is
# exactly what Docker's default bounding set produces (CAP_SETPCAP
# is dropped). The per-target ./docker-args file requests
# `--cap-add=SETPCAP` from the run-target.sh wrapper so the daemon
# can complete its capset.
#
# Build with: docker build -f test/integration/docker/pure-ftpd/Dockerfile \
#                          -t netfuzzlib-test-pure-ftpd .

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pure-ftpd \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# pure-ftpd doesn't ship an `ftp` user. Anonymous login resolves the
# UserAlias to a real account. Create a minimal one with /tmp as
# home so the daemon's chroot lands somewhere readable.
RUN useradd -d /tmp -s /bin/false ftp 2>/dev/null || true

COPY test/integration/docker/pure-ftpd/run.sh /opt/nfl/targets/pure-ftpd/run.sh
RUN chmod +x /opt/nfl/targets/pure-ftpd/run.sh

ENV NFL_TARGET_NAME=pure-ftpd \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/pure-ftpd/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
