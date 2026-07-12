# ProFTPD: fork-per-connection FTP server. Same architectural shape
# as bftpd (already in the suite): listener parent under nfl, forks a
# child per accept, child handles the FTP control connection in a
# single process. We use anonymous login on a non-privileged port
# (2121) to keep the test self-contained. No /etc/passwd entries
# needed.
#
# What this adds vs bftpd: a second forking-FTP daemon proves the
# bridge handles the pattern across implementations, and ProFTPD's
# control-channel state machine is meaningfully different (multi-line
# 331 → 230 anonymous login challenge, configuration-driven Anonymous
# blocks, distinct response phrasing). It's incremental coverage, not
# a new protocol.
#
# Build with: docker build -f test/integration/docker/proftpd/Dockerfile \
#                          -t netfuzzlib-test-proftpd .

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        proftpd-basic \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Self-contained config:
#   - listens on 2121 (non-privileged), loopback only via the listen
#     socket binding the bridge sets up (Port directive is enough)
#   - anonymous login backed by the package-installed `ftp` user with
#     /tmp as the chroot (no real filesystem state needed)
#   - User/Group set to the package's `proftpd` user so the listener
#     drops privs after binding (matches Debian default behaviour)
# Written with printf, not a heredoc: this Dockerfile frontend does not support
# `cat <<'EOF'` and silently produced a 0-byte config, so proftpd aborted with
# "Could not find configuration file".
RUN printf '%s\n' \
    'ServerName              "nfl-test"' \
    'ServerType              standalone' \
    'DefaultServer           on' \
    'Port                    2121' \
    'UseIPv6                 off' \
    'User                    proftpd' \
    'Group                   nogroup' \
    'RequireValidShell       off' \
    'DefaultRoot             ~' \
    '' \
    '<Anonymous /tmp>' \
    '  User                  ftp' \
    '  Group                 nogroup' \
    '  UserAlias             anonymous ftp' \
    '  AnonRequirePassword   off' \
    '  <Limit LOGIN>' \
    '    AllowAll' \
    '  </Limit>' \
    '</Anonymous>' \
    > /opt/nfl-proftpd.conf

COPY test/integration/docker/proftpd/run.sh /opt/nfl/targets/proftpd/run.sh
RUN chmod +x /opt/nfl/targets/proftpd/run.sh

ENV NFL_TARGET_NAME=proftpd \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/proftpd/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
