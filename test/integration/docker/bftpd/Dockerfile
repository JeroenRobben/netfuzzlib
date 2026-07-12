# bftpd: small fork()-or-thread-per-connection FTP server.
#
# Build with: docker build -f test/integration/docker/bftpd/Dockerfile \
#                          -t netfuzzlib-test-bftpd .

FROM netfuzzlib-base

# bftpd is published as a tarball on SourceForge, so the pin is by
# version number rather than git SHA. SF release tarballs are immutable
# once published.
ARG BFTPD_VERSION=6.6
ARG BFTPD_TARBALL_URL=https://sourceforge.net/projects/bftpd/files/bftpd/bftpd-${BFTPD_VERSION}/bftpd-${BFTPD_VERSION}.tar.gz/download

WORKDIR /opt/bftpd
RUN curl -sSL --retry 3 -o bftpd.tar.gz "$BFTPD_TARBALL_URL" \
    && tar xzf bftpd.tar.gz \
    && cd bftpd \
    && ./configure --prefix=/usr/local --sysconfdir=/etc \
    && make \
    && install -m 755 bftpd /usr/local/bin/bftpd

# Anonymous read-only FTP rooted at /srv/ftp serving one known file.
# Port 2200 to match the lightftp slice (so the run.sh template is
# trivially copy-able) and a small fixed PASSIVE_PORTS range. Port 0
# would also work via the nfl_sock_listen callback, but pinning the
# range keeps the test scenario reproducible across containers.
# Written with printf rather than a heredoc: a `cat <<'EOF'` after a
# backslash-continued RUN silently produced a 0-byte config on the default
# Dockerfile frontend (no `# syntax=` directive), so bftpd fell back to its
# port-21 defaults. printf is frontend-independent. bftpd's parser needs one
# directive per line, which '%s\n' guarantees.
RUN mkdir -p /srv/ftp /var/run/bftpd \
    && printf 'hello from bftpd under nfl\n' > /srv/ftp/hello.txt \
    && printf '%s\n' \
        'global {' \
        '    DENY_LOGIN="no"' \
        '    PORT="2200"' \
        '    PASSIVE_PORTS="40020-40030"' \
        '    DATAPORT20="no"' \
        '    PATH_BFTPDUTMP=""' \
        '    XFER_BUFSIZE="2048"' \
        '    AUTO_CHDIR="yes"' \
        '}' \
        'user ftp {' \
        '    ANONYMOUS_USER="yes"' \
        '    DENY_LOGIN="no"' \
        '    ROOTDIR="/srv/ftp"' \
        '}' \
        'user anonymous {' \
        '    ALIAS="ftp"' \
        '}' \
        > /etc/bftpd.conf

COPY test/integration/docker/bftpd/run.sh /opt/nfl/targets/bftpd/run.sh
RUN chmod +x /opt/nfl/targets/bftpd/run.sh

ENV NFL_TARGET_NAME=bftpd \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/bftpd/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
