# LightFTP: small single-binary FTP server, easy proof-of-concept target
# for the netfuzzlib bridge.
#
# Build with: docker build -f test/integration/docker/lightftp/Dockerfile \
#                          -t netfuzzlib-test-lightftp .
#       (run from the repo root.)
#
# The image runs the LightFTP server under LD_PRELOAD=libnfl.so:
# libmodule-bridge-kernel.so, then drives a real `curl` against it via FTP.
# Pass = curl exited 0 and the file content round-tripped.

FROM netfuzzlib-base

# LightFTP upstream, pinned. Bump intentionally so a build break is a
# code change, not a silent regression.
ARG LIGHTFTP_REPO=https://github.com/hfiref0x/LightFTP.git
ARG LIGHTFTP_REF=4ae857a8a16287e6808d67daf0088568424dded6

# LightFTP build deps. The upstream Makefile wires in -lgnutls
# unconditionally (see src/Release/makefile), so libgnutls28-dev is
# load-bearing.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgnutls28-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lightftp
RUN git init -q \
    && git fetch --depth 1 "$LIGHTFTP_REPO" "$LIGHTFTP_REF" \
    && git checkout -q FETCH_HEAD \
    && cd src/Release && make fftp \
    && install -m 755 fftp /usr/local/bin/lightftp

# A minimal config + filesystem layout the daemon expects. Anonymous
# read-only FTP rooted at /srv/ftp serving one known file. We bind to
# 127.0.0.1:2200 to avoid clashing with anything on the host's port 21
# inside an unprivileged container. The run script knows that port.
# pswd=* matches any password (curl's anonymous password); accs=readonly allows
# USER, PASS, list, RETR, QUIT but blocks uploads; root= is the FTP root.
# Written with printf, not a heredoc: a `cat <<'EOF'` after a backslash-continued
# RUN silently produced a 0-byte config on the default Dockerfile frontend (no
# `# syntax=` directive), so the daemon never came up on 2200.
RUN mkdir -p /srv/ftp \
    && printf 'hello from lightftp under nfl\n' > /srv/ftp/hello.txt \
    && printf '%s\n' \
        '[ftpconfig]' \
        'port=2200' \
        'maxusers=2' \
        'interface=127.0.0.1' \
        'external_ip=127.0.0.1' \
        'local_mask=255.255.255.0' \
        'minport=40000' \
        'maxport=40010' \
        'keepalive=0' \
        'follow_symlinks=0' \
        '[anonymous]' \
        'pswd=*' \
        'accs=readonly' \
        'root=/srv/ftp' \
        > /etc/fftp.conf

# Per-target run script.
COPY test/integration/docker/lightftp/run.sh /opt/nfl/targets/lightftp/run.sh
RUN chmod +x /opt/nfl/targets/lightftp/run.sh

ENV NFL_TARGET_NAME=lightftp \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/lightftp/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
