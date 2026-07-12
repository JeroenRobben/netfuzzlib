# rsync daemon, fork-per-connection. Same shape as bftpd / pure-ftpd.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        rsync \
    && rm -rf /var/lib/apt/lists/*

# Module exposing /tftproot equivalent.
RUN mkdir -p /srv/rsync-test && echo "nfl-rsync-ok" > /srv/rsync-test/file.txt

COPY test/integration/docker/rsync/run.sh /opt/nfl/targets/rsync/run.sh
RUN chmod +x /opt/nfl/targets/rsync/run.sh

ENV NFL_TARGET_NAME=rsync \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/rsync/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
