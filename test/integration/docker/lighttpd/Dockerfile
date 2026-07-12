# lighttpd: small HTTP server. Single-process by default with one
# worker (`server.max-worker = 0`). Replaces what would have been thttpd
# (not packaged in Ubuntu 24.04).
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        lighttpd \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/lighttpd/run.sh /opt/nfl/targets/lighttpd/run.sh
RUN chmod +x /opt/nfl/targets/lighttpd/run.sh

ENV NFL_TARGET_NAME=lighttpd \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/lighttpd/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
