# Redis: single-threaded event loop, RESP text protocol over TCP.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        redis-server \
        redis-tools \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/redis/run.sh /opt/nfl/targets/redis/run.sh
RUN chmod +x /opt/nfl/targets/redis/run.sh

ENV NFL_TARGET_NAME=redis \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/redis/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
