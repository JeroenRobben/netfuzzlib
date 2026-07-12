# memcached: in-memory KV store, ASCII text protocol over TCP.
# Default-shipped with worker threads (`-t N`). We force `-t 1` so
# everything funnels through a single accept-loop thread.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        memcached \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/memcached/run.sh /opt/nfl/targets/memcached/run.sh
RUN chmod +x /opt/nfl/targets/memcached/run.sh

ENV NFL_TARGET_NAME=memcached \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/memcached/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
