# curl as SUT: exercises nfl's *client*-side bridge path (nfl_tcp_connect,
# nfl_send, nfl_receive over a real kernel socket). A python http.server
# runs in the same container as the unmodified peer. curl runs under
# LD_PRELOAD=libnfl + libmodule-bridge-kernel and fetches a
# canned page over real loopback.

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
    && rm -rf /var/lib/apt/lists/*

# curl is already installed in netfuzzlib-base.

# Static page the python http.server will serve.
RUN mkdir -p /tmp/curl-root && echo "nfl-curl-ok" > /tmp/curl-root/index.html

COPY test/integration/docker/curl/run.sh /opt/nfl/targets/curl/run.sh
RUN chmod +x /opt/nfl/targets/curl/run.sh

ENV NFL_TARGET_NAME=curl \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/curl/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
