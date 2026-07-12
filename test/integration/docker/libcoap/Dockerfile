# libcoap: CoAP server (`coap-server-notls`) on UDP. Single-process
# event loop. Uses an internal control eventfd in epoll, which the nfl
# epoll shadow forwards onto the real kernel epoll.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libcoap3-bin \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/libcoap/run.sh /opt/nfl/targets/libcoap/run.sh
RUN chmod +x /opt/nfl/targets/libcoap/run.sh

ENV NFL_TARGET_NAME=libcoap \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/libcoap/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
