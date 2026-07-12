# Mosquitto: MQTT broker. Default config is single-process event loop.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        mosquitto \
        mosquitto-clients \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/mosquitto/run.sh /opt/nfl/targets/mosquitto/run.sh
RUN chmod +x /opt/nfl/targets/mosquitto/run.sh

ENV NFL_TARGET_NAME=mosquitto \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/mosquitto/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
