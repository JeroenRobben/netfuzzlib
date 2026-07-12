# Net-SNMP snmpd: single-process UDP agent on port 161.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        snmpd \
        snmp \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/snmpd/run.sh /opt/nfl/targets/snmpd/run.sh
RUN chmod +x /opt/nfl/targets/snmpd/run.sh

ENV NFL_TARGET_NAME=snmpd \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/snmpd/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
