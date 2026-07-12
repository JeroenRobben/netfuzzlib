# rsyslog: UDP/TCP syslog receiver. Multi-threaded by default but the
# `imudp` worker pool is configurable. We start with a single-process
# config and a UDP listener. If it threads internally and breaks under
# nfl, we'll bail out.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        rsyslog \
        bsdutils \
    && rm -rf /var/lib/apt/lists/*

COPY test/integration/docker/rsyslog/run.sh /opt/nfl/targets/rsyslog/run.sh
RUN chmod +x /opt/nfl/targets/rsyslog/run.sh

ENV NFL_TARGET_NAME=rsyslog \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/rsyslog/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
