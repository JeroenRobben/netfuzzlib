# python3 -m http.server: does CPython's socket.socket / select event
# loop go through libc cleanly under LD_PRELOAD? CPython's `socket`
# module is a C extension that calls libc socket()/bind()/listen()/
# accept() directly, so the interceptors should fire. Single-process,
# single-threaded by default.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /tmp/pyhttp-root && echo "nfl-python-ok" > /tmp/pyhttp-root/index.html

COPY test/integration/docker/python-http/run.sh /opt/nfl/targets/python-http/run.sh
RUN chmod +x /opt/nfl/targets/python-http/run.sh

ENV NFL_TARGET_NAME=python-http \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/python-http/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
