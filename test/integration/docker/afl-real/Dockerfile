# Real-AFL integration test: drives the tiny TCP target in src/ under
# afl-fuzz with libnfl + libnfl-afl AFL_PRELOAD'd. Pass = AFL
# finds the magic-bytes crash inside the time budget.
#
# Cold-cache cost: ~30 s for `apt install afl++` on the netfuzzlib-base.
# Warm-cache: ~5 s. Runtime budget itself is 60 s of fuzzing.

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        afl++ \
        llvm \
        libclang-rt-17-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/afl-real
COPY test/integration/docker/afl-real/src/afl_target.c /opt/afl-real/

# afl-clang-fast inserts the fork-server entry + coverage instrumentation.
# Without instrumentation AFL falls back to dumb fuzzing (no feedback) and
# would never find a 4-byte magic in a 60 s budget.
RUN AFL_USE_ASAN=0 afl-clang-fast -O0 -g \
        -o /opt/afl-real/afl_target \
        /opt/afl-real/afl_target.c

# Single 1-byte seed. AFL needs at least one corpus file to start.
RUN mkdir -p /opt/afl-real/seeds && printf 'a' > /opt/afl-real/seeds/seed

COPY test/integration/docker/afl-real/run.sh /opt/nfl/targets/afl-real/run.sh
RUN chmod +x /opt/nfl/targets/afl-real/run.sh

ENV NFL_TARGET_NAME=afl-real \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/afl-real/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
