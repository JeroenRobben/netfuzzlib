# AFL-fuzz redis-server's RESP TCP path. Builds redis from upstream
# source with afl-clang-fast, runs afl-fuzz with libnfl +
# libnfl-afl AFL_PRELOAD'd. Pass: AFL exited cleanly and grew the
# corpus past the seeds.

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        afl++ \
        libclang-rt-17-dev \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build
# Pin a known-good redis release. 7.4.x is current stable. The source
# tarball builds with a stock C toolchain and pulls no external deps.
ARG REDIS_VERSION=7.4.5
RUN wget -q "https://github.com/redis/redis/archive/refs/tags/${REDIS_VERSION}.tar.gz" \
        -O "redis-${REDIS_VERSION}.tar.gz" \
    && tar xzf "redis-${REDIS_VERSION}.tar.gz"

# MALLOC=libc skips jemalloc (would otherwise need its own instrumented
# build). BUILD_TLS=no skips OpenSSL. OPT override drops -flto: redis's
# default opt set includes LTO, which conflicts with afl-clang-fast's
# sancov instrumentation (linker errors about discarded ctor sections).
RUN cd "redis-${REDIS_VERSION}" \
    && make -j"$(nproc)" CC=afl-clang-fast MALLOC=libc BUILD_TLS=no \
        OPT='-O2 -fno-omit-frame-pointer -g' \
    && cp src/redis-server /opt/redis-server

# Two seeds: the inline-form PING and the RESP-2 array form.
COPY test/integration/docker/afl-redis/seeds/ /opt/afl-redis/seeds/

COPY test/integration/docker/afl-redis/run.sh /opt/nfl/targets/afl-redis/run.sh
RUN chmod +x /opt/nfl/targets/afl-redis/run.sh

ENV NFL_TARGET_NAME=afl-redis \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/afl-redis/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
