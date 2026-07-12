# AFL-fuzz dnsmasq's DNS UDP path. Builds dnsmasq from upstream source
# with afl-clang-fast for coverage instrumentation, runs afl-fuzz with
# libnfl + libnfl-afl AFL_PRELOAD'd. Pass condition: AFL ran
# the time budget cleanly and grew the corpus past the seed.
#
# Real bug-finding on a hardened daemon would need a much longer budget
# (and probably ASan). This entry is the smoke test that proves the AFL
# harness drives a non-trivial daemon end-to-end.

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        afl++ \
        libclang-rt-17-dev \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build
# Pinned tarball. Upstream serves stable archives by version. We don't
# want a moving "latest" because a build break would otherwise become a
# silent regression of this test.
ARG DNSMASQ_VERSION=2.91
RUN wget -q "https://thekelleys.org.uk/dnsmasq/dnsmasq-${DNSMASQ_VERSION}.tar.gz" \
    && tar xzf "dnsmasq-${DNSMASQ_VERSION}.tar.gz"

RUN cd "dnsmasq-${DNSMASQ_VERSION}" \
    && make -j"$(nproc)" CC=afl-clang-fast \
    && cp src/dnsmasq /opt/dnsmasq

# Seed corpus: one minimal DNS query (header + 1-label question for "a.").
COPY test/integration/docker/afl-dnsmasq/seeds/ /opt/afl-dnsmasq/seeds/

COPY test/integration/docker/afl-dnsmasq/run.sh /opt/nfl/targets/afl-dnsmasq/run.sh
RUN chmod +x /opt/nfl/targets/afl-dnsmasq/run.sh

ENV NFL_TARGET_NAME=afl-dnsmasq \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/afl-dnsmasq/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
