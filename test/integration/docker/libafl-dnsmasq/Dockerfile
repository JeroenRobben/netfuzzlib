# LibAFL ForkserverExecutor driving an afl-clang-fast'd dnsmasq through
# netfuzzlib's afl. Same SUT-side pipeline as afl-dnsmasq. The
# only difference is the driver, a Rust binary built on the LibAFL
# crate instead of afl-fuzz. Confirms LibAFL's forkserver speaks the
# same wire protocol afl already handles (no new module needed).
#
# Pass = the harness ran for the time budget AND LibAFL's stats line
# reports > LIBAFL_MIN_EXECS executions, proving fuzz bytes are
# reaching the SUT through afl.

# --- stage 1: build the LibAFL Rust harness --------------------------
# Pinned to rust:1.87 because libafl 0.15.4 declares rustc 1.87 as its MSRV
# (1.85 only buys you the 2024 edition, libafl itself wants newer).
# Ubuntu 24.04's stock rustc (1.75) is too old. A dedicated stage
# keeps the heavyweight toolchain out of the final image and lets
# Docker cache the slow `cargo build`.
FROM rust:1.87-slim-bookworm AS rust-builder
WORKDIR /build
# Source is COPY'd from the public examples/ tree as-is. This image
# build is also a smoke test that the published example still compiles.
COPY examples/libafl-forkserver-dnsmasq/ ./
RUN cargo build --release \
    && strip target/release/libafl-forkserver-dnsmasq

# --- stage 2: SUT + test runner --------------------------------------
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        afl++ \
        libclang-rt-17-dev \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build
# Pinned dnsmasq release, matching afl-dnsmasq. Floating "latest" would
# make a silent upstream change look like a regression of this test.
ARG DNSMASQ_VERSION=2.91
RUN wget -q "https://thekelleys.org.uk/dnsmasq/dnsmasq-${DNSMASQ_VERSION}.tar.gz" \
    && tar xzf "dnsmasq-${DNSMASQ_VERSION}.tar.gz" \
    && cd "dnsmasq-${DNSMASQ_VERSION}" \
    && make -j"$(nproc)" CC=afl-clang-fast \
    && cp src/dnsmasq /opt/dnsmasq

COPY --from=rust-builder /build/target/release/libafl-forkserver-dnsmasq /opt/libafl-fuzzer

COPY test/integration/docker/libafl-dnsmasq/seeds/ /opt/libafl-dnsmasq/seeds/
COPY test/integration/docker/libafl-dnsmasq/run.sh /opt/nfl/targets/libafl-dnsmasq/run.sh
RUN chmod +x /opt/nfl/targets/libafl-dnsmasq/run.sh

ENV NFL_TARGET_NAME=libafl-dnsmasq \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/libafl-dnsmasq/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
