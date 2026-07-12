# tinydtls, a small DTLS implementation from Eclipse, common
# fuzzing/testing target for IoT-class TLS code. Exercises a full DTLS
# handshake over UDP (cookie exchange, fragmented client/server hello,
# record-layer protection), substantively different from openssl
# s_server's TLS-over-TCP.
#
# We build from the upstream eclipse/tinydtls repo at a pinned commit.
# tinydtls ships an `examples/` subdirectory with `dtls-server` and
# `dtls-client` binaries that share PSK identities baked into the
# example config, sufficient for a closed-loop echo test.
#
# Build with: docker build -f test/integration/docker/tinydtls/Dockerfile \
#                          -t netfuzzlib-test-tinydtls .

FROM netfuzzlib-base

# autoreconf is in autoconf/automake/libtool. The project's autogen.sh
# expects them on PATH. pkg-config is needed because configure.ac
# references PKG_CHECK_MODULES (gated by --enable-tests=yes, which we
# don't pass, but the macro must still expand at autoconf time, else
# configure errors with `syntax error near unexpected token CUNIT`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        libtool \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Pin to a specific commit so a tinydtls upstream change can't silently
# break this test. Bump deliberately when needed.
ARG TINYDTLS_REPO=https://github.com/eclipse/tinydtls.git
ARG TINYDTLS_REF=f5e0ca7f10202225a277d4ea675203f77fe0d77c

WORKDIR /opt/tinydtls
# Patches for Ubuntu 24.04's autoconf 2.71 strictness:
#   1. AC_CONFIG_HEADERS lives at line 140 in upstream, AFTER the first
#      AC_DEFINE call at line 73. Modern autoconf rejects this with
#      "possibly undefined macro: AC_DEFINE". Hoist it to right after
#      AC_INIT and drop the late copy.
#   2. AC_DEFINE inside AC_ARG_WITH's action-if-not-given branches still
#      doesn't expand cleanly under autoconf 2.71 (m4 quoting rules
#      changed). m4_pattern_allow whitelists AC_DEFINE so the strict
#      pattern check doesn't trip on the literal string surviving in
#      configure output.
RUN git init -q \
    && git remote add origin "$TINYDTLS_REPO" \
    && git fetch --depth 1 origin "$TINYDTLS_REF" \
    && git checkout -q FETCH_HEAD \
    && sed -i '/^AC_CONFIG_HEADERS(\[dtls_config\.h\])$/d' configure.ac \
    && sed -i '/^AC_INIT(/a m4_pattern_allow([^AC_DEFINE$])\nAC_CONFIG_HEADERS([dtls_config.h])' configure.ac \
    && ./autogen.sh \
    && ./configure --without-debug \
    && make \
    && make -C tests \
    && install -m 755 tests/dtls-server /usr/local/bin/dtls-server \
    && install -m 755 tests/dtls-client /usr/local/bin/dtls-client

COPY test/integration/docker/tinydtls/run.sh /opt/nfl/targets/tinydtls/run.sh
RUN chmod +x /opt/nfl/targets/tinydtls/run.sh

ENV NFL_TARGET_NAME=tinydtls \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/tinydtls/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
