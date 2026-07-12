# tinydtls, client-side variant. Same upstream binaries as the
# tinydtls server target, but here the dtls-CLIENT runs under
# LD_PRELOAD as the SUT, with a native (un-preloaded) dtls-SERVER
# as the peer fixture. Together with the server-side test, this gives
# us coverage of both the listener path (server bind + recvmsg + reply)
# and the connect-style path (client bind + sendto + recv) through
# the kernel bridge.
#
# Build with: docker build -f test/integration/docker/tinydtls-client/Dockerfile \
#                          -t netfuzzlib-test-tinydtls-client .

FROM netfuzzlib-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        libtool \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Pin to a specific commit. See tinydtls/Dockerfile for the configure.ac
# patch rationale (autoconf 2.71 strictness).
ARG TINYDTLS_REPO=https://github.com/eclipse/tinydtls.git
ARG TINYDTLS_REF=f5e0ca7f10202225a277d4ea675203f77fe0d77c

WORKDIR /opt/tinydtls
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

COPY test/integration/docker/tinydtls-client/run.sh /opt/nfl/targets/tinydtls-client/run.sh
RUN chmod +x /opt/nfl/targets/tinydtls-client/run.sh

ENV NFL_TARGET_NAME=tinydtls-client \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/tinydtls-client/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
