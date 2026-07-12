# AFL-fuzz curl's HTTP response parser. curl is the SUT (a client).
# libnfl-afl runs in SUT_IS_CLIENT mode so curl's TCP connect to
# 127.0.0.1:80 succeeds synthetically, then nfl_receive delivers AFL's
# test case as the HTTP response. AFL mutates the response bytes, and
# curl's parser exercises the path from raw response → header parse → body.
#
# Pass: AFL exited cleanly + corpus grew past the seed.

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        afl++ \
        libclang-rt-17-dev \
        wget \
        autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build
ARG CURL_VERSION=8.10.1
RUN wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.gz" \
    && tar xzf "curl-${CURL_VERSION}.tar.gz"

# --without-* drops every optional dep so the build stays self-contained
# and the response-parser surface stays the focus of the fuzz. -O2 keeps
# things fast. -g preserves debug info for crash analysis.
RUN cd "curl-${CURL_VERSION}" \
    && CC=afl-clang-fast CFLAGS='-O2 -g' ./configure \
        --without-ssl --without-libpsl --without-zlib \
        --without-brotli --without-zstd --without-libidn2 \
        --without-nghttp2 --disable-ldap --disable-ldaps \
        --disable-rtsp --disable-mqtt --disable-imap --disable-pop3 \
        --disable-smtp --disable-gopher --disable-telnet \
        --disable-tftp --disable-dict --disable-file --disable-ftp \
        --disable-smb \
        > /tmp/configure.log 2>&1 \
    && make -j"$(nproc)" > /tmp/make.log 2>&1 \
    && cp src/.libs/curl /opt/curl

COPY test/integration/docker/afl-curl/seeds/ /opt/afl-curl/seeds/

COPY test/integration/docker/afl-curl/run.sh /opt/nfl/targets/afl-curl/run.sh
RUN chmod +x /opt/nfl/targets/afl-curl/run.sh

ENV NFL_TARGET_NAME=afl-curl \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/afl-curl/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
