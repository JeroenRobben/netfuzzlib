# Compiles all integration "programs" (small BSD-sockets test binaries) at
# image build time. One image, 9 binaries, selected at run time by
# $NFL_PROGRAM. Backend variants (libevent_udp_echo × {epoll,poll,select})
# share the same binary and pass the backend name via argv at run time.
#
# Each binary is a standalone SUT: under LD_PRELOAD it talks through nfl,
# and the test fixture (the scripted module) replays a scenario and asserts
# outbound traffic matches.

FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libevent-dev \
        libevent-pthreads-2.1-7t64 \
        libev-dev \
        libuv1-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/programs/src
COPY test/integration/docker/programs/src/ /opt/programs/src/

# Compile the simple ones (no event-loop dep).
RUN cc -O2 -o /opt/programs/udp_echo            udp_echo.c
RUN cc -O2 -o /opt/programs/http_get_responder  http_get_responder.c

# libevent
RUN cc -O2 -o /opt/programs/libevent_udp_echo \
        $(pkg-config --cflags libevent) libevent_udp_echo.c \
        $(pkg-config --libs libevent)
RUN cc -O2 -o /opt/programs/libevent_http_responder \
        $(pkg-config --cflags libevent) libevent_http_responder.c \
        $(pkg-config --libs libevent)
RUN cc -O2 -o /opt/programs/libevent_threaded_udp_echo \
        $(pkg-config --cflags libevent_pthreads) libevent_threaded_udp_echo.c \
        $(pkg-config --libs libevent_pthreads) -lpthread

# libev
RUN cc -O2 -o /opt/programs/libev_udp_echo            libev_udp_echo.c          -lev
RUN cc -O2 -o /opt/programs/libev_http_responder      libev_http_responder.c    -lev

# libuv
RUN cc -O2 -o /opt/programs/libuv_udp_echo \
        $(pkg-config --cflags libuv) libuv_udp_echo.c \
        $(pkg-config --libs libuv)
RUN cc -O2 -o /opt/programs/libuv_http_responder \
        $(pkg-config --cflags libuv) libuv_http_responder.c \
        $(pkg-config --libs libuv)

COPY test/integration/docker/programs/scenarios/ /opt/programs/scenarios/

COPY test/integration/docker/programs/run.sh /opt/nfl/targets/programs/run.sh
RUN chmod +x /opt/nfl/targets/programs/run.sh

ENV NFL_TARGET_NAME=programs \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/programs/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
