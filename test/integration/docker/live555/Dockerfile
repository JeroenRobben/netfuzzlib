# live555 testOnDemandRTSPServer: single-process, event-loop RTSP server
# from the live555 streaming media library. Exercises the bridge's TCP
# listen/accept path with multi-line CRLF-delimited RTSP traffic.
#
# Why live555: the binary is single-threaded by default (no fork, no
# pthread workers, just BasicTaskScheduler::doEventLoop), which keeps
# it inside the slice of SUTs nfl supports cleanly. RTSP is also a
# protocol shape we don't otherwise have in the suite (multi-line
# request headers, persistent connection, request-id-keyed responses).
#
# Current scope: TCP control path only, an `OPTIONS *` probe.
#
# What v2 (DESCRIBE/SETUP/PLAY with real RTP-over-UDP) would need: a
# fix for nfl's select()/poll() interceptors to honour their timeout
# argument. testOnDemandRTSPServer's BasicTaskScheduler computes
# `select(timeout = next_alarm_delay)`, but our select interceptor
# (`src/interceptors/poll.c`) sets the native timeout to 0 and ignores
# the caller's. The scheduler interprets the immediate 0-return as
# "all alarms fired", runs delayed tasks (some of which create+destroy
# sockets), and loops, a tight create/close socket cycle that
# starves SETUP processing of its UDP-port allocation. The bridge's
# 200ms wait on MSG_DONTWAIT recv (added for ssh-keyscan) doesn't
# help here because select() never reaches that path. Same root cause
# as the openssh blocker, just observed on the select() side.
#
# v1 (this OPTIONS probe) works because it's a one-shot
# request/response that the SUT can service between busy-loop ticks.
#
# Build with: docker build -f test/integration/docker/live555/Dockerfile \
#                          -t netfuzzlib-test-live555 .

FROM netfuzzlib-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Build live555 from the rgaufman GitHub mirror (the official
# live555.com only hosts a "latest" tarball that 404'd when we tried
# it). Same pin pattern as the tinydtls target, specific SHA, fully
# reproducible.
ARG LIVE555_REPO=https://github.com/rgaufman/live555.git
ARG LIVE555_REF=fbbfd5de544fac5967262554dfd09b1774241802

WORKDIR /opt/live555-build
RUN git init -q \
    && git remote add origin "$LIVE555_REPO" \
    && git fetch --depth 1 origin "$LIVE555_REF" \
    && git checkout -q FETCH_HEAD \
    && ./genMakefiles linux-no-openssl \
    # Recent live555 uses std::atomic_flag::test() (C++20 only). The
    # base image's gcc default standard predates that. The generated
    # Makefile already references $(CXXFLAGS) on the CPLUSPLUS_FLAGS
    # line, so passing CXXFLAGS through make appends the flag to C++
    # compilation only, without polluting the C compile path.
    && make -j"$(nproc)" CXXFLAGS=-std=c++20 \
    && install -m 755 testProgs/testOnDemandRTSPServer /usr/local/bin/

COPY test/integration/docker/live555/run.sh /opt/nfl/targets/live555/run.sh
RUN chmod +x /opt/nfl/targets/live555/run.sh

ENV NFL_TARGET_NAME=live555 \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/live555/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
