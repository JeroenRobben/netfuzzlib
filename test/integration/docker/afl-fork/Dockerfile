# Integration test for afl's child-pid tracker.
#
# Self-contained: no external client. The AFL module synthesises one
# accept(), the SUT (tcp_fork_server) forks a child, the child reads
# the synth packet and exits, and the parent's second blocking accept()
# reaps the child via the tracker before the framework drives the
# process out via nfl_end_priv().
#
# The tracker logs "afl tracker: reaped pid <N>". run.sh greps
# for that line as the pass condition.

FROM netfuzzlib-base

WORKDIR /opt/afl-fork
COPY test/integration/docker/afl-fork/src/tcp_fork_server.c /opt/afl-fork/
RUN cc -O2 -Wall -Wextra -o /opt/afl-fork/tcp_fork_server /opt/afl-fork/tcp_fork_server.c

COPY test/integration/docker/afl-fork/run.sh /opt/nfl/targets/afl-fork/run.sh
RUN chmod +x /opt/nfl/targets/afl-fork/run.sh

ENV NFL_TARGET_NAME=afl-fork \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/afl-fork/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
