#ifndef MODULE_AFL_CHILD_TRACKER_H
#define MODULE_AFL_CHILD_TRACKER_H

/* Tracks SUT-spawned PIDs (via interposed fork()) so nfl_socket_idle can
 * reap them. Used by the accept+fork-per-conn flow; idle in AFL runs. */
void afl_child_tracker_reset(void);
void afl_child_tracker_wait_all(void);

#endif // MODULE_AFL_CHILD_TRACKER_H
