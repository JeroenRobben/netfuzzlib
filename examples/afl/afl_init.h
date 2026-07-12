#ifndef MODULE_AFL_AFL_INIT_H
#define MODULE_AFL_AFL_INIT_H

/* Lazy AFL forkserver init. Fired exactly once on the first of:
 * nfl_receive, fork(), pthread_create(). Self-guards re-entry. */
void afl_lazy_manual_init(void);

#endif // MODULE_AFL_AFL_INIT_H
