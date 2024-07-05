#include <dlfcn.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <netfuzzlib/module_api.h>
#include "wait-child.h"

#define MAX_PIDS 10

typedef struct child_state {
    bool assigned;
    pid_t pid;
    bool killed;
    int status;
} child_state;

static bool track_child_pids_enabled = false;
static struct child_state child_pid_cache[MAX_PIDS];
static int tracked_pids = 0;

void init_wait_child() {
    for (int i = 0; i < MAX_PIDS; i++) {
        memset(child_pid_cache, 0, sizeof(child_pid_cache));
    }
}

void set_track_child_pids(bool track) {
    track_child_pids_enabled = track;
}

static int add_tracked_pid(pid_t pid) {
    for (int i = 0; i < MAX_PIDS; i++) {
        child_state *child = &child_pid_cache[i];
        if (!child->assigned) {
            child->assigned = true;
            child->pid = pid;
            child->killed = false;
            child->status = 0;
            tracked_pids++;
            return 0;
        }
    }
    return -1;
}

static pid_t pop_killed_pid(int *status) {
    for (int i = 0; (i < MAX_PIDS) && (tracked_pids > 0); i++) {
        child_state *child = &child_pid_cache[i];
        if (child->assigned && child->killed) {
            if (status) {
                *status = child->status;
            }
            child->assigned = false;
            tracked_pids--;
            return child->pid;
        }
    }
    return -1;
}

static pid_t find_killed_pid_or_clear(pid_t child_pid, int *status) {
    for (int i = 0; (i < MAX_PIDS) && (tracked_pids > 0); i++) {
        child_state *child = &child_pid_cache[i];
        if (child->assigned && child->pid == child_pid) {
            child->assigned = false;
            tracked_pids--;
            if (child->killed) {
                if (status) {
                    *status = child->status;
                }
                return child_pid;
            }
            return -1;
        }
    }
    return -1;
}

static pid_t fork_native() {
    static pid_t (*fork_libc)(void);
    if (!fork_libc)
        fork_libc = dlsym(RTLD_NEXT, "fork");
    return (*fork_libc)();
}

static pid_t waitpid_native(pid_t pid, int *status, int options) {
    static pid_t (*waitpid_libc)(pid_t, int *, int);
    if (!waitpid_libc)
        waitpid_libc = dlsym(RTLD_NEXT, "waitpid");
    return (*waitpid_libc)(pid, status, options);
}

pid_t fork(void) {
    pid_t child_pid = fork_native();
    if (child_pid <= 0 || !track_child_pids_enabled)
        return child_pid;
    add_tracked_pid(child_pid);
    return child_pid;
}

void wait_child_thread() {
    if (tracked_pids == 0)
        return;

    sigset_t sig_set;
    sigemptyset(&sig_set);
    sigaddset(&sig_set, SIGTERM);
    sigaddset(&sig_set, SIGCHLD);
    sigprocmask(SIG_BLOCK, &sig_set, NULL);

    for (int i = 0; i < MAX_PIDS; i++) {
        child_state *child = &child_pid_cache[i];
        if (child->assigned && !child->killed) {
            waitpid_native(child->pid, &child->status, 0);
            child->killed = true;
        }
    }
    sigprocmask(SIG_UNBLOCK, &sig_set, NULL);
}

pid_t waitpid(pid_t pid, int *status, int options) {
    if (tracked_pids == 0)
        return waitpid_native(pid, status, options);

    pid_t pid_ret;
    if (pid < 1) {
        pid_ret = pop_killed_pid(status);
    } else {
        pid_ret = find_killed_pid_or_clear(pid, status);
    }
    if (pid_ret >= 0) {
        return pid_ret;
    }

    pid_ret = waitpid_native(pid, status, options);
    if (pid_ret <= 0)
        return pid_ret;
    int dummy;
    find_killed_pid_or_clear(pid_ret, &dummy);
    return pid_ret;
}

pid_t wait(int *status) {
    return waitpid(-1, status, 0);
}
