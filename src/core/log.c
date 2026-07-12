#include <netfuzzlib/log.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void nfl_log_die(const int exit_code, const char *file, const int line, const char *fmt, ...) {
    char buf[1024];
    int prefix = snprintf(buf, sizeof(buf), "netfuzzlib FATAL %s:%d: ", file, line);
    if (prefix < 0) {
        prefix = 0;
    }
    if ((size_t)prefix > sizeof(buf) - 1) {
        prefix = sizeof(buf) - 1;
    }

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + prefix, sizeof(buf) - prefix, fmt, ap);
    va_end(ap);

    int total = prefix + (n > 0 ? n : 0);
    if (total > (int)sizeof(buf) - 1) {
        total = sizeof(buf) - 1;
    }
    buf[total] = '\n';

    (void)write(STDERR_FILENO, buf, total + 1);
    exit(exit_code);
}

#ifdef NFL_DEBUG

#include <fcntl.h>
#include <time.h>

#include <netfuzzlib/api.h>
#include "interceptors/native.h"
#include "network_env.h"

static FILE *log_fptr = NULL;

void nfl_init_logging(const char *logfile_path) {
    int log_fd = -1;
    if (logfile_path) {
        log_fd = open(logfile_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd < 0) {
            static const char msg[] = "netfuzzlib: could not open NETWORK_LOG_FILE, falling back to stderr\n";
            (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        }
    }
    const bool opened_file = log_fd >= 0;
    if (log_fd < 0) {
        log_fd = fileno_native(stderr);
    }
    dup2_native(log_fd, NFL_FD_LOG);
    if (opened_file) {
        close_native(log_fd);
    }
    log_fptr = fdopen(NFL_FD_LOG, "a");
    if (!log_fptr) {
        log_fptr = stderr;
    }
}

void nfl_log_impl(const char *file, const int line, const char *fmt, ...) {
    if (!log_fptr) {
        nfl_init_logging(NULL);
    }

    char ts[16];
    const time_t t = time(NULL);
    ts[strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t))] = '\0';

    fprintf(log_fptr, "%s %s:%d: ", ts, file, line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_fptr, fmt, ap);
    va_end(ap);
    fputc('\n', log_fptr);
    fflush(log_fptr);
}

#endif // NFL_DEBUG
