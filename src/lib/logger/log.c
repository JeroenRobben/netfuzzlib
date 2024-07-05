/*
 * Copyright (c) 2020 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <fcntl.h>
#include <unistd.h>
#include <netfuzzlib/api.h>
#include "hooks/native.h"
#include "environment/network_env.h"

static FILE *log_fptr = NULL;
static bool use_colors = true;

static struct {
    int level;
    bool quiet;
} L;

static const char *level_strings[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
static const char *level_colors[] = { "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m" };

void nfl_init_logging(char *logfile_path) {
    int log_fd = -1;
    bool close_log_fd = false;
    if (logfile_path) {
        log_fd = open(logfile_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd < 0) {
            log_fptr = stderr;
            nfl_log_error("Could not write/create log file (env NETWORK_LOG_FILE) at %s, using stderr", logfile_path);
        } else {
            close_log_fd = true;
            use_colors = false;
        }
    }
    if (log_fd < 0) {
        log_fd = fileno_native(stderr);
    }
    int log_fd2 = NFL_FD_LOG;
    dup2_native(log_fd, NFL_FD_LOG);
    if(close_log_fd) {
        close_native(log_fd);
    }
    log_fptr = fdopen(log_fd2, "a");
    if (!log_fptr) {
        log_fptr = stderr;
        nfl_log_error("Could not write/create log file (env NETWORK_LOG_FILE) at %s, using stderr", logfile_path);
    }
    log_fptr = stderr;
    printf("test");
}

void nfl_log_log(int level, const char *file, int line, const char *fmt, ...) {
    if (log_fptr == NULL) {
        nfl_init_logging(NULL);
    }

    if (L.quiet || level < L.level) {
        return;
    }

    char buf[16];
    time_t t = time(NULL);
    va_list ap;
    va_start(ap, fmt);

    buf[strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t))] = '\0';

    if (use_colors) {
        fprintf(log_fptr, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf, level_colors[level], level_strings[level], file, line);
    } else {
        fprintf(log_fptr, "%s %-5s %s:%d: ", buf, level_strings[level], file, line);
    }

    vfprintf(log_fptr, fmt, ap);
    fprintf(log_fptr, "\n");
    fflush(log_fptr);

    va_end(ap);
}
