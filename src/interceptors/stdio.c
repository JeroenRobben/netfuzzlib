#include "interceptors.h"
#include "native.h"
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

int fileno(FILE *stream) {
    // A FILE* handed back by our fdopen() is really an nfl fd cast straight to a
    // pointer (see fdopen below), so its value lands in the fd-table range. A
    // genuine libc FILE* (stdin/stderr, a fopen'd file) is a real pointer well
    // above that range, so ask libc for its fd.
    long fd = (long)stream;
    if (fd > 0 && fd < NFL_FD_TABLE_SIZE) {
        return (int)fd;
    }
    return fileno_native(stream);
}

// True if stdio on `stream` must go through the model: its backing fd is a
// modelled socket. Covers both our fdopen sentinel and a genuine libc FILE* the
// SUT has pointed at a modelled socket fd, the way an inetd-style daemon dup2's
// its accepted connection onto fileno(stderr)/stdin and then does its control
// I/O with fprintf/fgets on those pre-existing streams.
bool is_nfl_sock_stream(FILE *stream) {
    return is_nfl_sock_fd(fileno(stream));
}

FILE *fdopen(int fd, const char *mode) {
    if (is_nfl_sock_fd(fd)) {
        // NOLINTNEXTLINE(performance-no-int-to-ptr)
        return (FILE *)(long)fd;
    }
    return fdopen_native(fd, mode);
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, fread_nfl, fread_native, ptr, size, nmemb);
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, fwrite_nfl, fwrite_native, ptr, size, nmemb);
}

int fgetc(FILE *stream) {
    int fd = fileno(stream);
    if (is_nfl_sock_stream(stream)) {
        return fgetc_nfl(get_nfl_sock(fd));
    }
    return fgetc_native(stream);
}

int fflush(FILE *stream) {
    if (stream == NULL) {
        return fflush_native(stream);
    }
    if (is_nfl_sock_stream(stream)) {
        return 0;
    }
    return fflush_native(stream);
}

int fclose(FILE *stream) {
    int fd = fileno(stream);
    if (is_nfl_sock_stream(stream)) {
        return close_nfl_fd(fd);
    }
    return fclose_native(stream);
}

char *fgets(char *s, int size, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, fgets_nfl, fgets_native, s, size);
}

int getc(FILE *stream) {
    return fgetc(stream);
}

int vfprintf(FILE *stream, const char *format, va_list args) {
    if (is_nfl_sock_stream(stream)) {
        va_list args_copy;
        va_copy(args_copy, args);
        int buf_len = vsnprintf(NULL, 0, format, args_copy);
        va_end(args_copy);

        if (buf_len < 0) {
            errno = ENOBUFS;
            return buf_len;
        }
        char *buf = malloc(buf_len + 1);
        if (!buf) {
            errno = ENOBUFS;
            return -1;
        }

        int ret = vsprintf(buf, format, args);
        if (ret != buf_len) {
            free(buf);
            return -1;
        }
        ret = (int)write_nfl(get_nfl_sock(fileno(stream)), buf, buf_len);
        free(buf);
        return ret;
    }
    int ret = vfprintf_native(stream, format, args);
    return ret;
}

int fprintf(FILE *restrict stream, const char *restrict format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

int getchar(void) {
    return getc(stdin);
}

int feof(FILE *stream) {
    if (is_nfl_sock_stream(stream)) {
        return 0;
    }
    return feof_native(stream);
}

int ferror(FILE *stream) {
    if (is_nfl_sock_stream(stream)) {
        return 0;
    }
    return ferror_native(stream);
}

void clearerr(FILE *stream) {
    if (is_nfl_sock_stream(stream)) {
        return;
    }
    clearerr_native(stream);
}

/* Sockets are non-seekable. Return ESPIPE like glibc on real socket fds. */
int fseek(FILE *stream, long offset, int whence) {
    if (is_nfl_sock_stream(stream)) {
        errno = ESPIPE;
        return -1;
    }
    return fseek_native(stream, offset, whence);
}

long ftell(FILE *stream) {
    if (is_nfl_sock_stream(stream)) {
        errno = ESPIPE;
        return -1;
    }
    return ftell_native(stream);
}

void rewind(FILE *stream) {
    if (is_nfl_sock_stream(stream)) {
        return;
    }
    rewind_native(stream);
}

// setbuf/setvbuf are no-ops on nfl streams.
void setbuf(FILE *stream, char *buf) {
    if (is_nfl_sock_stream(stream)) {
        return;
    }
    setbuf_native(stream, buf);
}

int setvbuf(FILE *stream, char *buf, int mode, size_t size) {
    if (is_nfl_sock_stream(stream)) {
        return 0;
    }
    return setvbuf_native(stream, buf, mode, size);
}

char *__fgets_chk(char *s, size_t size, int n, FILE *stream) {
    (void)size;
    return fgets(s, n, stream);
}

size_t __fread_chk(void *ptr, size_t ptrlen, size_t size, size_t n, FILE *stream) {
    (void)ptrlen;
    return fread(ptr, size, n, stream);
}

int __fprintf_chk(FILE *stream, int flag, const char *format, ...) {
    (void)flag;
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list args) {
    (void)flag;
    return vfprintf(stream, format, args);
}

int fputs(const char *s, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, fputs_nfl, fputs_native, s);
}

int fputc(int c, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, fputc_nfl, fputc_native, c);
}

int putc(int c, FILE *stream) {
    return fputc(c, stream);
}

int putchar(int c) {
    return fputc(c, stdout);
}

int puts(const char *s) {
    if (fputs(s, stdout) == EOF) {
        return EOF;
    }
    return fputc('\n', stdout);
}

int ungetc(int c, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, ungetc_nfl, ungetc_native, c);
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
    SWITCH_MODEL_NATIVE_STREAM(stream, getdelim_nfl, getdelim_native, lineptr, n, delim);
}

ssize_t __getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
    return getdelim(lineptr, n, delim, stream);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    return getdelim(lineptr, n, '\n', stream);
}

// fscanf/vfscanf is not modeled, and usually not used for network I/O.
int vfscanf(FILE *stream, const char *format, va_list args) {
    if (is_nfl_sock_stream(stream)) {
        nfl_die(1, "vfscanf is not modeled for nfl streams. The SUT called "
                   "fscanf/vfscanf on a FILE* derived from a socket fd, but "
                   "netfuzzlib does not yet model formatted input on sockets.");
    }
    return vfscanf_native(stream, format, args);
}

int fscanf(FILE *stream, const char *format, ...) {
    va_list args;
    va_start(args, format);
    const int ret = vfscanf(stream, format, args);
    va_end(args);
    return ret;
}
