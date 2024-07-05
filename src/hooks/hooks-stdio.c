#include "hooks.h"
#include "environment/fd_table.h"

bool stream_is_casted_fd(FILE *stream) {
    long fd = (long)stream;
    return fd > 0 && fd < SOCKET_FD_MAX;
}

int fileno(FILE *stream) {
    if (stream_is_casted_fd(stream)) {
        return (int)(long)stream;
    }
    return fileno_native(stream);
}

FILE *fdopen(int fd, const char *mode) {
    if (is_nfl_sock_fd(fd)) {
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
    if (stream_is_casted_fd(stream) || is_nfl_sock_fd(fd)) {
        return fgetc_nfl(get_nfl_sock(fd));
    }
    return fgetc_native(stream);
}

int fflush(FILE *stream) {
    if(stream == NULL) {
        return fflush_native(stream);
    }
    int fd = fileno(stream);
    if (stream_is_casted_fd(stream) || is_nfl_sock_fd(fd)) {
        return 0;
    }
    return fflush_native(stream);
}

int fclose(FILE *stream) {
    int fd = fileno(stream);
    if (stream_is_casted_fd(stream) || is_nfl_sock_fd(fd)) {
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
    if (stream_is_casted_fd(stream) || is_nfl_sock_fd(fileno(stream))) {
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