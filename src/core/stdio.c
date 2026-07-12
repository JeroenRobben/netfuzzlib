#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_types.h"
#include "handlers.h"

char *fgets_nfl(char *s, const int size, nfl_sock_full_t *sock) {
    if (!sock) {
        if (size > 0) {
            s[0] = '\0';
        }
        return NULL;
    }

    if (size == 1) {
        s[0] = '\0';
        return s;
    }
    size_t bytes_read = 0;
    bool newline_detected = false;

    for (int i = 0; i < (size - 1); i++) {
        const int c = fgetc_nfl(sock);
        if (c == EOF) {
            return NULL;
        }
        s[i] = (char)c;
        bytes_read++;
        if (c == '\n') {
            newline_detected = true;
            break;
        }
    }
    s[bytes_read] = '\0';
    if (bytes_read == 0) {
        return NULL;
    }
    if (bytes_read < size - 1 && !newline_detected) {
        return NULL;
    }
    return s;
}

int fgetc_nfl(nfl_sock_full_t *sock) {
    if (!sock) {
        return EOF;
    }
    if (sock->stdio_has_pushback) {
        sock->stdio_has_pushback = false;
        return sock->stdio_pushback;
    }
    unsigned char c;
    if (recvfrom_nfl(sock, &c, 1, 0, NULL, NULL) == 1) {
        return c;
    }
    return EOF;
}

int ungetc_nfl(int c, nfl_sock_full_t *sock) {
    // C99: ungetc on EOF returns EOF without affecting the stream.
    if (!sock || c == EOF) {
        return EOF;
    }
    // Only one byte of pushback is required by the standard
    if (sock->stdio_has_pushback) {
        return EOF;
    }
    sock->stdio_pushback = (unsigned char)c;
    sock->stdio_has_pushback = true;
    return (unsigned char)c;
}

int fputs_nfl(const char *s, nfl_sock_full_t *sock) {
    if (!sock || !s) {
        return EOF;
    }
    const size_t len = strlen(s);
    if (len == 0) {
        return 0;
    }
    const ssize_t ret = sendto_nfl(sock, s, len, MSG_DONTWAIT, NULL, 0);
    if (ret < 0 || (size_t)ret != len) {
        return EOF;
    }
    return 0;
}

int fputc_nfl(int c, nfl_sock_full_t *sock) {
    if (!sock) {
        return EOF;
    }
    const unsigned char byte = (unsigned char)c;
    const ssize_t ret = sendto_nfl(sock, &byte, 1, MSG_DONTWAIT, NULL, 0);
    if (ret != 1) {
        return EOF;
    }
    return byte;
}

ssize_t getdelim_nfl(char **lineptr, size_t *n, int delim, nfl_sock_full_t *sock) {
    if (!lineptr || !n || !sock) {
        errno = EINVAL;
        return -1;
    }
    if (!*lineptr || *n == 0) {
        *n = 128;
        char *fresh = realloc(*lineptr, *n);
        if (!fresh) {
            errno = ENOMEM;
            return -1;
        }
        *lineptr = fresh;
    }
    size_t pos = 0;
    while (1) {
        const int c = fgetc_nfl(sock);
        if (c == EOF) {
            if (pos == 0) {
                return -1;
            }
            break;
        }
        // Reserve room for the byte plus a trailing NUL.
        if (pos + 1 >= *n) {
            const size_t newn = *n * 2;
            char *bigger = realloc(*lineptr, newn);
            if (!bigger) {
                errno = ENOMEM;
                return -1;
            }
            *lineptr = bigger;
            *n = newn;
        }
        (*lineptr)[pos++] = (char)c;
        if (c == delim) {
            break;
        }
    }
    (*lineptr)[pos] = '\0';
    return (ssize_t)pos;
}

size_t fread_nfl(void *ptr, const size_t size, const size_t nmemb, nfl_sock_full_t *sock) {
    if (!sock) {
        return 0;
    }
    /* fread(3) is blocking like fgetc(3). The recv path adds MSG_DONTWAIT
     * itself for non-blocking socks based on sock->status_flags.blocking. */
    const ssize_t ret = recvfrom_nfl(sock, ptr, size * nmemb, 0, NULL, NULL);
    if (ret < 0) {
        return 0;
    }
    return ret;
}

size_t fwrite_nfl(const void *ptr, const size_t size, const size_t nmemb, nfl_sock_full_t *sock) {
    if (!sock) {
        return 0;
    }
    const ssize_t ret = sendto_nfl(sock, ptr, size * nmemb, MSG_DONTWAIT, NULL, 0);
    if (ret < 0) {
        return 0;
    }
    return ret;
}
