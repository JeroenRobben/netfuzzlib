#include <stdio.h>
#include <stdlib.h>
#include "network_types.h"
#include "hooks/models.h"

char *fgets_nfl(char *s, int size, nfl_sock_t *sock) {
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
    int i;
    size_t bytes_read = 0;
    bool newline_detected = false;

    for (i = 0; i < (size - 1); i++) {
        int c = fgetc_nfl(sock);
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

int fgetc_nfl(nfl_sock_t *sock) {
    if (!sock) {
        return EOF;
    }
    unsigned char c;
    if (recvfrom_nfl(sock, &c, 1, MSG_DONTWAIT, NULL, 0) == 1) {
        return (int)c;
    }
    return EOF;
}

size_t fread_nfl(void *ptr, size_t size, size_t nmemb, nfl_sock_t *sock) {
    if(!sock) {
        return 0;
    }
    ssize_t ret = recvfrom_nfl(sock, ptr, size * nmemb, MSG_DONTWAIT, NULL, 0);
    if( ret < 0) {
        return 0;
    }
    return ret;
}

size_t fwrite_nfl(const void *ptr, size_t size, size_t nmemb, nfl_sock_t *sock) {
    if(!sock) {
        return 0;
    }
    ssize_t ret = sendto_nfl(sock, ptr, size * nmemb, MSG_DONTWAIT, NULL, 0);
    if( ret < 0) {
        return 0;
    }
    return ret;
}