/* Vanilla UDP echo: bind to a known port, recvfrom one datagram, send the
 * same bytes back to the sender, exit. No netfuzzlib awareness. The harness
 * injects the model via LD_PRELOAD. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(8888);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 1;
    }

    char buf[1500];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (n < 0) {
        perror("recvfrom");
        return 1;
    }
    ssize_t m = sendto(s, buf, (size_t)n, 0, (struct sockaddr *)&from, fromlen);
    if (m != n) {
        perror("sendto");
        return 1;
    }
    close(s);
    return 0;
}
