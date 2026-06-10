#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: direct_syscall_client HOST PORT PAYLOAD\n");
        return 2;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *payload = argv[3];

    int fd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid IPv4 address: %s\n", host);
        close(fd);
        return 2;
    }

    long rc = syscall(SYS_connect, fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        printf("connect failed: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }

    if (syscall(SYS_write, fd, payload, strlen(payload)) < 0) {
        printf("write failed: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }

    printf("connect succeeds\n");
    close(fd);
    return 0;
}
