#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char** argv){
    int port = argc>1?atoi(argv[1]):0;
    int fd = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
    long rc = syscall(SYS_connect, fd, (struct sockaddr*)&sa, sizeof sa);
    int e = rc<0?(int)-rc:0;
    printf("MX rc=%ld errno=%d(%s)\n", rc, e, strerror(e));
    return rc==0?0:e;
}
