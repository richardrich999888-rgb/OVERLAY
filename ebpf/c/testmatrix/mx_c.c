/* connect() via libc (glibc). Built dynamic and -static. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc, char** argv){
    int port = argc>1?atoi(argv[1]):0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family=AF_INET; sa.sin_port=htons(port);
    inet_pton(AF_INET,"127.0.0.1",&sa.sin_addr);
    int rc = connect(fd,(struct sockaddr*)&sa,sizeof sa);
    printf("MX rc=%d errno=%d(%s)\n", rc, errno, strerror(errno));
    return rc==0?0:errno;
}
