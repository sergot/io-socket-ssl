#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int client_connect(char *hostname, int port) {
    int error, handle;
    struct addrinfo hints, *servinfo, *p;
    char PORT[5]; // max port number is 65535
    snprintf(PORT, 5, "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if( getaddrinfo(hostname, "443", &hints, &servinfo) != 0 )
        return 0;

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((handle = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;

        if( connect(handle, p->ai_addr, p->ai_addrlen) == -1 ) {
            close(handle);
            continue;
        }

        break;
    }

    if (p == NULL)
        return 0;

    freeaddrinfo(servinfo);

    return handle;
}

void client_disconnect(int fd) {
    close(fd);
}
