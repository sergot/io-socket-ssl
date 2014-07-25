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
    char PORT[6]; // max port number is 65535 + \0
    snprintf(PORT, 6, "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if( getaddrinfo(hostname, PORT, &hints, &servinfo) != 0 )
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

int server_init(int port, int if_listen, char *cert) {
    struct addrinfo hints, *res;
    int handle;
    char PORT[6]; // max port number is 65535 + \0
    snprintf(PORT, 6, "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(NULL, PORT, &hints, &res);

    handle = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if( bind(handle, res->ai_addr, res->ai_addrlen) != 0 )
        return -1;

    if( if_listen && (listen(handle, 10) != 0) )
        return 0;

    return handle;
}

void client_disconnect(int fd) {
    close(fd);
}
