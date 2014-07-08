#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int client_connect(char *hostname, int port) {
    int error, handle;
    struct hostent *host;
    struct sockaddr_in server;

    host = gethostbyname(hostname);
    if( (handle = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
        handle = 0;
    }
    else {
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr = *((struct in_addr *) host->h_addr);
        bzero( &(server.sin_zero), 8 );

        if( connect(handle, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1 ) {
            handle = 0;
        }
    }

    return handle;
}

void client_disconnect(int fd) {
    close(fd);
}

char *get_buff(int n) {
    return (char *) malloc(n * sizeof(char));
}
