#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFERLENGTH 256


// error handling
void error(char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *results, *rp;
    int res;
    char buffer[BUFFERLENGTH];

    if (argc < 4) {
        printf("Usage is %s hostname port command\n", argv[0]);
        exit(0);
    }

    // Obtain addresses matching hostname port
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;        // Allow IPV4 or IPV6
    hints.ai_socktype = SOCK_STREAM;    // Socket stream type
    hints.ai_flags = 0;                 // No flags
    hints.ai_protocol = 0;              // Any protocol

    res = getaddrinfo(argv[1], argv[2], &hints, &results);

    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    // gai returns a linked list of addresses in case the address can
    // be resolved to multiple places or resolved in multiple ways

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (sockfd == -1)
            continue;
        
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; // success
        
        close(sockfd);
    }

    if (rp == NULL) {
        error("Could not connect");
    }

    freeaddrinfo(results);

    // prepare message
    strcpy(buffer, argv[3]);

    for (int i=4; i<argc; i++) {
        strcat(buffer, " ");
        strcat(buffer, argv[i]);
    }
    strcat(buffer, "\n");

    // send message
    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0) {
        error("Error writing to socket");
    }

    // get reply
    bzero(buffer, BUFFERLENGTH);
    n = read(sockfd, buffer, BUFFERLENGTH-1);
    
    while (n > 0) {
        printf("%s", buffer);
        bzero(buffer, BUFFERLENGTH);
        n = read(sockfd, buffer, BUFFERLENGTH-1);
    }

    if (n == -1) {
        error("Error reading from socket");
    }

    return 0;
}
