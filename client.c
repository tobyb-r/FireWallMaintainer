#include <stdio.h>      // input/output
#include <sys/socket.h> // socket(), connect()
#include <sys/types.h>
#include <netinet/in.h> // addrinfo
#include <netdb.h>      // getaddrinfo
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
    struct addrinfo *results;
    int res;
    char buffer[BUFFERLENGTH];

    if (argc < 4) {
        printf("Usage is %s hostname port command\n", argv[0]);
        exit(0);
    }

    /// CONNECTING TO SERVER
    /// ====================

    // Obtain addresses matching hostname port
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;        // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;    // Socket stream type
    hints.ai_flags = 0;                 // No flags
    hints.ai_protocol = 0;              // Any protocol

    // we fill out hints with hints about the addresses we want
    // gai fills out a list of full addresses that match our description
    res = getaddrinfo(argv[1], argv[2], &hints, &results);

    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    // gai returns a linked list of addresses in case the address can
    // be resolved to multiple places or resolved in multiple ways
    // 
    // we just use the first address that works

    struct addrinfo *rp;

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (sockfd == -1) // this socket is dogshit
            continue;
        
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; // success
        
        // failure
        close(sockfd);
    }

    if (rp == NULL) {
        error("Could not connect");
    }

    freeaddrinfo(results);

    /// MESSAGING SERVER
    /// ================

    // prepare message
    strcpy(buffer, argv[3]);

    // concatenate arguments
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
