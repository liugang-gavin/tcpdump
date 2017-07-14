
/*
1.everyone can send measage to net
2.everyone can receive the measage in the net
*/
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

#define BROAD_PORT 1234

int main(int argc, char **argv)
{
    struct sockaddr_in peer, client;
    int sockfd, on = 1;
    char *buf = "send from board";
    int addrlen = sizeof(struct sockaddr_in);

    if(argc != 2) {
        printf("Usage:%s <ip address>\n", argv[0] );
        exit(1);
    }
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0) ) < 0) {
        perror("socket error\n");
        exit(1);
    }


    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int));
    memset(&peer, 0, addrlen);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(BROAD_PORT);
    if(inet_pton(AF_INET, argv[1], &(peer.sin_addr)) < 0) {
        printf("Wrong IP address\n");
        exit(1);
    }

    memset(&client, 0, addrlen);
    int opt = SO_REUSEADDR;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    client.sin_family = AF_INET;
    client.sin_port = htons(BROAD_PORT);
    client.sin_addr.s_addr=htonl(INADDR_ANY);
    if((bind(sockfd, (struct sockaddr *)&client, addrlen) ) == -1) {
        perror("Bind()error");
        exit(1);
    }

    while(1) {
        sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, addrlen);
        sleep(1);
    }
    fflush(stdout);
    close(sockfd);

}

