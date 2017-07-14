#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>


int main(int argc, char **argv)
{

int fd = socket (AF_INET, SOCK_DGRAM, 0);
int yes = 1;
setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

struct sockaddr_in server_to_add;
server_to_add.sin_family = AF_INET;
server_to_add.sin_port = htons(1234);
server_to_add.sin_addr.s_addr = htonl(INADDR_BROADCAST);
char *buf = "senddddddddddddddd";
int res = sendto (fd, buf, 5, 0, &server_to_add, sizeof(struct sockaddr_in));


}
