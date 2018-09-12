#include <assert.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "shared.h"

int main(void) {
    //Daemonize
    switch (fork()) {
        case 0:
            //Child
            break;
        case -1:
            perror("fork()");
            exit(EXIT_FAILURE);
        default:
            //Parent
            exit(EXIT_SUCCESS);
    }

    //Split into 2 processes
    pid_t pid;
    switch ((pid = fork())) {
        case 0:
            //Child
            break;
        case -1:
            perror("fork()");
            exit(EXIT_FAILURE);
        default:
            //Parent
            break;
    }

    if (pid == 0) {
        //Raw
        int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

        size_t buffer_size = sizeof(struct tcphdr) + sizeof(struct iphdr) + MAX_PAYLOAD;

        unsigned char buffer[buffer_size];

        int packet_size;

        while ((packet_size = recvfrom(raw_sock, buffer, buffer_size, 0, NULL, 0)) > 0) {
            printf("Received packet of length %d from raw sock\n", packet_size);
        }
        puts("Raw server closed");

        close(raw_sock);
    } else {
        //TCP recv loop
        int listen_sock = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in sin;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(PORT);

        if (bind(listen_sock, (struct sockaddr*) &sin, sizeof(struct sockaddr_in)) == -1) {
            perror("bind");
            return EXIT_FAILURE;
        }
        listen(listen_sock, 5);

        int conn_sock = accept(listen_sock, NULL, 0);

        unsigned char buffer[MAX_PAYLOAD];

        while (recv(conn_sock, buffer, MAX_PAYLOAD, 0) > 0) {
            //Do nothing with the data
        }
        puts("Read server closed");

        close(listen_sock);
    }
    return EXIT_SUCCESS;
}
