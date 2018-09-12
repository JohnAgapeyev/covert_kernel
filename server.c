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
            unsigned char* timestamps;
            struct iphdr* ip = (struct iphdr*) buffer;
            struct tcphdr* tcp = (struct tcphdr*) (buffer + ip->ihl * 4);
            if (ntohs(tcp->dest) == 666) {
                printf("Received packet of length %d from raw sock\n", packet_size);
                if (tcp->doff > 5) {
                    //Move to the start of the tcp options
                    timestamps = buffer + (ip->ihl * 4) + 20;
                    for (int i = 0; i < tcp->doff - 5; ++i) {
                        if (*timestamps == 0x00) {
                            //End of options
                            timestamps = NULL;
                            break;
                        }
                        if (*timestamps == 0x01) {
                            //NOP
                            ++timestamps;
                        } else if (*timestamps == 8) {
                            //Timestamp option
                            if (timestamps[1] != 10) {
                                printf("Timestamp option was malformed\n");
                                continue;
                            }
                            //EVEN IS 0, ODD IS 1
                            unsigned long timestamp_val
                                    = ntohl(*((unsigned long*) (timestamps + 2)));
                            printf("Received timestamp with value %lu\n", timestamp_val);
                            if (timestamp_val & 1) {
                                //Odd
                                printf("Timestamp is a 1\n");
                            } else {
                                //Even
                                printf("Timestamp is a 0\n");
                            }
                            break;
                        } else if (*timestamps == 3) {
                            timestamps += 3;
                        } else if (*timestamps == 4) {
                            timestamps += 2;
                        } else if (*timestamps == 5) {
                            timestamps += timestamps[1];
                        } else {
                            timestamps += 4;
                        }
                    }
                }
            }
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
