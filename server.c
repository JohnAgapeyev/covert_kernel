#include <assert.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

static int byte_count = 0;
static int bit_count = 0;
static unsigned char covert_buffer[MAX_PAYLOAD];
static unsigned char key[KEY_LEN];

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

    memset(key, 0xab, KEY_LEN);

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
            if (ntohs(tcp->dest) == 666 && !tcp->syn) {
                //printf("Received packet of length %d from raw sock\n", packet_size);
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
                            //printf("Received timestamp with value %lu\n", timestamp_val);
                            if (timestamp_val & 1) {
                                //Odd
                                printf("Timestamp is a 1\n");
                                covert_buffer[byte_count] |= (1 << bit_count);
                            } else {
                                //Even
                                printf("Timestamp is a 0\n");
                                covert_buffer[byte_count] &= ~(1 << bit_count);
                            }

                            printf("Location %d %d\n", byte_count, bit_count);

                            if (bit_count == 7) {
                                ++byte_count;
                                if (byte_count >= MAX_PAYLOAD) {
                                    printf("Time to decrypt\n");
                                    unsigned char* plaintext = decrypt_data(
                                            covert_buffer, MAX_PAYLOAD, key, NULL, 0);
                                    printf("Received message: %.*s\n", MAX_USER_DATA, plaintext);
                                    free(plaintext);
                                    byte_count = 0;
                                }
                            }
                            bit_count = (bit_count + 1) % 8;

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
        init_openssl();
        SSL_CTX* ctx = create_context();
        configure_context(ctx);

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

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }

        unsigned char buffer[MAX_PAYLOAD];

        while (SSL_read(ssl, buffer, MAX_PAYLOAD) > 0) {
            //Do nothing with the data
        }

        puts("Read server closed");

        SSL_free(ssl);

        close(listen_sock);

        SSL_CTX_free(ctx);

        cleanup_openssl();
    }
    return EXIT_SUCCESS;
}
