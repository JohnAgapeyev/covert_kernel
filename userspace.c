#include <asm/types.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "crypto.h"
#include "shared.h"

static unsigned char secret_key[KEY_LEN];

void socket_loop(const pid_t pid, const int sock) {
    unsigned char buffer[MAX_PAYLOAD];

    int conn_sock = accept(sock, NULL, 0);

    for (;;) {
        int size = read(conn_sock, buffer, MAX_PAYLOAD);
        if (size < 0) {
            perror("read");
            break;
        } else if (size == 0) {
            break;
        }

        unsigned char* modified_data;

        if (pid == 0) {
            //Decrypt
            modified_data = decrypt_data(buffer, size, secret_key, NULL, 0);
            if (modified_data) {
                write(conn_sock, modified_data, size - TAG_LEN - NONCE_LEN);
            } else {
                fprintf(stderr, "Data failed to decrypt\n");
            }
        } else {
            //Encrypt
            modified_data = encrypt_data(buffer, size, secret_key, NULL, 0);
            write(conn_sock, modified_data, size + TAG_LEN + NONCE_LEN);
        }

        free(modified_data);
    }
    close(conn_sock);
}

int main(void) {
#if 0
    unsigned char mesg[32];
    memset(mesg, 'A', 32);

    unsigned char nonce[NONCE_LEN];
    memset(nonce, 0xab, NONCE_LEN);

    unsigned char key[KEY_LEN];
    memset(key, 0xfe, KEY_LEN);

    const char* aad = "Goodbye World";

    unsigned char* ciphertext = encrypt_data(mesg, 32, key, NULL, 0);

    unsigned char* plaintext = decrypt_data(ciphertext, 32 + TAG_LEN + NONCE_LEN, key, NULL, 0);

    if (plaintext && memcmp(mesg, plaintext, 32) == 0) {
        puts("Encryption works fine");
    } else {
        puts("Encryption FAILED");
    }
#else

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

    memset(secret_key, 0xab, KEY_LEN);

    if (pid == 0) {
        //Decrypt
        const char* decrypt_sock_path = "/var/run/covert_module_decrypt";

        int decrypt_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);

        struct sockaddr_un su;
        memset(&su, 0, sizeof(struct sockaddr_un));
        su.sun_family = AF_UNIX;
        strcpy(su.sun_path, decrypt_sock_path);

        unlink(decrypt_sock_path);
        if (bind(decrypt_socket, (struct sockaddr*) &su, sizeof(struct sockaddr_un)) == -1) {
            perror("bind");
            return EXIT_FAILURE;
        }

        listen(decrypt_socket, 5);

        socket_loop(pid, decrypt_socket);

        close(decrypt_socket);

        unlink(decrypt_sock_path);
    } else {
        //Encrypt
        const char* encrypt_sock_path = "/var/run/covert_module_encrypt";

        int encrypt_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);

        struct sockaddr_un su;
        memset(&su, 0, sizeof(struct sockaddr_un));
        su.sun_family = AF_UNIX;
        strcpy(su.sun_path, encrypt_sock_path);

        unlink(encrypt_sock_path);
        if (bind(encrypt_socket, (struct sockaddr*) &su, sizeof(struct sockaddr_un)) == -1) {
            perror("bind");
            return EXIT_FAILURE;
        }
        listen(encrypt_socket, 5);

        socket_loop(pid, encrypt_socket);

        close(encrypt_socket);

        unlink(encrypt_sock_path);
    }

#endif

    return EXIT_SUCCESS;
}
