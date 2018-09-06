#include <asm/types.h>
#include <linux/netlink.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define TAG_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 16
#define MAX_PAYLOAD 1024

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
        const unsigned char* key, const unsigned char* nonce, const unsigned char* aad,
        const size_t aad_len);
unsigned char* decrypt_data(unsigned char* message, const size_t mesg_len, const unsigned char* key,
        const unsigned char* nonce, const unsigned char* aad, const size_t aad_len);
void socket_loop(const pid_t pid, const int sock);

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
        const unsigned char* key, const unsigned char* nonce, const unsigned char* aad,
        const size_t aad_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);

    int len;
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    //Allocate enough for the message and the tag
    unsigned char* ciphertext = malloc(mesg_len + TAG_LEN);

    EVP_EncryptUpdate(ctx, ciphertext, &len, message, mesg_len);

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, ciphertext + mesg_len);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

unsigned char* decrypt_data(unsigned char* message, const size_t mesg_len, const unsigned char* key,
        const unsigned char* nonce, const unsigned char* aad, const size_t aad_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);

    int len;
    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

    if (mesg_len <= TAG_LEN) {
        return NULL;
    }

    unsigned char* plaintext = malloc(mesg_len - TAG_LEN);

    EVP_DecryptUpdate(ctx, plaintext, &len, message, mesg_len - TAG_LEN);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, message + mesg_len - TAG_LEN)) {
        return NULL;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

void socket_loop(const pid_t pid, const int sock) {
    unsigned char buffer[MAX_PAYLOAD];
    unsigned char key[KEY_LEN];
    unsigned char nonce[NONCE_LEN];

    memset(key, 0xab, KEY_LEN);
    memset(nonce, 0, NONCE_LEN);

    int conn_sock = accept(sock, NULL, 0);

    for (;;) {
        int size = read(conn_sock, buffer, MAX_PAYLOAD);

        if (pid == 0) {
            //Decrypt
            decrypt_data(buffer, size, key, nonce, NULL, 0);
        } else {
            //Encrypt
            encrypt_data(buffer, size, key, nonce, NULL, 0);
        }
        write(conn_sock, buffer, size);

        //Increment the nonce after a successful write
        for (int i = NONCE_LEN - 1; i >= 0; --i) {
            if (nonce[i] == UCHAR_MAX) {
                if (i == 0) {
                    fprintf(stderr, "NONCE WRAPPED AROUND\n");
                    abort();
                }
                continue;
            } else {
                ++nonce[i];
                break;
            }
        }
    }
    close(conn_sock);
}

int main(void) {
#if 0
    const char* m = "Hello World";

    unsigned char nonce[NONCE_LEN];
    memset(nonce, 0xab, NONCE_LEN);

    unsigned char key[KEY_LEN];
    memset(key, 0xfe, KEY_LEN);

    const char* aad = "Goodbye World";

    unsigned char* ciphertext = encrypt_data((const unsigned char*) m, strlen(m), key, nonce,
            (const unsigned char*) aad, strlen(aad));

    unsigned char* plaintext = decrypt_data(
            ciphertext, strlen(m) + TAG_LEN, key, nonce, (const unsigned char*) aad, strlen(aad));

    if (plaintext && memcmp(m, plaintext, strlen(m)) == 0) {
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
        }
        listen(encrypt_socket, 5);

        socket_loop(pid, encrypt_socket);

        close(encrypt_socket);

        unlink(encrypt_sock_path);
    }

#endif

    return EXIT_SUCCESS;
}
