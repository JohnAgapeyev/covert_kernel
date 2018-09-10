#include <asm/types.h>
#include <assert.h>
#include <linux/netlink.h>
#include <openssl/err.h>
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

#define libcrypto_error() \
    do { \
        fprintf(stderr, "Libcrypto error %s at %s, line %d in function %s\n", \
                ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE); \
    } while (0)

#define checkCryptoAPICall(pred) \
    do { \
        if ((pred) != 1) { \
            libcrypto_error(); \
        } \
    } while (0)

#define nullCheckCryptoAPICall(pred) \
    do { \
        if ((pred) == NULL) { \
            libcrypto_error(); \
        } \
    } while (0)

size_t encrypt_aead(const unsigned char* plaintext, size_t plain_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag);
ssize_t decrypt_aead(const unsigned char* ciphertext, size_t cipher_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        const unsigned char* tag, unsigned char* plaintext);

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

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce)) {
        puts("Init failure");
        return NULL;
    }

    int len;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        puts("AAD set failure");
        return NULL;
    }

    if (mesg_len <= TAG_LEN) {
        return NULL;
    }

    //unsigned char* plaintext = malloc(mesg_len - TAG_LEN);
    unsigned char* plaintext = malloc(mesg_len);

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, message, mesg_len - TAG_LEN - 1)) {
        puts("decrypt update failure");
        return NULL;
    }

    if (!EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, message + mesg_len - TAG_LEN - 1)) {
        puts("Set tag failure");
        return NULL;
    }

    printf("Decrypt len %d\n", len);

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        puts("Decrypt call failure");
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

        unsigned char* modified_data;

        if (pid == 0) {
            fprintf(stderr, "Decrypt Key %.*s\nNonce %.*s\n", KEY_LEN, key, NONCE_LEN, nonce);
            puts("Key:");
            for (int i = 0; i < KEY_LEN; ++i) {
                printf("%02x", key[i]);
            }
            printf("\n");
            puts("Nonce:");
            for (int i = 0; i < NONCE_LEN; ++i) {
                printf("%02x", nonce[i]);
            }
            printf("\n");
            puts("Data:");
            for (int i = 0; i < size; ++i) {
                printf("%02x", buffer[i]);
            }
            printf("\n");
            //Decrypt
            //modified_data = decrypt_data(buffer, size, key, nonce, NULL, 0);
            ssize_t res = decrypt_aead(buffer, size, NULL, 0, key, nonce, modified_data);
            if (modified_data) {
                write(conn_sock, modified_data, size - TAG_LEN);
            } else {
                fprintf(stderr, "Data failed to decrypt\n");
            }
        } else {
            fprintf(stderr, "Encrypt Key %.*s\nNonce %.*s\n", KEY_LEN, key, NONCE_LEN, nonce);
            //Encrypt
            modified_data = encrypt_data(buffer, size, key, nonce, NULL, 0);
            puts("Key:");
            for (int i = 0; i < KEY_LEN; ++i) {
                printf("%02x", key[i]);
            }
            printf("\n");
            puts("Nonce:");
            for (int i = 0; i < NONCE_LEN; ++i) {
                printf("%02x", nonce[i]);
            }
            printf("\n");
            puts("Data:");
            for (int i = 0; i < size + TAG_LEN; ++i) {
                printf("%02x", modified_data[i]);
            }
            printf("\n");
            write(conn_sock, modified_data, size + TAG_LEN);
        }

        free(modified_data);

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
    unsigned char mesg[32];
    memset(mesg, 'A', 32);

    unsigned char nonce[NONCE_LEN];
    memset(nonce, 0xab, NONCE_LEN);

    unsigned char key[KEY_LEN];
    memset(key, 0xfe, KEY_LEN);

    const char* aad = "Goodbye World";

    unsigned char* ciphertext = encrypt_data(mesg, 32, key, nonce,
            NULL, 0);

    unsigned char* plaintext = decrypt_data(
            ciphertext, 32 + TAG_LEN, key, nonce, NULL, 0);

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

EVP_PKEY* allocateKeyPair(void) {
    EVP_PKEY* out;
    nullCheckCryptoAPICall(out = EVP_PKEY_new());
    return out;
}

size_t encrypt_aead(const unsigned char* plaintext, size_t plain_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TAG_LEN, NULL));

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len));

    checkCryptoAPICall(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len));

    int ciphertextlen = len;
    checkCryptoAPICall(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));

    ciphertextlen += len;

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag));

    EVP_CIPHER_CTX_free(ctx);

    assert(ciphertextlen >= 0);

    return ciphertextlen;
}

ssize_t decrypt_aead(const unsigned char* ciphertext, size_t cipher_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        const unsigned char* tag, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TAG_LEN, NULL));

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));

    checkCryptoAPICall(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len));

    int plaintextlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (unsigned char*) tag)) {
        libcrypto_error();
    }

    ssize_t ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    plaintextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        assert(plaintextlen >= 0);
        return plaintextlen;
    }
    return -1;
}
