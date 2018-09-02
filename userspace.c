#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 16

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

int main(void) {
    const char* m = "Hello World";

    unsigned char nonce[NONCE_LEN];
    memset(nonce, 0xab, NONCE_LEN);

    unsigned char key[KEY_LEN];
    memset(key, 0xfe, KEY_LEN);

    const char* aad = "Goodbye World";

    unsigned char* ciphertext = encrypt_data((const unsigned char*) m, strlen(m), key, nonce,
            (const unsigned char*) aad, strlen(aad));

    unsigned char* plaintext = decrypt_data(ciphertext, strlen(m) + TAG_LEN, key, nonce,
            (const unsigned char*) aad, strlen(aad));

    if (plaintext && memcmp(m, plaintext, strlen(m)) == 0) {
        puts("Encryption works fine");
    } else {
        puts("Encryption FAILED");
    }

    return EXIT_SUCCESS;
}
