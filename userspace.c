#include <linux/netlink.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
void send_netlink(const int sock, const unsigned char* data, const size_t len);
void recv_netlink(const int sock, unsigned char* buffer, size_t* size);
int init_netlink(void);

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

struct sockaddr_nl src_addr;
struct sockaddr_nl dest_addr;
struct nlmsghdr* nlh;

int init_netlink(void) {
    int sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock < 0) {
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(sock, (struct sockaddr*) &src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    //For Linux Kernel
    dest_addr.nl_pid = 0;
    //Unicast
    dest_addr.nl_groups = 0;

    nlh = calloc(1, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    return sock;
}

void send_netlink(const int sock, const unsigned char* data, const size_t len) {
    if (len > MAX_PAYLOAD) {
        abort();
    }
    memcpy(NLMSG_DATA(nlh), data, len);

    struct iovec iov;
    memset(&iov, 0, sizeof(struct iovec));
    iov.iov_base = (void*) nlh;
    iov.iov_len = nlh->nlmsg_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = (void*) &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(sock, &msg, 0);
}

void recv_netlink(const int sock, unsigned char* buffer, size_t* size) {
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct iovec));
    memset(&nladdr, 0, sizeof(struct sockaddr_nl));

    iov.iov_base = (void*) nlh;
    iov.iov_len = MAX_PAYLOAD;
    msg.msg_name = (void*) &(nladdr);
    msg.msg_namelen = sizeof(nladdr);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    recvmsg(sock, &msg, 0);

    if (msg.msg_iovlen == 0 || msg.msg_iov->iov_len == 0) {
        abort();
    }

    memcpy(buffer, msg.msg_iov->iov_base, msg.msg_iov->iov_len);
    *size = msg.msg_iov->iov_len;
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
    int net_sock = init_netlink();

    unsigned char buffer[MAX_PAYLOAD];
    size_t mesg_len;

    for (;;) {
        mesg_len = 35;
        memset(buffer, 0xa, mesg_len);
        send_netlink(net_sock, buffer, mesg_len);
        printf("Sending %zu bytes to kernel\n", mesg_len);
        sleep(1);
        recv_netlink(net_sock, buffer, &mesg_len);
        printf("Got %zu bytes from the kernel\n", mesg_len);
    }
#endif

    return EXIT_SUCCESS;
}
