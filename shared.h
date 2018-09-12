#ifndef SHARED_H
#define SHARED_H

#define SERVER_IP (192 | 168 << 8 | 0 << 16 | 1 << 24)

#define PORT 666
#define MAX_PAYLOAD 1024

#define TAG_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32

#define OVERHEAD_LEN TAG_LEN + NONCE_LEN

#endif /* end of include guard: SHARED_H */
