#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
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

        //printk(KERN_INFO "Packet length %u\n", ntohs(ip_header->tot_len));
        //printk(KERN_INFO "Packet length %u\n", (ip_header->ihl) * 4);
        //printk(KERN_INFO "Packet length %u\n", (tcp_header->doff) * 4);
        printk(KERN_INFO "Packet length %u\n", packet_len);

        if (ntohs(tcp_header->dest) == 666 && !tcp_header->syn && tcp_header->psh && packet_len > 0) {
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
                                printk(KERN_INFO "SEQ %lu\n", tcp_header->seq);
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

static int __init mod_init(void) {
    int err;

    memset(&seq_history, 0, sizeof(struct seqack) * 10);

    nfhi.hook = incoming_hook;
    nfhi.hooknum = NF_INET_LOCAL_IN;
    nfhi.pf = PF_INET;
    //Set hook highest priority
    nfhi.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfhi);

    memcpy(&nfho, &nfhi, sizeof(struct nf_hook_ops));
    nfho.hook = outgoing_hook;
    nfho.hooknum = NF_INET_LOCAL_OUT;

    nf_register_net_hook(&init_net, &nfho);

    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    if ((err = init_userspace_conn()) < 0) {
        printk(KERN_ALERT "Failed to initialize userspace sockets; error code %d\n", err);
        kfree(svc);

        nf_unregister_net_hook(&init_net, &nfho);
        nf_unregister_net_hook(&init_net, &nfhi);

        return err;
    }
    buffer = kmalloc(MAX_PAYLOAD, GFP_KERNEL);
    encrypted_test_data = kmalloc(MAX_PAYLOAD, GFP_KERNEL);

    //Get the encrypted version of my test data
    strcpy(buffer, test_data);
    send_msg(svc->encrypt_socket, buffer, strlen(test_data));
    recv_msg(svc->encrypt_socket, encrypted_test_data, strlen(test_data) + OVERHEAD_LEN + 4);

    data_len = strlen(test_data) + OVERHEAD_LEN + 4;

    printk(KERN_INFO "Data length %zu\n", data_len);

    svc->thread = kthread_run((void*) start_transmit, NULL, "packet_send");
    printk(KERN_ALERT "covert_kernel module loaded\n");

    return 0;
}

static void __exit mod_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    nf_unregister_net_hook(&init_net, &nfhi);

    if (svc) {
#if 0
        if (svc->remote_socket) {
            //kernel_sock_shutdown(svc->remote_socket, SHUT_RDWR);
            sock_release(svc->remote_socket);
            printk(KERN_INFO "release remote socket\n");
        }
#endif
        if (svc->encrypt_socket) {
            sock_release(svc->encrypt_socket);
            printk(KERN_INFO "release encrypt_socket\n");
        }
        if (svc->decrypt_socket) {
            sock_release(svc->decrypt_socket);
            printk(KERN_INFO "release decrypt_socket\n");
        }
        if (svc->tls_socket) {
            sock_release(svc->tls_socket);
            printk(KERN_INFO "release tls_socket\n");
        }
        kfree(svc);
    }

    if (buffer) {
        kfree(buffer);
    }
    if (encrypted_test_data) {
        kfree(encrypted_test_data);
    }

    printk(KERN_ALERT "removed covert_kernel module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
