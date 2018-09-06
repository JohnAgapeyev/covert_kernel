#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <linux/un.h>

#define PORT 666
#define MAX_PAYLOAD 1024

struct service {
    struct socket* listen_socket;
    struct task_struct* thread;
};

struct nf_hook_ops nfho;
struct service* svc;
struct sock* nl_sk;
unsigned char* buffer;

int recv_msg(struct socket* sock, unsigned char* buf, int len) {
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

    if (size > 0) {
        printk(KERN_ALERT "the message is : %s\n", buf);
    }

    return size;
}

int send_msg(struct socket* sock, char* buf, int len) {
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

    if (size > 0) {
        printk(KERN_INFO "message sent!\n");
    }

    return size;
}

int start_listen(void) {
    struct socket* acsock;
    int error;
    int i;
    int size;
    struct sockaddr_in sin;
    struct sockaddr_un sun;
    int len = 100;
    unsigned char buf[len + 1];
    const char* sock_path = "/var/run/covert_module";
    const char* m = "Hello userspace!\n";
#if 0
    error = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &svc->listen_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return -1;
    }

    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    error = kernel_bind(svc->listen_socket, (struct sockaddr*) &sin, sizeof(sin));
    if (error < 0) {
        printk(KERN_ERR "cannot bind socket, error code: %d\n", error);
        return -1;
    }

    error = kernel_listen(svc->listen_socket, 5);
    if (error < 0) {
        printk(KERN_ERR "cannot listen, error code: %d\n", error);
        return -1;
    }

    i = 0;
    while (!kthread_should_stop()) {
        error = kernel_accept(svc->listen_socket, &acsock, 0);
        if (error < 0) {
            printk(KERN_ERR "cannot accept socket\n");
            return -1;
        }
        printk(KERN_ERR "sock %d accepted\n", i++);

        memset(&buf, 0, len + 1);
        while (!kthread_should_stop() && (size = recv_msg(acsock, buf, len)) > 0) {
            send_msg(acsock, buf, size);
            memset(&buf, 0, len + 1);
        }

        sock_release(acsock);
    }
#else
    error = sock_create(AF_UNIX, SOCK_SEQPACKET, 0, &svc->listen_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return -1;
    }
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, sock_path);

    error = kernel_bind(svc->listen_socket, (struct sockaddr*) &sun, sizeof(sun));
    if (error < 0) {
        printk(KERN_ERR "cannot bind socket, error code: %d\n", error);
        return -1;
    }
    error = kernel_listen(svc->listen_socket, 5);
    if (error < 0) {
        printk(KERN_ERR "cannot listen, error code: %d\n", error);
        return -1;
    }
    i = 0;
    while (!kthread_should_stop()) {
        error = kernel_accept(svc->listen_socket, &acsock, 0);
        if (error < 0) {
            printk(KERN_ERR "cannot accept socket\n");
            return -1;
        }
        if (kthread_should_stop()) {
            sock_release(acsock);
            return 0;
        }
        printk(KERN_ERR "sock %d accepted\n", i++);

        memset(&buf, 0, len + 1);
        while (!kthread_should_stop() && (size = recv_msg(acsock, buf, len)) > 0) {
            printk(KERN_INFO "Received user message: %s\n", buf);

            strcpy(buf, m);

            send_msg(acsock, buf, strlen(m) + 1);
        }

        sock_release(acsock);
    }
#endif

    return 0;
}

unsigned int hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    unsigned char* packet_data;
    unsigned char* timestamps = NULL;
    int i;
    if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr*) skb_transport_header(skb);
        packet_data = skb->data + (ip_header->ihl * 4) + (tcp_header->doff * 4);

        if (ntohs(tcp_header->source) == 666) {
            if (tcp_header->doff > 5) {
                //Move to the start of the tcp options
                timestamps = skb->data + (ip_header->ihl * 4) + 20;
                for (i = 0; i < tcp_header->doff - 5; ++i) {
                    printk(KERN_INFO "Parsing an option\n");
                    if (*timestamps == 0x00) {
                        //End of options
                        timestamps = NULL;
                        break;
                    }
                    if (*timestamps == 0x01) {
                        //NOP
                        ++timestamps;
                    } else if (*timestamps == 8) {
                        printk(KERN_INFO "Timestamp option\n");
                        //Timestamp option
                        if (timestamps[1] != 10) {
                            printk(KERN_INFO "Timestamp option was malformed\n");
                            continue;
                        }
                        //Here we can modify send timestamp
                        //Not receive since the echo is unidirectional
                        //*((unsigned long *) (timestamps + 2)) = ntohl(0x12345678);
                        timestamps[5] = 0x05;
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

            //Modify first byte of data
            packet_data[0] += 1;
            return NF_ACCEPT;
        }
    }
    return NF_ACCEPT;
}

static int __init mod_init(void) {
    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    svc->thread = kthread_run((void*) start_listen, NULL, "packet_send");
    printk(KERN_ALERT "covert_kernel module loaded\n");

    buffer = kmalloc(MAX_PAYLOAD, GFP_KERNEL);

    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    //Set hook highest priority
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

static void __exit mod_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);

    if (svc) {
        if (svc->listen_socket) {
            //kernel_sock_shutdown(svc->listen_socket, SHUT_RDWR);
            sock_release(svc->listen_socket);
            printk(KERN_ALERT "release socket\n");
        }
        kfree(svc);
    }

    if (buffer) {
        kfree(buffer);
    }

    printk(KERN_ALERT "removed covert_kernel module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
