#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <net/sock.h>

#define PORT 666

struct service {
    struct socket* listen_socket;
    struct task_struct* thread;
};

struct service* svc;

static struct nf_hook_ops nfho;

int recv_msg(struct socket* sock, unsigned char* buf, int len) {
    struct msghdr msg;
    struct kvec iov;
    int size = 0;

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
    int len = 15;
    unsigned char buf[len + 1];

    error = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &svc->listen_socket);
    if (error < 0) {
        printk(KERN_ERR "cannot create socket\n");
        return -1;
    }

    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);

    printk(KERN_ALERT "Finding null svc %p\n", (void*) svc);
    printk(KERN_ALERT "Finding null socket %p\n", (void*) svc->listen_socket);
    printk(KERN_ALERT "Finding null sin %p\n", (void*) &sin);

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

    return 0;
}

unsigned int hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header = (struct iphdr*) skb_network_header(skb);
    struct tcphdr* tcp_header;
    if (ip_header->protocol == 6) {
        printk(KERN_INFO "TCP Packet\n");
        printk(KERN_INFO "IP Header len %d\n", ip_header->ihl);
        tcp_header = (struct tcphdr*) skb_transport_header(skb);
        printk(KERN_INFO "Source Port: %u\n", ntohs(tcp_header->source));
        printk(KERN_INFO "Destination Port: %u\n", ntohs(tcp_header->dest));
    }
    return NF_ACCEPT; //accept the packet
}

static int __init mod_init(void) {
    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    svc->thread = kthread_run((void*) start_listen, NULL, "packet_send");
    printk(KERN_ALERT "covert_kernel module loaded\n");

    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    //Set hook highest priority
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}

static void __exit mod_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);

    if (svc->listen_socket != NULL) {
        kernel_sock_shutdown(svc->listen_socket, SHUT_RDWR);
        sock_release(svc->listen_socket);
        printk(KERN_ALERT "release socket\n");
    }

    kfree(svc);
    printk(KERN_ALERT "removed covert_kernel module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
