#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <net/sock.h>

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

static int recv_netlink(struct sk_buff* skb, struct nlmsghdr* nlm, struct netlink_ext_ack* ack) {
    unsigned char* data = NLMSG_DATA(nlm);
    size_t data_len = NLMSG_PAYLOAD(nlm, 0);
    int pid = nlm->nlmsg_pid;
    int res;
    char* msg = "Hello from kernel TEST";
    int msg_size = strlen(msg);
    struct sk_buff* skb_out;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    printk(KERN_INFO "Netlink received msg payload:(%.*s)\n", (int) data_len, data);

    printk(KERN_INFO "Netlink received msg pid:%d\n", pid);

    if (!pid) {
        printk(KERN_ERR "Received pid 0\n");
        return -EINVAL;
    }

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return -ENOMEM;
    }

    //nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    nlm = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    //Not in multicast group
    NETLINK_CB(skb_out).dst_group = 0;

    //memcpy(nlmsg_data(nlh), msg, msg_size);
    memcpy(nlmsg_data(nlm), msg, msg_size);

    printk(KERN_ALERT "About to send\n");

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    printk(KERN_ALERT "Post send %d\n", res);
    if (res < 0) {
        printk(KERN_INFO "Error while sending back to user\n");
    }
    printk(KERN_INFO "Finished echo\n");
    printk(KERN_INFO "Exiting: %s\n", __FUNCTION__);

    return 0;
}

static void echo_netlink(struct sk_buff* skb) {
#if 1
    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
    netlink_rcv_skb(skb, recv_netlink);
    printk(KERN_INFO "Exiting: %s\n", __FUNCTION__);
#else
    struct nlmsghdr* nlh;
    int pid;
    struct sk_buff* skb_out;
    int msg_size;
    char* msg = "Hello from kernel TEST";
    int res;

    dump_stack();

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = strlen(msg);

    //nlh = (struct nlmsghdr*) skb->data;
    nlh = nlmsg_hdr(skb);

    printk(KERN_INFO "Netlink received msg payload:%.*s\n", 3, (char*) nlmsg_data(nlh));
    //PID of sending process
    pid = nlh->nlmsg_pid;

    printk(KERN_INFO "Netlink received msg pid:%d\n", pid);

    if (!pid) {
        printk(KERN_ERR "Received pid 0\n");
        return;
    }

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    //Not in multicast group
    NETLINK_CB(skb_out).dst_group = 0;

    memcpy(nlmsg_data(nlh), msg, msg_size);

    printk(KERN_ALERT "About to send\n");

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    printk(KERN_ALERT "Post send %d\n", res);
    if (res < 0) {
        printk(KERN_INFO "Error while sending back to user\n");
    }
    printk(KERN_INFO "Finished echo\n");
#endif
}

static int __init mod_init(void) {
    struct netlink_kernel_cfg cfg = {
            .input = echo_netlink,
    };

    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    svc->thread = kthread_run((void*) start_listen, NULL, "packet_send");
    printk(KERN_ALERT "covert_kernel module loaded\n");

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -ENOMEM;
    }

    //nl_socket_disable_auto_ack(nl_sk);

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

    netlink_kernel_release(nl_sk);

    if (svc->listen_socket != NULL) {
        kernel_sock_shutdown(svc->listen_socket, SHUT_RDWR);
        sock_release(svc->listen_socket);
        printk(KERN_ALERT "release socket\n");
    }

    kfree(svc);
    kfree(buffer);
    printk(KERN_ALERT "removed covert_kernel module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
