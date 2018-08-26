#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <net/sock.h>

#define PORT 2325

struct service {
    struct socket* listen_socket;
    struct task_struct* thread;
};

struct service* svc;

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
    int error, i, size;
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
    while (1) {
        error = kernel_accept(svc->listen_socket, &acsock, 0);
        if (error < 0) {
            printk(KERN_ERR "cannot accept socket\n");
            return -1;
        }
        printk(KERN_ERR "sock %d accepted\n", i++);

        memset(&buf, 0, len + 1);
        while ((size = recv_msg(acsock, buf, len)) > 0) {
            send_msg(acsock, buf, size);
            memset(&buf, 0, len + 1);
        }

        sock_release(acsock);
    }

    return 0;
}

static int __init mod_init(void) {
    svc = kmalloc(sizeof(struct service), GFP_KERNEL);
    svc->thread = kthread_run((void*) start_listen, NULL, "echo-serv");
    printk(KERN_ALERT "echo-serv module loaded\n");

    return 0;
}

static void __exit mod_exit(void) {
    if (svc->listen_socket != NULL) {
        kernel_sock_shutdown(svc->listen_socket, SHUT_RDWR);
        sock_release(svc->listen_socket);
        printk(KERN_ALERT "release socket\n");
    }

    kfree(svc);
    printk(KERN_ALERT "removed echo-serv module\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("Kernel based networking hub");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Agapeyev <jagapeyev@gmail.com>");
