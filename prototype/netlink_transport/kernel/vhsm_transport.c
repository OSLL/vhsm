#include <linux/kernel.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/ve.h>
#include <net/net_namespace.h>

struct nl_sock {
    struct sock *sk;
    struct list_head list;
    uint32_t veid;
};

//----------------------------------------------------------------------------

#define VHSM_REQUEST    0
#define VHSM_RESPONSE   1
#define VHSM_ERROR      2
#define VHSM_REGISTER   3
#define VHSM_UNREGISTER 4

struct vmsghdr {
    int type;
    uint32_t veid;
    uint32_t pid;
};

//----------------------------------------------------------------------------

static struct sock *vhsm_sock = NULL;
static uint32_t vhsm_pid;

static LIST_HEAD(sock_list);
static DEFINE_MUTEX(sock_list_mutex);

static void nl_callback(struct sk_buff *skb);

//----------------------------------------------------------------------------

static int net_init(struct net *net) {
    struct nl_sock *nl_sk;

    nl_sk = kzalloc(sizeof(*nl_sk), GFP_KERNEL);
    if (!nl_sk) return -ENOMEM;

    nl_sk->sk = netlink_kernel_create(net, NETLINK_USERSOCK, 0, nl_callback, NULL, THIS_MODULE);
    if (!nl_sk->sk) {
        printk(KERN_ERR"Unable to create netlink socket\n");
        kfree(nl_sk);
        return -ENODEV;
    }

    mutex_lock(&sock_list_mutex);
    list_add_tail(&nl_sk->list, &sock_list);
    mutex_unlock(&sock_list_mutex);
    nl_sk->veid = nl_sk->sk->owner_env->veid;

    printk(KERN_ERR"Register socket for veid: %d\n", nl_sk->veid);
    return 0;
}

static void net_exit(struct net *net) {
    struct nl_sock *nl_sk;

    mutex_lock(&sock_list_mutex);
    list_for_each_entry(nl_sk, &sock_list, list) {
        if (sock_net(nl_sk->sk) == net) goto found;
    }
    mutex_unlock(&sock_list_mutex);
    return;

found:
    list_del(&nl_sk->list);
    mutex_unlock(&sock_list_mutex);

    netlink_kernel_release(nl_sk->sk);
    kfree(nl_sk);
}

static struct pernet_operations net_ops = {
    .init   = net_init,
    .exit   = net_exit,
};

//----------------------------------------------------------------------------

static struct sock *find_sock(uint32_t veid) {
    struct nl_sock *nl_sk;

    mutex_lock(&sock_list_mutex);
    list_for_each_entry(nl_sk, &sock_list, list) {
        if (nl_sk->veid == veid) {
            mutex_unlock(&sock_list_mutex);
            return nl_sk->sk;
        }
    }

    mutex_unlock(&sock_list_mutex);
    return NULL;
}

static struct sk_buff *copy_message(struct nlmsghdr *data) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    skb = nlmsg_new(data->nlmsg_len, 0);
    if(!skb) return NULL;
    NETLINK_CB(skb).dst_group = 0;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, data->nlmsg_len - NLMSG_HDRLEN, 0);
    if(!nlh) {
        kfree(skb);
        return NULL;
    }

    memcpy(NLMSG_DATA(nlh), NLMSG_DATA(data), data->nlmsg_len - NLMSG_HDRLEN);
    return skb;
}

static bool send_vhsm_request(struct sock *from, struct sk_buff *skb) {
    struct sk_buff *skb_to;
    struct vmsghdr *msgh;

    if(!vhsm_sock) return false;

    skb_to = copy_message((struct nlmsghdr*)skb->data);
    if(!skb_to) return false;

    msgh = (struct vmsghdr*)NLMSG_DATA(skb_to->data);
    //msgh->pid = data->nlmsg_pid;
    msgh->pid = NETLINK_CB(skb).pid;    //portid in new kernels
    msgh->veid = from->owner_env->veid;

    return nlmsg_unicast(vhsm_sock, skb_to, vhsm_pid) >= 0;
}

static bool send_vhsm_response(struct nlmsghdr *data) {
    struct sk_buff *skb_to;
    struct vmsghdr *msgh;
    struct sock *sk;
    uint32_t pid, veid;

    msgh = (struct vmsghdr*)NLMSG_DATA(data);
    pid = msgh->pid;
    veid = msgh->veid;
    msgh->pid = 0;
    msgh->veid = 0;

    sk = find_sock(veid);
    if(!sk) return false;

    skb_to = copy_message(data);
    if(!skb_to) return false;

    return nlmsg_unicast(sk, skb_to, pid) >= 0;
}

static void send_error_message(struct sock *sk, uint32_t pid) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct vmsghdr msgh;
    msgh.type = VHSM_ERROR;
    msgh.pid = 0;
    msgh.veid = 0;

    skb = nlmsg_new(sizeof(struct vmsghdr), 0);
    if(!skb) return;
    NETLINK_CB(skb).dst_group = 0;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct vmsghdr), 0);
    if(!nlh) {
        kfree(skb);
        return;
    }

    memcpy(NLMSG_DATA(nlh), &msgh, sizeof(msgh));
    nlmsg_unicast(sk, skb, pid);
}

//----------------------------------------------------------------------------

static void nl_callback(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    struct vmsghdr *msgh;
    uint32_t pid;

    nlh = (struct nlmsghdr*)skb->data;
    msgh = (struct vmsghdr*)NLMSG_DATA(nlh);
    //pid = nlh->nlmsg_pid;
    pid = NETLINK_CB(skb).pid; //portid in new kernels

    printk(KERN_ERR"Got message type: %d | pid: %d | veid: %d\n", msgh->type, pid, skb->sk->owner_env->veid);

    switch(msgh->type) {
    case VHSM_REQUEST:
        if(!send_vhsm_request(skb->sk, skb))
            send_error_message(skb->sk, pid);
        break;
    case VHSM_RESPONSE:
        if(vhsm_sock && skb->sk == vhsm_sock)
            send_vhsm_response(nlh);
        else
            send_error_message(skb->sk, pid);
        break;
    case VHSM_ERROR:
        break;
    case VHSM_REGISTER:
        if(vhsm_sock) break;
        vhsm_sock = skb->sk;
        vhsm_pid = pid;
        printk(KERN_ERR"Registered VHSM | pid: %d | veid: %d\n", vhsm_pid, vhsm_sock->owner_env->veid);
        break;
    case VHSM_UNREGISTER:
        if(!vhsm_sock || pid != vhsm_pid || vhsm_sock->owner_env->veid != skb->sk->owner_env->veid) break;
        vhsm_sock = 0;
        vhsm_pid = 0;
        printk(KERN_ERR"VHSM unregistered\n");
        break;
    default:
        send_error_message(skb->sk, pid);
    }
}

static int __init nlexample_init(void) {
    return register_pernet_subsys(&net_ops);
}

void __exit nlexample_exit(void) {
   unregister_pernet_subsys(&net_ops);
}

module_init(nlexample_init);
module_exit(nlexample_exit);

MODULE_LICENSE("GPL");

