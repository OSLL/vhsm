#include <linux/kernel.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/ve.h>

struct nl_sock {
    struct sock *sk;
    struct list_head list;
};

static LIST_HEAD(sock_list);

static void nl_callback(struct sk_buff *skb);

static int net_init(struct net *net) {
    struct nl_sock *nl_sk;

    nl_sk = kzalloc(sizeof(*nl_sk), GFP_KERNEL);
    if (!nl_sk) return -ENOMEM;

    nl_sk->sk = netlink_kernel_create(net, NETLINK_USERSOCK, 0, nl_callback, NULL, THIS_MODULE);
    if (!nl_sk->sk) {
        printk(KERN_ERR"Unable to create netlink socket!\n");
        kfree(nl_sk);
        return -ENODEV;
    }

    list_add_tail(&nl_sk->list, &sock_list);
    return 0;
}

static void net_exit(struct net *net) {
    struct nl_sock *nl_sk;

    list_for_each_entry(nl_sk, &sock_list, list) {
        if (sock_net(nl_sk) == net) {
            list_del(&nl_sk->list);
            netlink_kernel_release(nl_sk->sk);
            kfree(nl_sk);
        }
    }
}

static struct pernet_operations net_ops = {
    .init   = net_init,
    .exit   = net_exit,
};

static void nl_callback(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid, res;
    struct sk_buff *skb_out;

    nlh = (struct nlmsghdr*)skb->data;
    pid = nlh->nlmsg_pid;

    printk(KERN_ERR"Netlink received msg: %s | pid: %d | veid: %d\n",(char*)NLMSG_DATA(nlh), pid, skb->sk->owner_env->veid);

    char *msg = "Hello from kernel";
    int msg_size = strlen(msg);

    skb_out = nlmsg_new(msg_size, 0);
    if(!skb_out) {
        printk(KERN_ERR"Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(NLMSG_DATA(nlh), msg, msg_size);
    res = nlmsg_unicast(skb->sk, skb_out, pid);

    if(res < 0) printk(KERN_ERR"Unable to send message to to user\n");
}

static int __init nlexample_init(void) {
    return register_pernet_subsys(&net_ops);
//   nlsk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, nl_callback, NULL, THIS_MODULE);
//   if (nlsk == NULL) {
//      printk(KERN_ERR "Can't create netlink\n");
//      return -ENOMEM;
//   }
//   return 0;
}

void __exit nlexample_exit(void) {
   unregister_pernet_subsys(&net_ops); 
}

module_init(nlexample_init);
module_exit(nlexample_exit);

MODULE_LICENSE("GPL");

