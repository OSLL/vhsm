#include <linux/kernel.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>

#ifndef NETLINK_EXAMPLE
#define NETLINK_EXAMPLE 21
#endif

#define NLEX_GRP_MAX    0

static struct sock *nlsk;



static int
nl_step(struct sk_buff *skb,
        struct nlmsghdr *nlh)
{
    printk(KERN_INFO " From pid %u\n",nlh->nlmsg_pid);
}

static void
nl_callback(struct sk_buff *skb)
{
    printk(KERN_INFO "call_back - ");
    printk(KERN_INFO " From pid %u\n",NETLINK_CB(skb).pid);
}

static int __init nlexample_init(void)
{
   nlsk = netlink_kernel_create(&init_net,
                NETLINK_EXAMPLE,
                NLEX_GRP_MAX,
                nl_callback,
                NULL,
                THIS_MODULE);
   if (nlsk == NULL) {
      printk(KERN_ERR "Can't create netlink\n");
      return -ENOMEM;
   }
   return 0;
}

void __exit nlexample_exit(void)
{
    netlink_kernel_release(nlsk);
}

module_init(nlexample_init);
module_exit(nlexample_exit);

MODULE_AUTHOR("Pablo Neira Ayuso <pablo@netfilter.org>");
MODULE_LICENSE("GPL");