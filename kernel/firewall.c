#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/netlink.h>

#define NETLINK_GROUP 2

static struct nf_hook_ops hook_in;
struct sock *nl_sk = NULL;
static int pid = -1;
static unsigned int seq = 0;

static void set_netlink_pid(struct sk_buff *skb){
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload: %s\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid; /*pid of sending process */
}

unsigned int printInfo(void* priv, struct sk_buff* skb, const struct nf_hook_state *state){
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct ethhdr *ether;
    int msg_size, res, ip_len;

    if (pid == -1) {
        printk(KERN_ERR "Pid or Buffer not configured\n");
        return NF_ACCEPT;
    }

    msg_size = 100;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    ether = eth_hdr(skb);
    ip_len = ntohs(iph->tot_len);

    skb_out = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return NF_ACCEPT;
    }

    nlh = nlmsg_put(skb_out, 0, seq++, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    snprintf(nlmsg_data(nlh), msg_size, "%pI4,%pI4,%d,%d,%x:%x:%x:%x:%x:%x,%x:%x:%x:%x:%x:%x,%02x,%hu,%c,%c",
             &(iph->saddr), &(iph->daddr), // src/dest ip
             ntohs(tcph->source), ntohs(tcph->dest), // src/dest port
             ether->h_source[0], ether->h_source[1], ether->h_source[2], ether->h_source[3], ether->h_source[4], ether->h_source[5], // src MAC
             ether->h_dest[0], ether->h_dest[1], ether->h_dest[2], ether->h_dest[3], ether->h_dest[4], ether->h_dest[5], // dest MAC
             iph->protocol, // ip protocol
             ip_len, // total packet length
             tcph->syn ? '1' : '0', // syn flag
             tcph->ack ? '1' : '0' // ack flag
             // timestamp
             );


    res = nlmsg_multicast(nl_sk, skb_out, 0, NETLINK_GROUP, GFP_KERNEL);
    if (res < 0){
        printk(KERN_ERR "Error while sending to user\n");
        pid = -1;
    }

    return NF_ACCEPT;
}

int firewall_init(void){
    struct netlink_kernel_cfg cfg = {
        .input = set_netlink_pid,
    };

    printk(KERN_INFO "-- Registering Filters --\n");
    hook_in.hook = printInfo;
    hook_in.hooknum = NF_INET_LOCAL_IN;
    hook_in.pf = PF_INET;
    hook_in.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_in);

    // Netlink initialization
    printk(KERN_INFO "-- Initializing Netlink --\n");
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
    if (!nl_sk) {
        printk(KERN_CRIT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

void firewall_exit(void){
    printk(KERN_INFO "-- Removing Filters --\n");
    nf_unregister_net_hook(&init_net, &hook_in);

    //Release netlink
    printk(KERN_INFO "-- Removing Netlink --\n");
    netlink_kernel_release(nl_sk);
}


module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
