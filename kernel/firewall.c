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
//#include <net/sock.h>
#include <linux/netlink.h>
#define NETLINK_USER 31

static struct nf_hook_ops hook1, hook2;
struct sock *nl_sk = NULL;
static int pid = -1;
static int seq = 0;
static int buffer_size = 0;

void pkt_hex_dump(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    printk("Packet hex dump:\n");
    data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t) ch);
        }

        data += linelen;
        li += 10;

        printk(KERN_CONT "\n");
    }
}

static void set_netlink_pid(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid; /*pid of sending process */
}

unsigned int printInfo(void* priv, struct sk_buff* skb, const struct nf_hook_state *state){
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    int tcp_len;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct ethhdr *ether;
    unsigned char* user_data;
    char addr_str[16] = "127.0.0.1";
    //char msg[50];

    u32 ipaddr;

    in4_pton(addr_str, -1, (u8*)&ipaddr, '\0', NULL);


    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    ether = eth_hdr(skb);
    tcp_len = ntohs(iph->tot_len);
    user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));

    /*
    // don't print unless sender is the specified address and port
	if (iph->saddr != ipaddr || ntohs(tcph->source) != 80) {
		return NF_ACCEPT;
	}
    */
    /*if (iph->protocol == IPPROTO_ICMP && state->hook == NF_INET_LOCAL_IN) {
        printk(KERN_INFO "Drop ICMP (pong) packet \n");
        return NF_DROP;   // drop TCP packet
    }*/

    switch (state->hook){
        case NF_INET_PRE_ROUTING: printk("*** PRE ROUTING"); break;
        case NF_INET_LOCAL_IN: printk("*** LOCAL IN"); break;
        case NF_INET_FORWARD: printk("*** FORWARD"); break;
        case NF_INET_POST_ROUTING: printk("*** POST ROUTING"); break;
        case NF_INET_LOCAL_OUT: printk("*** LOCAL OUT"); break;
        default: printk("*** DEFAULT");
    }

    printk("\t %pI4:%d --> %pI4:%hu\n", &(iph->saddr), ntohs(tcph->source), &(iph->daddr), ntohs(tcph->dest));
    printk("\t Protocol: %d\n", ether->h_proto);
    printk("\t Source: %x:%x:%x:%x:%x:%x\n", ether->h_source[0], ether->h_source[1], ether->h_source[2], ether->h_source[3], ether->h_source[4], ether->h_source[5]);
    printk("\t Destination: %x:%x:%x:%x:%x:%x\n", ether->h_dest[0], ether->h_dest[1], ether->h_dest[2], ether->h_dest[3], ether->h_dest[4], ether->h_dest[5]);
    printk("\t Seq: %d", ntohl(tcph->seq));
    printk("\t Size: %d", tcp_len);
    printk("\t Data: %s", user_data);
    printk("\t Pid: %d\n", pid);
    // pkt_hex_dump(skb);

    //invio dato ricevuto a user space
    // buffer_size = (buffer_size + 1) % 50;


    if(pid != -1 /*&& buffer_size == 0*/){
        msg_size = 24; // xxx.xxx.xxx.xxx:yyyyy0
        
        skb_out = nlmsg_new(msg_size, 0);
        if (!skb_out) {
            printk(KERN_ERR "Failed to allocate new skb\n");
            return NF_ACCEPT;
        }

        nlh = nlmsg_put(skb_out, 0, seq, NLMSG_DONE, msg_size, 0);
        NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
        snprintf(nlmsg_data(nlh), msg_size, "%pI4:%d\0", &(iph->saddr), ntohs(tcph->source));

        seq = (seq + msg_size + 1) % 4294967295;

        res = nlmsg_unicast(nl_sk, skb_out, pid);
        if (res < 0){
            printk(KERN_INFO "Error while sending bak to user\n");
            pid = -1;
        }
    }
    else{
        printk(KERN_INFO "Error, pid/buffer not configured\n");
    }

    return NF_ACCEPT;
}

int firewall_init(void){
    printk(KERN_INFO "-- Registering Filters --\n");
    hook1.hook = printInfo;
    hook1.hooknum = NF_INET_LOCAL_IN;
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook1);

    //hook2.hook = printInfo;
    //hook2.hooknum = NF_INET_LOCAL_OUT;
    //hook2.pf = PF_INET;
    //hook2.priority = NF_IP_PRI_FIRST;
    //nf_register_net_hook(&init_net, &hook2);

    //Inizializzo netlink
    printk(KERN_INFO "-- Registering Netlink --\n");
    struct netlink_kernel_cfg cfg = {
        .input = set_netlink_pid,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

void firewall_exit(void){
    printk(KERN_INFO "-- Removing Filters --\n");
    nf_unregister_net_hook(&init_net, &hook1);
    //nf_unregister_net_hook(&init_net, &hook2);

    //Release netlink
    printk(KERN_INFO "-- Removing Netlink --\n");
    netlink_kernel_release(nl_sk);
}


module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
