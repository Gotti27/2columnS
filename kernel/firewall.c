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

static struct nf_hook_ops hook1, hook2;

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

unsigned int printInfo(void* priv, struct sk_buff* skb, const struct nf_hook_state *state){
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct ethhdr *ether;
    unsigned char* user_data;
    char addr_str[16] = "127.0.0.1";
    u32 ipaddr;

    in4_pton(addr_str, -1, (u8*)&ipaddr, '\0', NULL);


    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    ether = eth_hdr(skb);
    int tcp_len = ntohs(iph->tot_len);
    user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));

    /*
    // don't print unless sender is the specified address and port
	if (iph->saddr != ipaddr || ntohs(tcph->source) != 80) {
		return NF_ACCEPT;
	}
    */
    if (iph->protocol == IPPROTO_ICMP && state->hook == NF_INET_LOCAL_IN) {
        printk(KERN_INFO "Drop ICMP (pong) packet \n");
        return NF_DROP;   // drop TCP packet
    }

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
    // pkt_hex_dump(skb);


    return NF_ACCEPT;
}

int registerFilter(void){
    printk(KERN_INFO "-- Registering Filters --\n");
    hook1.hook = printInfo;
    hook1.hooknum = NF_INET_LOCAL_IN;
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook1);

    hook2.hook = printInfo;
    hook2.hooknum = NF_INET_LOCAL_OUT;
    hook2.pf = PF_INET;
    hook2.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook2);

    return 0;
}

void removeFilter(void){
    printk(KERN_INFO "-- Removing Filters --\n");
    nf_unregister_net_hook(&init_net, &hook1);
}





module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
