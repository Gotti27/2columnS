#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

static struct nf_hook_ops hook1, hook2;

unsigned int printInfo(void* priv, struct sk_buff* skb, const struct nf_hook_state *state){
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned char* user_data;

	switch (state->hook){
		case NF_INET_LOCAL_IN: printk("*** LOCAL_IN"); break;
		default: printk("*** DEFAULT");
	}

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));

	printk("\t %pI4:%d --> %pI4:%hu\n", &(iph->saddr), ntohs(tcph->source), &(iph->daddr), ntohs(tcph->dest));
	printk("\t Seq: %d", ntohl(tcph->seq));
	printk("\t Data: %x%x%x%x", user_data[0], user_data[1], user_data[2], user_data[3]);

	struct ethhdr *ether = eth_hdr(skb);

	printk("\t Source: %x:%x:%x:%x:%x:%x\n", ether->h_source[0], ether->h_source[1], ether->h_source[2], ether->h_source[3], ether->h_source[4], ether->h_source[5]);
	printk("\t Destination: %x:%x:%x:%x:%x:%x\n", ether->h_dest[0], ether->h_dest[1], ether->h_dest[2], ether->h_dest[3], ether->h_dest[4], ether->h_dest[5]);
	printk("\t Protocol: %d\n", ether->h_proto);

	return NF_ACCEPT;
}

int registerFilter(void){
	printk(KERN_INFO "-- Registering Filters --\n");
	hook1.hook = printInfo;
	hook1.hooknum = NF_INET_LOCAL_IN;
	hook1.pf = PF_INET;
	hook1.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &hook1);


	return 0;
}

void removeFilter(void){
	printk(KERN_INFO "-- Removing Filters --\n");
	nf_unregister_net_hook(&init_net, &hook1);
}





module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
