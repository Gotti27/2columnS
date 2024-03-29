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
#include <linux/timekeeping.h>

#define NETLINK_GROUP 2

#define TC_ACCEPT 0
#define TC_DROP 1
#define TC_NO_MATCH 2

typedef struct rule_struct {
	char source[16];
	char destination[16];
	unsigned short port;
	unsigned char protocol;
	char action;
} *rule;


typedef struct rule_list_struct {
	rule data;
	struct rule_list_struct *next;
} *rule_list;

static struct nf_hook_ops hook_in;
struct sock *nl_sk = NULL;
static int pid = -1;
static unsigned int seq = 0;
static int LOCK = TC_ACCEPT;
static int DEFAULT = TC_ACCEPT;
static rule_list r_list = NULL;

void clean_rule_list(void) {
	rule_list next; 
	
	while (r_list != NULL) {
		next = (r_list)->next;
		kfree(r_list);
		r_list = next;
	}
}

void create_rule(rule r) {
	rule_list curr, next;

	if (r_list == NULL) {
		r_list = (rule_list) kmalloc(sizeof(struct rule_list_struct), GFP_KERNEL);
        next = r_list;
	} else {
        curr = r_list;

        while (curr->next != NULL) {
            curr = curr->next;
        }

        curr->next = (rule_list) kmalloc(sizeof(struct rule_list_struct), GFP_KERNEL);
        next = curr->next;
    }

	next->data = (rule) kmalloc(sizeof(struct rule_struct), GFP_KERNEL);

	strncpy(next->data->source, r->source, 16);
	strncpy(next->data->destination, r->destination, 16);
	next->data->port = r->port;
	next->data->protocol = r->protocol;
	next->data->action = r->action;
	next->next = NULL;
}

void print_list(void) {
	rule_list curr = r_list;
	int index = 0;
	
	if (curr == NULL) {
		printk(KERN_DEBUG " -- The list is empty\n");
		return;
	}

	printk(KERN_INFO " -- Begin printing rules\n");
	while (curr != NULL) {
		printk(KERN_DEBUG "\tRule %d: source %s\n\tdest: %s\n\tport: %hd\n\tproto: %x\n\taction: %x\n", index, curr->data->source, curr->data->destination, curr->data->port, curr->data->protocol, curr->data->action);
		curr = curr->next;
		index++;
        if (index == 34){
            printk(KERN_INFO "You are such a naughty boy");
        }
	}
	printk(KERN_DEBUG " -- End printing rules\n");
}

static void netlink_handler(struct sk_buff *skb){
    struct nlmsghdr *nlh;
    char *payload; 
    char *msg_rule;
	rule r;

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload: %s\n", (char *)nlmsg_data(nlh));

    payload = (char *)nlmsg_data(nlh);
    msg_rule = payload + 5;

    if (strncmp(payload, "RULE", 4) == 0) {
        printk(KERN_INFO "Oh look! a new rule\n");

        if (msg_rule[0] == '0') {
            msg_rule++;
            if (strncmp(msg_rule, "LOCK", 4) == 0) {
                LOCK = TC_DROP;
                printk(KERN_INFO "IN chain locked!");
                clean_rule_list();
            } else if (strncmp(msg_rule, "UNLOCK", 6) == 0) {
                LOCK = TC_ACCEPT;
                printk(KERN_INFO "IN chain unlocked!");
                clean_rule_list();
            } else if (strncmp(msg_rule, "DEFAULT", 7) == 0) {
                msg_rule += 8;
                DEFAULT = strncmp(msg_rule, "DROP", 4) == 0 ? TC_DROP : TC_ACCEPT;
            }
        } else {
            msg_rule++;
            r = (rule) msg_rule;
            create_rule(r);
            printk(KERN_INFO "Added rule:\n\t- Source: %s\n\t- Dest: %s\n\t- Port: %hd\n\t- Proto: %x\n\t- Action: %x\n", r->source, r->destination, r->port, r->protocol, r->action);
            print_list();
        }
    }
    pid = nlh->nlmsg_pid; /*pid of sending process */
}

int convert_target(unsigned int target){
    if (target == TC_NO_MATCH){
        return DEFAULT == TC_DROP ? NF_DROP : NF_ACCEPT;
    }
    return target == TC_DROP ? NF_DROP : NF_ACCEPT;
}

unsigned int match_rules(struct ethhdr *ether, struct iphdr *iph, struct tcphdr *tcph) {
	int source_match, dest_match, port_match, proto_match;
	char packet_source[16];
	char packet_dest[16];
	int index = 0;

	rule_list curr = r_list;
	
	snprintf(packet_source, 16, "%pI4", &(iph->saddr));
	snprintf(packet_dest, 16, "%pI4", &(iph->daddr));

	while (curr != NULL) {
		rule rule = curr->data;

		source_match = strncmp(rule->source, "*", 1) == 0 || strncmp(rule->source, packet_source, 16) == 0;
		dest_match = strncmp(rule->destination, "*", 1) == 0 || strncmp(rule->destination, packet_dest, 16) == 0;
		port_match = rule->port == 0 || ntohs(tcph->dest) == rule->port;
        proto_match = rule->protocol == 250 || (char)iph->protocol == rule->protocol;

		if (source_match && dest_match && port_match && proto_match) {
			printk(KERN_INFO "Packet matched Rule %d\n", index);
			return rule->action;
		}
		curr = curr->next;
		index++;
	}	
	return TC_NO_MATCH;
}

unsigned int firewall_main(void* priv, struct sk_buff* skb, const struct nf_hook_state *state){
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct ethhdr *ether;
    int msg_size, res;
    unsigned int target;

    if (LOCK) {
    	return NF_DROP;
    }

    ether = eth_hdr(skb);
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);

    target = match_rules(ether, iph, tcph);
    if (target == TC_DROP) {
    	return NF_DROP;
    }

    if (pid == -1) {
        printk(KERN_ERR "Pid or Buffer not configured\n");
        return convert_target(target);
    }

    msg_size = 100;
    skb_out = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return convert_target(target);
    }

    nlh = nlmsg_put(skb_out, 0, seq++, NLMSG_DONE, msg_size, 0);
    snprintf(nlmsg_data(nlh), msg_size, "%pI4,%pI4,%d,%d,%x:%x:%x:%x:%x:%x,%x:%x:%x:%x:%x:%x,%02x,%hu,%c,%c,%llu",
             &(iph->saddr), &(iph->daddr), // src/dest ip
             ntohs(tcph->source), ntohs(tcph->dest), // src/dest port
             ether->h_source[0], ether->h_source[1], ether->h_source[2], ether->h_source[3], ether->h_source[4], ether->h_source[5], // src MAC
             ether->h_dest[0], ether->h_dest[1], ether->h_dest[2], ether->h_dest[3], ether->h_dest[4], ether->h_dest[5], // dest MAC
             iph->protocol, // ip protocol
             ntohs(iph->tot_len), // total packet length
             tcph->syn ? '1' : '0', // syn flag
             tcph->ack ? '1' : '0', // ack flag
             ktime_get_real_ns()              
	     );


    res = nlmsg_multicast(nl_sk, skb_out, 0, NETLINK_GROUP, GFP_KERNEL);
    if (res < 0){
        printk(KERN_ERR "Error while sending to user\n");
        pid = -1;
    }

    return convert_target(target);
}

int firewall_init(void){
    struct netlink_kernel_cfg cfg = {
        .input = netlink_handler,
    };

    printk(KERN_INFO "-- Registering Filters --\n");
    hook_in.hook = firewall_main;
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
