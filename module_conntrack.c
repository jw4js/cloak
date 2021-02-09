#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kallsyms.h>
#include <linux/netdevice.h>
#include <linux/percpu-defs.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/ipv4/nf_conntrack_ipv4.h>
#include <net/netfilter/ipv6/nf_conntrack_ipv6.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");

#include "patch.h"
#include "mm.h"
#include "spinlock.h"

struct nf_conn_netcloak
{
	u32 id;
};

struct nf_ct_ext_type nf_conn_netcloak =
{
	.id = NF_CT_EXT_NETCLOAK,
	.len = sizeof(struct nf_conn_netcloak),
	.align = 1,
};

#define NF_CT_EXT_NETCLOAK_TYPE struct nf_conn_netcloak

enum ip_icmp_fragment
{
	IP_FRAGMENT_DEFAULT = 2,
	IP_FRAGMENT_RANDOM = 3,
	IP_FRAGMENT_N = 0,
	IP_FRAGMENT_Y = 1,
	IP_FRAGMENT_ICMP_S = 4,
	IP_FRAGMENT_ICMP_O = 5,
};

enum icmp_code_type
{
	ICMP_CODE_CONST = 0,
	ICMP_CODE_RANDOM = 1,
	ICMP_CODE_SAME = 2,
};

struct ipv4_id_sequence
{
	union
	{
		u16 max;
		u16 value;
	};
	u16 min:13;
	u16 endian:1; // 1 -> little 0 -> big
	u16 random:1;
	u16 increment:1;
} __attribute__((packed));

struct icmp_code
{
	union
	{
		u8 max;
		u8 value;
	};
	u8 min:6;
	enum icmp_code_type type:2;
} __attribute__((packed));

static const u32 IP_ID_TCP_CLOS = 0;
static const u32 IP_ID_TCP_OPEN = 1;
static const u32 IP_ID_ICMP = 2;
static const u32 IP_ID_MAX = 3;

struct netcloak_config
{
	enum ip_icmp_fragment icmp_reply_fragment;
	enum ip_icmp_fragment ipv4_fragment;
	struct icmp_code icmp_code;
	struct ipv4_id_sequence ipv4_id_seq[3];
	u8 ipv4_initial_ttl;
	u8 icmp_id_seq:1;
};

static const struct netcloak_config CONFIG_DEFAULT =
{
	.icmp_reply_fragment = IP_FRAGMENT_DEFAULT,
	.ipv4_fragment = IP_FRAGMENT_DEFAULT,
	.icmp_code =
	{
		.value = 0,
		.type = ICMP_CODE_CONST,
	},
	.ipv4_id_seq =
	{
		{
			.random = 0,
			.increment = 1,
			.value = 1,
		},
		{
			.random = 0,
			.increment = 0,
			.value = 0,
		},
		{
			.random = 0,
			.increment = 1,
			.value = 1,
		},
	},
	.ipv4_initial_ttl = 64,
	.icmp_id_seq = 0,
};

static struct netcloak_config config;

static const u8 icmp_request_reply[NR_ICMP_TYPES + 1] = 
{
	[ICMP_ECHO] = ICMP_ECHOREPLY,
	[ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY,
	[ICMP_INFO_REQUEST] = ICMP_INFO_REPLY,
	[ICMP_ADDRESS] = ICMP_ADDRESSREPLY,
};

static const int icmp_stack_max = 256;
static struct sk_buff * icmp_stack[256]; // should not overflow
static int icmp_stack_i = 0;
static DEFINE_SPINLOCK(icmp_stack_lock);

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wparentheses"

static u16 ip_id_state[2];

static u16 ip_gen_id(struct ipv4_id_sequence algorithm,u32 id)
{
	u16 value = algorithm.value;
	if(algorithm.random)
	{
		get_random_bytes(&value,2);
		value = value % (algorithm.max - algorithm.min) + algorithm.min;
	}
	value = cpu_to_be16(value) &~- algorithm.endian | cpu_to_le16(value) &- algorithm.endian;
	if(algorithm.increment)
		return ip_id_state[id] += value;
	return value;
}

static inline u8 get_random_byte(void)
{
	u8 _;
	get_random_bytes(&_,1);
	return _;
}

static u32 ipv4_hook_o(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
/*
	enum ip_conntrack_info ctstate;
	struct nf_conn * nfct = nf_ct_get(skb,&ctstate);
	printk(KERN_INFO "struct nf_conn at %p\n",nfct);
	if(ctstate == IP_CT_NEW)
		printk(KERN_INFO "It is a new connection!\n");
*/
	struct iphdr * iph = ip_hdr(skb);
	u16 fragment = be16_to_cpu(iph->frag_off) >> 14 & 1;
	iph->frag_off &=~ cpu_to_be16(1 << 14);
	switch(iph->protocol)
	{
		case IPPROTO_ICMP:;
		struct icmphdr * icmph = icmp_hdr(skb);
		struct iphdr * iph_req;
		struct icmphdr * icmph_req;
		skb = NULL;
		if(icmph->type == ICMP_ECHOREPLY || icmph->type == ICMP_TIMESTAMPREPLY)
		{
			spinlock_lock(icmp_stack_lock,0);
			while(icmp_stack_i > 0)
			{
				skb = icmp_stack[--icmp_stack_i];
				iph_req = ip_hdr(skb);
				icmph_req = icmp_hdr(skb);
				// printk(KERN_INFO "INCOMING type:%u saddr:%x daddr:%x OUTGOING type:%u saddr:%x daddr:%x XREF %u\n",icmph_req->type,iph_req->saddr,iph_req->daddr,icmph->type,iph->saddr,iph->daddr,icmp_request_reply[icmph_req->type]);
				if(icmph->type == icmp_request_reply[icmph_req->type] && iph_req->daddr == iph->saddr && iph_req->saddr == iph->daddr)
					break;
				kfree_skb(skb);
				skb = NULL;
			}
			spinlock_free(icmp_stack_lock,0);
		}
		switch(config.icmp_reply_fragment)
		{
			case IP_FRAGMENT_RANDOM:
			fragment |= get_random_byte() & 1;
			break;
			case IP_FRAGMENT_ICMP_O:
			case IP_FRAGMENT_ICMP_S:
			if(skb == NULL)
				break;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
			fragment |= be16_to_cpu(iph_req->frag_off) >> 14 & 1;
#pragma GCC diagnostic pop
			if(config.icmp_reply_fragment == IP_FRAGMENT_ICMP_O)
				fragment ^= 1;
			break;
			default:
			fragment |= (u16)config.icmp_reply_fragment;
			break;
			case IP_FRAGMENT_DEFAULT:
			break;
		}
		u8 code = icmph->code;
		switch(config.icmp_code.type)
		{
			case ICMP_CODE_CONST:
			code = config.icmp_code.value;
			break;
			case ICMP_CODE_RANDOM:
			code = get_random_byte() % (config.icmp_code.max - config.icmp_code.min) + config.icmp_code.min;
			break;
			case ICMP_CODE_SAME:
			if(skb != NULL)
				code = icmph_req->code;
			break;
		}
		kfree_skb(skb);
		if(code != icmph->code)
		{
			icmph->checksum = csum16_add(csum16_sub(icmph->checksum,icmph->code),code);
			icmph->code = code;
		}
		iph->id = ip_gen_id(config.ipv4_id_seq[IP_ID_ICMP],config.icmp_id_seq);
		goto transmit;
		case IPPROTO_TCP:;
		struct tcphdr * tcph = tcp_hdr(skb);
		iph->id = ip_gen_id(config.ipv4_id_seq[tcph->rst ^ 1],0);
		default:
		if(config.ipv4_fragment == IP_FRAGMENT_DEFAULT)
			goto transmit;
		switch(config.ipv4_fragment)
		{
			case IP_FRAGMENT_RANDOM:
			fragment |= get_random_byte() & 1;
			break;
			default:
			fragment |= (u16)config.ipv4_fragment;
			break;
			case IP_FRAGMENT_DEFAULT:
			break;
		}
	}
transmit:
	iph->frag_off |= cpu_to_be16(fragment << 14);
	iph->ttl = config.ipv4_initial_ttl;
	ip_send_check(iph);
	return NF_ACCEPT;
}

static u32 ipv4_hook_i(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
	if((config.icmp_reply_fragment == IP_FRAGMENT_ICMP_S || config.icmp_reply_fragment == IP_FRAGMENT_ICMP_O) && ip_hdr(skb)->protocol == IPPROTO_ICMP)
	{
		enum ip_conntrack_info ctstate;
		struct nf_conn * nfct = nf_ct_get(skb,&ctstate);
		printk(KERN_INFO "struct nf_conn at %p\n",nfct);
		if(ctstate == IP_CT_NEW)
			printk(KERN_INFO "It is a new connection!\n");
		u8 type = icmp_hdr(skb)->type;
		if(type == ICMP_ECHO || type == ICMP_TIMESTAMP)
		{
			spinlock_lock(icmp_stack_lock,0);
			if(icmp_stack_i == icmp_stack_max)
				goto accept;
			icmp_stack[icmp_stack_i++] = skb_clone(skb,GFP_ATOMIC);
			spinlock_free(icmp_stack_lock,0);
		}
	}

accept:
	return NF_ACCEPT;
}

static struct nf_hook_ops ipv4_hook_o_ops =
{
	.pf = NFPROTO_IPV4,
	.priority = NF_IP_PRI_LAST,
	.hooknum = NF_INET_LOCAL_OUT,
	.hook = ipv4_hook_o,
};

static struct nf_hook_ops ipv4_hook_i_ops =
{
	.pf = NFPROTO_IPV4,
	.priority = NF_IP_PRI_LAST,
	.hooknum = NF_INET_LOCAL_IN,
	.hook = ipv4_hook_i,
};

int init_module(void)
{
	int err = 0;
	memcpy(&config,&CONFIG_DEFAULT,sizeof(struct netcloak_config));
	get_random_bytes(ip_id_state,sizeof(ip_id_state));
	config.ipv4_id_seq[IP_ID_TCP_OPEN].value = -1;
	config.ipv4_id_seq[IP_ID_TCP_OPEN].increment = 1;
	config.ipv4_id_seq[IP_ID_TCP_OPEN].random = 1;
	config.ipv4_id_seq[IP_ID_ICMP].increment = 1;
	config.ipv4_id_seq[IP_ID_ICMP].value = 2;
	config.ipv4_id_seq[IP_ID_ICMP].min = 0;
	config.ipv4_id_seq[IP_ID_ICMP].random = 0;
	config.icmp_id_seq = 1;
	config.icmp_reply_fragment = IP_FRAGMENT_ICMP_O;
	config.icmp_code.type = ICMP_CODE_SAME;
	if(err = nf_ct_extend_register(&nf_conn_netcloak))
		goto out;
	if(err = nf_register_hook(&ipv4_hook_o_ops))
		goto out;
	if(err = nf_register_hook(&ipv4_hook_i_ops))
		goto out;
out:
	return err;
}

void exit_module(void)
{
	nf_ct_extend_unregister(&nf_conn_netcloak);
	nf_unregister_hook(&ipv4_hook_o_ops);
	nf_unregister_hook(&ipv4_hook_i_ops);
}

// module_init(init_module);
module_exit(exit_module);