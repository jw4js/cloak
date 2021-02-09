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
	struct
	{
		u16 frag_off;
	} ipv4;
	struct
	{
		u8 code;
	} icmp;
	struct
	{
		union
		{
			struct
			{
#if defined(__BIG_ENDIAN_BITFIELD)
				u8 __bitpad0:4,
					reserved_bit0:1,
					reserved_bit1:1,
					reserved_bit2:1,
					__bitpad1:1;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
				u8 __bitpad1:1,
					reserved_bit2:1,
					reserved_bit1:1,
					reserved_bit0:1,
					__bitpad0:4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
			} __attribute__((packed));
			u8 reserved_bits;
		};
		u16 urg_ptr;
	} tcp;
};

struct nf_ct_ext_type nf_conn_netcloak =
{
	.id = NF_CT_EXT_NETCLOAK,
	.len = sizeof(struct nf_conn_netcloak),
	.align = 1,
};

#define NF_CT_EXT_NETCLOAK_TYPE struct nf_conn_netcloak

enum bitstate
{
	BITSTATE_DEFAULT = 2,
	BITSTATE_RANDOM = 3,
	BITSTATE_N = 0,
	BITSTATE_Y = 1,
	BITSTATE_S = 4,
	BITSTATE_O = 5,
};

enum value_algorithm
{
	VALUE_CONST = 0,
	VALUE_RANDOM = 1,
	VALUE_COPY = 2,
	VALUE_DEFAULT = 3,
};

struct value_u16
{
	union
	{
		u16 max;
		u16 value;
	};
	u16 min:14;
	enum value_algorithm algorithm:2;
} __attribute__((packed));

struct value_u8
{
	union
	{
		u8 max;
		u8 value;
	};
	u8 min:6;
	enum value_algorithm algorithm:2;
} __attribute__((packed));

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

static const u32 IP_ID_TCP_CLOS = 0;
static const u32 IP_ID_TCP_OPEN = 1;
static const u32 IP_ID_ICMP = 2;
static const u32 IP_ID_MAX = 3;

#ifdef __BIG_ENDIAN
static const u32 IP_FRAG_DF_SHIFT = 14;
static const u32 IP_FRAG_RESERVED_SHIFT = 15;
#else
static const u32 IP_FRAG_DF_SHIFT = 6;
static const u32 IP_FRAG_RESERVED_SHIFT = 7;
#endif
static const u16 IP_FRAG_DF_BIT = __constant_cpu_to_be16(1 << 14);
static const u16 IP_FRAG_RESERVED_BIT = __constant_cpu_to_be16(1 << 15);

static const u32 TCP_RESERVED0_SHIFT = 3;
static const u32 TCP_RESERVED1_SHIFT = 2;
static const u32 TCP_RESERVED2_SHIFT = 1;

/* u8 avoids endianness issues */
static const u8 TCP_RESERVED0_BIT = 1 << 3;
static const u8 TCP_RESERVED1_BIT = 1 << 2;
static const u8 TCP_RESERVED2_BIT = 1 << 1;

static const u8 TCP_RESERVED_MASK = 7 << 1;

static const u32 TCP_RESERVED_BYTE_OFFSET = 12;

struct netcloak_config
{
	enum bitstate icmp_reply_fragment;
	struct value_u8 icmp_code;
	u8 icmp_id_seq:1;
	enum bitstate ipv4_fragment;
	struct ipv4_id_sequence ipv4_id_seq[3];
	u8 ipv4_initial_ttl;
	enum bitstate tcp_reserved[3];
	struct value_u16 tcp_urg_ptr;
};

static const struct netcloak_config CONFIG_DEFAULT =
{
	.icmp_reply_fragment = BITSTATE_DEFAULT,
	.icmp_code =
	{
		.algorithm = VALUE_DEFAULT,
	},
	.icmp_id_seq = 0,
	.ipv4_fragment = BITSTATE_DEFAULT,
	.ipv4_id_seq =
	{
		{
			.random = 0,
			.increment = 1,
			.value = 1,
		},
		{
			.random = 0,
			.increment = 1,
			.value = 1,
		},
		{
			.random = 0,
			.increment = 1,
			.value = 1,
		},
	},
	.ipv4_initial_ttl = 64,
	.tcp_reserved = 
	{
		BITSTATE_N,
		BITSTATE_N,
		BITSTATE_N,
	},
	.tcp_urg_ptr =
	{
		.algorithm = VALUE_DEFAULT,
	},
};

static struct netcloak_config config;

static const u8 icmp_request_reply[NR_ICMP_TYPES + 1] = 
{
	[ICMP_ECHO] = ICMP_ECHOREPLY,
	[ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY,
	[ICMP_INFO_REQUEST] = ICMP_INFO_REPLY,
	[ICMP_ADDRESS] = ICMP_ADDRESSREPLY,
};

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wparentheses"

static u16 ip_id_state[2];

static u16 ip_gen_id(const struct ipv4_id_sequence algorithm,const u32 id)
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

static inline u16 get_random_u16(void)
{
	u16 _;
	get_random_bytes(&_,2);
	return _;
}

static u32 bitstate(const enum bitstate algorithm,u32 a,const u32 b)
{
	switch(algorithm)
	{
		case BITSTATE_RANDOM:
		a = get_random_byte() & 1;
		break;
		case BITSTATE_O:
		case BITSTATE_S:
		if(b == -1)
			break;
		a = b;
		if(algorithm == BITSTATE_O)
			a ^= 1;
		break;
		case BITSTATE_N:
		case BITSTATE_Y:
		a = (u32)algorithm;
		case BITSTATE_DEFAULT:
		break;
	}
	return a;
}

static u16 value_u16(const struct value_u16 value_algorithm,u16 a,const u32 b)
{
	switch(value_algorithm.algorithm)
	{
		case VALUE_CONST:
		a = value_algorithm.value;
		break;
		case VALUE_RANDOM:
		a = get_random_u16() % (value_algorithm.max - value_algorithm.min) + value_algorithm.min;
		break;
		case VALUE_COPY:
		if(b == -1)
			break;
		a = b;
		break;
		case VALUE_DEFAULT:
		break;
	}
	return a;
}

static u8 value_u8(const struct value_u8 value_algorithm,u8 a,const u8 b)
{
	switch(value_algorithm.algorithm)
	{
		case VALUE_CONST:
		a = value_algorithm.value;
		break;
		case VALUE_RANDOM:
		a = get_random_byte() % (value_algorithm.max - value_algorithm.min) + value_algorithm.min;
		break;
		case VALUE_COPY:
		a = b;
		break;
		case VALUE_DEFAULT:
		break;
	}
	return a;
}

static u32 ipv4_hook_o(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
	enum ip_conntrack_info ctstate;
	struct nf_conn * nfct = nf_ct_get(skb,&ctstate);
	struct nf_conn_netcloak * ncstate = NULL;
	if(nfct != NULL)
		ncstate = nf_ct_ext_find(nfct,NF_CT_EXT_NETCLOAK);
	struct iphdr * iph = ip_hdr(skb);
	switch(iph->protocol)
	{
		case IPPROTO_ICMP:;
		struct icmphdr * icmph = icmp_hdr(skb);
		iph->frag_off = 
			iph->frag_off &~ IP_FRAG_DF_BIT |
			(u16)bitstate(
				config.icmp_reply_fragment,
				iph->frag_off >> IP_FRAG_DF_SHIFT & 1,
				ncstate == NULL ? -1 : (ncstate->ipv4.frag_off >> IP_FRAG_DF_SHIFT & 1)
			) << IP_FRAG_DF_SHIFT;
		u8 code = value_u8(config.icmp_code,icmph->code,ncstate->icmp.code);
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
		u8 * doff_res1 = (u8 *)tcph + TCP_RESERVED_BYTE_OFFSET;
		u8 res1 = *doff_res1 |
			bitstate(config.tcp_reserved[0],*doff_res1 >> TCP_RESERVED0_SHIFT & 1,ncstate == NULL ? -1 : ncstate->tcp.reserved_bit0) << TCP_RESERVED0_SHIFT |
			bitstate(config.tcp_reserved[1],*doff_res1 >> TCP_RESERVED1_SHIFT & 1,ncstate == NULL ? -1 : ncstate->tcp.reserved_bit1) << TCP_RESERVED1_SHIFT |
			bitstate(config.tcp_reserved[2],*doff_res1 >> TCP_RESERVED2_SHIFT & 1,ncstate == NULL ? -1 : ncstate->tcp.reserved_bit2) << TCP_RESERVED2_SHIFT;
		if(res1 != *doff_res1)
		{
			tcph->check = csum16_add(csum16_sub(tcph->check,*doff_res1),res1);
			*doff_res1 = res1;
		}
		if(!tcph->urg)
		{
			__be16 urg_ptr = value_u16(config.tcp_urg_ptr,tcph->urg_ptr,ncstate == NULL ? -1 : ncstate->tcp.urg_ptr);
			if(urg_ptr != tcph->urg_ptr)
			{
				tcph->check = csum16_add(csum16_sub(tcph->check,tcph->urg_ptr),urg_ptr);
				tcph->urg_ptr = urg_ptr;
			}
		}
		default:
		iph->frag_off = 
			iph->frag_off &~ IP_FRAG_DF_BIT |
			(u16)bitstate(
				config.ipv4_fragment,
				iph->frag_off >> IP_FRAG_DF_SHIFT & 1,
				ncstate == NULL ? -1 : (ncstate->ipv4.frag_off >> IP_FRAG_DF_SHIFT & 1)
			) << IP_FRAG_DF_SHIFT;
	}
transmit:
	iph->ttl = config.ipv4_initial_ttl;
	ip_send_check(iph);
	return NF_ACCEPT;
}

static const u32 ICMP_CODE_ZERO =
	(1 << ICMP_ECHOREPLY) |
	(1 << ICMP_SOURCE_QUENCH) |
	(1 << ICMP_ECHO) |
	(1 << 9) | /* Router Advertisement */
	(1 << 10) | /* Router solicitation */
	(1 << ICMP_TIMESTAMP) |
	(1 << ICMP_TIMESTAMPREPLY) |
	(1 << ICMP_INFO_REQUEST) |
	(1 << ICMP_INFO_REPLY) |
	(1 << ICMP_ADDRESS) |
	(1 << ICMP_ADDRESSREPLY) |
	(1 << 30); /* ICMP Traceroute */

static u32 ipv4_hook_i(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
	enum ip_conntrack_info ctstate;
	struct nf_conn * nfct = nf_ct_get(skb,&ctstate);
	if(nfct == NULL)
		goto accept;
	struct nf_conn_netcloak * ncstate = ctstate == IP_CT_NEW ? nf_ct_ext_add(nfct,NF_CT_EXT_NETCLOAK,GFP_ATOMIC) : nf_ct_ext_find(nfct,NF_CT_EXT_NETCLOAK);
	if(ncstate == NULL)
		goto accept;
	struct iphdr * iph = ip_hdr(skb);
	switch(iph->protocol)
	{
		case IPPROTO_ICMP:;
		struct icmphdr * icmph = icmp_hdr(skb);
		if(ICMP_CODE_ZERO >> icmph->type & 1)
			ncstate->icmp.code = icmph->code;
		break;
		case IPPROTO_TCP:;
		struct tcphdr * tcph = tcp_hdr(skb);
		if(ctstate == IP_CT_NEW)
			ncstate->tcp.reserved_bits = ((u8 *)tcph)[TCP_RESERVED_BYTE_OFFSET];
		ncstate->tcp.urg_ptr = tcph->urg ? 0 : be16_to_cpu(tcph->urg_ptr);
		break;
	}
	if(IP_CT_NEW == ctstate)
		ncstate->ipv4.frag_off = iph->frag_off & (IP_FRAG_DF_BIT | IP_FRAG_RESERVED_BIT);
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
	config.icmp_id_seq = 1;
	config.icmp_reply_fragment = BITSTATE_O;
	config.icmp_code.algorithm = VALUE_COPY;
	config.ipv4_fragment = BITSTATE_O;
	config.tcp_reserved[0] = BITSTATE_Y;
	config.tcp_reserved[1] = BITSTATE_Y;
	config.tcp_reserved[2] = BITSTATE_Y;
	config.tcp_urg_ptr.algorithm = VALUE_RANDOM;
	config.tcp_urg_ptr.max = -1;
	config.tcp_urg_ptr.min = 0;
	config.ipv4_initial_ttl = 255;
	config.ipv4_fragment = BITSTATE_N;
	config.ipv4_id_seq[0].endian = 1;
	config.ipv4_id_seq[1].endian = 1;
	config.ipv4_id_seq[2].endian = 1;
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