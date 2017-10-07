#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_reject.h>	// for nf_send_reset()
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <linux/skbuff.h>

#include "./wm/wm.c"
#include "./pattern.h"

unsigned int FASP_PORT = 33001;

char **TARGET_PATTERNS = NULL;
WM_STRUCT *TARGET_PATTERN_WMSTRUCT = NULL;

typedef struct tra_flag_strcut
{
	char flag;
	struct tra_flag *next;
}TRA_FLAG_STRUCT;
TRA_FLAG_STRUCT *FASP_TRA_FLAGS = NULL;

TRA_FLAG_STRUCT *TRA_FLAG_NEW(char flag)
{
	TRA_FLAG_STRUCT *tmpnew = (TRA_FLAG_STRUCT *)kmalloc(sizeof(TRA_FLAG_STRUCT), GFP_KERNEL);
	tmpnew->flag = flag;
	tmpnew->next = NULL;
	return tmpnew; 
}

int search_FASP_TRA_FLAGS(char flag)
{
	if (FASP_TRA_FLAGS->next == NULL)
		return 0;

	TRA_FLAG_STRUCT *tmp = FASP_TRA_FLAGS->next;
	while(tmp != NULL)
	{
		if (tmp->flag == flag)
			return 1;
		tmp = tmp->next;
	}
	return 0;
}

int add_FASP_TRA_FLAGS(char flag)
{
	if (FASP_TRA_FLAGS->next == NULL)
	{
		FASP_TRA_FLAGS->next = TRA_FLAG_NEW(flag);
		return 1;
	}

	TRA_FLAG_STRUCT *tmp = FASP_TRA_FLAGS->next;
	TRA_FLAG_STRUCT *tmppre = NULL;
	while(tmp != NULL)
	{
		if (tmp->flag == flag)
			return 1;
		tmppre = tmp;
		tmp = tmp->next;
	}
	tmppre->next = TRA_FLAG_NEW(flag);
	return 1;
}

int del_FASP_TRA_FLAGS(char flag)
{
	if (FASP_TRA_FLAGS->next == NULL)
		return 1;

	TRA_FLAG_STRUCT *tmp = FASP_TRA_FLAGS->next;
	TRA_FLAG_STRUCT *tmppre = FASP_TRA_FLAGS;
	while(tmp != NULL)
	{
		if (tmp->flag == flag)
		{
			tmppre->next = tmp->next;
			kfree(tmp);
			tmp = NULL;
			//printk(KERN_ALERT "---TEST del FASP_TRA_FLAG---\n");
			return 1;
		}
		tmppre = tmp;
		tmp = tmp->next;
	}
	return 1;
}

typedef struct target_ip_struct
{
	unsigned int ip_src;
	unsigned int ip_dst;
	struct target_ip_struct *left;
	struct target_ip_struct *right;

	int flag;
	char tra_flag;
}TARGET_IP_STRUCT;

TARGET_IP_STRUCT *TARGET_IP_ROOT = NULL;

TARGET_IP_STRUCT *TIS_NEW(unsigned int ip_src, unsigned int ip_dst, char tra_flag)
{
	TARGET_IP_STRUCT *tmpnew = (TARGET_IP_STRUCT *)kmalloc(sizeof(TARGET_IP_STRUCT), GFP_KERNEL);
	tmpnew->ip_src = ip_src;
	tmpnew->ip_dst = ip_dst;
	tmpnew->left = NULL;
	tmpnew->right = NULL;
	tmpnew->flag = 1;
	tmpnew->tra_flag = tra_flag;
	return tmpnew;
}

int init_globalvalue(void)
{
	// WM_SEARCH_RESULT = (WM_SEARCH_OUTPUT *)vmalloc(sizeof(WM_SEARCH_OUTPUT));
	// WM_SEARCH_RESULT_TEMP = WM_SEARCH_RESULT;

	//char tmp[4][MAXM] = { "SEMIA 3007", "GCA_000254515.2", "Chromosome", "Scaffold"};
	TARGET_PATTERNS = FASP_PATTERNS;
	TARGET_PATTERN_WMSTRUCT = wmNew();

	InitFilePattern(TARGET_PATTERN_WMSTRUCT, TARGET_PATTERNS);

	TARGET_IP_ROOT = TIS_NEW(0, 0, 'A');
	FASP_TRA_FLAGS = TRA_FLAG_NEW(0);

	//printk(KERN_ALERT "---TEST TARGET_PATTERNS: %s---\n", TARGET_PATTERNS);

	return 1;
}

TARGET_IP_STRUCT *search_TARGET_IP_ROOT(unsigned int ip_src, unsigned int ip_dst)
{
	if (TARGET_IP_ROOT->left == NULL)
		return NULL;

	TARGET_IP_STRUCT *tmp = TARGET_IP_ROOT->left;
	while (tmp != NULL)
	{
		if (tmp->ip_src > ip_src || tmp->ip_dst > ip_dst)
		{
			tmp = tmp->left;
		}
		else if (tmp->ip_src < ip_src || tmp->ip_dst < ip_dst)
		{
			tmp = tmp->right;
		}
		else if (tmp->ip_src == ip_src && tmp->ip_dst == ip_dst && tmp->flag != 0)
		{
			return tmp;
		}
	}

	return NULL;
}

int add_TARGET_IP_ROOT(unsigned int ip_src, unsigned int ip_dst, char tra_flag)
{
	
	if (TARGET_IP_ROOT->left == NULL)
	{
		TARGET_IP_ROOT->left = TIS_NEW(ip_src, ip_dst, tra_flag);
		return 1;
	}

	TARGET_IP_STRUCT *tmp = TARGET_IP_ROOT->left;
	TARGET_IP_STRUCT *tmppre = TARGET_IP_ROOT;
	while (tmp != NULL)
	{
		if (tmp->ip_src > ip_src || tmp->ip_dst > ip_dst)
		{
			tmppre = tmp;
			tmp = tmp->left;
		}
		else if (tmp->ip_src < ip_src || tmp->ip_dst < ip_dst)
		{
			tmppre = tmp;
			tmp = tmp->right;
		}
		else if (tmp->ip_src == ip_src && tmp->ip_dst == ip_dst)
		{
			tmp->flag == 1;
			//printk(KERN_ALERT "---TEST add---\n");
			return 1;
		}
	}

	TARGET_IP_STRUCT *tmpnew = TIS_NEW(ip_src, ip_dst, tra_flag);
	if (tmppre->left == NULL)
		tmppre->left = tmpnew;
	else
		tmppre->right = tmpnew;
	return 1;
}

int del_TARGET_IP_ROOT(unsigned int ip_src, unsigned int ip_dst)
{
	if (TARGET_IP_ROOT->left == NULL)
		return 1;

	TARGET_IP_STRUCT *tmp = TARGET_IP_ROOT->left;
	while (tmp != NULL)
	{
		if (tmp->ip_src > ip_src || tmp->ip_dst > ip_dst)
		{
			tmp = tmp->left;
		}
		else if (tmp->ip_src < ip_src || tmp->ip_dst < ip_dst)
		{
			tmp = tmp->right;
		}
		else if (tmp->ip_src == ip_src && tmp->ip_dst == ip_dst)
		{
			tmp->flag = 0;
			//printk(KERN_ALERT "---TEST del TARGET_IP---\n");
			return 1;
		}
	}

	return 1;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	if (0 != skb_linearize(skb)) {
		return NF_ACCEPT;
	}

	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udph = (void *)iph + iph->ihl * 4;
		unsigned short sport = (unsigned int)ntohs(udph->source);
		unsigned short dport = (unsigned int)ntohs(udph->dest);
		unsigned int udp_len = (unsigned int)ntohs(udph->len);

		if (dport == FASP_PORT || sport == FASP_PORT)
		{
			char tmp_flag = *((u_char*)udph + 0x08);
			
			if (FASP_TRA_FLAGS->next != NULL)
			{
				if (search_FASP_TRA_FLAGS(tmp_flag) == 1)
				{
					return NF_DROP;
				}

				//printk(KERN_ALERT "FASP---UDP PACKET: Transfer\n");
			}

			if ( (*((u_char*)udph + 0x09) == 0x19) && (*((u_char*)udph + 0x10) == 0x00) && (*((u_char*)udph + 0x11) == 0x00) )
			{
				/* ---Search patterns with WM---  */
				char *faspdata = (void *)udph + 8 + 12;
				int faspdata_len = udp_len - 8 - 12;

				nfound = 0;
				wmSearch(TARGET_PATTERN_WMSTRUCT, (unsigned char*)faspdata, faspdata_len);
				if (nfound > 0)
				{
					add_FASP_TRA_FLAGS(tmp_flag);

					unsigned char src_ip[4], dst_ip[4];
					*(unsigned int *)src_ip = iph->saddr;
					*(unsigned int *)dst_ip = iph->daddr;

					printk(KERN_ALERT "FASP---Target UDP PACKET -%d- %d.%d.%d.%d->%d.%d.%d.%d\n", nfound, 
						src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

					add_TARGET_IP_ROOT((unsigned int)iph->saddr, (unsigned int)iph->daddr, tmp_flag);
					//printk(KERN_ALERT "---TEST 3---\n");

					return NF_DROP;
				}

			}
		}
	}

	
	if ( (iph->protocol == IPPROTO_TCP) && (FASP_TRA_FLAGS->next != NULL) )
	{
		TARGET_IP_STRUCT *tmp_find = search_TARGET_IP_ROOT(iph->saddr, iph->daddr);
		if (tmp_find != NULL)
		{
			struct tcphdr *tcph = (void*)iph + iph->ihl*4;
			//unsigned int tcplen = skb->len - (iph->ihl*4) - (tcph->doff*4);

			unsigned int sport = (unsigned int)ntohs(tcph->source);
			unsigned int dport = (unsigned int)ntohs(tcph->dest);

			if (sport == 22 || dport == 22)
			{

				/* ---Send RST packet--- */
				nf_send_reset(skb, NF_INET_FORWARD);

				nf_send_reset(skb, NF_INET_FORWARD);

				nf_send_reset(skb, NF_INET_FORWARD);

				//printk(KERN_ALERT "---TEST 1---\n");
				del_TARGET_IP_ROOT(iph->saddr, iph->daddr);
				del_FASP_TRA_FLAGS(tmp_find->tra_flag);
				//printk(KERN_ALERT "---TEST 2---\n");

				unsigned char src_ip[4], dst_ip[4];
				*(unsigned int *)src_ip = iph->saddr;
				*(unsigned int *)dst_ip = iph->daddr;

				printk(KERN_ALERT "FASP---Target TCP PACKET %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", 
					src_ip[0], src_ip[1], src_ip[2], src_ip[3], sport, dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], dport);
			}

		}
	}


	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
		.hook 			= hook_func,
		.pf 			= NFPROTO_IPV4,
		.hooknum 		= NF_INET_FORWARD, 
		.priority 		= NF_IP_PRI_MANGLE,
		.owner			= THIS_MODULE
};

static int init_hook_module(void)
{
	init_globalvalue();

	nf_register_hook(&nfho);
	return 0;
}

static void cleanup_hook_module(void)
{
	nf_unregister_hook(&nfho);
}

module_init(init_hook_module);
module_exit(cleanup_hook_module);
MODULE_AUTHOR("LCL");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("...");
MODULE_VERSION("1.0");