/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H

#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/netdevice.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>
#include <net/netns/hash.h>
#include <net/tcp_states.h>
#include <net/l3mdev.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @nexthop - Saved nexthop address in LSRR and SSRR
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	__be32		nexthop;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[];
};

struct ip_options_rcu {
	struct rcu_head rcu;
	struct ip_options opt;
};

struct ip_options_data {
	struct ip_options_rcu	opt;
	char			data[40];
};

struct inet_request_sock {
	struct request_sock	req;
#define ir_loc_addr		req.__req_common.skc_rcv_saddr
#define ir_rmt_addr		req.__req_common.skc_daddr
#define ir_num			req.__req_common.skc_num
#define ir_rmt_port		req.__req_common.skc_dport
#define ir_v6_rmt_addr		req.__req_common.skc_v6_daddr
#define ir_v6_loc_addr		req.__req_common.skc_v6_rcv_saddr
#define ir_iif			req.__req_common.skc_bound_dev_if
#define ir_cookie		req.__req_common.skc_cookie
#define ireq_net		req.__req_common.skc_net
#define ireq_state		req.__req_common.skc_state
#define ireq_family		req.__req_common.skc_family

	u16			snd_wscale : 4,
				rcv_wscale : 4,
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1,
				no_srccheck: 1,
				smc_ok	   : 1;
	u32                     ir_mark;
	union {
		struct ip_options_rcu __rcu	*ireq_opt;
#if IS_ENABLED(CONFIG_IPV6)
		struct {
			struct ipv6_txoptions	*ipv6_opt;
			struct sk_buff		*pktopts;
		};
#endif
	};
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

static inline u32 inet_request_mark(const struct sock *sk, struct sk_buff *skb)
{
	if (!sk->sk_mark && sock_net(sk)->ipv4.sysctl_tcp_fwmark_accept)
		return skb->mark;

	return sk->sk_mark;
}

static inline int inet_request_bound_dev_if(const struct sock *sk,
					    struct sk_buff *skb)
{
	int bound_dev_if = READ_ONCE(sk->sk_bound_dev_if);
#ifdef CONFIG_NET_L3_MASTER_DEV
	struct net *net = sock_net(sk);

	if (!bound_dev_if && net->ipv4.sysctl_tcp_l3mdev_accept)
		return l3mdev_master_ifindex_by_index(net, skb->skb_iif);
#endif

	return bound_dev_if;
}

static inline int inet_sk_bound_l3mdev(const struct sock *sk)
{
#ifdef CONFIG_NET_L3_MASTER_DEV
	struct net *net = sock_net(sk);

	if (!net->ipv4.sysctl_tcp_l3mdev_accept)
		return l3mdev_master_ifindex_by_index(net,
						      sk->sk_bound_dev_if);
#endif

	return 0;
}

static inline bool inet_bound_dev_eq(bool l3mdev_accept, int bound_dev_if,
				     int dif, int sdif)
{
	if (!bound_dev_if)
		return !sdif || l3mdev_accept;
	return bound_dev_if == dif || bound_dev_if == sdif;
}

struct inet_cork {
	// IPCORK_OPT：标志IP选项信息是否已在cork的opt成员中
	// IPCORK_ALLFRAG：总是分片(只用于IPv6)
	unsigned int		flags;
	// 输出IP数据报的目的地址
	__be32			addr;
	// 指向此次发送数据报的IP选项
	struct ip_options	*opt;
	// UDP数据报或者原始IP数据报分片大小 
	unsigned int		fragsize;
	// 当前发送的数据报的数据长度
	int			length; /* Total length of all frames */
	struct dst_entry	*dst;
	u8			tx_flags;
	__u8			ttl;
	__s16			tos;
	char			priority;
	__u16			gso_size;
	u64			transmit_time;
	u32			mark;
};

struct inet_cork_full {
	struct inet_cork	base;
	// 用flowi结构来缓存目的地址、目的端口、源地址和源端口，构造UDP报文时有关信息就取自这里
	struct flowi		fl;
};

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;
// inet_sock结构是IPv4协议专用的传输控制块，是对sock结构的扩展，在传输控制块的基础属性已经具备的基础上，
// 进一步提供了IPv4协议专有的一些属性，如TTL，组播列表，IP地址和端口
/** struct inet_sock - representation of INET sockets
 * inet_sock 结构：INET套接字的表现
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_dport - Destination port
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_sport - Source port
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @uc_index - Unicast outgoing device index
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
	// 如果支持IPv6的特性，pinet6是指向IPv6控制块的指针
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	// 目的IP地址
#define inet_daddr		sk.__sk_common.skc_daddr
	// 已绑定的本地IP地址,接收数据时，作为条件的一部分查找数据所属的传输控制块
#define inet_rcv_saddr		sk.__sk_common.skc_rcv_saddr
	// 目的端口
#define inet_dport		sk.__sk_common.skc_dport
	// 主机字节序存储的本地端口
#define inet_num		sk.__sk_common.skc_num
	// 也标识本地IP地址，但在发送时使用。rcv_saddr和saddr都描述本地IP地址，但用途不同。
	__be32			inet_saddr;
	// 单播报文的TTL，默认值为-1，表示使用默认的TTL值。在输出IP数据报时，TTL值首先从这里获取，若没有设置，则从路由缓存的metric中获取。
	__s16			uc_ttl;
	// 存放一些IPProto级别的选项值
	__u16			cmsg_flags;
	// 指向IP数据报选项的指针
	struct ip_options_rcu __rcu	*inet_opt;
	// 由num转换成的网络字节序的源端口
	__be16			inet_sport;
	// 一个单调递增的值，用于赋值IP首部的id域
	__u16			inet_id;
	// 用于设置IP数据报首部的TOS域，参见IP_TOS套接口选项
	__u8			tos;
	__u8			min_ttl;
	// 用于设置多播数据报的TTL
	__u8			mc_ttl;
	// 标志套接口是否启用路径MTU发现功能，初始值根据系数控制参数ip_no_pmtu_disc来确定
	__u8			pmtudisc;
	// 标识是否允许接收扩展的可靠错误信息
	__u8			recverr:1,
	// 标志是否为基于连接的传输控制块，即是否为基于inet_connection_sock结构的传输控制块，如TCP的传输控制块
				is_icsk:1,
	// 标识是否允许绑定非主机地址。
				freebind:1,
	// 标识IP首部是否由用户数据构建。该标志只用于RAW套接口，一旦设置后，IP选项中的IP_TTL和IP_TOS都将被忽略
				hdrincl:1,
	// 标识组播是否发向回路
				mc_loop:1,
				transparent:1,
				mc_all:1,
				nodefrag:1;
	__u8			bind_address_no_port:1,
				recverr_rfc4884:1,
				defer_connect:1; /* Indicates that fastopen_connect is set
						  * and cookie exists so we defer connect
						  * until first data frame is written
						  */
	__u8			rcv_tos;
	__u8			convert_csum;
	int			uc_index;
	// 发送组播报文的网络设备索引号。如果为0，则表示可以从任何网络设备发送。
	int			mc_index;
	// 发送组播报文的源地址
	__be32			mc_addr;
	// 所在套接口加入的组播地址列表
	struct ip_mc_socklist __rcu	*mc_list;
	// UDP或原始IP在每次发送时缓存的一些临时信息。如，UDP数据报或原始IP数据报分片的大小
	struct inet_cork_full	cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

/* cmsg flags for inet */
#define IP_CMSG_PKTINFO		BIT(0)
#define IP_CMSG_TTL		BIT(1)
#define IP_CMSG_TOS		BIT(2)
#define IP_CMSG_RECVOPTS	BIT(3)
#define IP_CMSG_RETOPTS		BIT(4)
#define IP_CMSG_PASSSEC		BIT(5)
#define IP_CMSG_ORIGDSTADDR	BIT(6)
#define IP_CMSG_CHECKSUM	BIT(7)
#define IP_CMSG_RECVFRAGSIZE	BIT(8)

/**
 * sk_to_full_sk - Access to a full socket
 * @sk: pointer to a socket
 *
 * SYNACK messages might be attached to request sockets.
 * Some places want to reach the listener in this case.
 */
static inline struct sock *sk_to_full_sk(struct sock *sk)
{
#ifdef CONFIG_INET
	if (sk && sk->sk_state == TCP_NEW_SYN_RECV)
		sk = inet_reqsk(sk)->rsk_listener;
#endif
	return sk;
}

/* sk_to_full_sk() variant with a const argument */
static inline const struct sock *sk_const_to_full_sk(const struct sock *sk)
{
#ifdef CONFIG_INET
	if (sk && sk->sk_state == TCP_NEW_SYN_RECV)
		sk = ((const struct request_sock *)sk)->rsk_listener;
#endif
	return sk;
}

static inline struct sock *skb_to_full_sk(const struct sk_buff *skb)
{
	return sk_to_full_sk(skb->sk);
}

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}

int inet_sk_rebuild_header(struct sock *sk);

/**
 * inet_sk_state_load - read sk->sk_state for lockless contexts
 * @sk: socket pointer
 *
 * Paired with inet_sk_state_store(). Used in places we don't hold socket lock:
 * tcp_diag_get_info(), tcp_get_info(), tcp_poll(), get_tcp4_sock() ...
 */
static inline int inet_sk_state_load(const struct sock *sk)
{
	/* state change might impact lockless readers. */
	return smp_load_acquire(&sk->sk_state);
}

/**
 * inet_sk_state_store - update sk->sk_state
 * @sk: socket pointer
 * @newstate: new state
 *
 * Paired with inet_sk_state_load(). Should be used in contexts where
 * state change might impact lockless readers.
 */
void inet_sk_state_store(struct sock *sk, int newstate);

void inet_sk_set_state(struct sock *sk, int state);

static inline unsigned int __inet_ehashfn(const __be32 laddr,
					  const __u16 lport,
					  const __be32 faddr,
					  const __be16 fport,
					  u32 initval)
{
	return jhash_3words((__force __u32) laddr,
			    (__force __u32) faddr,
			    ((__u32) lport) << 16 | (__force __u32)fport,
			    initval);
}

struct request_sock *inet_reqsk_alloc(const struct request_sock_ops *ops,
				      struct sock *sk_listener,
				      bool attach_listener);

static inline __u8 inet_sk_flowi_flags(const struct sock *sk)
{
	__u8 flags = 0;

	if (inet_sk(sk)->transparent || inet_sk(sk)->hdrincl)
		flags |= FLOWI_FLAG_ANYSRC;
	return flags;
}

static inline void inet_inc_convert_csum(struct sock *sk)
{
	inet_sk(sk)->convert_csum++;
}

static inline void inet_dec_convert_csum(struct sock *sk)
{
	if (inet_sk(sk)->convert_csum > 0)
		inet_sk(sk)->convert_csum--;
}

static inline bool inet_get_convert_csum(struct sock *sk)
{
	return !!inet_sk(sk)->convert_csum;
}


static inline bool inet_can_nonlocal_bind(struct net *net,
					  struct inet_sock *inet)
{
	return net->ipv4.sysctl_ip_nonlocal_bind ||
		inet->freebind || inet->transparent;
}

static inline bool inet_addr_valid_or_nonlocal(struct net *net,
					       struct inet_sock *inet,
					       __be32 addr,
					       int addr_type)
{
	return inet_can_nonlocal_bind(net, inet) ||
		addr == htonl(INADDR_ANY) ||
		addr_type == RTN_LOCAL ||
		addr_type == RTN_MULTICAST ||
		addr_type == RTN_BROADCAST;
}

#endif	/* _INET_SOCK_H */
