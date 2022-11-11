/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/static_key.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/cgroup-defs.h>
#include <linux/rbtree.h>
#include <linux/rculist_nulls.h>
#include <linux/poll.h>
#include <linux/sockptr.h>
#include <linux/indirect_call_wrapper.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/llist.h>
#include <net/dst.h>
#include <net/checksum.h>
#include <net/tcp_states.h>
#include <linux/net_tstamp.h>
#include <net/l3mdev.h>
#include <uapi/linux/socket.h>

/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the SOCK_DBG debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)
#else
/* Validate arguments and do nothing */
static inline __printf(2, 3)
void SOCK_DEBUG(const struct sock *sk, const char *msg, ...)
{
}
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
typedef struct {
	// 用来实现下半部间的同步锁，同时也用于保护对owned的写操作
	spinlock_t		slock;
	// 0：未被用户进程锁定
	// 1：被用户进程锁定
	int			owned;
	// 等待队列。当进程调用lock_sock对传输控制块进行上锁时，如果此时传输控制块已被软中断
	// 锁定，则此时进程只能睡眠并将进程信息添加到此队列中，当软中断解锁传输控制块时，会唤
	// 醒此队列上的进程。
	wait_queue_head_t	wq;
	/*
	 * We express the mutex-alike socket_lock semantics
	 * to the lock validator by explicitly managing
	 * the slock as a lock variant (in addition to
	 * the slock itself):
	 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} socket_lock_t;

struct sock;
struct proto;
struct net;

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_daddr: Foreign IPv4 addr
 *	@skc_rcv_saddr: Bound local IPv4 addr
 *	@skc_addrpair: 8-byte-aligned __u64 union of @skc_daddr & @skc_rcv_saddr
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_u16hashes: two u16 hash values used by UDP lookup tables
 *	@skc_dport: placeholder for inet_dport/tw_dport
 *	@skc_num: placeholder for inet_num/tw_num
 *	@skc_portpair: __u32 union of @skc_dport & @skc_num
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_reuseport: %SO_REUSEPORT setting
 *	@skc_ipv6only: socket is IPV6 only
 *	@skc_net_refcnt: socket is using net ref counting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_portaddr_node: second hash linkage for UDP/UDP-Lite protocol
 *	@skc_prot: protocol handlers inside a network family
 *	@skc_net: reference to the network namespace of this socket
 *	@skc_v6_daddr: IPV6 destination address
 *	@skc_v6_rcv_saddr: IPV6 source address
 *	@skc_cookie: socket's cookie value
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_nulls_node: main hash linkage for TCP/UDP/UDP-Lite protocol
 *	@skc_tx_queue_mapping: tx queue number for this connection
 *	@skc_rx_queue_mapping: rx queue number for this connection
 *	@skc_flags: place holder for sk_flags
 *		%SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE,
 *		%SO_OOBINLINE settings, %SO_TIMESTAMPING settings
 *	@skc_listener: connection request listener socket (aka rsk_listener)
 *		[union with @skc_flags]
 *	@skc_tw_dr: (aka tw_dr) ptr to &struct inet_timewait_death_row
 *		[union with @skc_flags]
 *	@skc_incoming_cpu: record/match cpu processing incoming packets
 *	@skc_rcv_wnd: (aka rsk_rcv_wnd) TCP receive window size (possibly scaled)
 *		[union with @skc_incoming_cpu]
 *	@skc_tw_rcv_nxt: (aka tw_rcv_nxt) TCP window next expected seq number
 *		[union with @skc_incoming_cpu]
 *	@skc_refcnt: reference count
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
// 这是套接字的最小网络层表示,struct sock 和 struct inet_timewait_sock的头
// sock_common结构被单独定义，是因为sock结构和inet_timewait_sock结构前面一部分
// 成员是一样的，因为把这些成员提出来构成sock_common结构，可以提高代码的可读性
struct sock_common {
	union {
		__addrpair	skc_addrpair;
		struct {
			// 外部ipv4地址 
			__be32	skc_daddr;
			// 绑定的本地ipv4地址  
			__be32	skc_rcv_saddr;
		};
	};
	union  {
		// 存储TCP状态为established时加入到散列表的关键字键值。由于计算键值对相对耗时，
		// 因此用一个成员来存储键值有利于提高效率。
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			// 目的端口号 
			__be16	skc_dport;
			// 本地端口号 
			__u16	skc_num;
		};
	};
	// 所属协议族
	unsigned short		skc_family;
	// 等同于TCP的状态，虽然UDP不存在链接或传输状态，
	// 但是实现中用到了一些状态值，如TCP_CLOSE
	volatile unsigned char	skc_state;
	// 标识是否重用地址和端口，参见SO_REUSEADDR
	unsigned char		skc_reuse:4;
	unsigned char		skc_reuseport:1;

	unsigned char		skc_ipv6only:1;
	// 引用计数器，当引用计数器为0时，该结构体被释放
	unsigned char		skc_net_refcnt:1;
	// 如果不为0，即为输出报文的网络设备索引号
	int			skc_bound_dev_if;
	union {
		// 已绑定端口的传输控制块利用该字段插入到与之绑定端口信息结构为头结点的链表中。
		// 释放端口时，会从中删除，仅用于基于链接的传输控制块，如TCP
		struct hlist_node	skc_bind_node;
		struct hlist_node	skc_portaddr_node;
	};
	// 指向网络接口层的指针
	struct proto		*skc_prot;
	possible_net_t		skc_net;

#if IS_ENABLED(CONFIG_IPV6)
	struct in6_addr		skc_v6_daddr;
	struct in6_addr		skc_v6_rcv_saddr;
#endif

	atomic64_t		skc_cookie;

	/* following fields are padding to force
	 * offset(struct sock, sk_refcnt) == 128 on 64bit arches
	 * assuming IPV6 is enabled. We use this padding differently
	 * for different kind of 'sockets'
	 */
	union {
		unsigned long	skc_flags;
		struct sock	*skc_listener; /* request_sock */
		struct inet_timewait_death_row *skc_tw_dr; /* inet_timewait_sock */
	};
	/*
	 * fields between dontcopy_begin/dontcopy_end
	 * are not copied in sock_copy()
	 */
	/* private: */
	int			skc_dontcopy_begin[0];
	/* public: */
	union {
		struct hlist_node	skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	unsigned short		skc_tx_queue_mapping;
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	unsigned short		skc_rx_queue_mapping;
#endif
	union {
		int		skc_incoming_cpu;
		u32		skc_rcv_wnd;
		u32		skc_tw_rcv_nxt; /* struct tcp_timewait_sock  */
	};

	refcount_t		skc_refcnt;
	/* private: */
	int                     skc_dontcopy_end[0];
	union {
		u32		skc_rxhash;
		u32		skc_window_clamp;
		u32		skc_tw_snd_nxt; /* struct tcp_timewait_sock */
	};
	/* public: */
};

struct bpf_local_storage;
struct sk_filter;

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_kern_sock: True if sock is using kernel lock classes
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_rx_dst: receive input route used by early demux
  *	@sk_rx_dst_ifindex: ifindex for @sk_rx_dst
  *	@sk_rx_dst_cookie: cookie for @sk_rx_dst
  *	@sk_dst_cache: destination cache
  *	@sk_dst_pending_confirm: need to confirm neighbour
  *	@sk_policy: flow policy
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_tsq_flags: TCP Small Queues flags
  *	@sk_write_queue: Packet sending queue
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_reserved_mem: space reserved and non-reclaimable for the socket
  *	@sk_napi_id: id of the last napi context to receive data for sk
  *	@sk_ll_usec: usecs to busypoll when there is no data
  *	@sk_allocation: allocation mode
  *	@sk_pacing_rate: Pacing rate (if supported by transport/packet scheduler)
  *	@sk_pacing_status: Pacing status (requested, handled by sch_fq)
  *	@sk_max_pacing_rate: Maximum pacing rate (%SO_MAX_PACING_RATE)
  *	@sk_sndbuf: size of send buffer in bytes
  *	@__sk_flags_offset: empty field used to determine location of bitfield
  *	@sk_padding: unused element for alignment
  *	@sk_no_check_tx: %SO_NO_CHECK setting, set checksum in TX packets
  *	@sk_no_check_rx: allow zero checksum in RX packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_gso_disabled: if set, NETIF_F_GSO_MASK is forbidden.
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_gso_max_segs: Maximum number of GSO segments
  *	@sk_pacing_shift: scaling factor for TCP Small Queues
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_uid: user id of owner
  *	@sk_prefer_busy_poll: prefer busypolling over softirq processing
  *	@sk_busy_poll_budget: napi processing budget when busypolling
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peer_lock: lock protecting @sk_peer_pid and @sk_peer_cred
  *	@sk_peer_pid: &struct pid for this socket's peer
  *	@sk_peer_cred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_txhash: computed flow hash for use on transmit
  *	@sk_txrehash: enable TX hash rethink
  *	@sk_filter: socket filtering instructions
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_stamp_seq: lock for accessing sk_stamp on 32 bit architectures only
  *	@sk_tsflags: SO_TIMESTAMPING flags
  *	@sk_bind_phc: SO_TIMESTAMPING bind PHC index of PTP virtual clock
  *	              for timestamping
  *	@sk_tskey: counter to disambiguate concurrent tstamp requests
  *	@sk_zckey: counter to order MSG_ZEROCOPY notifications
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_frag: cached page frag
  *	@sk_peek_off: current peek_offset value
  *	@sk_send_head: front of stuff to transmit
  *	@tcp_rtx_queue: TCP re-transmit queue [union with @sk_send_head]
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_cgrp_data: cgroup data for this cgroup
  *	@sk_memcg: this socket's memory cgroup association
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_validate_xmit_skb: ptr to an optional validate function
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
  *	@sk_reuseport_cb: reuseport group container
  *	@sk_bpf_storage: ptr to cache and control for bpf_sk_storage
  *	@sk_rcu: used during RCU grace period
  *	@sk_clockid: clockid used by time-based scheduling (SO_TXTIME)
  *	@sk_txtime_deadline_mode: set deadline mode for SO_TXTIME
  *	@sk_txtime_report_errors: set report errors mode for SO_TXTIME
  *	@sk_txtime_unused: unused txtime flags
  *	@ns_tracker: tracker for netns reference
  */
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	// 公共头部
	struct sock_common	__sk_common;
#define sk_node			__sk_common.skc_node
#define sk_nulls_node		__sk_common.skc_nulls_node
#define sk_refcnt		__sk_common.skc_refcnt
#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
#define sk_rx_queue_mapping	__sk_common.skc_rx_queue_mapping
#endif

#define sk_dontcopy_begin	__sk_common.skc_dontcopy_begin
#define sk_dontcopy_end		__sk_common.skc_dontcopy_end
#define sk_hash			__sk_common.skc_hash
#define sk_portpair		__sk_common.skc_portpair
#define sk_num			__sk_common.skc_num
#define sk_dport		__sk_common.skc_dport
#define sk_addrpair		__sk_common.skc_addrpair
#define sk_daddr		__sk_common.skc_daddr
#define sk_rcv_saddr		__sk_common.skc_rcv_saddr
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_reuseport		__sk_common.skc_reuseport
#define sk_ipv6only		__sk_common.skc_ipv6only
#define sk_net_refcnt		__sk_common.skc_net_refcnt
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_prot			__sk_common.skc_prot
#define sk_net			__sk_common.skc_net
#define sk_v6_daddr		__sk_common.skc_v6_daddr
#define sk_v6_rcv_saddr	__sk_common.skc_v6_rcv_saddr
#define sk_cookie		__sk_common.skc_cookie
#define sk_incoming_cpu		__sk_common.skc_incoming_cpu
// 一些状态和标志，这个标志是个杂集
#define sk_flags		__sk_common.skc_flags
#define sk_rxhash		__sk_common.skc_rxhash

	/* early demux fields */
	// 缓存入口路由
	struct dst_entry __rcu	*sk_rx_dst;
	int			sk_rx_dst_ifindex;
	u32			sk_rx_dst_cookie;
	// 同步锁，其中包含两种锁：一是用于用户进程读取数据和网络层向传输层传递数据之间的同步锁；
	// 二是控制linux下半部访问本传输控制块的同步锁，以免多个下半部同时访问本传输控制块
	socket_lock_t		sk_lock;
	atomic_t		sk_drops;
	// 标志接收缓存下限值，参见SO_RCVLOWAT选项
	int			sk_rcvlowat;
	// 错误链表，存放详细的出错信息。应用程序通过setsockopt系统调用设置IP_RECVERR选项，即需要获取详细出错信息。
	// 当有错误发生时，可通过recvmsg()，参数flags为MSG_ERRQUEUE，获取详细的错误信息。
	struct sk_buff_head	sk_error_queue;
	// 接收队列，等待用户进程读取，TCP比较特别，当接收到的数据不能直接复制到用户空间时才会缓存在此。
	struct sk_buff_head	sk_receive_queue;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 * Note : rmem_alloc is in this structure to fill a hole
	 * on 64bit arches, not because its logically part of
	 * backlog.
	 */
	// 后备接收队列，目前只用于TCP，传输控制块被上锁后（如应用层读取数据时），当有新的报文传递到传输控制块时，
	// 只能把报文放到后备接收队列中，之后有用户进程读取TCP数据时，再从该队列取出复制到用户空间中。
	struct {
		atomic_t	rmem_alloc;
		int		len;
		struct sk_buff	*head;
		struct sk_buff	*tail;
	} sk_backlog;
	// 接收队列sk_receive_queue中所有报文的数据，即所有段的数据总长度
#define sk_rmem_alloc sk_backlog.rmem_alloc
	// 预分配缓存长度，这只是一个标识，目前只用于TCP，当分配的缓存小于该值时，分配必然成功，
	// 否则需重新确认分配的缓存是否有效
	int			sk_forward_alloc;
	u32			sk_reserved_mem;
#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int		sk_ll_usec;
	/* ===== mostly read cache line ===== */
	unsigned int		sk_napi_id;
#endif
	// 接收缓冲区大小的上限。SO_RCVBUF选项，通常情况下，接收队列中所有段的数据总长度
	// sk_rmem_alloc不能超过该值。sk_rcvbuff的值由tcp_rmem来设置和调整。
	int			sk_rcvbuf;
	// 套接口过滤器，在传输层对输入的数据包通过BPF过滤代码进行过滤，
	// 只对设置了套接口过滤器的进程有效，参见SO_ATTACH_FILTER选项
	struct sk_filter __rcu	*sk_filter;
	// 进程等待队列。进程等待连接、等待输出缓冲区、等待读数据时，都会将进程暂存到此队列中。
	union {
		struct socket_wq __rcu	*sk_wq;
		/* private: */
		struct socket_wq	*sk_wq_raw;
		/* public: */
	};
	// 与IPSec相关的传输策略
#ifdef CONFIG_XFRM
	struct xfrm_policy __rcu *sk_policy[2];
#endif
	// 目的的路由项缓存。一般都是在创建传输控制块发送数据报文时，发现未设置该字段才从路由表或路由缓存中
	// 查询到相应的路由项来设置该字段，这样可以加速数据的输出，后续数据的输出不必再查询目的路由。某些情况下
	// 会刷新此目的的路由缓存，比如断开连接、重新进行了连接、TCP重传、重新绑定端口等操作。
	struct dst_entry __rcu	*sk_dst_cache;
	// 分配辅助缓冲区的上限，辅助数据包括进行设置选项、设置过滤时分配的内存和组播设置等。
	atomic_t		sk_omem_alloc;
	// 发送缓冲区长度的上限，发送队列中报文数据总长度不能超过该值。参见SO_SNDBUF选项。
	int			sk_sndbuf;

	/* ===== cache line for TX ===== */
	// 发送队列中所有报文段数据的总长度，目前只用于TCP
	int			sk_wmem_queued;
	// 所在的传输控制块中，为发送而分配的所有SKB数据区的总长度
	refcount_t		sk_wmem_alloc;
	unsigned long		sk_tsq_flags;
	union {
		// 指向sk_write_queue队列中第一个未发送的节点，如果sk_send_head为空则表示发送队列是空的，
		// 发送队列上的报文已全部发送
		struct sk_buff	*sk_send_head;
		struct rb_root	tcp_rtx_queue;
	};
	// 发送队列。在TCP中，此队列同时也是重传队列，在sk_send_head之前为重传队列，之后为发送队列。
	struct sk_buff_head	sk_write_queue;
	__s32			sk_peek_off;
	// 标识有数据即将写入套接口，也就是有写数据的请求 
	int			sk_write_pending;
	__u32			sk_dst_pending_confirm;
	u32			sk_pacing_status; /* see enum sk_pacing */
	// 套接口发送超时时间，参见SO_SNDTIMEO选项
	long			sk_sndtimeo;
	// 通过tcp的不同状态，来实现连接定时器，FIN_WAIT_2定时器以及TCP保活定时器，在tcp_keepalive_timer中实现
	struct timer_list	sk_timer;
	// 用于设置由此套接口输出数据报的QoS类别，参见SO_PRIORITY选项和IP_TOS选项
	__u32			sk_priority;
	__u32			sk_mark;
	unsigned long		sk_pacing_rate; /* bytes per second */
	unsigned long		sk_max_pacing_rate;
	struct page_frag	sk_frag;
	// 目的路由网络设备的特性，在sk_setup_caps中根据net_device结构的features成员设置
	netdev_features_t	sk_route_caps;
	// 传输层支持的GSO类型
	int			sk_gso_type;
	unsigned int		sk_gso_max_size;
	// 内存分配方式，
	// __GFP_DMA：要求在DMA的内存区分配内存
	// __GFP_HIGHMEM：要求优先在高端内存区域分配内存
	// __GFP_DMA32：如果系统支持32位的DMA区域，则要求从32位DMA区域分配内存
	// __GFP_WAIT：在分配内存时，允许睡眠
	// 下面很多类型不再赘述
	gfp_t			sk_allocation;
	__u32			sk_txhash;

	/*
	 * Because of non atomicity rules, all
	 * changes are protected by socket lock.
	 */
	// sk_no_check_tx：在TX数据包中设置校验和，Tx Packets就是发送数据包的意思
	// sk_no_check_rx：允许RX数据包中的校验和为零，Rx Packets就是接收数据包的意思
	// sk_userlocks：标志传输层的一些状态：
	// SOCK_SNDBUF_LOCK：用户通过套接口选项设置了发送缓冲区大小
	// SOCK_RCVBUF_LOCK：用户通过套接口选项设置了接收缓冲区大小
	// SOCK_BINDADDR_LOCK：已经绑定了本地地址
	// SOCK_BINDPORT_LOCK：已经绑定了本地端口
	u8			sk_gso_disabled : 1,
				sk_kern_sock : 1,
				sk_no_check_tx : 1,
				sk_no_check_rx : 1,
				sk_userlocks : 4;
	u8			sk_pacing_shift;
	// 所属的套接口类型。比如SOCK_STREAM等
	u16			sk_type;
	// 当前域中套接字所属的协议
	u16			sk_protocol;
	u16			sk_gso_max_segs;
	// 关闭套接口前发送剩余数据的数据，参见SO_LINGER选项
	unsigned long	        sk_lingertime;
	// 原始网络协议块指针。因为传输控制块中的另一个网络协议块指针是sk_prot在IPv6的
	// IPV6_ADDRFORM套接口选择设置时被修改。
	struct proto		*sk_prot_creator;
	// 确保传输控制块中一些成员同步访问的锁。因为有些成员在软中断中被访问，存在异步访问的问题。
	rwlock_t		sk_callback_lock;
	// 记录当前传输层中发送的最后一次致命错误的错误码，但应用层读取后会自动恢复为初始正常状态。
	int			sk_err,
	// 用于记录非致命性错误，或者用作在传输控制块被锁定时记录错误的后备成员。
				sk_err_soft;
	// 当前已经建立的连接数
	u32			sk_ack_backlog;
	// 连接队列长度的上限
	u32			sk_max_ack_backlog;
	kuid_t			sk_uid;
	u8			sk_txrehash;
#ifdef CONFIG_NET_RX_BUSY_POLL
	u8			sk_prefer_busy_poll;
	u16			sk_busy_poll_budget;
#endif
	spinlock_t		sk_peer_lock;
	int			sk_bind_phc;
	struct pid		*sk_peer_pid;
	// 返回连接至该套接字的外部进程的身份验证，目前主要是用于PF_UNIX协议族，参见SO_PEERCRED选项
	const struct cred	*sk_peer_cred;
	// 套接口层接收超时，参见SO_RCVTIMEO选项
	long			sk_rcvtimeo;
	// 在未启用SOCK_RCVTSTAMP套接字选项时，记录报文接收数据到应用层的时间戳，
	// 在启用SOCK_RCVTSTAMP套接字选项时，接收数据到应用层的时间戳记录在SKB的tstamp字段中
	ktime_t			sk_stamp;
#if BITS_PER_LONG==32
	seqlock_t		sk_stamp_seq;
#endif
	u16			sk_tsflags;
	// 关闭的标志，
	// RCV_SHUTDOWN：接收通道关闭，不允许继续接收数据
	// SEND_SHUTDOWN：发送通道关闭，不允许继续发送数据
	// SHUTDOWN_MASK：表示完全关闭
	u8			sk_shutdown;
	atomic_t		sk_tskey;
	atomic_t		sk_zckey;

	u8			sk_clockid;
	u8			sk_txtime_deadline_mode : 1,
				sk_txtime_report_errors : 1,
				sk_txtime_unused : 6;

	struct socket		*sk_socket;
	// RPC层存放私有数据的指针，IPV4中未使用
	void			*sk_user_data;
	// 指向sk_security_struct的指针,安全模块使用
#ifdef CONFIG_SECURITY
	void			*sk_security;
#endif
	struct sock_cgroup_data	sk_cgrp_data;
	// 该套接字的内存 cgroup 关联
	struct mem_cgroup	*sk_memcg;
	// 当传输控制块的状态发生变化时，唤醒那些等待本套接字的进程。在创建套接口时初始化，IPV4中为sock_def_wakeup
	void			(*sk_state_change)(struct sock *sk);
	// 当有数据到达接收处理时，唤醒或者发信号通知准备读本套接字的进程，在创建套接口时被初始化，IPV4中为sock_def_readable
	void			(*sk_data_ready)(struct sock *sk);
	// 在发送缓存大小发生变化或者套接字被释放时，唤醒因等待本套接字而处于睡眠状态的进程，
	// 包括sk_sleep队列以及fasync_list队列上的进程。创建套接口时被初始化，IPv4中为sock_def_write_space，
	// TCP中为sk_stream_write_space
	void			(*sk_write_space)(struct sock *sk);
	// 报告错误的回调函数，如果等待该传输控制块的进程正在睡眠，则将其唤醒（例如MSG_ERRQUEUE）。
	// 在创建套接口时被初始化，IPV4中为sock_def_error_report
	void			(*sk_error_report)(struct sock *sk);
	// 用于TCP和PPPoE中，在TCP中，用于接收预备队列和后备队列中的TCP段，TCP的sk_backlog_rcv接口为tcp_v4_do_rcv，
	// 如果预备队列中还存在TCP段，则调用tcp_prequeue_process预处理，在该函数中会回调sk_backlog_rcv接口，
	// 如果后备队列中还存在TCP段，则调用release_sock处理，也会回调sk_backlog_rcv。该函数指针在创建套接口的传输控制块
	// 时偶传输层backlog_rcv接口初始化。
	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sk_buff*		(*sk_validate_xmit_skb)(struct sock *sk,
							struct net_device *dev,
							struct sk_buff *skb);
#endif
	// 进行传输控制块的销毁，在释放传输控制块前释放一些其他的资源，在sk_free释放传输控制块时调用。
	// 当传输控制块的引用计数器为0时，才真正释放。IPv4中为inet_sock_destruct。
	void                    (*sk_destruct)(struct sock *sk);
	struct sock_reuseport __rcu	*sk_reuseport_cb;
#ifdef CONFIG_BPF_SYSCALL
	struct bpf_local_storage __rcu	*sk_bpf_storage;
#endif
	struct rcu_head		sk_rcu;
	netns_tracker		ns_tracker;
};

enum sk_pacing {
	SK_PACING_NONE		= 0,
	SK_PACING_NEEDED	= 1,
	SK_PACING_FQ		= 2,
};

/* Pointer stored in sk_user_data might not be suitable for copying
 * when cloning the socket. For instance, it can point to a reference
 * counted object. sk_user_data bottom bit is set if pointer must not
 * be copied.
 */
#define SK_USER_DATA_NOCOPY	1UL
#define SK_USER_DATA_BPF	2UL	/* Managed by BPF */
#define SK_USER_DATA_PTRMASK	~(SK_USER_DATA_NOCOPY | SK_USER_DATA_BPF)

/**
 * sk_user_data_is_nocopy - Test if sk_user_data pointer must not be copied
 * @sk: socket
 */
static inline bool sk_user_data_is_nocopy(const struct sock *sk)
{
	return ((uintptr_t)sk->sk_user_data & SK_USER_DATA_NOCOPY);
}

#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))

#define rcu_dereference_sk_user_data(sk)				\
({									\
	void *__tmp = rcu_dereference(__sk_user_data((sk)));		\
	(void *)((uintptr_t)__tmp & SK_USER_DATA_PTRMASK);		\
})
#define rcu_assign_sk_user_data(sk, ptr)				\
({									\
	uintptr_t __tmp = (uintptr_t)(ptr);				\
	WARN_ON_ONCE(__tmp & ~SK_USER_DATA_PTRMASK);			\
	rcu_assign_pointer(__sk_user_data((sk)), __tmp);		\
})
#define rcu_assign_sk_user_data_nocopy(sk, ptr)				\
({									\
	uintptr_t __tmp = (uintptr_t)(ptr);				\
	WARN_ON_ONCE(__tmp & ~SK_USER_DATA_PTRMASK);			\
	rcu_assign_pointer(__sk_user_data((sk)),			\
			   __tmp | SK_USER_DATA_NOCOPY);		\
})

static inline
struct net *sock_net(const struct sock *sk)
{
	return read_pnet(&sk->sk_net);
}

static inline
void sock_net_set(struct sock *sk, struct net *net)
{
	write_pnet(&sk->sk_net, net);
}

/*
 * SK_CAN_REUSE and SK_NO_REUSE on a socket mean that the socket is OK
 * or not whether his port will be reused by someone else. SK_FORCE_REUSE
 * on a socket means that the socket will reuse everybody else's port
 * without looking at the other's sk_reuse value.
 */

#define SK_NO_REUSE	0
#define SK_CAN_REUSE	1
#define SK_FORCE_REUSE	2

int sk_set_peek_off(struct sock *sk, int val);

static inline int sk_peek_offset(struct sock *sk, int flags)
{
	if (unlikely(flags & MSG_PEEK)) {
		return READ_ONCE(sk->sk_peek_off);
	}

	return 0;
}

static inline void sk_peek_offset_bwd(struct sock *sk, int val)
{
	s32 off = READ_ONCE(sk->sk_peek_off);

	if (unlikely(off >= 0)) {
		off = max_t(s32, off - val, 0);
		WRITE_ONCE(sk->sk_peek_off, off);
	}
}

static inline void sk_peek_offset_fwd(struct sock *sk, int val)
{
	sk_peek_offset_bwd(sk, -val);
}

/*
 * Hashed lists helper routines
 */
static inline struct sock *sk_entry(const struct hlist_node *node)
{
	return hlist_entry(node, struct sock, sk_node);
}

static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *__sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_entry(head->first, struct sock, sk_nulls_node);
}

static inline struct sock *sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_empty(head) ? NULL : __sk_nulls_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return hlist_entry_safe(sk->sk_node.next, struct sock, sk_node);
}

static inline struct sock *sk_nulls_next(const struct sock *sk)
{
	return (!is_a_nulls(sk->sk_nulls_node.next)) ?
		hlist_nulls_entry(sk->sk_nulls_node.next,
				  struct sock, sk_nulls_node) :
		NULL;
}

static inline bool sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline bool sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static inline void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static inline void sk_nulls_node_init(struct hlist_nulls_node *node)
{
	node->pprev = NULL;
}

static inline void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

/* NB: equivalent to hlist_del_init_rcu */
static inline bool __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return true;
	}
	return false;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static __always_inline void sock_hold(struct sock *sk)
{
	refcount_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static __always_inline void __sock_put(struct sock *sk)
{
	refcount_dec(&sk->sk_refcnt);
}

static inline bool sk_del_node_init(struct sock *sk)
{
	bool rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(refcount_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)

static inline bool __sk_nulls_del_node_init_rcu(struct sock *sk)
{
	if (sk_hashed(sk)) {
		hlist_nulls_del_init_rcu(&sk->sk_nulls_node);
		return true;
	}
	return false;
}

static inline bool sk_nulls_del_node_init_rcu(struct sock *sk)
{
	bool rc = __sk_nulls_del_node_init_rcu(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(refcount_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static inline void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static inline void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static inline void sk_add_node_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport &&
	    sk->sk_family == AF_INET6)
		hlist_add_tail_rcu(&sk->sk_node, list);
	else
		hlist_add_head_rcu(&sk->sk_node, list);
}

static inline void sk_add_node_tail_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	hlist_add_tail_rcu(&sk->sk_node, list);
}

static inline void __sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_head_rcu(&sk->sk_nulls_node, list);
}

static inline void __sk_nulls_add_node_tail_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_tail_rcu(&sk->sk_nulls_node, list);
}

static inline void sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	sock_hold(sk);
	__sk_nulls_add_node_rcu(sk, list);
}

static inline void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static inline void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_node)
#define sk_for_each_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_for_each_from(__sk) \
	hlist_for_each_entry_from(__sk, sk_node)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_for_each_safe(__sk, tmp, list) \
	hlist_for_each_entry_safe(__sk, tmp, list, sk_node)
#define sk_for_each_bound(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_bind_node)

/**
 * sk_for_each_entry_offset_rcu - iterate over a list at a given struct offset
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @offset:	offset of hlist_node within the struct.
 *
 */
#define sk_for_each_entry_offset_rcu(tpos, pos, head, offset)		       \
	for (pos = rcu_dereference(hlist_first_rcu(head));		       \
	     pos != NULL &&						       \
		({ tpos = (typeof(*tpos) *)((void *)pos - offset); 1;});       \
	     pos = rcu_dereference(hlist_next_rcu(pos)))

static inline struct user_namespace *sk_user_ns(struct sock *sk)
{
	/* Careful only use this in a context where these parameters
	 * can not change and must all be valid, such as recvmsg from
	 * userspace.
	 */
	return sk->sk_socket->file->f_cred->user_ns;
}

/* Sock flags */
enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_MEMALLOC, /* VM depends on this socket for swapping */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_FASYNC, /* fasync() active */
	SOCK_RXQ_OVFL,
	SOCK_ZEROCOPY, /* buffers from userspace */
	SOCK_WIFI_STATUS, /* push wifi status to userspace */
	SOCK_NOFCS, /* Tell NIC not to do the Ethernet FCS.
		     * Will use last 4 bytes of packet sent from
		     * user-space instead.
		     */
	SOCK_FILTER_LOCKED, /* Filter cannot be changed anymore */
	SOCK_SELECT_ERR_QUEUE, /* Wake select on error queue */
	SOCK_RCU_FREE, /* wait rcu grace period in sk_destruct() */
	SOCK_TXTIME,
	SOCK_XDP, /* XDP is attached */
	SOCK_TSTAMP_NEW, /* Indicates 64 bit timestamps always */
	SOCK_RCVMARK, /* Receive SO_MARK  ancillary data with packet */
};

#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline void sock_valbool_flag(struct sock *sk, enum sock_flags bit,
				     int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

static inline bool sock_flag(const struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

#ifdef CONFIG_NET
DECLARE_STATIC_KEY_FALSE(memalloc_socks_key);
static inline int sk_memalloc_socks(void)
{
	return static_branch_unlikely(&memalloc_socks_key);
}

void __receive_sock(struct file *file);
#else

static inline int sk_memalloc_socks(void)
{
	return 0;
}

static inline void __receive_sock(struct file *file)
{ }
#endif

static inline gfp_t sk_gfp_mask(const struct sock *sk, gfp_t gfp_mask)
{
	return gfp_mask | (sk->sk_allocation & __GFP_MEMALLOC);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	WRITE_ONCE(sk->sk_ack_backlog, sk->sk_ack_backlog - 1);
}

static inline void sk_acceptq_added(struct sock *sk)
{
	WRITE_ONCE(sk->sk_ack_backlog, sk->sk_ack_backlog + 1);
}

/* Note: If you think the test should be:
 *	return READ_ONCE(sk->sk_ack_backlog) >= READ_ONCE(sk->sk_max_ack_backlog);
 * Then please take a look at commit 64a146513f8f ("[NET]: Revert incorrect accept queue backlog changes.")
 */
static inline bool sk_acceptq_is_full(const struct sock *sk)
{
	return READ_ONCE(sk->sk_ack_backlog) > READ_ONCE(sk->sk_max_ack_backlog);
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(const struct sock *sk)
{
	return READ_ONCE(sk->sk_wmem_queued) >> 1;
}

static inline int sk_stream_wspace(const struct sock *sk)
{
	return READ_ONCE(sk->sk_sndbuf) - READ_ONCE(sk->sk_wmem_queued);
}

static inline void sk_wmem_queued_add(struct sock *sk, int val)
{
	WRITE_ONCE(sk->sk_wmem_queued, sk->sk_wmem_queued + val);
}

void sk_stream_write_space(struct sock *sk);

/* OOB backlog add */
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	/* dont let skb dst not refcounted, we are going to leave rcu lock */
	skb_dst_force(skb);

	if (!sk->sk_backlog.tail)
		WRITE_ONCE(sk->sk_backlog.head, skb);
	else
		sk->sk_backlog.tail->next = skb;

	WRITE_ONCE(sk->sk_backlog.tail, skb);
	skb->next = NULL;
}

/*
 * Take into account size of receive queue and backlog queue
 * Do not take into account this skb truesize,
 * to allow even a single big packet to come.
 */
static inline bool sk_rcvqueues_full(const struct sock *sk, unsigned int limit)
{
	unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);

	return qsize > limit;
}

/* The per-socket spinlock must be held here. */
static inline __must_check int sk_add_backlog(struct sock *sk, struct sk_buff *skb,
					      unsigned int limit)
{
	if (sk_rcvqueues_full(sk, limit))
		return -ENOBUFS;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC))
		return -ENOMEM;

	__sk_add_backlog(sk, skb);
	sk->sk_backlog.len += skb->truesize;
	return 0;
}

int __sk_backlog_rcv(struct sock *sk, struct sk_buff *skb);

INDIRECT_CALLABLE_DECLARE(int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb));
INDIRECT_CALLABLE_DECLARE(int tcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb));

static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (sk_memalloc_socks() && skb_pfmemalloc(skb))
		return __sk_backlog_rcv(sk, skb);

	return INDIRECT_CALL_INET(sk->sk_backlog_rcv,
				  tcp_v6_do_rcv,
				  tcp_v4_do_rcv,
				  sk, skb);
}

static inline void sk_incoming_cpu_update(struct sock *sk)
{
	int cpu = raw_smp_processor_id();

	if (unlikely(READ_ONCE(sk->sk_incoming_cpu) != cpu))
		WRITE_ONCE(sk->sk_incoming_cpu, cpu);
}

static inline void sock_rps_record_flow_hash(__u32 hash)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	rps_record_sock_flow(sock_flow_table, hash);
	rcu_read_unlock();
#endif
}

static inline void sock_rps_record_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	if (static_branch_unlikely(&rfs_needed)) {
		/* Reading sk->sk_rxhash might incur an expensive cache line
		 * miss.
		 *
		 * TCP_ESTABLISHED does cover almost all states where RFS
		 * might be useful, and is cheaper [1] than testing :
		 *	IPv4: inet_sk(sk)->inet_daddr
		 * 	IPv6: ipv6_addr_any(&sk->sk_v6_daddr)
		 * OR	an additional socket flag
		 * [1] : sk_state and sk_prot are in the same cache line.
		 */
		if (sk->sk_state == TCP_ESTABLISHED)
			sock_rps_record_flow_hash(sk->sk_rxhash);
	}
#endif
}

static inline void sock_rps_save_rxhash(struct sock *sk,
					const struct sk_buff *skb)
{
#ifdef CONFIG_RPS
	if (unlikely(sk->sk_rxhash != skb->hash))
		sk->sk_rxhash = skb->hash;
#endif
}

static inline void sock_rps_reset_rxhash(struct sock *sk)
{
#ifdef CONFIG_RPS
	sk->sk_rxhash = 0;
#endif
}

#define sk_wait_event(__sk, __timeo, __condition, __wait)		\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = wait_woken(__wait,			\
						TASK_INTERRUPTIBLE,	\
						*(__timeo));		\
		}							\
		sched_annotate_sleep();					\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})

int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
void sk_stream_wait_close(struct sock *sk, long timeo_p);
int sk_stream_error(struct sock *sk, int flags, int err);
void sk_stream_kill_queues(struct sock *sk);
void sk_set_memalloc(struct sock *sk);
void sk_clear_memalloc(struct sock *sk);

void __sk_flush_backlog(struct sock *sk);

static inline bool sk_flush_backlog(struct sock *sk)
{
	if (unlikely(READ_ONCE(sk->sk_backlog.tail))) {
		__sk_flush_backlog(sk);
		return true;
	}
	return false;
}

int sk_wait_data(struct sock *sk, long *timeo, const struct sk_buff *skb);

struct request_sock_ops;
struct timewait_sock_ops;
struct inet_hashinfo;
struct raw_hashinfo;
struct smc_hashinfo;
struct module;
struct sk_psock;

/*
 * caches using SLAB_TYPESAFE_BY_RCU should let .next pointer from nulls nodes
 * un-modified. Special care is taken when initializing object to zero.
 */
static inline void sk_prot_clear_nulls(struct sock *sk, int size)
{
	if (offsetof(struct sock, sk_node.next) != 0)
		memset(sk, 0, offsetof(struct sock, sk_node.next));
	memset(&sk->sk_node.pprev, 0,
	       size - offsetof(struct sock, sk_node.pprev));
}

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 */
// proto结构为网络接口层，结构中的操作实现传输层的操作和从传输层到网络层调用的跳转，
// 在proto结构中的某些成员跟proto_ops结构中的成员对应，比如connect等，这里可称之为传输层接口。
// 如果对有关数据的函数调用（如sendmsg())通过此接口后，进入网络层，在IPv4协议族中，则进入了IP层的处理。
struct proto {
	void			(*close)(struct sock *sk,
					long timeout);
	int			(*pre_connect)(struct sock *sk,
					struct sockaddr *uaddr,
					int addr_len);
	int			(*connect)(struct sock *sk,
					struct sockaddr *uaddr,
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept)(struct sock *sk, int flags, int *err,
					  bool kern);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	// 传输层接口初始化接口，在创建套接口时，在inet_create中被调用
	int			(*init)(struct sock *sk);
	// 没有与之对应的系统调用，当关闭套接口时被调用
	void			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level,
					int optname, sockptr_t optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level,
					int optname, char __user *optval,
					int __user *option);
	void			(*keepalive)(struct sock *sk, int valbool);
#ifdef CONFIG_COMPAT
	int			(*compat_ioctl)(struct sock *sk,
					unsigned int cmd, unsigned long arg);
#endif
	int			(*sendmsg)(struct sock *sk, struct msghdr *msg,
					   size_t len);
	int			(*recvmsg)(struct sock *sk, struct msghdr *msg,
					   size_t len, int flags, int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk,
					struct sockaddr *addr, int addr_len);
	int			(*bind_add)(struct sock *sk,
					struct sockaddr *addr, int addr_len);
	// 用于接收预备队列和后备队列中的TCP段。
	int			(*backlog_rcv) (struct sock *sk,
						struct sk_buff *skb);
	bool			(*bpf_bypass_getsockopt)(int level,
							 int optname);

	void		(*release_cb)(struct sock *sk);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	// hash为添加到管理传输控制块散列表的接口，unhash为从管理传输控制块散列表中删除的接口。由于不用的传输层协议
	// 组织管理的传输控制块也不一样，因此需要提供不同的方法，比如，在TCP中实现接口函数分别为tcp_v4_hash和tcp_unsh.
	// 而UDP传输控制块的管理相对比较简单，只有绑定端口的传输控制块才能添加到散列表中，这由绑定过程来完成，
	// 因而不需要实现hash接口，只需要实现unhash接口即可。
	int			(*hash)(struct sock *sk);
	void			(*unhash)(struct sock *sk);
	void			(*rehash)(struct sock *sk);
	// 实现地址与端口的绑定。参数sk为进行绑定操作的传输控制块，snum为进行绑定的端口号（如果为0，端口号在绑定时自动选择）。
	// TCP为tcp_v4_get_port，UDP为udp_v4_get_port。
	int			(*get_port)(struct sock *sk, unsigned short snum);
	void			(*put_port)(struct sock *sk);
#ifdef CONFIG_BPF_SYSCALL
	int			(*psock_update_sk_prot)(struct sock *sk,
							struct sk_psock *psock,
							bool restore);
#endif

	/* Keeping track of sockets in use */
#ifdef CONFIG_PROC_FS
	unsigned int		inuse_idx;
#endif

#if IS_ENABLED(CONFIG_MPTCP)
	int			(*forward_alloc_get)(const struct sock *sk);
#endif

	bool			(*stream_memory_free)(const struct sock *sk, int wake);
	bool			(*sock_is_readable)(struct sock *sk);
	/* Memory pressure */
	// 目前只有TCP在使用，当前整个TCP传输层为缓存区分配的内存超过tcp_mem[1]，便进入了告警状态，会调用此接口设置
	// 告警状态。在TCP中它指向tcp_enter_memory_pressure.
	void			(*enter_memory_pressure)(struct sock *sk);
	void			(*leave_memory_pressure)(struct sock *sk);
	// 目前只有TCP使用，表示当前整个TCP传输层为缓冲区分配的内存（包括输入缓冲队列）。
	// 在TCP中它指向变量tcp_memory_allocated
	atomic_long_t		*memory_allocated;	/* Current allocated memory. */
	// 表示当前整个TCP传输层中已创建的套接口的数目。目前只在TCP中使用，它指向变量tcp_sockets_allocated
	struct percpu_counter	*sockets_allocated;	/* Current number of sockets. */

	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the __sk_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	// 标志，目前只有TCP使用，在TCP传输层中缓冲区大小进入警告状态时，它置1，否则置0.目前只在TCP中使用，
	// 它指向变量tcp_memory_pressure
	unsigned long		*memory_pressure;
	// 指向sysctl_tcp_mem数组，参见tcp_mem系统参数。
	long			*sysctl_mem;
	// 指向sysctl_tcp_wmem数组，参见tcp_wmem系统参数。
	int			*sysctl_wmem;
	// 指向sysctl_tcp_rmem数组，参见tcp_rmem系统参数。
	int			*sysctl_rmem;
	u32			sysctl_wmem_offset;
	u32			sysctl_rmem_offset;
	// 目前只有TCP使用，TCP首部的最大长度，考虑了所有的选项。
	int			max_header;
	bool			no_autobind;
	// 用于分配传输控制块的slab高速缓存，在注册对应的传输层协议时建立。
	struct kmem_cache	*slab;
	// 标识传输控制块的大小，如果在初始化时建立分配传输控制块的slab缓存失败，则通过kmalloc分配obj_size大小的空间
	// 来完成传输控制块的分配。
	unsigned int		obj_size;
	slab_flags_t		slab_flags;
	unsigned int		useroffset;	/* Usercopy region offset */
	unsigned int		usersize;	/* Usercopy region size */
	// 目前只在TCP中使用，表示整个TCP传输层中待销毁的套接口的数目。在TCP中，它指向变量tcp_orphan_count
	unsigned int __percpu	*orphan_count;
	// 目前只在TCP中使用，指向连接请求处理接口集合，包括发送SYN+ACK、发送ACK等实现
	struct request_sock_ops	*rsk_prot;
	// 目前只在TCP中使用，指向timewait控制块操作接口，TCP中的实例为tcp_timewait_sock_ops。
	// tcp_timewait_sock_ops结构提供了两个操作接口，tcp_twsk_unique用于检测被timewait控制块绑定的端口是否可用，
	// 而twsk_destructor用于释放timewait控制块时，在启用MD5数字签名的情况下做一些清理工作。
	struct timewait_sock_ops *twsk_prot;

	union {
		struct inet_hashinfo	*hashinfo;
		struct udp_table	*udp_table;
		struct raw_hashinfo	*raw_hash;
		struct smc_hashinfo	*smc_hash;
	} h;

	struct module		*owner;
	// 标识传输层的名称，TCP协议为“TCP”，UDP协议为“UDP”
	char			name[32];
	// 通过node注册到proto_list中。
	struct list_head	node;
#ifdef SOCK_REFCNT_DEBUG
	atomic_t		socks;
#endif
	int			(*diag_destroy)(struct sock *sk, int err);
} __randomize_layout;

int proto_register(struct proto *prot, int alloc_slab);
void proto_unregister(struct proto *prot);
int sock_load_diag_module(int family, int protocol);

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (refcount_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, refcount_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */

INDIRECT_CALLABLE_DECLARE(bool tcp_stream_memory_free(const struct sock *sk, int wake));

static inline int sk_forward_alloc_get(const struct sock *sk)
{
#if IS_ENABLED(CONFIG_MPTCP)
	if (sk->sk_prot->forward_alloc_get)
		return sk->sk_prot->forward_alloc_get(sk);
#endif
	return sk->sk_forward_alloc;
}

static inline bool __sk_stream_memory_free(const struct sock *sk, int wake)
{
	if (READ_ONCE(sk->sk_wmem_queued) >= READ_ONCE(sk->sk_sndbuf))
		return false;

	return sk->sk_prot->stream_memory_free ?
		INDIRECT_CALL_INET_1(sk->sk_prot->stream_memory_free,
				     tcp_stream_memory_free, sk, wake) : true;
}

static inline bool sk_stream_memory_free(const struct sock *sk)
{
	return __sk_stream_memory_free(sk, 0);
}

static inline bool __sk_stream_is_writeable(const struct sock *sk, int wake)
{
	return sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) &&
	       __sk_stream_memory_free(sk, wake);
}

static inline bool sk_stream_is_writeable(const struct sock *sk)
{
	return __sk_stream_is_writeable(sk, 0);
}

static inline int sk_under_cgroup_hierarchy(struct sock *sk,
					    struct cgroup *ancestor)
{
#ifdef CONFIG_SOCK_CGROUP_DATA
	return cgroup_is_descendant(sock_cgroup_ptr(&sk->sk_cgrp_data),
				    ancestor);
#else
	return -ENOTSUPP;
#endif
}

static inline bool sk_has_memory_pressure(const struct sock *sk)
{
	return sk->sk_prot->memory_pressure != NULL;
}

static inline bool sk_under_memory_pressure(const struct sock *sk)
{
	if (!sk->sk_prot->memory_pressure)
		return false;

	if (mem_cgroup_sockets_enabled && sk->sk_memcg &&
	    mem_cgroup_under_socket_pressure(sk->sk_memcg))
		return true;

	return !!*sk->sk_prot->memory_pressure;
}

static inline long
sk_memory_allocated(const struct sock *sk)
{
	return atomic_long_read(sk->sk_prot->memory_allocated);
}

// 调整已分配的内存，加上之前计算得到的页面数
static inline long
sk_memory_allocated_add(struct sock *sk, int amt)
{
	return atomic_long_add_return(amt, sk->sk_prot->memory_allocated);
}

static inline void
sk_memory_allocated_sub(struct sock *sk, int amt)
{
	atomic_long_sub(amt, sk->sk_prot->memory_allocated);
}

#define SK_ALLOC_PERCPU_COUNTER_BATCH 16

static inline void sk_sockets_allocated_dec(struct sock *sk)
{
	percpu_counter_add_batch(sk->sk_prot->sockets_allocated, -1,
				 SK_ALLOC_PERCPU_COUNTER_BATCH);
}

static inline void sk_sockets_allocated_inc(struct sock *sk)
{
	percpu_counter_add_batch(sk->sk_prot->sockets_allocated, 1,
				 SK_ALLOC_PERCPU_COUNTER_BATCH);
}

static inline u64
sk_sockets_allocated_read_positive(struct sock *sk)
{
	return percpu_counter_read_positive(sk->sk_prot->sockets_allocated);
}

static inline int
proto_sockets_allocated_sum_positive(struct proto *prot)
{
	return percpu_counter_sum_positive(prot->sockets_allocated);
}

static inline long
proto_memory_allocated(struct proto *prot)
{
	return atomic_long_read(prot->memory_allocated);
}

static inline bool
proto_memory_pressure(struct proto *prot)
{
	if (!prot->memory_pressure)
		return false;
	return !!*prot->memory_pressure;
}


#ifdef CONFIG_PROC_FS
#define PROTO_INUSE_NR	64	/* should be enough for the first time */
struct prot_inuse {
	int all;
	int val[PROTO_INUSE_NR];
};

static inline void sock_prot_inuse_add(const struct net *net,
				       const struct proto *prot, int val)
{
	this_cpu_add(net->core.prot_inuse->val[prot->inuse_idx], val);
}

static inline void sock_inuse_add(const struct net *net, int val)
{
	this_cpu_add(net->core.prot_inuse->all, val);
}

int sock_prot_inuse_get(struct net *net, struct proto *proto);
int sock_inuse_get(struct net *net);
#else
static inline void sock_prot_inuse_add(const struct net *net,
				       const struct proto *prot, int val)
{
}

static inline void sock_inuse_add(const struct net *net, int val)
{
}
#endif


/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline int __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	return sk->sk_prot->hash(sk);
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
// 0-1023的端口号只有超级用户才能绑定
#define PROT_SOCK	1024

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

/*
 * Functions for memory accounting
 */
int __sk_mem_raise_allocated(struct sock *sk, int size, int amt, int kind);
int __sk_mem_schedule(struct sock *sk, int size, int kind);
void __sk_mem_reduce_allocated(struct sock *sk, int amount);
void __sk_mem_reclaim(struct sock *sk, int amount);

/* We used to have PAGE_SIZE here, but systems with 64KB pages
 * do not necessarily have 16x time more memory than 4KB ones.
 */
#define SK_MEM_QUANTUM 4096
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

/* sysctl_mem values are in pages, we convert them in SK_MEM_QUANTUM units */
static inline long sk_prot_mem_limits(const struct sock *sk, int index)
{
	long val = sk->sk_prot->sysctl_mem[index];

#if PAGE_SIZE > SK_MEM_QUANTUM
	val <<= PAGE_SHIFT - SK_MEM_QUANTUM_SHIFT;
#elif PAGE_SIZE < SK_MEM_QUANTUM
	val >>= SK_MEM_QUANTUM_SHIFT - PAGE_SHIFT;
#endif
	return val;
}

// 得到amt的内存大小需要占用的内存页面数
static inline int sk_mem_pages(int amt)
{
	return (amt + SK_MEM_QUANTUM - 1) >> SK_MEM_QUANTUM_SHIFT;
}

static inline bool sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	return !!sk->sk_prot->memory_allocated;
}

// 确认发送缓存是否可用
static inline bool sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return true;
	// 如果分配的长度少于预分配量，则确认成功，否则需要调用__sk_mem_schedule()进行全面的确认。
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static inline bool
sk_rmem_schedule(struct sock *sk, struct sk_buff *skb, int size)
{
	if (!sk_has_account(sk))
		return true;
	// 如果小于sk_forward_alloc，必然成功，否则就需要调用__sk_mem_schedule确认
	// 段得大小是否有效，无效就丢弃
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_RECV) ||
		skb_pfmemalloc(skb);
}

static inline int sk_unused_reserved_mem(const struct sock *sk)
{
	int unused_mem;

	if (likely(!sk->sk_reserved_mem))
		return 0;

	unused_mem = sk->sk_reserved_mem - sk->sk_wmem_queued -
			atomic_read(&sk->sk_rmem_alloc);

	return unused_mem > 0 ? unused_mem : 0;
}
// 缓存回收
static inline void sk_mem_reclaim(struct sock *sk)
{
	int reclaimable;

	if (!sk_has_account(sk))
		return;

	reclaimable = sk->sk_forward_alloc - sk_unused_reserved_mem(sk);
	// 只有可以回收的量大于一个页面时，才调用__sk_mem_reclaim进行真正的回收
	if (reclaimable >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk, reclaimable);
}

static inline void sk_mem_reclaim_final(struct sock *sk)
{
	sk->sk_reserved_mem = 0;
	sk_mem_reclaim(sk);
}

static inline void sk_mem_reclaim_partial(struct sock *sk)
{
	int reclaimable;

	if (!sk_has_account(sk))
		return;

	reclaimable = sk->sk_forward_alloc - sk_unused_reserved_mem(sk);

	if (reclaimable > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk, reclaimable - 1);
}

static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

/* the following macros control memory reclaiming in sk_mem_uncharge()
 */
#define SK_RECLAIM_THRESHOLD	(1 << 21)
#define SK_RECLAIM_CHUNK	(1 << 20)

static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	int reclaimable;

	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;
	reclaimable = sk->sk_forward_alloc - sk_unused_reserved_mem(sk);

	/* Avoid a possible overflow.
	 * TCP send queues can make this happen, if sk_mem_reclaim()
	 * is not called and more than 2 GBytes are released at once.
	 *
	 * If we reach 2 MBytes, reclaim 1 MBytes right now, there is
	 * no need to hold that much forward allocation anyway.
	 */
	if (unlikely(reclaimable >= SK_RECLAIM_THRESHOLD))
		__sk_mem_reclaim(sk, SK_RECLAIM_CHUNK);
}

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key)	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
				(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

static inline bool lockdep_sock_is_held(const struct sock *sk)
{
	return lockdep_is_held(&sk->sk_lock) ||
	       lockdep_is_held(&sk->sk_lock.slock);
}

void lock_sock_nested(struct sock *sk, int subclass);
// 用于进程加锁传输控制块，当进程调用网络相关的系统调用时，在访问传输控制块之前会调用此函数，
// 加锁传输控制块
static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

void __lock_sock(struct sock *sk);
void __release_sock(struct sock *sk);
void release_sock(struct sock *sk);

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))

#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
// 虽然进程不能中断软中断的执行，但在SMP架构上，很有可能多个软中断同时访问传输控制块，
// 因此软中断之间还需考虑同步。在软中断访问控制块时会先调用bh_lock_sock()函数上锁，
// 以免其他软中断对其进行访问，完成访问后调用bh_unlock_sock()函数解锁。这个锁是由
// 自旋锁来实现的，因此在非SMP架构上，bh_lock_sock和bh_unlock_sock不会真正执行。
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

bool __lock_sock_fast(struct sock *sk) __acquires(&sk->sk_lock.slock);

/**
 * lock_sock_fast - fast version of lock_sock
 * @sk: socket
 *
 * This version should be used for very small section, where process wont block
 * return false if fast path is taken:
 *
 *   sk_lock.slock locked, owned = 0, BH disabled
 *
 * return true if slow path is taken:
 *
 *   sk_lock.slock unlocked, owned = 1, BH enabled
 */
static inline bool lock_sock_fast(struct sock *sk)
{
	/* The sk_lock has mutex_lock() semantics here. */
	mutex_acquire(&sk->sk_lock.dep_map, 0, 0, _RET_IP_);

	return __lock_sock_fast(sk);
}

/* fast socket lock variant for caller already holding a [different] socket lock */
static inline bool lock_sock_fast_nested(struct sock *sk)
{
	mutex_acquire(&sk->sk_lock.dep_map, SINGLE_DEPTH_NESTING, 0, _RET_IP_);

	return __lock_sock_fast(sk);
}

/**
 * unlock_sock_fast - complement of lock_sock_fast
 * @sk: socket
 * @slow: slow mode
 *
 * fast unlock socket for user context.
 * If slow mode is on, we call regular release_sock()
 */
static inline void unlock_sock_fast(struct sock *sk, bool slow)
	__releases(&sk->sk_lock.slock)
{
	if (slow) {
		release_sock(sk);
		__release(&sk->sk_lock.slock);
	} else {
		mutex_release(&sk->sk_lock.dep_map, _RET_IP_);
		spin_unlock_bh(&sk->sk_lock.slock);
	}
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */

static inline void sock_owned_by_me(const struct sock *sk)
{
#ifdef CONFIG_LOCKDEP
	WARN_ON_ONCE(!lockdep_sock_is_held(sk) && debug_locks);
#endif
}
// 软中断和进程是不能同时访问接收队列的，因此在tcp_v4_rcv()中处理段时会调用
// sock_owned_by_user函数来检测传输控制块此时有没有被进程锁定。如果传输控制块被进程
// 锁定，则只能将数据包添加到后备队列中，否则可以进行正常的处理。
static inline bool sock_owned_by_user(const struct sock *sk)
{
	sock_owned_by_me(sk);
	return sk->sk_lock.owned;
}

static inline bool sock_owned_by_user_nocheck(const struct sock *sk)
{
	return sk->sk_lock.owned;
}

static inline void sock_release_ownership(struct sock *sk)
{
	if (sock_owned_by_user_nocheck(sk)) {
		sk->sk_lock.owned = 0;

		/* The sk_lock has mutex_unlock() semantics: */
		mutex_release(&sk->sk_lock.dep_map, _RET_IP_);
	}
}

/* no reclassification while locks are held */
static inline bool sock_allow_reclassification(const struct sock *csk)
{
	struct sock *sk = (struct sock *)csk;

	return !sock_owned_by_user_nocheck(sk) &&
		!spin_is_locked(&sk->sk_lock.slock);
}

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot, int kern);
void sk_free(struct sock *sk);
void sk_destruct(struct sock *sk);
struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority);
void sk_free_unlock_clone(struct sock *sk);

struct sk_buff *sock_wmalloc(struct sock *sk, unsigned long size, int force,
			     gfp_t priority);
void __sock_wfree(struct sk_buff *skb);
void sock_wfree(struct sk_buff *skb);
struct sk_buff *sock_omalloc(struct sock *sk, unsigned long size,
			     gfp_t priority);
void skb_orphan_partial(struct sk_buff *skb);
void sock_rfree(struct sk_buff *skb);
void sock_efree(struct sk_buff *skb);
#ifdef CONFIG_INET
void sock_edemux(struct sk_buff *skb);
void sock_pfree(struct sk_buff *skb);
#else
#define sock_edemux sock_efree
#endif

int sock_setsockopt(struct socket *sock, int level, int op,
		    sockptr_t optval, unsigned int optlen);

int sock_getsockopt(struct socket *sock, int level, int op,
		    char __user *optval, int __user *optlen);
int sock_gettstamp(struct socket *sock, void __user *userstamp,
		   bool timeval, bool time32);
// 主要是为UDP和RAW套接口分配用于输出的SKB。与sock_wmalloc()相比，在分配过程中考虑的
// 细节比较多，支持检测传输控制块已发生的错误、检测关闭套接口的标准、阻塞等特性。
// sk：待分配skb的传输控制块
// size：要分配的skb的大小
// noblock：分配SKB时是否允许阻塞
// errcode：返回操作的错误码
// 返回值，操作成功，返回分配的SKB，否则返回NULL
struct sk_buff *sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
				     unsigned long data_len, int noblock,
				     int *errcode, int max_page_order);

static inline struct sk_buff *sock_alloc_send_skb(struct sock *sk,
						  unsigned long size,
						  int noblock, int *errcode)
{
	return sock_alloc_send_pskb(sk, size, 0, noblock, errcode, 0);
}

void *sock_kmalloc(struct sock *sk, int size, gfp_t priority);
void sock_kfree_s(struct sock *sk, void *mem, int size);
void sock_kzfree_s(struct sock *sk, void *mem, int size);
void sk_send_sigurg(struct sock *sk);

struct sockcm_cookie {
	u64 transmit_time;
	u32 mark;
	u16 tsflags;
};

static inline void sockcm_init(struct sockcm_cookie *sockc,
			       const struct sock *sk)
{
	*sockc = (struct sockcm_cookie) { .tsflags = sk->sk_tsflags };
}

int __sock_cmsg_send(struct sock *sk, struct msghdr *msg, struct cmsghdr *cmsg,
		     struct sockcm_cookie *sockc);
int sock_cmsg_send(struct sock *sk, struct msghdr *msg,
		   struct sockcm_cookie *sockc);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
int sock_no_bind(struct socket *, struct sockaddr *, int);
int sock_no_connect(struct socket *, struct sockaddr *, int, int);
int sock_no_socketpair(struct socket *, struct socket *);
int sock_no_accept(struct socket *, struct socket *, int, bool);
int sock_no_getname(struct socket *, struct sockaddr *, int);
int sock_no_ioctl(struct socket *, unsigned int, unsigned long);
int sock_no_listen(struct socket *, int);
int sock_no_shutdown(struct socket *, int);
int sock_no_sendmsg(struct socket *, struct msghdr *, size_t);
int sock_no_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len);
int sock_no_recvmsg(struct socket *, struct msghdr *, size_t, int);
int sock_no_mmap(struct file *file, struct socket *sock,
		 struct vm_area_struct *vma);
ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
			 size_t size, int flags);
ssize_t sock_no_sendpage_locked(struct sock *sk, struct page *page,
				int offset, size_t size, int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
int sock_common_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			int flags);
int sock_common_setsockopt(struct socket *sock, int level, int optname,
			   sockptr_t optval, unsigned int optlen);

void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */

/* Initialise core socket variables */
void sock_init_data(struct socket *sock, struct sock *sk);

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
// 虽然传输控制块是通过sk_free来释放的，但在使用过程中并不是直接调用sk_free的，
// 因为这涉及待释放传输控制块的引用计数，只有当引用计数为0时，才能真正被释放，
// 否则只是递减引用计数而已。sock_put就完成了这样的功能。
static inline void sock_put(struct sock *sk)
{
	if (refcount_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}
/* Generic version of sock_put(), dealing with all sockets
 * (TCP_TIMEWAIT, TCP_NEW_SYN_RECV, ESTABLISHED...)
 */
void sock_gen_put(struct sock *sk);

int __sk_receive_skb(struct sock *sk, struct sk_buff *skb, const int nested,
		     unsigned int trim_cap, bool refcounted);
static inline int sk_receive_skb(struct sock *sk, struct sk_buff *skb,
				 const int nested)
{
	return __sk_receive_skb(sk, skb, nested, 1, true);
}

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	/* sk_tx_queue_mapping accept only upto a 16-bit value */
	if (WARN_ON_ONCE((unsigned short)tx_queue >= USHRT_MAX))
		return;
	sk->sk_tx_queue_mapping = tx_queue;
}

#define NO_QUEUE_MAPPING	USHRT_MAX

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = NO_QUEUE_MAPPING;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	if (sk && sk->sk_tx_queue_mapping != NO_QUEUE_MAPPING)
		return sk->sk_tx_queue_mapping;

	return -1;
}

static inline void __sk_rx_queue_set(struct sock *sk,
				     const struct sk_buff *skb,
				     bool force_set)
{
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	if (skb_rx_queue_recorded(skb)) {
		u16 rx_queue = skb_get_rx_queue(skb);

		if (force_set ||
		    unlikely(READ_ONCE(sk->sk_rx_queue_mapping) != rx_queue))
			WRITE_ONCE(sk->sk_rx_queue_mapping, rx_queue);
	}
#endif
}

static inline void sk_rx_queue_set(struct sock *sk, const struct sk_buff *skb)
{
	__sk_rx_queue_set(sk, skb, true);
}

static inline void sk_rx_queue_update(struct sock *sk, const struct sk_buff *skb)
{
	__sk_rx_queue_set(sk, skb, false);
}

static inline void sk_rx_queue_clear(struct sock *sk)
{
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	WRITE_ONCE(sk->sk_rx_queue_mapping, NO_QUEUE_MAPPING);
#endif
}

static inline int sk_rx_queue_get(const struct sock *sk)
{
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	if (sk) {
		int res = READ_ONCE(sk->sk_rx_queue_mapping);

		if (res != NO_QUEUE_MAPPING)
			return res;
	}
#endif

	return -1;
}

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk->sk_socket = sock;
}

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	BUILD_BUG_ON(offsetof(struct socket_wq, wait) != 0);
	return &rcu_dereference_raw(sk->sk_wq)->wait;
}
/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

// 将套接口和传输控制块关联起来，
static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	WARN_ON(parent->sk);
	write_lock_bh(&sk->sk_callback_lock);
	rcu_assign_pointer(sk->sk_wq, &parent->wq);
	// 设置套接字的传输控制块
	parent->sk = sk;
	// 设置传输控制块对应的套接字
	sk_set_socket(sk, parent);
	sk->sk_uid = SOCK_INODE(parent)->i_uid;
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}

kuid_t sock_i_uid(struct sock *sk);
unsigned long sock_i_ino(struct sock *sk);

static inline kuid_t sock_net_uid(const struct net *net, const struct sock *sk)
{
	return sk ? sk->sk_uid : make_kuid(net->user_ns, 0);
}

static inline u32 net_tx_rndhash(void)
{
	u32 v = prandom_u32();

	return v ?: 1;
}

static inline void sk_set_txhash(struct sock *sk)
{
	/* This pairs with READ_ONCE() in skb_set_hash_from_sk() */
	WRITE_ONCE(sk->sk_txhash, net_tx_rndhash());
}

static inline bool sk_rethink_txhash(struct sock *sk)
{
	if (sk->sk_txhash && sk->sk_txrehash == SOCK_TXREHASH_ENABLED) {
		sk_set_txhash(sk);
		return true;
	}
	return false;
}

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return rcu_dereference_check(sk->sk_dst_cache,
				     lockdep_sock_is_held(sk));
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	rcu_read_lock();
	dst = rcu_dereference(sk->sk_dst_cache);
	if (dst && !atomic_inc_not_zero(&dst->__refcnt))
		dst = NULL;
	rcu_read_unlock();
	return dst;
}

static inline void __dst_negative_advice(struct sock *sk)
{
	struct dst_entry *ndst, *dst = __sk_dst_get(sk);

	if (dst && dst->ops->negative_advice) {
		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			rcu_assign_pointer(sk->sk_dst_cache, ndst);
			sk_tx_queue_clear(sk);
			sk->sk_dst_pending_confirm = 0;
		}
	}
}

static inline void dst_negative_advice(struct sock *sk)
{
	sk_rethink_txhash(sk);
	__dst_negative_advice(sk);
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	sk->sk_dst_pending_confirm = 0;
	old_dst = rcu_dereference_protected(sk->sk_dst_cache,
					    lockdep_sock_is_held(sk));
	rcu_assign_pointer(sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	sk->sk_dst_pending_confirm = 0;
	old_dst = xchg((__force struct dst_entry **)&sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	__sk_dst_set(sk, NULL);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	sk_dst_set(sk, NULL);
}

struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

static inline void sk_dst_confirm(struct sock *sk)
{
	if (!READ_ONCE(sk->sk_dst_pending_confirm))
		WRITE_ONCE(sk->sk_dst_pending_confirm, 1);
}

static inline void sock_confirm_neigh(struct sk_buff *skb, struct neighbour *n)
{
	if (skb_get_dst_pending_confirm(skb)) {
		struct sock *sk = skb->sk;

		if (sk && READ_ONCE(sk->sk_dst_pending_confirm))
			WRITE_ONCE(sk->sk_dst_pending_confirm, 0);
		neigh_confirm(n);
	}
}

bool sk_mc_loop(struct sock *sk);

static inline bool sk_can_gso(const struct sock *sk)
{
	return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

void sk_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void sk_gso_disable(struct sock *sk)
{
	sk->sk_gso_disabled = 1;
	sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
}

static inline int skb_do_copy_data_nocache(struct sock *sk, struct sk_buff *skb,
					   struct iov_iter *from, char *to,
					   int copy, int offset)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		__wsum csum = 0;
		if (!csum_and_copy_from_iter_full(to, copy, &csum, from))
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, offset);
	} else if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY) {
		if (!copy_from_iter_full_nocache(to, copy, from))
			return -EFAULT;
	} else if (!copy_from_iter_full(to, copy, from))
		return -EFAULT;

	return 0;
}

static inline int skb_add_data_nocache(struct sock *sk, struct sk_buff *skb,
				       struct iov_iter *from, int copy)
{
	int err, offset = skb->len;

	err = skb_do_copy_data_nocache(sk, skb, from, skb_put(skb, copy),
				       copy, offset);
	if (err)
		__skb_trim(skb, offset);

	return err;
}

static inline int skb_copy_to_page_nocache(struct sock *sk, struct iov_iter *from,
					   struct sk_buff *skb,
					   struct page *page,
					   int off, int copy)
{
	int err;

	err = skb_do_copy_data_nocache(sk, skb, from, page_address(page) + off,
				       copy, skb->len);
	if (err)
		return err;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk_wmem_queued_add(sk, copy);
	sk_mem_charge(sk, copy);
	return 0;
}

/**
 * sk_wmem_alloc_get - returns write allocations
 * @sk: socket
 *
 * Return: sk_wmem_alloc minus initial offset of one
 */
static inline int sk_wmem_alloc_get(const struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) - 1;
}

/**
 * sk_rmem_alloc_get - returns read allocations
 * @sk: socket
 *
 * Return: sk_rmem_alloc
 */
static inline int sk_rmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_rmem_alloc);
}

/**
 * sk_has_allocations - check if allocations are outstanding
 * @sk: socket
 *
 * Return: true if socket has write or read allocations
 */
static inline bool sk_has_allocations(const struct sock *sk)
{
	return sk_wmem_alloc_get(sk) || sk_rmem_alloc_get(sk);
}

/**
 * skwq_has_sleeper - check if there are any waiting processes
 * @wq: struct socket_wq
 *
 * Return: true if socket_wq has waiting processes
 *
 * The purpose of the skwq_has_sleeper and sock_poll_wait is to wrap the memory
 * barrier call. They were added due to the race found within the tcp code.
 *
 * Consider following tcp code paths::
 *
 *   CPU1                CPU2
 *   sys_select          receive packet
 *   ...                 ...
 *   __add_wait_queue    update tp->rcv_nxt
 *   ...                 ...
 *   tp->rcv_nxt check   sock_def_readable
 *   ...                 {
 *   schedule               rcu_read_lock();
 *                          wq = rcu_dereference(sk->sk_wq);
 *                          if (wq && waitqueue_active(&wq->wait))
 *                              wake_up_interruptible(&wq->wait)
 *                          ...
 *                       }
 *
 * The race for tcp fires when the __add_wait_queue changes done by CPU1 stay
 * in its cache, and so does the tp->rcv_nxt update on CPU2 side.  The CPU1
 * could then endup calling schedule and sleep forever if there are no more
 * data on the socket.
 *
 */
static inline bool skwq_has_sleeper(struct socket_wq *wq)
{
	return wq && wq_has_sleeper(&wq->wait);
}

/**
 * sock_poll_wait - place memory barrier behind the poll_wait call.
 * @filp:           file
 * @sock:           socket to wait on
 * @p:              poll_table
 *
 * See the comments in the wq_has_sleeper function.
 */
static inline void sock_poll_wait(struct file *filp, struct socket *sock,
				  poll_table *p)
{
	if (!poll_does_not_wait(p)) {
		poll_wait(filp, &sock->wq.wait, p);
		/* We need to be sure we are in sync with the
		 * socket flags modification.
		 *
		 * This memory barrier is paired in the wq_has_sleeper.
		 */
		smp_mb();
	}
}

static inline void skb_set_hash_from_sk(struct sk_buff *skb, struct sock *sk)
{
	/* This pairs with WRITE_ONCE() in sk_set_txhash() */
	u32 txhash = READ_ONCE(sk->sk_txhash);

	if (txhash) {
		skb->l4_hash = 1;
		skb->hash = txhash;
	}
}

void skb_set_owner_w(struct sk_buff *skb, struct sock *sk);

/*
 *	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 *	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
// 当UDP数据报的SKB传输并添加到UDP传输控制块的接收队列中，便会调用skb_set_owner_r()设置
// 该SKB的宿主，并设置此SKB的销毁函数，还要更新接收队列中所有报文数据的总长度。
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->truesize);
}

static inline __must_check bool skb_set_owner_sk_safe(struct sk_buff *skb, struct sock *sk)
{
	if (sk && refcount_inc_not_zero(&sk->sk_refcnt)) {
		skb_orphan(skb);
		skb->destructor = sock_efree;
		skb->sk = sk;
		return true;
	}
	return false;
}

static inline void skb_prepare_for_gro(struct sk_buff *skb)
{
	if (skb->destructor != sock_wfree) {
		skb_orphan(skb);
		return;
	}
	skb->slow_gro = 1;
}

void sk_reset_timer(struct sock *sk, struct timer_list *timer,
		    unsigned long expires);

void sk_stop_timer(struct sock *sk, struct timer_list *timer);

void sk_stop_timer_sync(struct sock *sk, struct timer_list *timer);

int __sk_queue_drop_skb(struct sock *sk, struct sk_buff_head *sk_queue,
			struct sk_buff *skb, unsigned int flags,
			void (*destructor)(struct sock *sk,
					   struct sk_buff *skb));
int __sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

int sock_queue_rcv_skb_reason(struct sock *sk, struct sk_buff *skb,
			      enum skb_drop_reason *reason);

static inline int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return sock_queue_rcv_skb_reason(sk, skb, NULL);
}

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);
struct sk_buff *sock_dequeue_err_skb(struct sock *sk);

/*
 *	Recover an error report and clear atomically
 */

static inline int sock_error(struct sock *sk)
{
	int err;

	/* Avoid an atomic operation for the common case.
	 * This is racy since another cpu/thread can change sk_err under us.
	 */
	if (likely(data_race(!sk->sk_err)))
		return 0;

	err = xchg(&sk->sk_err, 0);
	return -err;
}

void sk_error_report(struct sock *sk);

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - refcount_read(&sk->sk_wmem_alloc);
		if (amt < 0)
			amt = 0;
	}
	return amt;
}

/* Note:
 *  We use sk->sk_wq_raw, from contexts knowing this
 *  pointer is not NULL and cannot disappear/change.
 */
static inline void sk_set_bit(int nr, struct sock *sk)
{
	if ((nr == SOCKWQ_ASYNC_NOSPACE || nr == SOCKWQ_ASYNC_WAITDATA) &&
	    !sock_flag(sk, SOCK_FASYNC))
		return;

	set_bit(nr, &sk->sk_wq_raw->flags);
}

static inline void sk_clear_bit(int nr, struct sock *sk)
{
	if ((nr == SOCKWQ_ASYNC_NOSPACE || nr == SOCKWQ_ASYNC_WAITDATA) &&
	    !sock_flag(sk, SOCK_FASYNC))
		return;

	clear_bit(nr, &sk->sk_wq_raw->flags);
}

// 用来将SIGIO或SIGURG信号发送给在该套接字接口上的进程，通知该进程可以对该文件进行读或写。
// sk：通知进程可进行I/O处理的传输控制块
// how：通知进程方式
// 		SOCK_WAKE_IO：检测标志应用程序通过recv等调用时，是否在等待数据的接收
// 		SOCK_WAKE_WAITD：检测传输控制块的发送队列是否曾经达到上限
//		SOCK_WAKE_SPACE：不做任何检测，直接向等待进程发送SIGIO信号
//		SOCK_WAKE_URG：向等待进程发送SIGURG信号
// band：通知进程的I/O读写类型
// 		POLL_IN：输入数据有效，可以读
//		POLL_OUT：输出缓冲区有效，可以写
//		POLL_MSG：输入消息，可以读
//		POLL_ERR：I/O异常
// 		POLL_PRI：高优先级的输入数据有效，可以读
//		POLL_HUP：设备挂起或者文件已关闭，无法继续读写
// 此函数只是做了简单的封装，在套接口的异步待通知队列有效时调用sock_wake_async()进行处理。
static inline void sk_wake_async(const struct sock *sk, int how, int band)
{
	if (sock_flag(sk, SOCK_FASYNC)) {
		rcu_read_lock();
		sock_wake_async(rcu_dereference(sk->sk_wq), how, band);
		rcu_read_unlock();
	}
}

/* Since sk_{r,w}mem_alloc sums skb->truesize, even a small frame might
 * need sizeof(sk_buff) + MTU + padding, unless net driver perform copybreak.
 * Note: for send buffers, TCP works better if we can build two skbs at
 * minimum.
 */
#define TCP_SKB_MIN_TRUESIZE	(2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)))

#define SOCK_MIN_SNDBUF		(TCP_SKB_MIN_TRUESIZE * 2)
#define SOCK_MIN_RCVBUF		 TCP_SKB_MIN_TRUESIZE

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	u32 val;

	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return;

	val = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
	val = max_t(u32, val, sk_unused_reserved_mem(sk));

	WRITE_ONCE(sk->sk_sndbuf, max_t(u32, val, SOCK_MIN_SNDBUF));
}

/**
 * sk_page_frag - return an appropriate page_frag
 * @sk: socket
 *
 * Use the per task page_frag instead of the per socket one for
 * optimization when we know that we're in process context and own
 * everything that's associated with %current.
 *
 * Both direct reclaim and page faults can nest inside other
 * socket operations and end up recursing into sk_page_frag()
 * while it's already in use: explicitly avoid task page_frag
 * usage if the caller is potentially doing any of them.
 * This assumes that page fault handlers use the GFP_NOFS flags.
 *
 * Return: a per task page_frag if context allows that,
 * otherwise a per socket one.
 */
// 返回一个合适的page_frag
// 返回值：如果上下文允许，每个任务一个，否则每个socket一个
static inline struct page_frag *sk_page_frag(struct sock *sk)
{
	if ((sk->sk_allocation & (__GFP_DIRECT_RECLAIM | __GFP_MEMALLOC | __GFP_FS)) ==
	    (__GFP_DIRECT_RECLAIM | __GFP_FS))
		return &current->task_frag;

	return &sk->sk_frag;
}

bool sk_page_frag_refill(struct sock *sk, struct page_frag *pfrag);

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline bool sock_writeable(const struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) < (READ_ONCE(sk->sk_sndbuf) >> 1);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline gfp_t gfp_memcg_charge(void)
{
	return in_softirq() ? GFP_NOWAIT : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	int v = waitall ? len : min_t(int, READ_ONCE(sk->sk_rcvlowat), len);

	return v ?: 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

struct sock_skb_cb {
	u32 dropcount;
};

/* Store sock_skb_cb at the end of skb->cb[] so protocol families
 * using skb->cb[] would keep using it directly and utilize its
 * alignement guarantee.
 */
#define SOCK_SKB_CB_OFFSET ((sizeof_field(struct sk_buff, cb) - \
			    sizeof(struct sock_skb_cb)))

#define SOCK_SKB_CB(__skb) ((struct sock_skb_cb *)((__skb)->cb + \
			    SOCK_SKB_CB_OFFSET))

#define sock_skb_cb_check_size(size) \
	BUILD_BUG_ON((size) > SOCK_SKB_CB_OFFSET)

static inline void
sock_skb_set_dropcount(const struct sock *sk, struct sk_buff *skb)
{
	SOCK_SKB_CB(skb)->dropcount = sock_flag(sk, SOCK_RXQ_OVFL) ?
						atomic_read(&sk->sk_drops) : 0;
}

static inline void sk_drops_add(struct sock *sk, const struct sk_buff *skb)
{
	int segs = max_t(u16, 1, skb_shinfo(skb)->gso_segs);

	atomic_add(segs, &sk->sk_drops);
}

static inline ktime_t sock_read_timestamp(struct sock *sk)
{
#if BITS_PER_LONG==32
	unsigned int seq;
	ktime_t kt;

	do {
		seq = read_seqbegin(&sk->sk_stamp_seq);
		kt = sk->sk_stamp;
	} while (read_seqretry(&sk->sk_stamp_seq, seq));

	return kt;
#else
	return READ_ONCE(sk->sk_stamp);
#endif
}

static inline void sock_write_timestamp(struct sock *sk, ktime_t kt)
{
#if BITS_PER_LONG==32
	write_seqlock(&sk->sk_stamp_seq);
	sk->sk_stamp = kt;
	write_sequnlock(&sk->sk_stamp_seq);
#else
	WRITE_ONCE(sk->sk_stamp, kt);
#endif
}

void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
			   struct sk_buff *skb);
void __sock_recv_wifi_status(struct msghdr *msg, struct sock *sk,
			     struct sk_buff *skb);

static inline void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	ktime_t kt = skb->tstamp;
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);

	/*
	 * generate control messages if
	 * - receive time stamping in software requested
	 * - software time stamp available and wanted
	 * - hardware time stamps available and wanted
	 */
	if (sock_flag(sk, SOCK_RCVTSTAMP) ||
	    (sk->sk_tsflags & SOF_TIMESTAMPING_RX_SOFTWARE) ||
	    (kt && sk->sk_tsflags & SOF_TIMESTAMPING_SOFTWARE) ||
	    (hwtstamps->hwtstamp &&
	     (sk->sk_tsflags & SOF_TIMESTAMPING_RAW_HARDWARE)))
		__sock_recv_timestamp(msg, sk, skb);
	else
		sock_write_timestamp(sk, kt);

	if (sock_flag(sk, SOCK_WIFI_STATUS) && skb->wifi_acked_valid)
		__sock_recv_wifi_status(msg, sk, skb);
}

void __sock_recv_cmsgs(struct msghdr *msg, struct sock *sk,
		       struct sk_buff *skb);

#define SK_DEFAULT_STAMP (-1L * NSEC_PER_SEC)
static inline void sock_recv_cmsgs(struct msghdr *msg, struct sock *sk,
				   struct sk_buff *skb)
{
#define FLAGS_RECV_CMSGS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP)			| \
			   (1UL << SOCK_RCVMARK))
#define TSFLAGS_ANY	  (SOF_TIMESTAMPING_SOFTWARE			| \
			   SOF_TIMESTAMPING_RAW_HARDWARE)

	if (sk->sk_flags & FLAGS_RECV_CMSGS || sk->sk_tsflags & TSFLAGS_ANY)
		__sock_recv_cmsgs(msg, sk, skb);
	else if (unlikely(sock_flag(sk, SOCK_TIMESTAMP)))
		sock_write_timestamp(sk, skb->tstamp);
	else if (unlikely(sk->sk_stamp == SK_DEFAULT_STAMP))
		sock_write_timestamp(sk, 0);
}

void __sock_tx_timestamp(__u16 tsflags, __u8 *tx_flags);

/**
 * _sock_tx_timestamp - checks whether the outgoing packet is to be time stamped
 * @sk:		socket sending this packet
 * @tsflags:	timestamping flags to use
 * @tx_flags:	completed with instructions for time stamping
 * @tskey:      filled in with next sk_tskey (not for TCP, which uses seqno)
 *
 * Note: callers should take care of initial ``*tx_flags`` value (usually 0)
 */
static inline void _sock_tx_timestamp(struct sock *sk, __u16 tsflags,
				      __u8 *tx_flags, __u32 *tskey)
{
	if (unlikely(tsflags)) {
		__sock_tx_timestamp(tsflags, tx_flags);
		if (tsflags & SOF_TIMESTAMPING_OPT_ID && tskey &&
		    tsflags & SOF_TIMESTAMPING_TX_RECORD_MASK)
			*tskey = atomic_inc_return(&sk->sk_tskey) - 1;
	}
	if (unlikely(sock_flag(sk, SOCK_WIFI_STATUS)))
		*tx_flags |= SKBTX_WIFI_STATUS;
}

static inline void sock_tx_timestamp(struct sock *sk, __u16 tsflags,
				     __u8 *tx_flags)
{
	_sock_tx_timestamp(sk, tsflags, tx_flags, NULL);
}

static inline void skb_setup_tx_timestamp(struct sk_buff *skb, __u16 tsflags)
{
	_sock_tx_timestamp(skb->sk, tsflags, &skb_shinfo(skb)->tx_flags,
			   &skb_shinfo(skb)->tskey);
}

static inline bool sk_is_tcp(const struct sock *sk)
{
	return sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP;
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

static inline bool
skb_sk_is_prefetched(struct sk_buff *skb)
{
#ifdef CONFIG_INET
	return skb->destructor == sock_pfree;
#else
	return false;
#endif /* CONFIG_INET */
}

/* This helper checks if a socket is a full socket,
 * ie _not_ a timewait or request socket.
 */
static inline bool sk_fullsock(const struct sock *sk)
{
	return (1 << sk->sk_state) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
}

static inline bool
sk_is_refcounted(struct sock *sk)
{
	/* Only full sockets have sk->sk_flags. */
	return !sk_fullsock(sk) || !sock_flag(sk, SOCK_RCU_FREE);
}

/**
 * skb_steal_sock - steal a socket from an sk_buff
 * @skb: sk_buff to steal the socket from
 * @refcounted: is set to true if the socket is reference-counted
 */
static inline struct sock *
skb_steal_sock(struct sk_buff *skb, bool *refcounted)
{
	if (skb->sk) {
		struct sock *sk = skb->sk;

		*refcounted = true;
		if (skb_sk_is_prefetched(skb))
			*refcounted = sk_is_refcounted(sk);
		skb->destructor = NULL;
		skb->sk = NULL;
		return sk;
	}
	*refcounted = false;
	return NULL;
}

/* Checks if this SKB belongs to an HW offloaded socket
 * and whether any SW fallbacks are required based on dev.
 * Check decrypted mark in case skb_orphan() cleared socket.
 */
static inline struct sk_buff *sk_validate_xmit_skb(struct sk_buff *skb,
						   struct net_device *dev)
{
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sock *sk = skb->sk;

	if (sk && sk_fullsock(sk) && sk->sk_validate_xmit_skb) {
		skb = sk->sk_validate_xmit_skb(sk, dev, skb);
#ifdef CONFIG_TLS_DEVICE
	} else if (unlikely(skb->decrypted)) {
		pr_warn_ratelimited("unencrypted skb with no associated socket - dropping\n");
		kfree_skb(skb);
		skb = NULL;
#endif
	}
#endif

	return skb;
}

/* This helper checks if a socket is a LISTEN or NEW_SYN_RECV
 * SYNACK messages can be attached to either ones (depending on SYNCOOKIE)
 */
static inline bool sk_listener(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_LISTEN | TCPF_NEW_SYN_RECV);
}

void sock_enable_timestamp(struct sock *sk, enum sock_flags flag);
int sock_recv_errqueue(struct sock *sk, struct msghdr *msg, int len, int level,
		       int type);

bool sk_ns_capable(const struct sock *sk,
		   struct user_namespace *user_ns, int cap);
bool sk_capable(const struct sock *sk, int cap);
bool sk_net_capable(const struct sock *sk, int cap);

void sk_get_meminfo(const struct sock *sk, u32 *meminfo);

/* Take into consideration the size of the struct sk_buff overhead in the
 * determination of these values, since that is non-constant across
 * platforms.  This makes socket queueing behavior and performance
 * not depend upon such differences.
 */
#define _SK_MEM_PACKETS		256
#define _SK_MEM_OVERHEAD	SKB_TRUESIZE(256)
#define SK_WMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)
#define SK_RMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

extern int sysctl_tstamp_allow_data;
extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

#define SKB_FRAG_PAGE_ORDER	get_order(32768)
DECLARE_STATIC_KEY_FALSE(net_high_order_alloc_disable_key);

static inline int sk_get_wmem0(const struct sock *sk, const struct proto *proto)
{
	/* Does this proto have per netns sysctl_wmem ? */
	if (proto->sysctl_wmem_offset)
		return *(int *)((void *)sock_net(sk) + proto->sysctl_wmem_offset);

	return *proto->sysctl_wmem;
}

static inline int sk_get_rmem0(const struct sock *sk, const struct proto *proto)
{
	/* Does this proto have per netns sysctl_rmem ? */
	if (proto->sysctl_rmem_offset)
		return *(int *)((void *)sock_net(sk) + proto->sysctl_rmem_offset);

	return *proto->sysctl_rmem;
}

/* Default TCP Small queue budget is ~1 ms of data (1sec >> 10)
 * Some wifi drivers need to tweak it to get more chunks.
 * They can use this helper from their ndo_start_xmit()
 */
static inline void sk_pacing_shift_update(struct sock *sk, int val)
{
	if (!sk || !sk_fullsock(sk) || READ_ONCE(sk->sk_pacing_shift) == val)
		return;
	WRITE_ONCE(sk->sk_pacing_shift, val);
}

/* if a socket is bound to a device, check that the given device
 * index is either the same or that the socket is bound to an L3
 * master device and the given device index is also enslaved to
 * that L3 master
 */
static inline bool sk_dev_equal_l3scope(struct sock *sk, int dif)
{
	int bound_dev_if = READ_ONCE(sk->sk_bound_dev_if);
	int mdif;

	if (!bound_dev_if || bound_dev_if == dif)
		return true;

	mdif = l3mdev_master_ifindex_by_index(sock_net(sk), dif);
	if (mdif && mdif == bound_dev_if)
		return true;

	return false;
}

void sock_def_readable(struct sock *sk);

int sock_bindtoindex(struct sock *sk, int ifindex, bool lock_sk);
void sock_set_timestamp(struct sock *sk, int optname, bool valbool);
int sock_set_timestamping(struct sock *sk, int optname,
			  struct so_timestamping timestamping);

void sock_enable_timestamps(struct sock *sk);
void sock_no_linger(struct sock *sk);
void sock_set_keepalive(struct sock *sk);
void sock_set_priority(struct sock *sk, u32 priority);
void sock_set_rcvbuf(struct sock *sk, int val);
void sock_set_mark(struct sock *sk, u32 val);
void sock_set_reuseaddr(struct sock *sk);
void sock_set_reuseport(struct sock *sk);
void sock_set_sndtimeo(struct sock *sk, s64 secs);

int sock_bind_add(struct sock *sk, struct sockaddr *addr, int addr_len);

int sock_get_timeout(long timeo, void *optval, bool old_timeval);
int sock_copy_user_timeval(struct __kernel_sock_timeval *tv,
			   sockptr_t optval, int optlen, bool old_timeval);

static inline bool sk_is_readable(struct sock *sk)
{
	if (sk->sk_prot->sock_is_readable)
		return sk->sk_prot->sock_is_readable(sk);
	return false;
}
#endif	/* _SOCK_H */
