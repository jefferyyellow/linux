/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NET		Generic infrastructure for INET connection oriented protocols.
 *
 *		Definitions for inet_connection_sock 
 *
 * Authors:	Many people, see the TCP sources
 *
 * 		From code originally in TCP
 */
#ifndef _INET_CONNECTION_SOCK_H
#define _INET_CONNECTION_SOCK_H

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>
#include <linux/kernel.h>
#include <linux/sockptr.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

/* Cancel timers, when they are not required. */
#undef INET_CSK_CLEAR_TIMERS

struct inet_bind_bucket;
struct tcp_congestion_ops;

/*
 * Pointers to address related TCP functions
 * (i.e. things that depend on the address family)
 */
// 封装了一组与传输层相关的操作集，包括向网络层发送的接口，传输层的setsockopt接口等。
struct inet_connection_sock_af_ops {
	// 从传输层向网络层传递的接口，TCP中设置为ip_queue_xmit
	int	    (*queue_xmit)(struct sock *sk, struct sk_buff *skb, struct flowi *fl);
	// 计算传输层首部校验和函数,TCP中初始化为tcp_v4_send_check
	void	    (*send_check)(struct sock *sk, struct sk_buff *skb);
	// 如果传输控制块还没有路由缓存项,为传输控制块选择路由缓存项,TCP中设置为inet_sk_rebuild_header
	int	    (*rebuild_header)(struct sock *sk);
	// 
	void	    (*sk_rx_dst_set)(struct sock *sk, const struct sk_buff *skb);
	// 处理连接请求接口,TCP中设置为tcp_v4_conn_request
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);
	// 在完成三次握手后,调用此接口来创建一个新的套接口,在TCP中初始化为tcp_v4_syn_recv_sock
	struct sock *(*syn_recv_sock)(const struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst,
				      struct request_sock *req_unhash,
				      bool *own_req);
	// 在IPv4中为IP首部的长度，即iphdr结构的大小
	u16	    net_header_len;
	u16	    net_frag_header_len;
	// IP套接字地址长度，在IPv4中就是sockaddr_in结构的长度
	u16	    sockaddr_len;
	// setsockopt和getsockopt传输层的系统调用接口
	int	    (*setsockopt)(struct sock *sk, int level, int optname,
				  sockptr_t optval, unsigned int optlen);
	int	    (*getsockopt)(struct sock *sk, int level, int optname,
				  char __user *optval, int __user *optlen);
	// 将IP套接口地址结构中的地址信息复制到传输控制块中，TCP中为inet_csk_addr2_sockaddr()，
	// 实际上这个接口并未使用
	void	    (*addr2sockaddr)(struct sock *sk, struct sockaddr *);
	void	    (*mtu_reduced)(struct sock *sk);
};

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_accept_queue:	   FIFO of established children
 * @icsk_bind_hash:	   Bind node
 * @icsk_timeout:	   Timeout
 * @icsk_retransmit_timer: Resend (no ack)
 * @icsk_rto:		   Retransmit timeout
 * @icsk_pmtu_cookie	   Last pmtu seen by socket
 * @icsk_ca_ops		   Pluggable congestion control hook
 * @icsk_af_ops		   Operations which are AF_INET{4,6} specific
 * @icsk_ulp_ops	   Pluggable ULP control hook
 * @icsk_ulp_data	   ULP private data
 * @icsk_clean_acked	   Clean acked data hook
 * @icsk_ca_state:	   Congestion control state
 * @icsk_retransmits:	   Number of unrecovered [RTO] timeouts
 * @icsk_pending:	   Scheduled timer event
 * @icsk_backoff:	   Backoff
 * @icsk_syn_retries:      Number of allowed SYN (or equivalent) retries
 * @icsk_probes_out:	   unanswered 0 window probes
 * @icsk_ext_hdr_len:	   Network protocol overhead (IP/IPv6 options)
 * @icsk_ack:		   Delayed ACK control data
 * @icsk_mtup;		   MTU probing control data
 * @icsk_probes_tstamp:    Probe timestamp (cleared by non-zero window ack)
 * @icsk_user_timeout:	   TCP_USER_TIMEOUT value
 */
// 所有面向连接传输控制块的表示，在inet_sock结构的基础上，增加了有关进行连接、确认和重传等成员
struct inet_connection_sock {
	/* inet_sock has to be the first member! */
	// 基础结构，一层层的扩展
	struct inet_sock	  icsk_inet;
	// TCP传输层收到客户端的连接请求以后，会创建一个客户端套接字存放到icsk_accept_queue容器中，
	// 等待应用程序调用accept进行读取，注意这个是连接完成的列表（完成了3次握手的）
	struct request_sock_queue icsk_accept_queue;
	// 指向与之绑定的本地端口信息，在绑定过程中被设置
	struct inet_bind_bucket	  *icsk_bind_hash;
	// 如果TCP段在指定时间内没接收到ACK，则认为发送失败，而进行重传的超时时间。通常为jiffies+icsk_rto，
	// 即在jiffies+rto之后进行重传
	unsigned long		  icsk_timeout;
	// 通过标识符icsk_pending来区分重传定时器和持续定时器的实现，在超时时间内没有接收到相应的ACK段会发送重传。
	// 在连接对方通告接收窗口为0时会启动持续定时器。
 	struct timer_list	  icsk_retransmit_timer;
	// 用于延迟发送ACK段的定时器
 	struct timer_list	  icsk_delack_timer;
	// 超时重传的时间，初始值为TCP_TIMEOUT_INIT，当往返时间超过此值时被认为传输失败。需要注意的是，
	// 超时重传的时间是根据当前网络的情况动态计算的。
	__u32			  icsk_rto;
	// 
	__u32                     icsk_rto_min;
	__u32                     icsk_delack_max;
	// 最后一次更新的路径MTU(PMTU)。
	__u32			  icsk_pmtu_cookie;
	// 指向实现某个拥塞控制算法的指针。到目前为止，Linux支持多种拥塞控制算法，而用户也可以编写自己的
	// 拥塞控制机制模块加载到内核中，参见TCP_CONGESTION选项。
	const struct tcp_congestion_ops *icsk_ca_ops;
	// TCP的一个操作接口集，包括向IP层发送的接口，TCP层setsockopt接口等。加载TCP协议模块时，在tcp_v4_init_sock中被
	// 初始化为inet_connection_sock_af_ops结构类型常量ipv4_specific
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	const struct tcp_ulp_ops  *icsk_ulp_ops;
	void __rcu		  *icsk_ulp_data;
	void (*icsk_clean_acked)(struct sock *sk, u32 acked_seq);
	// 根据PMTU同步本地MSS函数指针，加载TCP协议模块时，在tcp_v4_init_sock中被初始化为tcp_sync_mss结构类型常量
	unsigned int		  (*icsk_sync_mss)(struct sock *sk, u32 pmtu);
	// 拥塞控制状态
	__u8			  icsk_ca_state:5,
				  icsk_ca_initialized:1,
				  icsk_ca_setsockopt:1,
				  icsk_ca_dst_locked:1;
	// 记录超时重传次数
	__u8			  icsk_retransmits;
	// 标识预定的定时器事件，实际上，只取ICSK_TIME_RETRANS或ICSK_TIME_PROBE0,因为这两种定时操作使用的是同一个定时器，
	// 因此需要用这个标志来区分正在使用的是哪个定时器。重传和零窗口探测时会调用inet_csk_reset_xmit_timer()设置该字段。
	__u8			  icsk_pending;
	// 用来计算持续定时器的下一个设定值的指数退避算法指数，在传送超时时会递增
	__u8			  icsk_backoff;
	// 在建立TCP连接时最多允许重试发送SYN或SYN+ACK段的次数，参见TCP_SYNCNT选项和tcp_synack_retries系统参数。
	__u8			  icsk_syn_retries;
	// 持续定时器或保活定时器周期性发送出去但未被确认的TCP段数目，在收到ACK之后清零。
	__u8			  icsk_probes_out;
	// IP首部中选项部分长度
	__u16			  icsk_ext_hdr_len;
	// 延时确认控制数据块
	struct {
		// 标识当前需要确认的紧急程度和状态，在数据从内核空间复制到用户空间时会检测该状态，
		// 如果需要则立即发送确认：而在计算rcv_mss时，会根据情况调整此状态。由于pending是按位存储的，
		// 因此多个状态可以同时存在。
		__u8		  pending;	 /* ACK is pending			   */
		// 标识启用或禁用确认模式，通过TCP_QUICKACK选项设置其值。
		// 0：不延迟ACK段的发送，而是进行快速发送，
		// 1：将会延迟发送ACK
		// 在快速确认模式下，会立即发送ACK。整个TCP处理过程中，如果需要还会进入到正常模式允许，也就是说，
		// 这个标志的设置不是永久性的，而只是在当时启用/禁用快速确认模式，在这之后，根据延时确认超时、数据传输等因素，
		// 有可能会再次进入或离开快速确认模式。
		__u8		  quick;	 /* Scheduled number of quick acks	   */
		__u8		  pingpong;	 /* The session is interactive		   */
		__u8		  retry;	 /* Number of attempts			   */
		// 用来计算延迟确认的估值，在接收到TCP段时会根据本次与上次接收的时间间隔来调整该值，
		// 而在设置延时确认定时器时会根据条件调整该值
		__u32		  ato;		 /* Predicted tick of soft clock	   */
		// 当前的延时确认时间，超时会发送ACK
		unsigned long	  timeout;	 /* Currently scheduled timeout		   */
		// 标识最近一次接收到数据包的时间。
		__u32		  lrcvtime;	 /* timestamp of last received data packet */
		// 最后一个接收到的段的长度，用来计算rcv_mss
		__u16		  last_seg_size; /* Size of last incoming segment	   */
		// 由最近接收到段计算的MSS，主要用来确定是否执行延时确认。
		__u16		  rcv_mss;	 /* MSS used for delayed ACK decisions	   */
	} icsk_ack;
	// 路径MTU发现的控制数据块，在tcp_mtup_init中初始化。
	struct {
		/* Range of MTUs to search */
		// 用于标识进行路径MTU发现的区间的上下限。
		int		  search_high;
		int		  search_low;

		/* Information on the current probe. */
		// 为当前路径MTU探测段的长度，也用于判断路径MTU探测是否完成。无论成功还是失败，
		// 路径MTU探测完成后此值都将初始化为0
		u32		  probe_size:31,
		/* Is the MTUP feature enabled for this connection? */
				  enabled:1;

		u32		  probe_timestamp;
	} icsk_mtup;
	u32			  icsk_probes_tstamp;
	u32			  icsk_user_timeout;
	// 存储各种有关TCP拥塞控制算法的私有参数。虽然这里定义的是16个无符号整型，但在实际存储时的类型因拥塞控制算法而异
	u64			  icsk_ca_priv[104 / sizeof(u64)];
#define ICSK_CA_PRIV_SIZE	  sizeof_field(struct inet_connection_sock, icsk_ca_priv)
};

#define ICSK_TIME_RETRANS	1	/* Retransmit timer */
#define ICSK_TIME_DACK		2	/* Delayed ack timer */
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */
#define ICSK_TIME_LOSS_PROBE	5	/* Tail loss probe timer */
#define ICSK_TIME_REO_TIMEOUT	6	/* Reordering timer */

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

struct sock *inet_csk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority);

enum inet_csk_ack_state_t {
	ICSK_ACK_SCHED	= 1,
	ICSK_ACK_TIMER  = 2,
	ICSK_ACK_PUSHED = 4,
	ICSK_ACK_PUSHED2 = 8,
	ICSK_ACK_NOW = 16	/* Send the next ACK immediately (once) */
};

void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(struct timer_list *),
			       void (*delack_handler)(struct timer_list *),
			       void (*keepalive_handler)(struct timer_list *));
void inet_csk_clear_xmit_timers(struct sock *sk);

static inline void inet_csk_schedule_ack(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_SCHED;
}

static inline int inet_csk_ack_scheduled(const struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pending & ICSK_ACK_SCHED;
}

static inline void inet_csk_delack_init(struct sock *sk)
{
	memset(&inet_csk(sk)->icsk_ack, 0, sizeof(inet_csk(sk)->icsk_ack));
}

void inet_csk_delete_keepalive_timer(struct sock *sk);
void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long timeout);

static inline void inet_csk_clear_xmit_timer(struct sock *sk, const int what)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
#endif
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending = 0;
		icsk->icsk_ack.retry = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_delack_timer);
#endif
	} else {
		pr_debug("inet_csk BUG: unknown timer value\n");
	}
}

/*
 *	Reset the retransmission timer
 */
static inline void inet_csk_reset_xmit_timer(struct sock *sk, const int what,
					     unsigned long when,
					     const unsigned long max_when)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (when > max_when) {
		pr_debug("reset_xmit_timer: sk=%p %d when=0x%lx, caller=%p\n",
			 sk, what, when, (void *)_THIS_IP_);
		when = max_when;
	}

	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0 ||
	    what == ICSK_TIME_LOSS_PROBE || what == ICSK_TIME_REO_TIMEOUT) {
		icsk->icsk_pending = what;
		icsk->icsk_timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending |= ICSK_ACK_TIMER;
		icsk->icsk_ack.timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
	} else {
		pr_debug("inet_csk BUG: unknown timer value\n");
	}
}

static inline unsigned long
inet_csk_rto_backoff(const struct inet_connection_sock *icsk,
		     unsigned long max_when)
{
        u64 when = (u64)icsk->icsk_rto << icsk->icsk_backoff;

        return (unsigned long)min_t(u64, when, max_when);
}

struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern);

int inet_csk_get_port(struct sock *sk, unsigned short snum);

struct dst_entry *inet_csk_route_req(const struct sock *sk, struct flowi4 *fl4,
				     const struct request_sock *req);
struct dst_entry *inet_csk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req);

struct sock *inet_csk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child);
void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout);
struct sock *inet_csk_complete_hashdance(struct sock *sk, struct sock *child,
					 struct request_sock *req,
					 bool own_req);

static inline void inet_csk_reqsk_queue_added(struct sock *sk)
{
	reqsk_queue_added(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_len(const struct sock *sk)
{
	return reqsk_queue_len(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_is_full(const struct sock *sk)
{
	return inet_csk_reqsk_queue_len(sk) >= sk->sk_max_ack_backlog;
}

bool inet_csk_reqsk_queue_drop(struct sock *sk, struct request_sock *req);
void inet_csk_reqsk_queue_drop_and_put(struct sock *sk, struct request_sock *req);

static inline unsigned long
reqsk_timeout(struct request_sock *req, unsigned long max_timeout)
{
	u64 timeout = (u64)req->timeout << req->num_timeout;

	return (unsigned long)min_t(u64, timeout, max_timeout);
}

static inline void inet_csk_prepare_for_destroy_sock(struct sock *sk)
{
	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	this_cpu_inc(*sk->sk_prot->orphan_count);
}

void inet_csk_destroy_sock(struct sock *sk);
void inet_csk_prepare_forced_close(struct sock *sk);

/*
 * LISTEN is a special case for poll..
 */
static inline __poll_t inet_csk_listen_poll(const struct sock *sk)
{
	return !reqsk_queue_empty(&inet_csk(sk)->icsk_accept_queue) ?
			(EPOLLIN | EPOLLRDNORM) : 0;
}

int inet_csk_listen_start(struct sock *sk);
void inet_csk_listen_stop(struct sock *sk);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr);

/* update the fast reuse flag when adding a socket */
void inet_csk_update_fastreuse(struct inet_bind_bucket *tb,
			       struct sock *sk);

struct dst_entry *inet_csk_update_pmtu(struct sock *sk, u32 mtu);

#define TCP_PINGPONG_THRESH	3

static inline void inet_csk_enter_pingpong_mode(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pingpong = TCP_PINGPONG_THRESH;
}

static inline void inet_csk_exit_pingpong_mode(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pingpong = 0;
}

static inline bool inet_csk_in_pingpong_mode(struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pingpong >= TCP_PINGPONG_THRESH;
}

static inline void inet_csk_inc_pingpong_cnt(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ack.pingpong < U8_MAX)
		icsk->icsk_ack.pingpong++;
}

static inline bool inet_csk_has_ulp(struct sock *sk)
{
	return inet_sk(sk)->is_icsk && !!inet_csk(sk)->icsk_ulp_ops;
}

#endif /* _INET_CONNECTION_SOCK_H */
