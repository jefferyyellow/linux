/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H


#include <linux/skbuff.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>
#include <uapi/linux/tcp.h>
// 从skb中提取tcp头部
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int __tcp_hdrlen(const struct tcphdr *th)
{
	return th->doff * 4;
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return __tcp_hdrlen(tcp_hdr(skb));
}

static inline struct tcphdr *inner_tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_inner_transport_header(skb);
}

static inline unsigned int inner_tcp_hdrlen(const struct sk_buff *skb)
{
	return inner_tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* TCP Fast Open */
#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

/* TCP Fast Open Cookie as stored in memory */
struct tcp_fastopen_cookie {
	__le64	val[DIV_ROUND_UP(TCP_FASTOPEN_COOKIE_MAX, sizeof(u64))];
	s8	len;
	bool	exp;	/* In RFC6994 experimental option format */
};

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */
#define TCP_DSACK_SEEN    (1 << 2)   /*1 = DSACK was received from peer*/
// tcp_options_received结构主要用来保存接收到的TCP选项信息，如时间戳、SACK等；
// 同时标志对端支持的特性，如对端是否支持窗口扩大因子、是否支持SACK等
struct tcp_options_received {
/*	PAWS/RTTM data	*/
	// 记录从接收到的段中取出时间戳设置到ts_recent的时间，用于检测ts_recent的有效性：
	// 如果自从该时间之后已经经过了超过24天的时间，则认为ts_recent是无效的
	int	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	// 下一个待发送的TCP段中的时间戳回显值。当一个含有最后发送ACK中确认序号的段到达时，
	// 该段中的时间戳被保存在ts_recent中。而下一个待发送的TCP段的时间戳值是由SKB中TCP
	// 控制块的成员when填入的，when字段值是由协议栈取系统时间变量jiffies的低32位。
	u32	ts_recent;	/* Time stamp to echo next		*/
	// 保存最近一次接收到对端的TCP段的时间戳选项中的时间戳值。
	u32	rcv_tsval;	/* Time stamp value             	*/
	// 保存最近一次接收到对端的TCP段的时间戳选中的时间戳回显应答。
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	// 标识最近一次接收到的TCP段是否存在TCP时间戳选项，1为有，0为没有。
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		// 标识TCP连接是否启用时间戳选项。在TCP建立连接过程中如果接收到TCP段中有时间戳选项，
		// 则说明对端也支持时间戳选项，这时tstamp_ok字段设置为1。表示该连接支持时间戳选项，
		// 在随后的数据传说中，TCP首部中都会带有时间戳选项。
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		// 标志下次发送的段中SACK选项（选择性确认）是否存在D-SACK(duplicate-SACK)。
		dsack : 1,	/* D-SACK is scheduled			*/
		// 标志接收方是否支持窗口扩大因子，只能出现在SYN段中。
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		// 标志接收方是否支持SACK，如果为0则表示不支持SACK；如果为非0则表示支持SACK。
		// 此外，因为sack_ok占有4位，因此在正常带有负荷的段中，其余位还有其他的含义：
		// 第1位表示是否启用FACK拥塞避免，第2位表示在SACK选项中是否存在D-SACK，第3位保留。
		sack_ok : 3,	/* SACK seen on SYN packet		*/
		smc_ok : 1,	/* SMC seen on SYN packet		*/
		// 发送窗口扩大因子，即要把TCP首部中滑动窗口大小左移snd_wscale位后，才是真正的滑动窗口大小。
		// 在TCP首部中，滑动窗口大小值是16位的，而snd_wscale的值最大只能为14，所以，滑动窗口值最大
		// 可扩展到30位。在协议栈的实现中，可以看到窗口大小被置为5840，扩大因子为2，即实际的窗口大小为
		// 5840<<2=23360B。
		snd_wscale : 4,	/* indow scaling received from sender	*/
		// 接收窗口扩大因子
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
	u8	saw_unknown:1,	/* Received unknown option		*/
		unused:7;
	// 下一个待发送的段中SACK选项的SACK块数，同时用来计算eff_sacks。
	u8	num_sacks;	/* Number of SACK blocks		*/
	// 为用户设置的MSS上限，与建立连接时SYN段中的MSS，两者之间的最小值作为该连接的MSS上限，
	// 存储在mss_clamp中。使用setsockopt/getsockopt系统调用TCP_MAXSEG选项设置/获取，
	// 有效值在8至32767之间。
	u16	user_mss;	/* mss requested by user in ioctl	*/
	// 该连接的对端MSS上限。user_mss与建立连接时SYN段中的MSS，两者之间的最小值作为该连接的MSS上限
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

static inline void tcp_clear_options(struct tcp_options_received *rx_opt)
{
	rx_opt->tstamp_ok = rx_opt->sack_ok = 0;
	rx_opt->wscale_ok = rx_opt->snd_wscale = 0;
#if IS_ENABLED(CONFIG_SMC)
	rx_opt->smc_ok = 0;
#endif
}

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock_ops;
// TCP连接请求块，用来保存双方的初始序号、双方的端口及IP地址、TCP选项，
// 如是否支持窗口扩大因子、是否支持SACK等，并控制连接的建立。
struct tcp_request_sock {
	// 最前部由inet_request_sock扩展而来
	struct inet_request_sock 	req;
	const struct tcp_request_sock_ops *af_specific;
	u64				snt_synack; /* first SYNACK sent time */
	// 是否为快速打开listener
	bool				tfo_listener;
	bool				is_mptcp;
#if IS_ENABLED(CONFIG_MPTCP)
	bool				drop_req;
#endif
	u32				txhash;
	// 客户端的初始序号，接收到客户端连接请求SYN段的序号
	u32				rcv_isn;
	// 服务端的初始序号，服务端发送SYN+ACK段的序号。
	u32				snt_isn;
	u32				ts_off;
	u32				last_oow_ack_time; /* last SYNACK */
	u32				rcv_nxt; /* the ack # by SYNACK. For
						  * FastOpen it's the seq#
						  * after data-in-SYN.
						  */
	u8				syn_tos;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	// tcp_sock结构最前面的部分为inet_connection_sock结构
	struct inet_connection_sock	inet_conn;
	// TCP首部长度，包括TCP选项
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	// 每个GSO数据包的最大分段数
	u16	gso_segs;	/* Max number of segs per GSO packet	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	// 首部预测标志，会在发送和接收SYN，更新窗口或其他恰当的时候，设置该标志。该标志和
	// 时间戳以及序列号等因素一样是判断执行快速路径还是慢速路径的条件之一。
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
	u64	bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	u32	segs_in;	/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	u32	data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
	// 等待接收的下一个TCP段的序号，每接收到一个TCP段之后就会更新该值。
 	u32	rcv_nxt;	/* What we want to receive next 	*/
	// 尚未从内核空间复制到用户空间的段最前面一个字节的序号。
	u32	copied_seq;	/* Head of yet unread data		*/
	// 标志最早接收但未确认的段的序号，即当前接收窗口的左端，在发送ACK时，由rcv_nxt更新,
	// 因此rcv_wup的更新常比rcv_nxt滞后一些。
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	// 等待发送的下一个TCP段的序号。
 	u32	snd_nxt;	/* Next sequence we send		*/
	u32	segs_out;	/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	u32	data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	u64	bytes_sent;	/* RFC4898 tcpEStatsPerfHCDataOctetsOut
				 * total number of data bytes sent.
				 */
	// 启用tcp_abc之后，在拥塞回避阶段，保存已确认的字节数。
	u64	bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	u32	dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups
				 * total number of DSACK blocks received
				 */
	// 在输出的段中，最早一个未确认的序号
 	u32	snd_una;	/* First byte we want an ack for	*/
	// 最近发送的小包（小于MSS的段）的最后一个字节序号，在成功发送段后，如果报文小于MSS，
	// 即更新该字段，主要用来判断是否启用Nagle算法
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	// 最近一次收到ACK段的时间，用于TCP保活
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	// 最近一次发送数据包的时间，主要用于拥塞窗口的设置。
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */
	u32	compressed_ack_rcv_nxt;

	u32	tsoffset;	/* timestamp offset */

	struct list_head tsq_node; /* anchor in tsq_tasklet.head list */
	struct list_head tsorted_sent_queue; /* time-sorted sent but un-SACKed skbs */
	// 记录更新发送窗口的那个ACK段的序号，用来判断是否需要更新窗口，如果后续收到ACK段的序号大于snd_wl1，
	// 则说明需要更新窗口，否则无需更新。
	u32	snd_wl1;	/* Sequence for window update		*/
	// 接收方的接收窗口大小，即发送方发送窗口大小
	u32	snd_wnd;	/* The window we expect to receive	*/
	// 接收方通过的最大接收窗口值
	u32	max_window;	/* Maximal window ever seen from peer	*/
	// 发送方当前有效MSS，参见SOL_TCP选项
	u32	mss_cache;	/* Cached effective mss, not including SACKS */
	// 滑动窗口最大值，滑动窗口大小在变化过程中始终不能超出该值。在TCP建立连接时，该字段被初始化，
	// 置为最大的16位整数左移窗口的扩大因子的位数，因为滑动窗口在TCP首部中以16位表示，window_clamp
	// 太大会导致滑动窗口不能在TCP首部中表示。
	u32	window_clamp;	/* Maximal window to advertise		*/
	// 当前接收窗口大小的阈值。该字段与rcv_wnd两者配合，达到滑动窗口大小缓慢增长的效果：
	// 其初始值为rcv_wnd，当本地套接口收到段，并满足一定条件时，会递增该字段值；到下一次发送
	// 数据组建TCP首部时，需通告对端当前接收窗口大小，此时更新rcv_wnd，而rcv_wnd的
	// 取代不能超过rcv_ssthresh的值
	u32	rcv_ssthresh;	/* Current window clamp			*/

	/* Information of the most recently (s)acked skb */
	struct tcp_rack {
		u64 mstamp; /* (Re)sent time of the skb */
		u32 rtt_us;  /* Associated RTT */
		u32 end_seq; /* Ending TCP sequence of the skb */
		u32 last_delivered; /* tp->delivered at last reo_wnd adj */
		u8 reo_wnd_steps;   /* Allowed reordering window */
#define TCP_RACK_RECOVERY_THRESH 16
		u8 reo_wnd_persist:5, /* No. of recovery since last adj */
		   dsack_seen:1, /* Whether DSACK seen after last adj */
		   advanced:1;	 /* mstamp advanced since last lost marking */
	} rack;
	// 本段能接收的MSS上限，在建立连接时用来通告对端。此值由路由缓存项中MSS度量值（RTAX_ADVMSS）
	// 进行初始化，而路由缓存项中MSS度量值则直接取自网络设备接口的MTU减去IP首部及TCP首部的长度。
	// 参见rt_set_nexthop()
	u16	advmss;		/* Advertised MSS			*/
	u8	compressed_ack;
	u8	dup_ack_counter:2,
		tlp_retrans:1,	/* TLP is a retransmission */
		unused:5;
	u32	chrono_start;	/* Start time in jiffies of a TCP chrono */
	u32	chrono_stat[3];	/* Time in jiffies for chrono_stat stats */
	u8	chrono_type:2,	/* current chronograph type */
		rate_app_limited:1,  /* rate_{delivered,interval_us} limited? */
		fastopen_connect:1, /* FASTOPEN_CONNECT sockopt */
		fastopen_no_cookie:1, /* Allow send/recv SYN+data without a cookie */
		is_sack_reneg:1,    /* in recovery from loss with SACK reneg? */
		fastopen_client_fail:2; /* reason why fastopen failed */
	// 标识是否允许Nagle算法，Nagle算法把较小的段组装成更大的段，主要用于解决由于大量
	// 的小包导致的网络发送拥塞的问题。参见TCP_NODELAY选项和TCP_CORK选项
	u8	nonagle     : 4,/* Disable Nagle algorithm?             */
		thin_lto    : 1,/* Use linear timeouts for thin streams */
		recvmsg_inq : 1,/* Indicate # of bytes in queue upon recvmsg */
		repair      : 1,
		frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
	u8	repair_queue;
	u8	save_syn:2,	/* Save headers of SYN packet */
		syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
		is_cwnd_limited:1;/* forward progress limited by snd_cwnd? */
	u32	tlp_high_seq;	/* snd_nxt at the time of TLP */

	u32	tcp_tx_delay;	/* delay (in usec) added to TX packets */
	u64	tcp_wstamp_ns;	/* departure time for next sent data packet */
	u64	tcp_clock_cache; /* cache last tcp_clock_ns() (see tcp_mstamp_refresh()) */

/* RTT measurement */
	u64	tcp_mstamp;	/* most recent packet received/sent */
	// 平滑的RTT，为避免浮点运算，是将其放大8倍后存储的。用微秒表示
	u32	srtt_us;	/* smoothed round trip time << 3 in usecs */
	// RTT平均偏差，由RTT与RTT均值偏差绝对值加权平均而得到的，其值越大说明RTT抖动得越厉害
	u32	mdev_us;	/* medium deviation			*/
	// 跟踪每次发送窗口的段被全部确认过程中，RTT平均偏差的最大值，描述RTT抖动得最大范围。
	u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/
	// 平滑的RTT平均偏差，由mdev计算得到，用于计算RTO。
	u32	rttvar_us;	/* smoothed mdev_max			*/
	// 记录SND.UNA，用来在计算RTO时比较SND.UNA是否已经被更新了，如果被SND.UNA更新，
	// 则需要同时更新rttvar。
	u32	rtt_seq;	/* sequence number to update rttvar	*/
	struct  minmax rtt_min;
	// 从发送队列发出而未得到确认TCP段的数目（即SND.NXT-SND.UNA）,该值是动态的，
	// 当有新的段发出或者新的确认收到都会增加或减少该值。
	u32	packets_out;	/* Packets which are "in flight"	*/
	// 重传还未得到确认的TCP段数目
	u32	retrans_out;	/* Retransmitted packets out		*/
	u32	max_packets_out;  /* max packets_out in last window */
	u32	max_packets_seq;  /* right edge of max_packets_out flight */
	// 低8位用于存放接收到的紧急数据。
	// 高8位用于标识紧急数据相关的状态
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	// 显式拥塞通知状态位
	u8	ecn_flags;	/* ECN status bits.			*/
	// 保活探测次数，最大值为127，参见TCP_KEEPCNT选项
	u8	keepalive_probes; /* num of allowed keep alive probes	*/
	// 在不支持SACK时，为由于连接接收到重复确认而进入快速恢复阶段的重复确认数阈值。
	// 在支持SACK时，在没有确定丢失包的情况下，是TCP流中可以重排序的数据段数。
	// 由相关路由缓存项中的reordering度量值或者系统参数tcp_reordering进行初始化，
	// 更新时会同时更新到目的路由缓存的reordering度量值中。
	u32	reordering;	/* Packet reordering metric.		*/
	u32	reord_seen;	/* number of data packet reordering events */
	// 紧急数据指针，即带外数据的序号，用来计算TCP首部中的“紧急指针”
	u32	snd_up;		/* Urgent pointer		*/

/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	// 存储接收到的TCP选项
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
	// 拥塞控制时慢启动的阈值
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
	// 当前拥塞窗口大小
 	u32	snd_cwnd;	/* Sending congestion window		*/
	// 自从上次调整拥塞窗口到目前为止接收到的总ACK段数。如果该字段为0，则说明已经调整了
	// 拥塞窗口，到目前为止还没有接收到ACK段。调整拥塞窗口以后，每接收到一个ACK段就
	// 会使snd_cwnd_cnt加1.
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	// 允许的最大拥塞窗口值。初始值为65535，之后在接收SYN和ACK段时，会根据条件确定
	// 是否从路由配置项读取信息更新该字段，最后在TCP链接复位前，将更新后的值根据某种
	// 算法计算后再更新回相对应的路由配置项中，便于连接使用。
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	// 记录最近一次检验拥塞窗口的时间。在拥塞期间，接收到ACK后会进行拥塞窗口的检验。
	// 而在非拥塞期间，为了防止由于应用程序限制而造成拥塞窗口失效，因此在成功发送段
	// 后，如果有必要也会检验拥塞窗口。
	u32	snd_cwnd_used;
	// 记录最近一次检验拥塞窗口的时间。在拥塞期间，接收到ACK后会进行拥塞窗口的检验。
	// 而在非拥塞期间，为了防止由于应用程序限制而造成拥塞窗口失效，因此在成功发送段
	// 后，如果有必要也会检验拥塞窗口。
	u32	snd_cwnd_stamp;
	u32	prior_cwnd;	/* cwnd right before starting loss recovery */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */
	u32	delivered;	/* Total data packets delivered incl. rexmits */
	u32	delivered_ce;	/* Like the above but only ECE marked packets */
	u32	lost;		/* Total data packets lost incl. rexmits */
	u32	app_limited;	/* limited until "delivered" reaches this val */
	u64	first_tx_mstamp;  /* start of window send phase */
	u64	delivered_mstamp; /* time we reached "delivered" */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */

	// 当前接收窗口的大小
 	u32	rcv_wnd;	/* Current receiver window		*/
	// 已加入到发送队列中的最后一个字节序号。
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
	// 通常情况下表示已经真正发送出去的最后一个字节序号；但有时也可能表示期望发送出去
	// 的最后一个字节序号，如启用Nagle算法之后，或在发送持续探测段后。
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	// 发送后丢失在传输过程中段的数量。目前TCP协议还没有类似“段丢失通知”机制，
	// 因此丢失的段数量只能通过某种算法进行推测，如，当RTO超时之后，
	// 可以认为发送的段丢失,即：
	// lost_out = packets_out
	// in_flight = retrans_out
	u32	lost_out;	/* Lost packets			*/
	// 启用SACK时，通过SACK的TCP选项标识已接收到段的数量。不启用SACK时，标识
	// 接收到重复确认的次数。此值在接收到确认新数据的段时被清除。
	u32	sacked_out;	/* SACK'd packets			*/

	struct hrtimer	pacing_timer;
	struct hrtimer	compressed_ack_timer;

	/* from STCP, retrans queue hinting */
	// 
	struct sk_buff* lost_skb_hint;
	// 用于记录当前重传的位置，retransmit_skb_hint位置之前的段经过了重传，
	// 当认为重传的段已经丢失，则将其设置为NULL，这样重传又从sk_write_queue开始，
	// 即使该段并未真正丢失。重新排序也正是这个意思，这与系统参数tcp_reordering也有着密切关系。
	struct sk_buff *retransmit_skb_hint;

	/* OOO segments go in this rbtree. Socket lock must be held. */
	// 乱序缓存队列，用来暂存接收到的乱序的TCP段
	struct rb_root	out_of_order_queue;
	struct sk_buff	*ooo_last_skb; /* cache rb_last(out_of_order_queue) */

	/* SACKs data, these 2 need to be together (see tcp_options_write) */
	// 存储用于回复对端SACK的信息，duplicate_sack存储D-SACK信息，selective_acks存储SACK信息，在回复
	// SACK时会从中取出D-SACK和SACK信息，而在处理接收到乱序的段时，会向这两个字段中填入相应的信息。
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/
	// 存储接收到的SACK选项信息
	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* skb just after the highest
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */
	// 一般在拥塞状态没有撤销或没有进入Loss状态时，在重传队列中，缓存上一次标记记分牌未丢失的最后一个段,
	// 主要为了加速对重传队列的标记操作。
	int     lost_cnt_hint;
	// 在启用FRTO算法的情况下，路径MTU探测成功，进入拥塞控制Disorder,Recovery、Loss状态时
	// 保存的ssthresh值。主要用来在拥塞窗口撤销时，恢复拥塞控制的慢启动阈值。当prior_sshthresh
	// 被设置为0时，表示禁止拥塞窗口的撤销。
	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	// 记录发送拥塞时的SND.NXT,标识重传队列的尾部。
	u32	high_seq;	/* snd_nxt at onset of congestion	*/
	// 在主动连接时，记录第一个SYN段的发送时间，用来检测ACK序号是否回绕。
	// 在数据传输阶段，当发送超时重传时，记录上次重传阶段第一个重传段的发送时间，
	// 用来判断是否可以进行拥塞撤销。
	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	// 在使用F-RTO算法进行发送超时处理，或进入Recovery进行重传，或进入Loss开始
	// 慢启动时，记录当时SND.UNA，标记重传起始点。它是检测是否可以进入拥塞撤销的
	// 条件之一，一般在完成拥塞撤销操作或进入拥塞控制Loss状态后清零。
	u32	undo_marker;	/* snd_una upon a new recovery episode. */
	// 在恢复拥塞控制之前可进行撤销的重传段数。在进入FRTO算法或拥塞状态Loss时清零，
	// 在重传时计数，是检测是否可以进行拥塞撤销的条件之一。
	int	undo_retrans;	/* number of undoable retransmissions. */
	// 
	u64	bytes_retrans;	/* RFC4898 tcpEStatsPerfOctetsRetrans
				 * Total data bytes retransmitted
				 */
	// 在整个连接中总重传次数
	u32	total_retrans;	/* Total retransmits for entire connection */
	// 紧急数据的序号，由所在段的序号和紧急指针相加而得到。
	u32	urg_seq;	/* Seq of received urgent pointer */
	// TCP发送保活探测前，TCP连接的空闲时间，即保护定时器启动的时间阈值。在启用SO_KEEPALIVE选项的情况下，
	// 一个连接空闲了一段时间之后，TCP会发送保活探测到对端系统，如果对端系统没有对保活探测进行回应，TCP会
	// 重复发送保活探测，直到连续发送而没有得到回应的保活探测达到一定数量，才认为这个连接已经无效。参见TCP_KEEPIDLE选项。
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	// 发送保活探测的时间间隔，参见TCP_KEEPINTVAL选项。
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	// 标识TCP迁移到关闭CLOSED状态之前保持在FIN_WAIT_2状态的时间。参见TCP_LINGER2选项
	int			linger2;


/* Sock_ops bpf program related variables */
#ifdef CONFIG_BPF
	u8	bpf_sock_ops_cb_flags;  /* Control calling BPF programs
					 * values defined in uapi/linux/tcp.h
					 */
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) (TP->bpf_sock_ops_cb_flags & ARG)
#else
#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) 0
#endif

	u16 timeout_rehash;	/* Timeout-triggered rehash attempts */

	u32 rcv_ooopack; /* Received out-of-order packets, for tcpinfo */

/* Receiver side RTT estimation */
	u32 rcv_rtt_last_tsecr;
	// 存储接收方的RTT估算值，用于实现通过调节接收窗口来进行流量控制的功能。接收方RTT估算值用来限制调整TCP接收缓冲区空间的频率，
	// 每次调整TCP接收缓冲区空间的间隔时间不能小于RTT。	
	struct {
		// 存放接收方估算的RTT，计算方法因接收到的段中是否有时间戳选项而不同。
		u32	rtt_us;
		// 在接收到的段没有时间戳的情况下，更新接收方RTT时的接收窗口右端序号，没完成一个接收窗口的接收更新一次接收方RTT。
		u32	seq;
		// 在接收到的段没有时间戳的情况下，记录每次更新接收方RTT的时间，用来计算接收方的RTT。
		u64	time;
	} rcv_rtt_est;

/* Receiver queue space */
// 用来调整TCP接收缓存空间和接收窗口大小，也用于实现通过调节接收窗口来进行流量控制的功能。
// 每次将数据复制到用户空间，都会调用tcp_rcv_space_adjust来计算新的TCP接收缓冲空间大小。
	struct {
		// 用于调整接收缓存的大小
		u32	space;
		// 已复制到用户空间的TCP段序号
		u32	seq;
		// 记录最近一次进行调整的时间
		u64	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
// 存储已发送MTU发现段的起始序号和结束序号，与发送MTU发现段的SKB中
// tcp_skb_cb结构的seq和end_seq字段相对应，用来判断路径MTU发现是否成功。
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;
	u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG
			   * while socket was owned by user.
			   */
#if IS_ENABLED(CONFIG_MPTCP)
	bool	is_mptcp;
#endif
#if IS_ENABLED(CONFIG_SMC)
	bool	(*smc_hs_congested)(const struct sock *sk);
	bool	syn_smc;	/* SYN includes SMC */
#endif

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif

/* TCP fastopen related information */
	struct tcp_fastopen_request *fastopen_req;
	/* fastopen_rsk points to request_sock that resulted in this big
	 * socket. Used to retransmit SYNACKs etc.
	 */
	struct request_sock __rcu *fastopen_rsk;
	struct saved_syn *saved_syn;
};

enum tsq_enum {
	TSQ_THROTTLED,
	TSQ_QUEUED,
	TCP_TSQ_DEFERRED,	   /* tcp_tasklet_func() found socket was owned */
	TCP_WRITE_TIMER_DEFERRED,  /* tcp_write_timer() found socket was owned */
	TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
	TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
				    * tcp_v{4|6}_mtu_reduced()
				    */
};

enum tsq_flags {
	TSQF_THROTTLED			= (1UL << TSQ_THROTTLED),
	TSQF_QUEUED			= (1UL << TSQ_QUEUED),
	TCPF_TSQ_DEFERRED		= (1UL << TCP_TSQ_DEFERRED),
	TCPF_WRITE_TIMER_DEFERRED	= (1UL << TCP_WRITE_TIMER_DEFERRED),
	TCPF_DELACK_TIMER_DEFERRED	= (1UL << TCP_DELACK_TIMER_DEFERRED),
	TCPF_MTU_REDUCED_DEFERRED	= (1UL << TCP_MTU_REDUCED_DEFERRED),
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
#define tw_rcv_nxt tw_sk.__tw_common.skc_tw_rcv_nxt
#define tw_snd_nxt tw_sk.__tw_common.skc_tw_snd_nxt
	u32			  tw_rcv_wnd;
	u32			  tw_ts_offset;
	u32			  tw_ts_recent;

	/* The time we sent the last out-of-window ACK: */
	u32			  tw_last_oow_ack_time;

	int			  tw_ts_recent_stamp;
	u32			  tw_tx_delay;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key	  *tw_md5_key;
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

static inline bool tcp_passive_fastopen(const struct sock *sk)
{
	return sk->sk_state == TCP_SYN_RECV &&
	       rcu_access_pointer(tcp_sk(sk)->fastopen_rsk) != NULL;
}

static inline void fastopen_queue_tune(struct sock *sk, int backlog)
{
	struct request_sock_queue *queue = &inet_csk(sk)->icsk_accept_queue;
	int somaxconn = READ_ONCE(sock_net(sk)->core.sysctl_somaxconn);

	queue->fastopenq.max_qlen = min_t(unsigned int, backlog, somaxconn);
}

static inline void tcp_move_syn(struct tcp_sock *tp,
				struct request_sock *req)
{
	tp->saved_syn = req->saved_syn;
	req->saved_syn = NULL;
}

static inline void tcp_saved_syn_free(struct tcp_sock *tp)
{
	kfree(tp->saved_syn);
	tp->saved_syn = NULL;
}

static inline u32 tcp_saved_syn_len(const struct saved_syn *saved_syn)
{
	return saved_syn->mac_hdrlen + saved_syn->network_hdrlen +
		saved_syn->tcp_hdrlen;
}

struct sk_buff *tcp_get_timestamping_opt_stats(const struct sock *sk,
					       const struct sk_buff *orig_skb,
					       const struct sk_buff *ack_skb);

static inline u16 tcp_mss_clamp(const struct tcp_sock *tp, u16 mss)
{
	/* We use READ_ONCE() here because socket might not be locked.
	 * This happens for listeners.
	 */
	u16 user_mss = READ_ONCE(tp->rx_opt.user_mss);

	return (user_mss && user_mss < mss) ? user_mss : mss;
}

int tcp_skb_shift(struct sk_buff *to, struct sk_buff *from, int pcount,
		  int shiftlen);

void __tcp_sock_set_cork(struct sock *sk, bool on);
void tcp_sock_set_cork(struct sock *sk, bool on);
int tcp_sock_set_keepcnt(struct sock *sk, int val);
int tcp_sock_set_keepidle_locked(struct sock *sk, int val);
int tcp_sock_set_keepidle(struct sock *sk, int val);
int tcp_sock_set_keepintvl(struct sock *sk, int val);
void __tcp_sock_set_nodelay(struct sock *sk, bool on);
void tcp_sock_set_nodelay(struct sock *sk);
void tcp_sock_set_quickack(struct sock *sk, int val);
int tcp_sock_set_syncnt(struct sock *sk, int val);
void tcp_sock_set_user_timeout(struct sock *sk, u32 val);

#endif	/* _LINUX_TCP_H */
