// SPDX-License-Identifier: GPL-2.0-only
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/static_key.h>

#include <trace/events/tcp.h>

/* Refresh clocks of a TCP socket,
 * ensuring monotically increasing values.
 */
// 刷新TCP套接字的时钟，确保值单调递增。
void tcp_mstamp_refresh(struct tcp_sock *tp)
{
	u64 val = tcp_clock_ns();

	tp->tcp_clock_cache = val;
	tp->tcp_mstamp = div_u64(val, NSEC_PER_USEC);
}

static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp);

/* Account for new data that has been sent to the network. */
static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

	WRITE_ONCE(tp->snd_nxt, TCP_SKB_CB(skb)->end_seq);

	__skb_unlink(skb, &sk->sk_write_queue);
	tcp_rbtree_insert(&sk->tcp_rtx_queue, skb);

	if (tp->highest_sack == NULL)
		tp->highest_sack = skb;

	tp->packets_out += tcp_skb_pcount(skb);
	if (!prior_packets || icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)
		tcp_rearm_rto(sk);

	NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT,
		      tcp_skb_pcount(skb));
	tcp_check_space(sk);
}

/* SND.NXT, if window was not shrunk or the amount of shrunk was less than one
 * window scaling factor due to loss of precision.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (!before(tcp_wnd_end(tp), tp->snd_nxt) ||
	    (tp->rx_opt.wscale_ok &&
	     ((tp->snd_nxt - tcp_wnd_end(tp)) < (1 << tp->rx_opt.rcv_wscale))))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst) {
		unsigned int metric = dst_metric_advmss(dst);

		if (metric < mss) {
			mss = metric;
			tp->advmss = mss;
		}
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism.
 */
void tcp_cwnd_restart(struct sock *sk, s32 delta)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 restart_cwnd = tcp_init_cwnd(tp, __sk_dst_get(sk));
	u32 cwnd = tcp_snd_cwnd(tp);

	tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	tp->snd_ssthresh = tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tcp_snd_cwnd_set(tp, max(cwnd, restart_cwnd));
	tp->snd_cwnd_stamp = tcp_jiffies32;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void tcp_event_data_sent(struct tcp_sock *tp,
				struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_jiffies32;

	if (tcp_packets_in_flight(tp) == 0)
		tcp_ca_event(sk, CA_EVENT_TX_START);

	/* If this is the first data packet sent in response to the
	 * previous received data,
	 * and it is a reply for ato after last received packet,
	 * increase pingpong count.
	 */
	if (before(tp->lsndtime, icsk->icsk_ack.lrcvtime) &&
	    (u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		inet_csk_inc_pingpong_cnt(sk);

	tp->lsndtime = now;
}

/* Account for an ACK we sent. */
static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts,
				      u32 rcv_nxt)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(tp->compressed_ack)) {
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPACKCOMPRESSED,
			      tp->compressed_ack);
		tp->compressed_ack = 0;
		if (hrtimer_try_to_cancel(&tp->compressed_ack_timer) == 1)
			__sock_put(sk);
	}

	if (unlikely(rcv_nxt != tp->rcv_nxt))
		return;  /* Special ACK sent by DCTCP to reflect ECN */
	tcp_dec_quickack_mode(sk, pkts);
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(const struct sock *sk, int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale,
			       __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (U16_MAX << TCP_MAX_WSCALE);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = rounddown(space, mss);

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = min_t(u32, space, U16_MAX);

	if (init_rcv_wnd)
		*rcv_wnd = min(*rcv_wnd, init_rcv_wnd * mss);

	*rcv_wscale = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window */
		space = max_t(u32, space, sock_net(sk)->ipv4.sysctl_tcp_rmem[2]);
		space = max_t(u32, space, sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		*rcv_wscale = clamp_t(int, ilog2(space) - 15,
				      0, TCP_MAX_WSCALE);
	}
	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min_t(__u32, U16_MAX << (*rcv_wscale), *window_clamp);
}
EXPORT_SYMBOL(tcp_select_initial_window);

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 old_win = tp->rcv_wnd;
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		if (new_win == 0)
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPWANTZEROWINDOWADV);
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale &&
	    sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0) {
		tp->pred_flags = 0;
		if (old_win)
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPTOZEROWINDOWADV);
	} else if (old_win == 0) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFROMZEROWINDOWADV);
	}

	return new_win;
}

/* Packet ECN state for a SYN-ACK */
static void tcp_ecn_send_synack(struct sock *sk, struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_ECE;
	else if (tcp_ca_needs_ecn(sk) ||
		 tcp_bpf_ca_needs_ecn(sk))
		INET_ECN_xmit(sk);
}

/* Packet ECN state for a SYN.  */
static void tcp_ecn_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool bpf_needs_ecn = tcp_bpf_ca_needs_ecn(sk);
	bool use_ecn = sock_net(sk)->ipv4.sysctl_tcp_ecn == 1 ||
		tcp_ca_needs_ecn(sk) || bpf_needs_ecn;

	if (!use_ecn) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_feature(dst, RTAX_FEATURE_ECN))
			use_ecn = true;
	}

	tp->ecn_flags = 0;

	if (use_ecn) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ECE | TCPHDR_CWR;
		tp->ecn_flags = TCP_ECN_OK;
		if (tcp_ca_needs_ecn(sk) || bpf_needs_ecn)
			INET_ECN_xmit(sk);
	}
}

static void tcp_ecn_clear_syn(struct sock *sk, struct sk_buff *skb)
{
	if (sock_net(sk)->ipv4.sysctl_tcp_ecn_fallback)
		/* tp->ecn_flags are cleared at a later point in time when
		 * SYN ACK is ultimatively being received.
		 */
		TCP_SKB_CB(skb)->tcp_flags &= ~(TCPHDR_ECE | TCPHDR_CWR);
}

static void
tcp_ecn_make_synack(const struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
static void tcp_ecn_send(struct sock *sk, struct sk_buff *skb,
			 struct tcphdr *th, int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				th->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else if (!tcp_ca_needs_ecn(sk)) {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			th->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;

	TCP_SKB_CB(skb)->tcp_flags = flags;

	tcp_skb_pcount_set(skb, 1);

	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

static inline bool tcp_urg_mode(const struct tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

#define OPTION_SACK_ADVERTISE	BIT(0)
#define OPTION_TS		BIT(1)
#define OPTION_MD5		BIT(2)
#define OPTION_WSCALE		BIT(3)
#define OPTION_FAST_OPEN_COOKIE	BIT(8)
#define OPTION_SMC		BIT(9)
#define OPTION_MPTCP		BIT(10)

static void smc_options_write(__be32 *ptr, u16 *options)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (unlikely(OPTION_SMC & *options)) {
			*ptr++ = htonl((TCPOPT_NOP  << 24) |
				       (TCPOPT_NOP  << 16) |
				       (TCPOPT_EXP <<  8) |
				       (TCPOLEN_EXP_SMC_BASE));
			*ptr++ = htonl(TCPOPT_SMC_MAGIC);
		}
	}
#endif
}

struct tcp_out_options {
	u16 options;		/* bit field of OPTION_* */
	u16 mss;		/* 0 to disable */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	u8 bpf_opt_len;		/* length of BPF hdr option */
	__u8 *hash_location;	/* temporary pointer, overloaded */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	struct tcp_fastopen_cookie *fastopen_cookie;	/* Fast open cookie */
	struct mptcp_out_options mptcp;
};

static void mptcp_options_write(struct tcphdr *th, __be32 *ptr,
				struct tcp_sock *tp,
				struct tcp_out_options *opts)
{
#if IS_ENABLED(CONFIG_MPTCP)
	if (unlikely(OPTION_MPTCP & opts->options))
		mptcp_write_options(th, ptr, tp, &opts->mptcp);
#endif
}

#ifdef CONFIG_CGROUP_BPF
static int bpf_skops_write_hdr_opt_arg0(struct sk_buff *skb,
					enum tcp_synack_type synack_type)
{
	if (unlikely(!skb))
		return BPF_WRITE_HDR_TCP_CURRENT_MSS;

	if (unlikely(synack_type == TCP_SYNACK_COOKIE))
		return BPF_WRITE_HDR_TCP_SYNACK_COOKIE;

	return 0;
}

/* req, syn_skb and synack_type are used when writing synack */
static void bpf_skops_hdr_opt_len(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct sk_buff *syn_skb,
				  enum tcp_synack_type synack_type,
				  struct tcp_out_options *opts,
				  unsigned int *remaining)
{
	struct bpf_sock_ops_kern sock_ops;
	int err;

	if (likely(!BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk),
					   BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG)) ||
	    !*remaining)
		return;

	/* *remaining has already been aligned to 4 bytes, so *remaining >= 4 */

	/* init sock_ops */
	memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));

	sock_ops.op = BPF_SOCK_OPS_HDR_OPT_LEN_CB;

	if (req) {
		/* The listen "sk" cannot be passed here because
		 * it is not locked.  It would not make too much
		 * sense to do bpf_setsockopt(listen_sk) based
		 * on individual connection request also.
		 *
		 * Thus, "req" is passed here and the cgroup-bpf-progs
		 * of the listen "sk" will be run.
		 *
		 * "req" is also used here for fastopen even the "sk" here is
		 * a fullsock "child" sk.  It is to keep the behavior
		 * consistent between fastopen and non-fastopen on
		 * the bpf programming side.
		 */
		sock_ops.sk = (struct sock *)req;
		sock_ops.syn_skb = syn_skb;
	} else {
		sock_owned_by_me(sk);

		sock_ops.is_fullsock = 1;
		sock_ops.sk = sk;
	}

	sock_ops.args[0] = bpf_skops_write_hdr_opt_arg0(skb, synack_type);
	sock_ops.remaining_opt_len = *remaining;
	/* tcp_current_mss() does not pass a skb */
	if (skb)
		bpf_skops_init_skb(&sock_ops, skb, 0);

	err = BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(&sock_ops, sk);

	if (err || sock_ops.remaining_opt_len == *remaining)
		return;

	opts->bpf_opt_len = *remaining - sock_ops.remaining_opt_len;
	/* round up to 4 bytes */
	opts->bpf_opt_len = (opts->bpf_opt_len + 3) & ~3;

	*remaining -= opts->bpf_opt_len;
}

static void bpf_skops_write_hdr_opt(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req,
				    struct sk_buff *syn_skb,
				    enum tcp_synack_type synack_type,
				    struct tcp_out_options *opts)
{
	u8 first_opt_off, nr_written, max_opt_len = opts->bpf_opt_len;
	struct bpf_sock_ops_kern sock_ops;
	int err;

	if (likely(!max_opt_len))
		return;

	memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));

	sock_ops.op = BPF_SOCK_OPS_WRITE_HDR_OPT_CB;

	if (req) {
		sock_ops.sk = (struct sock *)req;
		sock_ops.syn_skb = syn_skb;
	} else {
		sock_owned_by_me(sk);

		sock_ops.is_fullsock = 1;
		sock_ops.sk = sk;
	}

	sock_ops.args[0] = bpf_skops_write_hdr_opt_arg0(skb, synack_type);
	sock_ops.remaining_opt_len = max_opt_len;
	first_opt_off = tcp_hdrlen(skb) - max_opt_len;
	bpf_skops_init_skb(&sock_ops, skb, first_opt_off);

	err = BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(&sock_ops, sk);

	if (err)
		nr_written = 0;
	else
		nr_written = max_opt_len - sock_ops.remaining_opt_len;

	if (nr_written < max_opt_len)
		memset(skb->data + first_opt_off + nr_written, TCPOPT_NOP,
		       max_opt_len - nr_written);
}
#else
static void bpf_skops_hdr_opt_len(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct sk_buff *syn_skb,
				  enum tcp_synack_type synack_type,
				  struct tcp_out_options *opts,
				  unsigned int *remaining)
{
}

static void bpf_skops_write_hdr_opt(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req,
				    struct sk_buff *syn_skb,
				    enum tcp_synack_type synack_type,
				    struct tcp_out_options *opts)
{
}
#endif

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operability perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void tcp_options_write(struct tcphdr *th, struct tcp_sock *tp,
			      struct tcp_out_options *opts)
{
	__be32 *ptr = (__be32 *)(th + 1);
	u16 options = opts->options;	/* mungable copy */

	// 与通过TCP MD5签名来保护BGP会话操作有关
	if (unlikely(OPTION_MD5 & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		/* overload cookie hash location */
		opts->hash_location = (__u8 *)ptr;
		ptr += 4;
	}

	// 组成MSS选项，在建立一个TCP连接的时候，连接双方都需通告对方各自的MSS，
	// 因此SYN或SYN+ACK段中通常总会有MSS选项，如果没有则默认为536B。
	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}

	// 如果启用TCP时间戳，则能把时间戳选项加入到TCP选项中，
	if (likely(OPTION_TS & options)) {
		// 如果启用了SACK，则把SACK允许选项加入到TCP选项中。
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			// 如果允许了时间戳选项但不允许SACK选项
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		// 继续填充时间戳值和时间戳回显应答
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}

	// 如果不允许时间戳选项但允许SACK
	if (unlikely(OPTION_SACK_ADVERTISE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	}
	// 如果允许窗口缩放，填充窗口扩大因子选项
	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}
	// SACK(Selective ACK)是TCP选项，它使得接收方能告诉发送方哪些报文段丢失，哪些报文段重传了，
	// 哪些报文段已经提前收到等信息。根据这些信息TCP就可以只重传哪些真正丢失的报文段。
	// 需要注意的是只有收到失序的分组时才会可能会发送SACK，TCP的ACK还是建立在累积确认的基础上的。
	// 也就是说如果收到的报文段与期望收到的报文段的序号相同就会发送累积的ACK，
	// SACK只是针对失序到达的报文段的。SACK包括了两个TCP选项，一个选项用于标识是否支持SACK，
	// 是在TCP连接建立时时发送；另一种选项则包含了具体的SACK信息。
	
	// num_sack_blocks是将要发送报文的SACK队列大小，即有多少个数据块左右边界值对。
	// 而TCPOLEN_SACK_PERBLOCK是每个数据块左右边界值对的大小，因此TCPOLEN_SACK_BASE + (opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK)
	// 是计算SACK选项的总长度。
	if (unlikely(opts->num_sack_blocks)) {
		// 如果有dsack，sp指向DSACK信息块，否则指向普通SACK信息块
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
			tp->duplicate_sack : tp->selective_acks;
		int this_sack;
		// 填充位、类型、长度
		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
						     TCPOLEN_SACK_PERBLOCK)));
		// 这里实际利用了struct tcp_sock中duplicate_sack和selective_acks紧邻这一前提，
		// eff_sacks已经考虑了dsack和sack，所以当填充了dsack后，紧接着就可以填充sack。
		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}
		// dsack选项一旦发送之后就会被清除，如果再次收到重复段，才会重新生成。但是普通的SACK选项
		// 即使发送过了，也不会清除，所以下次发送只要没有清除就还会携带。
		tp->rx_opt.dsack = 0;
	}

	// 是否有fast open cookie的选项
	// TFO的核心是一个安全cookie，服务器使用这个cookie来给客户端鉴权。一般来说这个cookie应该能鉴权SYN包中的源IP地址，
	// 不包含端口（client每次的端口都可能不同），并且不能被第三方伪造。为了保证安全，过一段时间后，server应该expire之前的cookie，
	// 并重新生成cookie。cookie验证通过，server在发送SYN-ACK的时候，如果有待发送数据也同样可以携带数据。
	if (unlikely(OPTION_FAST_OPEN_COOKIE & options)) {
		struct tcp_fastopen_cookie *foc = opts->fastopen_cookie;
		u8 *p = (u8 *)ptr;
		u32 len; /* Fast Open option length */

		if (foc->exp) {
			len = TCPOLEN_EXP_FASTOPEN_BASE + foc->len;
			*ptr = htonl((TCPOPT_EXP << 24) | (len << 16) |
				     TCPOPT_FASTOPEN_MAGIC);
			p += TCPOLEN_EXP_FASTOPEN_BASE;
		} else {
			len = TCPOLEN_FASTOPEN_BASE + foc->len;
			*p++ = TCPOPT_FASTOPEN;
			*p++ = len;
		}

		memcpy(p, foc->val, foc->len);
		if ((len & 3) == 2) {
			p[foc->len] = TCPOPT_NOP;
			p[foc->len + 1] = TCPOPT_NOP;
		}
		ptr += (len + 3) >> 2;
	}

	// 处理SMC选项
	smc_options_write(ptr, &options);
	// 处理多路径Tcp选项
	mptcp_options_write(th, ptr, tp, opts);
}

static void smc_set_option(const struct tcp_sock *tp,
			   struct tcp_out_options *opts,
			   unsigned int *remaining)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc) {
			if (*remaining >= TCPOLEN_EXP_SMC_BASE_ALIGNED) {
				opts->options |= OPTION_SMC;
				*remaining -= TCPOLEN_EXP_SMC_BASE_ALIGNED;
			}
		}
	}
#endif
}

static void smc_set_option_cond(const struct tcp_sock *tp,
				const struct inet_request_sock *ireq,
				struct tcp_out_options *opts,
				unsigned int *remaining)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc && ireq->smc_ok) {
			if (*remaining >= TCPOLEN_EXP_SMC_BASE_ALIGNED) {
				opts->options |= OPTION_SMC;
				*remaining -= TCPOLEN_EXP_SMC_BASE_ALIGNED;
			}
		}
	}
#endif
}

static void mptcp_set_option_cond(const struct request_sock *req,
				  struct tcp_out_options *opts,
				  unsigned int *remaining)
{
	if (rsk_is_mptcp(req)) {
		unsigned int size;

		if (mptcp_synack_options(req, &size, &opts->mptcp)) {
			if (*remaining >= size) {
				opts->options |= OPTION_MPTCP;
				*remaining -= size;
			}
		}
	}
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned int tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				struct tcp_out_options *opts,
				struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;
	struct tcp_fastopen_request *fastopen = tp->fastopen_req;

	*md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed) &&
	    rcu_access_pointer(tp->md5sig_info)) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			remaining -= TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(sock_net(sk)->ipv4.sysctl_tcp_timestamps && !*md5)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tp->tsoffset;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}

	if (fastopen && fastopen->cookie.len >= 0) {
		u32 need = fastopen->cookie.len;

		need += fastopen->cookie.exp ? TCPOLEN_EXP_FASTOPEN_BASE :
					       TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = &fastopen->cookie;
			remaining -= need;
			tp->syn_fastopen = 1;
			tp->syn_fastopen_exp = fastopen->cookie.exp ? 1 : 0;
		}
	}

	smc_set_option(tp, opts, &remaining);

	if (sk_is_mptcp(sk)) {
		unsigned int size;

		if (mptcp_syn_options(sk, skb, &size, &opts->mptcp)) {
			opts->options |= OPTION_MPTCP;
			remaining -= size;
		}
	}

	bpf_skops_hdr_opt_len(sk, skb, NULL, NULL, 0, opts, &remaining);

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Set up TCP options for SYN-ACKs. */
// 为SYN-ACK建立TCP选项
static unsigned int tcp_synack_options(const struct sock *sk,
				       struct request_sock *req,
				       unsigned int mss, struct sk_buff *skb,
				       struct tcp_out_options *opts,
				       const struct tcp_md5sig_key *md5,
				       struct tcp_fastopen_cookie *foc,
				       enum tcp_synack_type synack_type,
				       struct sk_buff *syn_skb)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;

#ifdef CONFIG_TCP_MD5SIG
	if (md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;

		/* We can't fit any SACK blocks in a packet with MD5 + TS
		 * options. There was discussion about disabling SACK
		 * rather than TS in order to fit in better with old,
		 * buggy kernels, but that was deemed to be unnecessary.
		 */
		if (synack_type != TCP_SYNACK_COOKIE)
			ireq->tstamp_ok &= !ireq->sack_ok;
	}
#endif

	/* We always send an MSS option. */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(ireq->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tcp_rsk(req)->ts_off;
		opts->tsecr = req->ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!ireq->tstamp_ok))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
	if (foc != NULL && foc->len >= 0) {
		u32 need = foc->len;

		need += foc->exp ? TCPOLEN_EXP_FASTOPEN_BASE :
				   TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = foc;
			remaining -= need;
		}
	}

	mptcp_set_option_cond(req, opts, &remaining);

	smc_set_option_cond(tcp_sk(sk), ireq, opts, &remaining);

	bpf_skops_hdr_opt_len((struct sock *)sk, skb, req, syn_skb,
			      synack_type, opts, &remaining);

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
// 计算ESTABLISHED套接字的TCP选项。 这不是最终的格式。
static unsigned int tcp_established_options(struct sock *sk, struct sk_buff *skb,
					struct tcp_out_options *opts,
					struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int size = 0;
	unsigned int eff_sacks;

	opts->options = 0;

	*md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed) &&
	    rcu_access_pointer(tp->md5sig_info)) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			size += TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = skb ? tcp_skb_timestamp(skb) + tp->tsoffset : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}

	/* MPTCP options have precedence over SACK for the limited TCP
	 * option space because a MPTCP connection would be forced to
	 * fall back to regular TCP if a required multipath option is
	 * missing. SACK still gets a chance to use whatever space is
	 * left.
	 */
	if (sk_is_mptcp(sk)) {
		unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
		unsigned int opt_size = 0;

		if (mptcp_established_options(sk, skb, &opt_size, remaining,
					      &opts->mptcp)) {
			opts->options |= OPTION_MPTCP;
			size += opt_size;
		}
	}

	eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
	if (unlikely(eff_sacks)) {
		const unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
		if (unlikely(remaining < TCPOLEN_SACK_BASE_ALIGNED +
					 TCPOLEN_SACK_PERBLOCK))
			return size;

		opts->num_sack_blocks =
			min_t(unsigned int, eff_sacks,
			      (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
			      TCPOLEN_SACK_PERBLOCK);

		size += TCPOLEN_SACK_BASE_ALIGNED +
			opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
	}

	if (unlikely(BPF_SOCK_OPS_TEST_FLAG(tp,
					    BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG))) {
		unsigned int remaining = MAX_TCP_OPTION_SPACE - size;

		bpf_skops_hdr_opt_len(sk, skb, NULL, NULL, 0, opts, &remaining);

		size = MAX_TCP_OPTION_SPACE - remaining;
	}

	return size;
}


/* TCP SMALL QUEUES (TSQ)
 *
 * TSQ goal is to keep small amount of skbs per tcp flow in tx queues (qdisc+dev)
 * to reduce RTT and bufferbloat.
 * We do this using a special skb destructor (tcp_wfree).
 *
 * Its important tcp_wfree() can be replaced by sock_wfree() in the event skb
 * needs to be reallocated in a driver.
 * The invariant being skb->truesize subtracted from sk->sk_wmem_alloc
 *
 * Since transmit from skb destructor is forbidden, we use a tasklet
 * to process all sockets that eventually need to send more skbs.
 * We use one tasklet per cpu, with its own queue of sockets.
 */
struct tsq_tasklet {
	struct tasklet_struct	tasklet;
	struct list_head	head; /* queue of tcp sockets */
};
static DEFINE_PER_CPU(struct tsq_tasklet, tsq_tasklet);

static void tcp_tsq_write(struct sock *sk)
{
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_CLOSING |
	     TCPF_CLOSE_WAIT  | TCPF_LAST_ACK)) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (tp->lost_out > tp->retrans_out &&
		    tcp_snd_cwnd(tp) > tcp_packets_in_flight(tp)) {
			tcp_mstamp_refresh(tp);
			tcp_xmit_retransmit_queue(sk);
		}

		tcp_write_xmit(sk, tcp_current_mss(sk), tp->nonagle,
			       0, GFP_ATOMIC);
	}
}

static void tcp_tsq_handler(struct sock *sk)
{
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		tcp_tsq_write(sk);
	else if (!test_and_set_bit(TCP_TSQ_DEFERRED, &sk->sk_tsq_flags))
		sock_hold(sk);
	bh_unlock_sock(sk);
}
/*
 * One tasklet per cpu tries to send more skbs.
 * We run in tasklet context but need to disable irqs when
 * transferring tsq->head because tcp_wfree() might
 * interrupt us (non NAPI drivers)
 */
static void tcp_tasklet_func(struct tasklet_struct *t)
{
	struct tsq_tasklet *tsq = from_tasklet(tsq,  t, tasklet);
	LIST_HEAD(list);
	unsigned long flags;
	struct list_head *q, *n;
	struct tcp_sock *tp;
	struct sock *sk;

	local_irq_save(flags);
	list_splice_init(&tsq->head, &list);
	local_irq_restore(flags);

	list_for_each_safe(q, n, &list) {
		tp = list_entry(q, struct tcp_sock, tsq_node);
		list_del(&tp->tsq_node);

		sk = (struct sock *)tp;
		smp_mb__before_atomic();
		clear_bit(TSQ_QUEUED, &sk->sk_tsq_flags);

		tcp_tsq_handler(sk);
		sk_free(sk);
	}
}

#define TCP_DEFERRED_ALL (TCPF_TSQ_DEFERRED |		\
			  TCPF_WRITE_TIMER_DEFERRED |	\
			  TCPF_DELACK_TIMER_DEFERRED |	\
			  TCPF_MTU_REDUCED_DEFERRED)
/**
 * tcp_release_cb - tcp release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void tcp_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & TCP_DEFERRED_ALL))
			return;
		nflags = flags & ~TCP_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	if (flags & TCPF_TSQ_DEFERRED) {
		tcp_tsq_write(sk);
		__sock_put(sk);
	}
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	if (flags & TCPF_WRITE_TIMER_DEFERRED) {
		tcp_write_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_DELACK_TIMER_DEFERRED) {
		tcp_delack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_MTU_REDUCED_DEFERRED) {
		inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
		__sock_put(sk);
	}
}
EXPORT_SYMBOL(tcp_release_cb);

void __init tcp_tasklet_init(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct tsq_tasklet *tsq = &per_cpu(tsq_tasklet, i);

		INIT_LIST_HEAD(&tsq->head);
		tasklet_setup(&tsq->tasklet, tcp_tasklet_func);
	}
}

/*
 * Write buffer destructor automatically called from kfree_skb.
 * We can't xmit new skbs from this context, as we might already
 * hold qdisc lock.
 */
void tcp_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long flags, nval, oval;

	/* Keep one reference on sk_wmem_alloc.
	 * Will be released by sk_free() from here or tcp_tasklet_func()
	 */
	WARN_ON(refcount_sub_and_test(skb->truesize - 1, &sk->sk_wmem_alloc));

	/* If this softirq is serviced by ksoftirqd, we are likely under stress.
	 * Wait until our queues (qdisc + devices) are drained.
	 * This gives :
	 * - less callbacks to tcp_write_xmit(), reducing stress (batches)
	 * - chance for incoming ACK (processed by another cpu maybe)
	 *   to migrate this flow (skb->ooo_okay will be eventually set)
	 */
	if (refcount_read(&sk->sk_wmem_alloc) >= SKB_TRUESIZE(1) && this_cpu_ksoftirqd() == current)
		goto out;

	for (oval = READ_ONCE(sk->sk_tsq_flags);; oval = nval) {
		struct tsq_tasklet *tsq;
		bool empty;

		if (!(oval & TSQF_THROTTLED) || (oval & TSQF_QUEUED))
			goto out;

		nval = (oval & ~TSQF_THROTTLED) | TSQF_QUEUED;
		nval = cmpxchg(&sk->sk_tsq_flags, oval, nval);
		if (nval != oval)
			continue;

		/* queue this socket to tasklet queue */
		local_irq_save(flags);
		tsq = this_cpu_ptr(&tsq_tasklet);
		empty = list_empty(&tsq->head);
		list_add(&tp->tsq_node, &tsq->head);
		if (empty)
			tasklet_schedule(&tsq->tasklet);
		local_irq_restore(flags);
		return;
	}
out:
	sk_free(sk);
}

/* Note: Called under soft irq.
 * We can call TCP stack right away, unless socket is owned by user.
 */
enum hrtimer_restart tcp_pace_kick(struct hrtimer *timer)
{
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, pacing_timer);
	struct sock *sk = (struct sock *)tp;

	tcp_tsq_handler(sk);
	sock_put(sk);

	return HRTIMER_NORESTART;
}

static void tcp_update_skb_after_send(struct sock *sk, struct sk_buff *skb,
				      u64 prior_wstamp)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (sk->sk_pacing_status != SK_PACING_NONE) {
		unsigned long rate = sk->sk_pacing_rate;

		/* Original sch_fq does not pace first 10 MSS
		 * Note that tp->data_segs_out overflows after 2^32 packets,
		 * this is a minor annoyance.
		 */
		if (rate != ~0UL && rate && tp->data_segs_out >= 10) {
			u64 len_ns = div64_ul((u64)skb->len * NSEC_PER_SEC, rate);
			u64 credit = tp->tcp_wstamp_ns - prior_wstamp;

			/* take into account OS jitter */
			len_ns -= min_t(u64, len_ns / 2, credit);
			tp->tcp_wstamp_ns += len_ns;
		}
	}
	list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
}

INDIRECT_CALLABLE_DECLARE(int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl));
INDIRECT_CALLABLE_DECLARE(int inet6_csk_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl));
INDIRECT_CALLABLE_DECLARE(void tcp_v4_send_check(struct sock *sk, struct sk_buff *skb));

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
// 该例程实际上传输由tcp_do_send排队的TCP数据包。这永远初始传输和以后可能的重传。
// 这里看到的所有的SKB都是没有包头的，我们的工作就是构建TCP包头，并将数据包向下传递
// IP，以便它可以做同样的事情，并将数据包给设备。
// 我们使用重传引擎制作出来的一个原始的SKB或者一个克隆的SKB
static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
			      int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct sk_buff *oskb = NULL;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	u64 prior_wstamp;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));
	tp = tcp_sk(sk);
	// 如果拥塞控制要作时间采样，则必须设置一个瞬间戳，之后再克隆或者数据包。Linux支持多达十种拥塞控制算法，
	// 但并不是每种算法都需要作时间采样的
	prior_wstamp = tp->tcp_wstamp_ns;
	tp->tcp_wstamp_ns = max(tp->tcp_wstamp_ns, tp->tcp_clock_cache);
	skb_set_delivery_time(skb, tp->tcp_wstamp_ns, true);

	// 根据参数clone_it确定是否克隆待发送的数据包
	if (clone_it) {
		oskb = skb;

		tcp_skb_tsorted_save(oskb) {
			// 判断待发送的数据包是否已被克隆，如果是，则只能复制SKB，注意这里用的是pskb_copy，否则可以克隆SKB
			if (unlikely(skb_cloned(oskb)))
				skb = pskb_copy(oskb, gfp_mask);
			else
				skb = skb_clone(oskb, gfp_mask);
		} tcp_skb_tsorted_restore(oskb);

		// 如果复制或克隆失败，则返回错误码ENOBUFS，表示无缓存空间。
		if (unlikely(!skb))
			return -ENOBUFS;
		/* retransmit skbs might have a non zero value in skb->dev
		 * because skb->dev is aliased with skb->rbnode.rb_left
		 */
		skb->dev = NULL;
	}

	// 获取TCP层的传输控制块，SKB中的TCP私有控制块
	inet = inet_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	// 判断当前TCP段是不是SYN段，因为有些选项只能出现在SYN段中国呢，需作特别处理
	// 计算选项的长度
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
	} else {
		// 
		tcp_options_size = tcp_established_options(sk, skb, &opts,
							   &md5);
		/* Force a PSH flag on all (GSO) packets to expedite GRO flush
		 * at receiver : This slightly improve GRO performance.
		 * Note that we do not force the PSH flag for non GSO packets,
		 * because they might be sent under high congestion events,
		 * and in this case it is better to delay the delivery of 1-MSS
		 * packets and thus the corresponding ACK packet that would
		 * release the following packet.
		 */
		if (tcp_skb_pcount(skb) > 1)
			tcb->tcp_flags |= TCPHDR_PSH;
	}
	// 计算TCP头的长度
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	/* if no packet is in qdisc/device queue, then allow XPS to select
	 * another queue. We can be called from tcp_tsq_handler()
	 * which holds one reference to sk.
	 *
	 * TODO: Ideally, in-flight pure ACK packets should not matter here.
	 * One way to get this would be to set skb->truesize = 2 on them.
	 */
	skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1);

	/* If we had to use memory reserve to allocate this skb,
	 * this might cause drops if packet is looped back :
	 * Other socket might not have SOCK_MEMALLOC.
	 * Packets not looped back do not care about pfmemalloc.
	 */
	// 如果我们必须使用内存预留来分配这个 skb，如果数据包被环回，这可能会导致丢包：
	// 其他套接字可能没有 SOCK_MEMALLOC。没有环回的数据包不关心 pfmemalloc。
	skb->pfmemalloc = 0;

	// 在报文中加入TCP首部，然后设置一些TCP首部的值
	// 调用skb_push在数据部分头部添加TCP首部，长度就是前面计算得到的tcp_header_size，实际上就是移动data指针。
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree;
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);

	skb_set_dst_pending_confirm(skb, sk->sk_dst_pending_confirm);

	/* Build TCP header and checksum it. */
	// 建立TCP头部和校验和
	th = (struct tcphdr *)skb->data;
	// 填充源端口、目标端口、TCP段的序号、确认序号以及各标志位。
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->tcp_flags);
	// 初始化校验码和紧急指针
	th->check		= 0;
	th->urg_ptr		= 0;

	/* The urg_mode check is necessary during a below snd_una win probe */
	// 在下面的 snd_una win 探测期间，urg_mode 检查是必要的
	// 判断是否需要设置紧急指针和带外数据标志位。判断条件有两个，一是发送时是否设置了紧急方式，
	// 二是紧急指针是否在以该报文数据序号为起始的65535范围之内。其中第二个条件主要是判断紧急指针的合法性。
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			// 设置紧急指针和带外数据标志位。
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	}

	// 设置gso的类型
	skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
		// 如果不是SYN段，则调用tcp_select_window计算当前接收窗口的大小
		th->window      = htons(tcp_select_window(sk));
		tcp_ecn_send(sk, skb, th, tcp_header_size);
	} else {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		// 如果是SYN段，则设置接收窗口初始值为rev_wnd
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	}
	// 构建TCP首部选项
	tcp_options_write(th, tp, &opts);

#ifdef CONFIG_TCP_MD5SIG
	// 通过TCP MD5签名来保护BGP会话操作相关
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk_gso_disable(sk);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       md5, sk, skb);
	}
#endif

	/* BPF prog is the last one writing header option */
	// BPF prog是最后一个写入的TCP头的选项
	bpf_skops_write_hdr_opt(sk, skb, NULL, NULL, 0, &opts);

	// 调用IPv4或IPv6的send_check执行校验和，并设置到TCP首部中
	INDIRECT_CALL_INET(icsk->icsk_af_ops->send_check,
			   tcp_v6_send_check, tcp_v4_send_check,
			   sk, skb);

	// 如果发出去的段有ACK标志，则需要通知延时确认模块，
	// 递减快速发送ACK的数量，同时停止延时确认计时器
	if (likely(tcb->tcp_flags & TCPHDR_ACK))
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb), rcv_nxt);

	// 如果发送出去的TCP段有负载，则检测拥塞窗口闲置是否超时，并使其失效。
	// 同时记录发送TCP的时间，根据最近接收段的时间确定本端延时确认是否进入pingpong模式。
	if (skb->len != tcp_header_size) {
		tcp_event_data_sent(tp, sk);
		tp->data_segs_out += tcp_skb_pcount(skb);
		tp->bytes_sent += skb->len - tcp_header_size;
	}

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));

	tp->segs_out += tcp_skb_pcount(skb);
	skb_set_hash_from_sk(skb, sk);
	/* OK, its time to fill skb_shinfo(skb)->gso_{segs|size} */
	// 设置gso的信息
	skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);
	skb_shinfo(skb)->gso_size = tcp_skb_mss(skb);

	/* Leave earliest departure time in skb->tstamp (skb->skb_mstamp_ns) */

	/* Cleanup our debris for IP stacks */
	//清理IP栈的碎片
	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),
			       sizeof(struct inet6_skb_parm)));

	tcp_add_tx_delay(skb, tp);

	// 调用发送接口queue_xmit发送报文，如果失败则返回错误码。
	err = INDIRECT_CALL_INET(icsk->icsk_af_ops->queue_xmit,
				 inet6_csk_xmit, ip_queue_xmit,
				 sk, skb, &inet->cork.fl);

	// 如果发送失败时，类似接收到显式的拥塞通知，使拥塞控制进入CWR状态
	if (unlikely(err > 0)) {
		tcp_enter_cwr(sk);
		err = net_xmit_eval(err);
	}
	if (!err && oskb) {
		tcp_update_skb_after_send(sk, oskb, prior_wstamp);
		tcp_rate_skb_sent(sk, oskb);
	}
	return err;
}

static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	return __tcp_transmit_skb(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	WRITE_ONCE(tp->write_seq, TCP_SKB_CB(skb)->end_seq);
	__skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk_wmem_queued_add(sk, skb->truesize);
	sk_mem_charge(sk, skb->truesize);
}

/* Initialize TSO segments for a packet. */
static void tcp_set_skb_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	if (skb->len <= mss_now) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		tcp_skb_pcount_set(skb, 1);
		TCP_SKB_CB(skb)->tcp_gso_size = 0;
	} else {
		tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
		TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	}
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
static void tcp_adjust_pcount(struct sock *sk, const struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->packets_out -= decr;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;

	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);

	if (tp->lost_skb_hint &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
	    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
		tp->lost_cnt_hint -= decr;

	tcp_verify_left_out(tp);
}

static bool tcp_has_tx_tstamp(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->txstamp_ack ||
		(skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP);
}

static void tcp_fragment_tstamp(struct sk_buff *skb, struct sk_buff *skb2)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);

	if (unlikely(tcp_has_tx_tstamp(skb)) &&
	    !before(shinfo->tskey, TCP_SKB_CB(skb2)->seq)) {
		struct skb_shared_info *shinfo2 = skb_shinfo(skb2);
		u8 tsflags = shinfo->tx_flags & SKBTX_ANY_TSTAMP;

		shinfo->tx_flags &= ~tsflags;
		shinfo2->tx_flags |= tsflags;
		swap(shinfo->tskey, shinfo2->tskey);
		TCP_SKB_CB(skb2)->txstamp_ack = TCP_SKB_CB(skb)->txstamp_ack;
		TCP_SKB_CB(skb)->txstamp_ack = 0;
	}
}

static void tcp_skb_fragment_eor(struct sk_buff *skb, struct sk_buff *skb2)
{
	TCP_SKB_CB(skb2)->eor = TCP_SKB_CB(skb)->eor;
	TCP_SKB_CB(skb)->eor = 0;
}

/* Insert buff after skb on the write or rtx queue of sk.  */
static void tcp_insert_write_queue_after(struct sk_buff *skb,
					 struct sk_buff *buff,
					 struct sock *sk,
					 enum tcp_queue tcp_queue)
{
	if (tcp_queue == TCP_FRAG_IN_WRITE_QUEUE)
		__skb_queue_after(&sk->sk_write_queue, skb, buff);
	else
		tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int tcp_fragment(struct sock *sk, enum tcp_queue tcp_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	long limit;
	int nlen;
	u8 flags;

	if (WARN_ON(len > skb->len))
		return -EINVAL;

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	/* tcp_sendmsg() can overshoot sk_wmem_queued by one full size skb.
	 * We need some allowance to not penalize applications setting small
	 * SO_SNDBUF values.
	 * Also allow first and last skb in retransmit queue to be split.
	 */
	limit = sk->sk_sndbuf + 2 * SKB_TRUESIZE(GSO_LEGACY_MAX_SIZE);
	if (unlikely((sk->sk_wmem_queued >> 1) > limit &&
		     tcp_queue != TCP_FRAG_IN_WRITE_QUEUE &&
		     skb != tcp_rtx_queue_head(sk) &&
		     skb != tcp_rtx_queue_tail(sk))) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPWQUEUETOOBIG);
		return -ENOMEM;
	}

	if (skb_unclone_keeptruesize(skb, gfp))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = tcp_stream_alloc_skb(sk, nsize, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */
	skb_copy_decrypted(buff, skb);
	mptcp_skb_ext_copy(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;
	tcp_skb_fragment_eor(skb, buff);

	skb_split(skb, buff, len);

	skb_set_delivery_time(buff, skb->tstamp, true);
	tcp_fragment_tstamp(skb, buff);

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk, tcp_queue);
	if (tcp_queue == TCP_FRAG_IN_RTX_QUEUE)
		list_add(&buff->tcp_tsorted_anchor, &skb->tcp_tsorted_anchor);

	return 0;
}

/* This is similar to __pskb_pull_tail(). The difference is that pulled
 * data is not copied, but immediately discarded.
 */
static int __pskb_trim_head(struct sk_buff *skb, int len)
{
	struct skb_shared_info *shinfo;
	int i, k, eat;

	eat = min_t(int, len, skb_headlen(skb));
	if (eat) {
		__skb_pull(skb, eat);
		len -= eat;
		if (!len)
			return 0;
	}
	eat = len;
	k = 0;
	shinfo = skb_shinfo(skb);
	for (i = 0; i < shinfo->nr_frags; i++) {
		int size = skb_frag_size(&shinfo->frags[i]);

		if (size <= eat) {
			skb_frag_unref(skb, i);
			eat -= size;
		} else {
			shinfo->frags[k] = shinfo->frags[i];
			if (eat) {
				skb_frag_off_add(&shinfo->frags[k], eat);
				skb_frag_size_sub(&shinfo->frags[k], eat);
				eat = 0;
			}
			k++;
		}
	}
	shinfo->nr_frags = k;

	skb->data_len -= len;
	skb->len = skb->data_len;
	return len;
}

/* Remove acked data from a packet in the transmit queue. */
int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	u32 delta_truesize;

	if (skb_unclone_keeptruesize(skb, GFP_ATOMIC))
		return -ENOMEM;

	delta_truesize = __pskb_trim_head(skb, len);

	TCP_SKB_CB(skb)->seq += len;

	if (delta_truesize) {
		skb->truesize	   -= delta_truesize;
		sk_wmem_queued_add(sk, -delta_truesize);
		if (!skb_zcopy_pure(skb))
			sk_mem_uncharge(sk, delta_truesize);
	}

	/* Any change of skb->len requires recalculation of tso factor. */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(skb, tcp_skb_mss(skb));

	return 0;
}

/* Calculate MSS not accounting any TCP options.  */
static inline int __tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mss_now -= icsk->icsk_af_ops->net_frag_header_len;
	}

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	mss_now = max(mss_now, sock_net(sk)->ipv4.sysctl_tcp_min_snd_mss);
	return mss_now;
}

/* Calculate MSS. Not accounting for SACKs here.  */
// 通过MTU计算MSS，即(MTU-TCP首部-TCP选项-IP首部-IP选项)
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	/* Subtract TCP options size, not including SACKs */
	return __tcp_mtu_to_mss(sk, pmtu) -
	       (tcp_sk(sk)->tcp_header_len - sizeof(struct tcphdr));
}
EXPORT_SYMBOL(tcp_mtu_to_mss);

/* Inverse of above */
// 将MSS转化为MTU，即(MSS+TCP首部+TCP选项+IP首部+IP选项)
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;

	mtu = mss +
	      tp->tcp_header_len +
	      icsk->icsk_ext_hdr_len +
	      icsk->icsk_af_ops->net_header_len;

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mtu += icsk->icsk_af_ops->net_frag_header_len;
	}
	return mtu;
}
EXPORT_SYMBOL(tcp_mss_to_mtu);

/* MTU probing init per socket */
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct net *net = sock_net(sk);

	icsk->icsk_mtup.enabled = net->ipv4.sysctl_tcp_mtu_probing > 1;
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
			       icsk->icsk_af_ops->net_header_len;
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, net->ipv4.sysctl_tcp_base_mss);
	icsk->icsk_mtup.probe_size = 0;
	if (icsk->icsk_mtup.enabled)
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
}
EXPORT_SYMBOL(tcp_mtup_init);

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
// 此函数同步snd mss到当前的pmtu和exthdr集合
// 为传输控制块中与MSS相关的成员进行数据同步
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	// 如果路径MTU发现段长度上限无效，则需更新之
	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;

	// 根据pmtu得到当前的mss，基本的计算方法是（PMTU - IP首部长度- TCP首部长度 - IP选项长度- TCP选项）
	// 其中IP选项和TCP选项的长度可以都为0.
	mss_now = tcp_mtu_to_mss(sk, pmtu);
	// MSS不能超过接收方通告过的接收窗口的最大值的一半。
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);

	/* And store cached results */
	// 保存最近更新的有效PMTU
	icsk->icsk_pmtu_cookie = pmtu;
	// 最后将得到的MSS更新到缓存中
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now;

	return mss_now;
}
EXPORT_SYMBOL(tcp_sync_mss);

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
// 计算当前有效的MSS，需考虑TCP首部中的SACK选项和IP选项，以及PMTU
unsigned int tcp_current_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	// 获取套接口的路由缓存项，用来从中取出PMTU
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned int header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;
	// 以当前有效MSS初始化mss_now变量，用于后续计算，后面还需要刷新回去
	mss_now = tp->mss_cache;

	// 如果获取到该套接口的路由，则从中取出PMTU与最近一次更新的路径MTU比较，
	// 如果不相等，即更新icsk_pmtu_cookie和当前有效MSS
	if (dst) {
		u32 mtu = dst_mtu(dst);
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
	}

	// 计算tcp首部的长度
	header_len = tcp_established_options(sk, NULL, &opts, &md5) +
		     sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	// mss_cache的大小基于tp->tcp_header_len，它假定了一些常用选项。 
	// 如果这是一个奇怪的数据包（因为我们有SACK块等），
	// 那么我们计算的header_len将是不同的，我们必须相应地调整mss_now
	// 如果TCP首部的长度和现在的首部长度不相等，减去变化的长度
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now;
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
static void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tcp_snd_cwnd(tp)) {
			tp->snd_ssthresh = tcp_current_ssthresh(sk);
			tcp_snd_cwnd_set(tp, (tcp_snd_cwnd(tp) + win_used) >> 1);
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_jiffies32;
}

static void tcp_cwnd_validate(struct sock *sk, bool is_cwnd_limited)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	struct tcp_sock *tp = tcp_sk(sk);

	/* Track the maximum number of outstanding packets in each
	 * window, and remember whether we were cwnd-limited then.
	 */
	if (!before(tp->snd_una, tp->max_packets_seq) ||
	    tp->packets_out > tp->max_packets_out ||
	    is_cwnd_limited) {
		tp->max_packets_out = tp->packets_out;
		tp->max_packets_seq = tp->snd_nxt;
		tp->is_cwnd_limited = is_cwnd_limited;
	}

	if (tcp_is_cwnd_limited(sk)) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_jiffies32;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

		if (sock_net(sk)->ipv4.sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_jiffies32 - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto &&
		    !ca_ops->cong_control)
			tcp_cwnd_application_limited(sk);

		/* The following conditions together indicate the starvation
		 * is caused by insufficient sender buffer:
		 * 1) just sent some data (see tcp_write_xmit)
		 * 2) not cwnd limited (this else condition)
		 * 3) no more data to send (tcp_write_queue_empty())
		 * 4) application is hitting buffer limit (SOCK_NOSPACE)
		 */
		if (tcp_write_queue_empty(sk) && sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) &&
		    (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
			tcp_chrono_start(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
}

/* Minshall's variant of the Nagle send check. */
static bool tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Update snd_sml if this skb is under mss
 * Note that a TSO packet might end with a sub-mss segment
 * The test is really :
 * if ((skb->len % mss) != 0)
 *        tp->snd_sml = TCP_SKB_CB(skb)->end_seq;
 * But we can avoid doing the divide again given we already have
 *  skb_pcount = skb->len / mss_now
 */
static void tcp_minshall_update(struct tcp_sock *tp, unsigned int mss_now,
				const struct sk_buff *skb)
{
	if (skb->len < tcp_skb_pcount(skb) * mss_now)
		tp->snd_sml = TCP_SKB_CB(skb)->end_seq;
}

/* Return false, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized. (provided by caller in %partial bool)
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_CORK is not set, and TCP_NODELAY is set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static bool tcp_nagle_check(bool partial, const struct tcp_sock *tp,
			    int nonagle)
{
	return partial &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out && tcp_minshall_check(tp)));
}

/* Return how many segs we'd like on a TSO packet,
 * depending on current pacing rate, and how close the peer is.
 *
 * Rationale is:
 * - For close peers, we rather send bigger packets to reduce
 *   cpu costs, because occasional losses will be repaired fast.
 * - For long distance/rtt flows, we would like to get ACK clocking
 *   with 1 ACK per ms.
 *
 * Use min_rtt to help adapt TSO burst size, with smaller min_rtt resulting
 * in bigger TSO bursts. We we cut the RTT-based allowance in half
 * for every 2^9 usec (aka 512 us) of RTT, so that the RTT-based allowance
 * is below 1500 bytes after 6 * ~500 usec = 3ms.
 */
static u32 tcp_tso_autosize(const struct sock *sk, unsigned int mss_now,
			    int min_tso_segs)
{
	unsigned long bytes;
	u32 r;

	bytes = sk->sk_pacing_rate >> READ_ONCE(sk->sk_pacing_shift);

	r = tcp_min_rtt(tcp_sk(sk)) >> sock_net(sk)->ipv4.sysctl_tcp_tso_rtt_log;
	if (r < BITS_PER_TYPE(sk->sk_gso_max_size))
		bytes += sk->sk_gso_max_size >> r;

	bytes = min_t(unsigned long, bytes, sk->sk_gso_max_size);

	return max_t(u32, bytes / mss_now, min_tso_segs);
}

/* Return the number of segments we want in the skb we are transmitting.
 * See if congestion control module wants to decide; otherwise, autosize.
 */
// 返回我们正在传输的skb中我们想要的段数。看看拥塞控制模块是否想要决定；否则，自动调整大小。
static u32 tcp_tso_segs(struct sock *sk, unsigned int mss_now)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	u32 min_tso, tso_segs;

	min_tso = ca_ops->min_tso_segs ?
			ca_ops->min_tso_segs(sk) :
			sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs;

	tso_segs = tcp_tso_autosize(sk, mss_now, min_tso);
	return min_t(u32, tso_segs, sk->sk_gso_max_segs);
}

/* Returns the portion of skb which can be sent right away */
// 返回可以立即发送的skb部分
static unsigned int tcp_mss_split_point(const struct sock *sk,
					const struct sk_buff *skb,
					unsigned int mss_now,
					unsigned int max_segs,
					int nonagle)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 partial, needed, window, max_len;

	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	max_len = mss_now * max_segs;

	if (likely(max_len <= window && skb != tcp_write_queue_tail(sk)))
		return max_len;

	needed = min(skb->len, window);

	if (max_len <= needed)
		return max_len;

	partial = needed % mss_now;
	/* If last segment is not a full MSS, check if Nagle rules allow us
	 * to include this last segment in this skb.
	 * Otherwise, we'll split the skb at last MSS boundary
	 */
	if (tcp_nagle_check(partial != 0, tp, nonagle))
		return needed - partial;

	return needed;
}

/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int tcp_cwnd_test(const struct tcp_sock *tp,
					 const struct sk_buff *skb)
{
	u32 in_flight, cwnd, halfcwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tcp_snd_cwnd(tp);
	if (in_flight >= cwnd)
		return 0;

	/* For better scheduling, ensure we have at least
	 * 2 GSO packets in flight.
	 */
	halfcwnd = max(cwnd >> 1, 1U);
	return min(halfcwnd, cwnd - in_flight);
}

/* Initialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int tcp_init_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);

	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_set_skb_tso_segs(skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}
	return tso_segs;
}


/* Return true if the Nagle test allows this packet to be
 * sent now.
 */
static inline bool tcp_nagle_test(const struct tcp_sock *tp, const struct sk_buff *skb,
				  unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return true;

	/* Don't use the nagle rule for urgent data (or for the final FIN). */
	if (tcp_urg_mode(tp) || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
		return true;

	if (!tcp_nagle_check(skb->len < cur_mss, tp, nonagle))
		return true;

	return false;
}

/* Does at least the first segment of SKB fit into the send window? */
static bool tcp_snd_wnd_test(const struct tcp_sock *tp,
			     const struct sk_buff *skb,
			     unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	return !after(end_seq, tcp_wnd_end(tp));
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
static int tso_fragment(struct sock *sk, struct sk_buff *skb, unsigned int len,
			unsigned int mss_now, gfp_t gfp)
{
	int nlen = skb->len - len;
	struct sk_buff *buff;
	u8 flags;

	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)
		return tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
				    skb, len, mss_now, gfp);

	buff = tcp_stream_alloc_skb(sk, 0, gfp, true);
	if (unlikely(!buff))
		return -ENOMEM;
	skb_copy_decrypted(buff, skb);
	mptcp_skb_ext_copy(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	sk_mem_charge(sk, buff->truesize);
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	tcp_skb_fragment_eor(skb, buff);

	skb_split(skb, buff, len);
	tcp_fragment_tstamp(skb, buff);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(buff, mss_now);

	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk, TCP_FRAG_IN_WRITE_QUEUE);

	return 0;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
static bool tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb,
				 bool *is_cwnd_limited,
				 bool *is_rwnd_limited,
				 u32 max_segs)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 send_win, cong_win, limit, in_flight;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *head;
	int win_divisor;
	s64 delta;

	if (icsk->icsk_ca_state >= TCP_CA_Recovery)
		goto send_now;

	/* Avoid bursty behavior by allowing defer
	 * only if the last write was recent (1 ms).
	 * Note that tp->tcp_wstamp_ns can be in the future if we have
	 * packets waiting in a qdisc or device for EDT delivery.
	 */
	delta = tp->tcp_clock_cache - tp->tcp_wstamp_ns - NSEC_PER_MSEC;
	if (delta > 0)
		goto send_now;

	in_flight = tcp_packets_in_flight(tp);

	BUG_ON(tcp_skb_pcount(skb) <= 1);
	BUG_ON(tcp_snd_cwnd(tp) <= in_flight);

	send_win = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
	cong_win = (tcp_snd_cwnd(tp) - in_flight) * tp->mss_cache;

	limit = min(send_win, cong_win);

	/* If a full-sized TSO skb can be sent, do it. */
	if (limit >= max_segs * tp->mss_cache)
		goto send_now;

	/* Middle in queue won't get any more data, full sendable already? */
	if ((skb != tcp_write_queue_tail(sk)) && (limit >= skb->len))
		goto send_now;

	win_divisor = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_tso_win_divisor);
	if (win_divisor) {
		u32 chunk = min(tp->snd_wnd, tcp_snd_cwnd(tp) * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= win_divisor;
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
		if (limit > tcp_max_tso_deferred_mss(tp) * tp->mss_cache)
			goto send_now;
	}

	/* TODO : use tsorted_sent_queue ? */
	head = tcp_rtx_queue_head(sk);
	if (!head)
		goto send_now;
	delta = tp->tcp_clock_cache - head->tstamp;
	/* If next ACK is likely to come too late (half srtt), do not defer */
	if ((s64)(delta - (u64)NSEC_PER_USEC * (tp->srtt_us >> 4)) < 0)
		goto send_now;

	/* Ok, it looks like it is advisable to defer.
	 * Three cases are tracked :
	 * 1) We are cwnd-limited
	 * 2) We are rwnd-limited
	 * 3) We are application limited.
	 */
	if (cong_win < send_win) {
		if (cong_win <= skb->len) {
			*is_cwnd_limited = true;
			return true;
		}
	} else {
		if (send_win <= skb->len) {
			*is_rwnd_limited = true;
			return true;
		}
	}

	/* If this packet won't get more data, do not wait. */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) ||
	    TCP_SKB_CB(skb)->eor)
		goto send_now;

	return true;

send_now:
	return false;
}

static inline void tcp_mtu_check_reprobe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	u32 interval;
	s32 delta;

	interval = net->ipv4.sysctl_tcp_probe_interval;
	delta = tcp_jiffies32 - icsk->icsk_mtup.probe_timestamp;
	if (unlikely(delta >= interval * HZ)) {
		int mss = tcp_current_mss(sk);

		/* Update current search range */
		icsk->icsk_mtup.probe_size = 0;
		icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp +
			sizeof(struct tcphdr) +
			icsk->icsk_af_ops->net_header_len;
		icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);

		/* Update probe time stamp */
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
	}
}

static bool tcp_can_coalesce_send_queue_head(struct sock *sk, int len)
{
	struct sk_buff *skb, *next;

	skb = tcp_send_head(sk);
	tcp_for_write_queue_from_safe(skb, next, sk) {
		if (len <= skb->len)
			break;

		if (unlikely(TCP_SKB_CB(skb)->eor) ||
		    tcp_has_tx_tstamp(skb) ||
		    !skb_pure_zcopy_same(skb, next))
			return false;

		len -= skb->len;
	}

	return true;
}

/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
// 如果我们准备好了就创建一个新的MTU探测包
// MTU探测定期尝试通过故意发送更大的数据包来增加路径MTU。这个发现函数在更大的路径MTU时更改结果。
// 返回值	描述
// 0		表示没有拥塞窗口可以使用，需延迟发送
// 1		已发送路径MTU发现段
// -1		其他情况
static int tcp_mtu_probe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *nskb, *next;
	struct net *net = sock_net(sk);
	int probe_size;
	int size_needed;
	int copy, len;
	int mss_now;
	int interval;

	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off)
	 */
	// 1.未启用路径MTU
	// 2.当前路径MTU探测段的长度不为0，表示路径MTU发现段已经发出尚未得到确认。
	// 3.拥塞控制状态不处于Open状态
	// 4.拥塞窗口大小不足使用时
	// 5.下一个发送的段中存在SACK选项
	if (likely(!icsk->icsk_mtup.enabled ||
		   icsk->icsk_mtup.probe_size ||
		   inet_csk(sk)->icsk_ca_state != TCP_CA_Open ||
		   tcp_snd_cwnd(tp) < 11 ||
		   tp->rx_opt.num_sacks || tp->rx_opt.dsack))
		return -1;

	/* Use binary search for probe_size between tcp_mss_base,
	 * and current mss_clamp. if (search_high - search_low)
	 * smaller than a threshold, backoff from probing.
	 */
	// 在tcp_mss_base和当前mss_clamp之间使用二分查找probe_size。 如果(search_high - search_low)小于阈值，则回退探测。
	mss_now = tcp_current_mss(sk);
	probe_size = tcp_mtu_to_mss(sk, (icsk->icsk_mtup.search_high +
				    icsk->icsk_mtup.search_low) >> 1);
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	interval = icsk->icsk_mtup.search_high - icsk->icsk_mtup.search_low;
	/* When misfortune happens, we are reprobing actively,
	 * and then reprobe timer has expired. We stick with current
	 * probing process by not resetting search range to its orignal.
	 */
	// 如果该段长度大于路径MTU发现段段长的上限，则不能进行路径MTU的探测。
	if (probe_size > tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_high) ||
		interval < net->ipv4.sysctl_tcp_probe_threshold) {
		/* Check whether enough time has elaplased for
		 * another round of probing.
		 */
		// 检查是否有足够的时间进行另一轮探测
		tcp_mtu_check_reprobe(sk);
		return -1;
	}

	/* Have enough data in the send queue to probe? */
	// 检测发送队列中是否存在足够的数据用于MTU探测
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	// 检测对方的接收窗口是否有足够的空间用来接收路径MTU的探测段
	if (tp->snd_wnd < size_needed)
		return -1;
	if (after(tp->snd_nxt + size_needed, tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight, don't stall */
	// 检测拥塞窗口是否被耗尽
	if (tcp_packets_in_flight(tp) + 2 > tcp_snd_cwnd(tp)) {
		if (!tcp_packets_in_flight(tp))
			return -1;
		else
			return 0;
	}

	if (!tcp_can_coalesce_send_queue_head(sk, probe_size))
		return -1;

	/* We're allowed to probe.  Build it now. */
	// 所有的检测通过以后，需要为路径MTU探测段分配SKB，并插入到发送队列的队首。然后设置SKB中TCP控制块的相关值
	nskb = tcp_stream_alloc_skb(sk, probe_size, GFP_ATOMIC, false);
	if (!nskb)
		return -1;
	// 将分配好的SKB，并插入到发送队列的队首。然后设置SKB中TCP控制块的相关值
	sk_wmem_queued_add(sk, nskb->truesize);
	sk_mem_charge(sk, nskb->truesize);

	skb = tcp_send_head(sk);
	skb_copy_decrypted(nskb, skb);
	mptcp_skb_ext_copy(nskb, skb);
	// 设置skb中TCP控制块的相关值
	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;
	TCP_SKB_CB(nskb)->tcp_flags = TCPHDR_ACK;

	tcp_insert_write_queue_before(nskb, skb, sk);
	tcp_highest_sack_replace(sk, skb, nskb);

	len = 0;
	// 将发送队列中路径MTU探测段后的SKB中的数据复制到路径MTU探测段中，并释放已被复制的SKB。
	tcp_for_write_queue_from_safe(skb, next, sk) {
		copy = min_t(int, skb->len, probe_size - len);
		skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);

		if (skb->len <= copy) {
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags;
			/* If this is the last SKB we copy and eor is set
			 * we need to propagate it to the new skb.
			 */
			TCP_SKB_CB(nskb)->eor = TCP_SKB_CB(skb)->eor;
			tcp_skb_collapse_tstamp(nskb, skb);
			tcp_unlink_write_queue(skb, sk);
			tcp_wmem_free_skb(sk, skb);
		} else {
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags &
						   ~(TCPHDR_FIN|TCPHDR_PSH);
			if (!skb_shinfo(skb)->nr_frags) {
				skb_pull(skb, copy);
			} else {
				__pskb_trim_head(skb, copy);
				tcp_set_skb_tso_segs(skb, mss_now);
			}
			TCP_SKB_CB(skb)->seq += copy;
		}

		len += copy;

		if (len >= probe_size)
			break;
	}
	tcp_init_tso_segs(nskb, nskb->len);

	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit().
	 */
	// 最后将该路径MTU探测段输出，并记录路径MTU探测段的序号，以便之后用来确认路径MTU探测成功与否。
	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) - 1);
		tcp_event_new_data_sent(sk, nskb);

		icsk->icsk_mtup.probe_size = tcp_mss_to_mtu(sk, nskb->len);
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;

		return 1;
	}

	return -1;
}

static bool tcp_pacing_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_needs_internal_pacing(sk))
		return false;

	if (tp->tcp_wstamp_ns <= tp->tcp_clock_cache)
		return false;

	if (!hrtimer_is_queued(&tp->pacing_timer)) {
		hrtimer_start(&tp->pacing_timer,
			      ns_to_ktime(tp->tcp_wstamp_ns),
			      HRTIMER_MODE_ABS_PINNED_SOFT);
		sock_hold(sk);
	}
	return true;
}

/* TCP Small Queues :
 * Control number of packets in qdisc/devices to two packets / or ~1 ms.
 * (These limits are doubled for retransmits)
 * This allows for :
 *  - better RTT estimation and ACK scheduling
 *  - faster recovery
 *  - high rates
 * Alas, some drivers / subsystems require a fair amount
 * of queued bytes to ensure line rate.
 * One example is wifi aggregation (802.11 AMPDU)
 */
static bool tcp_small_queue_check(struct sock *sk, const struct sk_buff *skb,
				  unsigned int factor)
{
	unsigned long limit;

	limit = max_t(unsigned long,
		      2 * skb->truesize,
		      sk->sk_pacing_rate >> READ_ONCE(sk->sk_pacing_shift));
	if (sk->sk_pacing_status == SK_PACING_NONE)
		limit = min_t(unsigned long, limit,
			      sock_net(sk)->ipv4.sysctl_tcp_limit_output_bytes);
	limit <<= factor;

	if (static_branch_unlikely(&tcp_tx_delay_enabled) &&
	    tcp_sk(sk)->tcp_tx_delay) {
		u64 extra_bytes = (u64)sk->sk_pacing_rate * tcp_sk(sk)->tcp_tx_delay;

		/* TSQ is based on skb truesize sum (sk_wmem_alloc), so we
		 * approximate our needs assuming an ~100% skb->truesize overhead.
		 * USEC_PER_SEC is approximated by 2^20.
		 * do_div(extra_bytes, USEC_PER_SEC/2) is replaced by a right shift.
		 */
		extra_bytes >>= (20 - 1);
		limit += extra_bytes;
	}
	if (refcount_read(&sk->sk_wmem_alloc) > limit) {
		/* Always send skb if rtx queue is empty.
		 * No need to wait for TX completion to call us back,
		 * after softirq/tasklet schedule.
		 * This helps when TX completions are delayed too much.
		 */
		if (tcp_rtx_queue_empty(sk))
			return false;

		set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED, so we must
		 * test again the condition.
		 */
		smp_mb__after_atomic();
		if (refcount_read(&sk->sk_wmem_alloc) > limit)
			return true;
	}
	return false;
}

static void tcp_chrono_set(struct tcp_sock *tp, const enum tcp_chrono new)
{
	const u32 now = tcp_jiffies32;
	enum tcp_chrono old = tp->chrono_type;

	if (old > TCP_CHRONO_UNSPEC)
		tp->chrono_stat[old - 1] += now - tp->chrono_start;
	tp->chrono_start = now;
	tp->chrono_type = new;
}

void tcp_chrono_start(struct sock *sk, const enum tcp_chrono type)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* If there are multiple conditions worthy of tracking in a
	 * chronograph then the highest priority enum takes precedence
	 * over the other conditions. So that if something "more interesting"
	 * starts happening, stop the previous chrono and start a new one.
	 */
	if (type > tp->chrono_type)
		tcp_chrono_set(tp, type);
}

void tcp_chrono_stop(struct sock *sk, const enum tcp_chrono type)
{
	struct tcp_sock *tp = tcp_sk(sk);


	/* There are multiple conditions worthy of tracking in a
	 * chronograph, so that the highest priority enum takes
	 * precedence over the other conditions (see tcp_chrono_start).
	 * If a condition stops, we only stop chrono tracking if
	 * it's the "most interesting" or current chrono we are
	 * tracking and starts busy chrono if we have pending data.
	 */
	if (tcp_rtx_and_write_queues_empty(sk))
		tcp_chrono_set(tp, TCP_CHRONO_UNSPEC);
	else if (type == tp->chrono_type)
		tcp_chrono_set(tp, TCP_CHRONO_BUSY);
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * LARGESEND note: !tcp_urg_mode is overkill, only frames between
 * snd_up-64k-mss .. snd_up cannot be large. However, taking into
 * account rare use of URG, this is not a big flaw.
 *
 * Send at most one packet when push_one > 0. Temporarily ignore
 * cwnd limit to force at most one packet out when push_one == 2.

 * Returns true, if no segments are in flight and we have queued segments,
 * but cannot send anything now because of SWS or another problem.
 */
// tcp_write_xmit将发送队列上的SKB发送出去，返回值为0表示发送成功。
// 该函数将数据包写入网络。并且推进send_head。这发生在传入的确认为我们打开远程窗口时。
// 返回值：如果没有分段在传送并且我们有排队的段，但是现在由于滑动窗口或者另外的问题，我们不能发送任何数据，就会返回true.
// 过程如下：
// 1.检测当前的状态是否是TCP_CLOSE.
// 2.检测拥塞窗口的大小。
// 3.检测当前段是否完全处在发送窗口内。
// 4.检测段是否使用nagle算法进行发送。
// 5.通过以上检测后将该SKB发送出去。
// 6.循环检测并发送队列上所有未发送的SKB。
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;
	bool is_cwnd_limited = false, is_rwnd_limited = false;
	u32 max_segs;
	// sent_pkts用来统计函数中已发送的总段数，首先初始化为0，接着发送一个路径MTU探测段，
	// 如果成功则发送段数加1。
	sent_pkts = 0;
	// 刷新时间戳
	tcp_mstamp_refresh(tp);
	// 如果不是发送新加的SKB
	if (!push_one) {
		/* Do MTU probing. */
		// 进行MTU探测
		result = tcp_mtu_probe(sk);
		if (!result) {
			return false;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}
	// 得到正在传输的skb中我们想要的段数
	max_segs = tcp_tso_segs(sk, mss_now);
	// 如果发送队列不为空，则准备开始发送段
	while ((skb = tcp_send_head(sk))) {
		unsigned int limit;

		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {
			/* "skb_mstamp_ns" is used as a start point for the retransmit timer */
			tp->tcp_wstamp_ns = tp->tcp_clock_cache;
			skb_set_delivery_time(skb, tp->tcp_wstamp_ns, true);
			list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
			tcp_init_tso_segs(skb, mss_now);
			goto repair; /* Skip network transmission */
		}

		if (tcp_pacing_check(sk))
			break;
		// 设置有关tso的信息，包括GSO类型，GSO分段的大小等。这些信息是准备给软件TSO分段使用的。
		// 如果网络设备不支持TSO，但又使用了TSO功能，则段在提给网络设备之前，需进行软分段，
		// 则由代码实现TSO分段。
		tso_segs = tcp_init_tso_segs(skb, mss_now);
		BUG_ON(!tso_segs);

		// 检测拥塞窗口的大小，如果为0，则说明拥塞窗口已满，目前不能发送。
		cwnd_quota = tcp_cwnd_test(tp, skb);
		if (!cwnd_quota) {
			if (push_one == 2)
				/* Force out a loss probe pkt. */
				cwnd_quota = 1;
			else
				break;
		}
		// 检测当前段是否完全处在发送窗口内，如果是则可以发送，否则目前不能发送
		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {
			is_rwnd_limited = true;
			break;
		}

		// 如果无需TSO分段，则检测是否使用Nagle算法，并确定当前能否立即发送该段
		if (tso_segs == 1) {
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
		} else {
			// 如果需要TSO分段，则检测该段是否应该延时发送，如果是则目前不能发送。
			// tcp_tso_should_defer用来检测GSO段是否需要延时发送。
			// 则段中有FIN标志，或者不处于Open拥塞状态，或者TSO段延时超过2个时钟滴答，或者拥塞窗口和
			// 发送窗口的最小值大于64KB或三倍的当前有效MSS，在这些情况下会立即发送，
			// 而其他情况下会延时发送，这样主要是为了减少软GSO分段的次数提高性能。
			if (!push_one &&
			    tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
						 &is_rwnd_limited, max_segs))
				break;
		}
		// 根据条件，可能需要对SKB中的段进行分段处理，分段的段包括两种：一种是普通的用MSS分段的段，
		// 另一种是TSO分段的段。能否发送段主要取决于两个条件：一是段需完全在发送窗口中，二是拥塞窗口未满。
		// 第一种段，应该不会在分段了，因为在tcp_sendmsg中创阶段的SKB时已经根据MSS处理了。而第二种段，
		// 则一般情况下都会大于MSS，因此通过TSO分段的段有可能大于拥塞窗口剩余空间，如果是这样，就需以发送
		// 窗口和拥塞窗口的最小值作为段长对数据包再次分段。

		// limit为再次分段的段长，初始化为当前MSS
		limit = mss_now;
		// 判断当前段是不是TSO分段的段，如果是才处理
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			// 已发送窗口和拥塞窗口最小值作为分段段长
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    min_t(unsigned int,
							  cwnd_quota,
							  max_segs),
						    nonagle);

		// 如果SKB中的数据长度大于分段段长，则调用tso_fragment根据该段长进行分段，
		// 如果分段失败则目前暂不发送。
		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
			break;

		// 检测small_queue
		if (tcp_small_queue_check(sk, skb, 0))
			break;

		/* Argh, we hit an empty skb(), presumably a thread
		 * is sleeping in sendmsg()/sk_stream_wait_memory().
		 * We do not want to send a pure-ack packet and have
		 * a strange looking rtx queue with empty packet(s).
		 */
		// 啊，我们遇到了一个空的 skb()，大概是一个线程在 sendmsg()/sk_stream_wait_memory() 中休眠。 
		// 我们不想发送一个纯 ack 数据包并且有一个看起来很奇怪的拥有空数据包的rtx队列。
		if (TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq)
			break;
		// 调用tcp_transmit_skb发送TCP段，其中第三个参数1表示需克隆被发送的段，
		// 如果发送失败，则中止剩余的发送。
		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

repair:
		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		// 推进send_head。 这个被发送出去。这个调用将增加packets_out。
		tcp_event_new_data_sent(sk, skb);
		// 如果发送的段小于MSS，则更新最后一个小包的序号
		tcp_minshall_update(tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb);

		if (push_one)
			break;
	}

	if (is_rwnd_limited)
		tcp_chrono_start(sk, TCP_CHRONO_RWND_LIMITED);
	else
		tcp_chrono_stop(sk, TCP_CHRONO_RWND_LIMITED);

	is_cwnd_limited |= (tcp_packets_in_flight(tp) >= tcp_snd_cwnd(tp));
	if (likely(sent_pkts || is_cwnd_limited))
		tcp_cwnd_validate(sk, is_cwnd_limited);

	// 如果发送了数据，那么久更新相关的统计
	if (likely(sent_pkts)) {
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += sent_pkts;

		/* Send one loss probe per tail loss episode. */
		// 每个尾部丢失事件发送一个丢失探测。
		if (push_one != 2)
			tcp_schedule_loss_probe(sk, false);
		return false;
	}
	return !tp->packets_out && !tcp_write_queue_empty(sk);
}

bool tcp_schedule_loss_probe(struct sock *sk, bool advancing_rto)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout, rto_delta_us;
	int early_retrans;

	/* Don't do any loss probe on a Fast Open connection before 3WHS
	 * finishes.
	 */
	if (rcu_access_pointer(tp->fastopen_rsk))
		return false;

	early_retrans = sock_net(sk)->ipv4.sysctl_tcp_early_retrans;
	/* Schedule a loss probe in 2*RTT for SACK capable connections
	 * not in loss recovery, that are either limited by cwnd or application.
	 */
	if ((early_retrans != 3 && early_retrans != 4) ||
	    !tp->packets_out || !tcp_is_sack(tp) ||
	    (icsk->icsk_ca_state != TCP_CA_Open &&
	     icsk->icsk_ca_state != TCP_CA_CWR))
		return false;

	/* Probe timeout is 2*rtt. Add minimum RTO to account
	 * for delayed ack when there's one outstanding packet. If no RTT
	 * sample is available then probe after TCP_TIMEOUT_INIT.
	 */
	if (tp->srtt_us) {
		timeout = usecs_to_jiffies(tp->srtt_us >> 2);
		if (tp->packets_out == 1)
			timeout += TCP_RTO_MIN;
		else
			timeout += TCP_TIMEOUT_MIN;
	} else {
		timeout = TCP_TIMEOUT_INIT;
	}

	/* If the RTO formula yields an earlier time, then use that time. */
	rto_delta_us = advancing_rto ?
			jiffies_to_usecs(inet_csk(sk)->icsk_rto) :
			tcp_rto_delta_us(sk);  /* How far in future is RTO? */
	if (rto_delta_us > 0)
		timeout = min_t(u32, timeout, usecs_to_jiffies(rto_delta_us));

	tcp_reset_xmit_timer(sk, ICSK_TIME_LOSS_PROBE, timeout, TCP_RTO_MAX);
	return true;
}

/* Thanks to skb fast clones, we can detect if a prior transmit of
 * a packet is still in a qdisc or driver queue.
 * In this case, there is very little point doing a retransmit !
 */
// 幸亏skb的快速克隆，我们能检测是否先前传送的一个包是否仍然在qdisc或者驱动队列。
// 在这种情况下，重传就没啥意义
static bool skb_still_in_host_queue(struct sock *sk,
				    const struct sk_buff *skb)
{
	if (unlikely(skb_fclone_busy(sk, skb))) {
		set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
		smp_mb__after_atomic();
		if (skb_fclone_busy(sk, skb)) {
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);
			return true;
		}
	}
	return false;
}

/* When probe timeout (PTO) fires, try send a new segment if possible, else
 * retransmit the last segment.
 */
void tcp_send_loss_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int pcount;
	int mss = tcp_current_mss(sk);

	/* At most one outstanding TLP */
	if (tp->tlp_high_seq)
		goto rearm_timer;

	tp->tlp_retrans = 0;
	skb = tcp_send_head(sk);
	if (skb && tcp_snd_wnd_test(tp, skb, mss)) {
		pcount = tp->packets_out;
		tcp_write_xmit(sk, mss, TCP_NAGLE_OFF, 2, GFP_ATOMIC);
		if (tp->packets_out > pcount)
			goto probe_sent;
		goto rearm_timer;
	}
	skb = skb_rb_last(&sk->tcp_rtx_queue);
	if (unlikely(!skb)) {
		WARN_ONCE(tp->packets_out,
			  "invalid inflight: %u state %u cwnd %u mss %d\n",
			  tp->packets_out, sk->sk_state, tcp_snd_cwnd(tp), mss);
		inet_csk(sk)->icsk_pending = 0;
		return;
	}

	if (skb_still_in_host_queue(sk, skb))
		goto rearm_timer;

	pcount = tcp_skb_pcount(skb);
	if (WARN_ON(!pcount))
		goto rearm_timer;

	if ((pcount > 1) && (skb->len > (pcount - 1) * mss)) {
		if (unlikely(tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb,
					  (pcount - 1) * mss, mss,
					  GFP_ATOMIC)))
			goto rearm_timer;
		skb = skb_rb_next(skb);
	}

	if (WARN_ON(!skb || !tcp_skb_pcount(skb)))
		goto rearm_timer;

	if (__tcp_retransmit_skb(sk, skb, 1))
		goto rearm_timer;

	tp->tlp_retrans = 1;

probe_sent:
	/* Record snd_nxt for loss detection. */
	tp->tlp_high_seq = tp->snd_nxt;

	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSSPROBES);
	/* Reset s.t. tcp_rearm_rto will restart timer from now */
	inet_csk(sk)->icsk_pending = 0;
rearm_timer:
	tcp_rearm_rto(sk);
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;
	// 如果写入失败，得考虑启动持续定时器去探测窗口
	if (tcp_write_xmit(sk, cur_mss, nonagle, 0,
			   sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
// 发送位于发送队列上的第一个SKB，参数mss_now为当前MSS。
// 此函数需要真正推送未决帧来设置探测计时器等
void tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = tcp_send_head(sk);

	BUG_ON(!skb || skb->len < mss_now);

	tcp_write_xmit(sk, mss_now, TCP_NAGLE_PUSH, 1, sk->sk_allocation);
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = icsk->icsk_ack.rcv_mss;
	int free_space = tcp_space(sk);
	int allowed_space = tcp_full_space(sk);
	int full_space, window;

	if (sk_is_mptcp(sk))
		mptcp_space(sk, &free_space, &allowed_space);

	full_space = min_t(int, tp->window_clamp, allowed_space);

	if (unlikely(mss > full_space)) {
		mss = full_space;
		if (mss <= 0)
			return 0;
	}
	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		if (tcp_under_memory_pressure(sk))
			tcp_adjust_rcv_ssthresh(sk);

		/* free_space might become our new window, make sure we don't
		 * increase it due to wscale.
		 */
		free_space = round_down(free_space, 1 << tp->rx_opt.rcv_wscale);

		/* if free space is less than mss estimate, or is below 1/16th
		 * of the maximum allowed, try to move to zero-window, else
		 * tcp_clamp_window() will grow rcv buf up to tcp_rmem[2], and
		 * new incoming data is dropped due to memory limits.
		 * With large window, mss test triggers way too late in order
		 * to announce zero window in time before rmem limit kicks in.
		 */
		if (free_space < (allowed_space >> 4) || free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		window = ALIGN(window, (1 << tp->rx_opt.rcv_wscale));
	} else {
		window = tp->rcv_wnd;
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = rounddown(free_space, mss);
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

void tcp_skb_collapse_tstamp(struct sk_buff *skb,
			     const struct sk_buff *next_skb)
{
	if (unlikely(tcp_has_tx_tstamp(next_skb))) {
		const struct skb_shared_info *next_shinfo =
			skb_shinfo(next_skb);
		struct skb_shared_info *shinfo = skb_shinfo(skb);

		shinfo->tx_flags |= next_shinfo->tx_flags & SKBTX_ANY_TSTAMP;
		shinfo->tskey = next_shinfo->tskey;
		TCP_SKB_CB(skb)->txstamp_ack |=
			TCP_SKB_CB(next_skb)->txstamp_ack;
	}
}

/* Collapses two adjacent SKB's during retransmission. */
static bool tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = skb_rb_next(skb);
	int next_skb_size;

	next_skb_size = next_skb->len;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	if (next_skb_size && !tcp_skb_shift(skb, next_skb, 1, next_skb_size))
		return false;

	tcp_highest_sack_replace(sk, next_skb, skb);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;
	TCP_SKB_CB(skb)->eor = TCP_SKB_CB(next_skb)->eor;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb));

	tcp_skb_collapse_tstamp(skb, next_skb);

	tcp_rtx_queue_unlink_and_free(next_skb, sk);
	return true;
}

/* Check if coalescing SKBs is legal. */
static bool tcp_can_collapse(const struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_skb_pcount(skb) > 1)
		return false;
	if (skb_cloned(skb))
		return false;
	/* Some heuristics for collapsing over SACK'd could be invented */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return false;

	return true;
}

/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
				     int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	bool first = true;

	if (!sock_net(sk)->ipv4.sysctl_tcp_retrans_collapse)
		return;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		return;

	skb_rbtree_walk_from_safe(skb, tmp) {
		if (!tcp_can_collapse(sk, skb))
			break;

		if (!tcp_skb_can_collapse(to, skb))
			break;

		space -= skb->len;

		if (first) {
			first = false;
			continue;
		}

		if (space < 0)
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp)))
			break;

		if (!tcp_collapse_retrans(sk, to))
			break;
	}
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
// 该函数重传一个skb。策略决定和重传队列状态的更新都由调用者决定。
// 如果阻止发送的错误发生将会返回一个非零值
int __tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cur_mss;
	int diff, len, err;


	/* Inconclusive MTU probe */
	// 如果路径MTU发现还没有结束，无论是何种原因导致的重传，都将其标志位结束
	if (icsk->icsk_mtup.probe_size)
		icsk->icsk_mtup.probe_size = 0;

	// 是否还在传送qdisc或者驱动器队列
	if (skb_still_in_host_queue(sk, skb))
		return -EBUSY;

	// 检测重传的段，接收方是否已经收到其部分或者全局。如果收到全部，则说明TCP的实现代码有BUG。
	// 如果收到部分，则需要调整TCP段的负载，即删除SKB存储区前部的接收方已接收到的数据
	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (unlikely(before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))) {
			WARN_ON_ONCE(1);
			return -EINVAL;
		}
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}
	
	// 根据目的地址等条件获取路由。如果获取路由失败，则不能发送。这里的"rebuild_header"
	// 似乎有些奇怪，从字面上理解会以为是重构首部，实际上是查询路由。
	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	// 得到当前的mss
	cur_mss = tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	// 如果接收方已经缩小了接收窗口，且待重传的SKB已经不在新窗口内，则不能再重传该SKB，
	// 但有一种情况例外，那就是当接收窗口缩小到零，在这种情况下，会发送零窗口探测段。
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	// 计算可以传递的最大长度
	len = cur_mss * segs;
	// 如果SKB中的数据长度大于mss，则需要对该SKB分段。这种情况一般出现在启动了路径MTU,
	// 接收到需要分片ICMP目的不可达报文时，如果ICMP中下一跳的PMTU小于当前PMTU，
	// 则更新当前PMTU以及当前的MSS
	if (skb->len > len) {
		if (tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb, len,
				 cur_mss, GFP_ATOMIC))
			return -ENOMEM; /* We'll try again later. */
	} else {
		if (skb_unclone_keeptruesize(skb, GFP_ATOMIC))
			return -ENOMEM;

		diff = tcp_skb_pcount(skb);
		tcp_set_skb_tso_segs(skb, cur_mss);
		diff -= tcp_skb_pcount(skb);
		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
		if (skb->len < cur_mss)
			tcp_retrans_try_collapse(sk, skb, cur_mss);
	}

	/* RFC3168, section 6.1.1.1. ECN fallback */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN_ECN) == TCPHDR_SYN_ECN)
		tcp_ecn_clear_syn(sk, skb);

	/* Update global and local TCP statistics. */
	// 更新全局和本地的TCP统计
	segs = tcp_skb_pcount(skb);
	TCP_ADD_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS, segs);
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
	// 增加总重传次数
	tp->total_retrans += segs;
	// 增加总重传的字节数
	tp->bytes_retrans += skb->len;

	/* make sure skb->data is aligned on arches that require it
	 * and check if ack-trimming & collapsing extended the headroom
	 * beyond what csum_start can cover.
	 */
	// 确保skb-data在结构上对齐并且检查ack-trimming和collapsing是否将headroom
	// 扩展超出csum_start可以覆盖的范围
	if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) ||
		     skb_headroom(skb) >= 0xFFFF)) {
		struct sk_buff *nskb;

		tcp_skb_tsorted_save(skb) {
			nskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
			if (nskb) {
				nskb->dev = NULL;
				err = tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC);
			} else {
				err = -ENOBUFS;
			}
		} tcp_skb_tsorted_restore(skb);

		if (!err) {
			tcp_update_skb_after_send(sk, skb, tp->tcp_wstamp_ns);
			tcp_rate_skb_sent(sk, skb);
		}
	} else {
		// 将tcp段发送出去
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	}

	/* To avoid taking spuriously low RTT samples based on a timestamp
	 * for a transmit that never happened, always mark EVER_RETRANS
	 */
	// 为了避免基于时间戳为从未发送的传输获取虚假的低RTT样本，请始终标志位EVER_RETRANS
	// 重传标志
	TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;

	if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RETRANS_CB_FLAG))
		tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RETRANS_CB,
				  TCP_SKB_CB(skb)->seq, segs, err);

	if (likely(!err)) {
		trace_tcp_retransmit_skb(sk, skb);
	} else if (err != -EBUSY) {
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL, segs);
	}
	return err;
}

int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int err = __tcp_retransmit_skb(sk, skb, segs);
	
	// 如果重传成功
	if (err == 0) {
#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
			net_dbg_ratelimited("retrans_out leaked\n");
		}
#endif
		// 设置上重传的标志
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		// 增加重传但是没有确认的数量
		tp->retrans_out += tcp_skb_pcount(skb);
	}

	/* Save stamp of the first (attempted) retransmit. */
	// 保存第一次重传的时间戳
	if (!tp->retrans_stamp)
		tp->retrans_stamp = tcp_skb_timestamp(skb);

	// 增加可以撤销的重传的段
	if (tp->undo_retrans < 0)
		tp->undo_retrans = 0;
	tp->undo_retrans += tcp_skb_pcount(skb);
	return err;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb, *rtx_head, *hole = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	bool rearm_timer = false;
	u32 max_segs;
	int mib_idx;

	if (!tp->packets_out)
		return;

	rtx_head = tcp_rtx_queue_head(sk);
	skb = tp->retransmit_skb_hint ?: rtx_head;
	max_segs = tcp_tso_segs(sk, tcp_current_mss(sk));
	skb_rbtree_walk_from(skb) {
		__u8 sacked;
		int segs;

		if (tcp_pacing_check(sk))
			break;

		/* we could do better than to assign each time */
		if (!hole)
			tp->retransmit_skb_hint = skb;

		segs = tcp_snd_cwnd(tp) - tcp_packets_in_flight(tp);
		if (segs <= 0)
			break;
		sacked = TCP_SKB_CB(skb)->sacked;
		/* In case tcp_shift_skb_data() have aggregated large skbs,
		 * we need to make sure not sending too bigs TSO packets
		 */
		segs = min_t(int, segs, max_segs);

		if (tp->retrans_out >= tp->lost_out) {
			break;
		} else if (!(sacked & TCPCB_LOST)) {
			if (!hole && !(sacked & (TCPCB_SACKED_RETRANS|TCPCB_SACKED_ACKED)))
				hole = skb;
			continue;

		} else {
			if (icsk->icsk_ca_state != TCP_CA_Loss)
				mib_idx = LINUX_MIB_TCPFASTRETRANS;
			else
				mib_idx = LINUX_MIB_TCPSLOWSTARTRETRANS;
		}

		if (sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))
			continue;

		if (tcp_small_queue_check(sk, skb, 1))
			break;

		if (tcp_retransmit_skb(sk, skb, segs))
			break;

		NET_ADD_STATS(sock_net(sk), mib_idx, tcp_skb_pcount(skb));

		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += tcp_skb_pcount(skb);

		if (skb == rtx_head &&
		    icsk->icsk_pending != ICSK_TIME_REO_TIMEOUT)
			rearm_timer = true;

	}
	if (rearm_timer)
		tcp_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				     inet_csk(sk)->icsk_rto,
				     TCP_RTO_MAX);
}

/* We allow to exceed memory limits for FIN packets to expedite
 * connection tear down and (memory) recovery.
 * Otherwise tcp_send_fin() could be tempted to either delay FIN
 * or even be forced to close flow without any FIN.
 * In general, we want to allow one skb per socket to avoid hangs
 * with edge trigger epoll()
 */
void sk_forced_mem_schedule(struct sock *sk, int size)
{
	int amt;

	if (size <= sk->sk_forward_alloc)
		return;
	amt = sk_mem_pages(size);
	sk->sk_forward_alloc += amt * SK_MEM_QUANTUM;
	sk_memory_allocated_add(sk, amt);

	if (mem_cgroup_sockets_enabled && sk->sk_memcg)
		mem_cgroup_charge_skmem(sk->sk_memcg, amt,
					gfp_memcg_charge() | __GFP_NOFAIL);
}

/* Send a FIN. The caller locks the socket for us.
 * We should try to send a FIN packet really hard, but eventually give up.
 */
void tcp_send_fin(struct sock *sk)
{
	struct sk_buff *skb, *tskb, *tail = tcp_write_queue_tail(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* Optimization, tack on the FIN if we have one skb in write queue and
	 * this skb was not yet sent, or we are under memory pressure.
	 * Note: in the latter case, FIN packet will be sent after a timeout,
	 * as TCP stack thinks it has already been transmitted.
	 */
	tskb = tail;
	if (!tskb && tcp_under_memory_pressure(sk))
		tskb = skb_rb_last(&sk->tcp_rtx_queue);

	if (tskb) {
		TCP_SKB_CB(tskb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(tskb)->end_seq++;
		tp->write_seq++;
		if (!tail) {
			/* This means tskb was already sent.
			 * Pretend we included the FIN on previous transmit.
			 * We need to set tp->snd_nxt to the value it would have
			 * if FIN had been sent. This is because retransmit path
			 * does not change tp->snd_nxt.
			 */
			WRITE_ONCE(tp->snd_nxt, tp->snd_nxt + 1);
			return;
		}
	} else {
		skb = alloc_skb_fclone(MAX_TCP_HEADER, sk->sk_allocation);
		if (unlikely(!skb))
			return;

		INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		skb_reserve(skb, MAX_TCP_HEADER);
		sk_forced_mem_schedule(sk, skb->truesize);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPHDR_ACK | TCPHDR_FIN);
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, tcp_current_mss(sk), TCP_NAGLE_OFF);
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by RFC 2525, section 2.17.  -DaveM
 */
void tcp_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTRSTS);

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
			     TCPHDR_ACK | TCPHDR_RST);
	tcp_mstamp_refresh(tcp_sk(sk));
	/* Send it off. */
	if (tcp_transmit_skb(sk, skb, 0, priority))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);

	/* skb of trace_tcp_send_reset() keeps the skb that caused RST,
	 * skb here is different to the troublesome skb, so use NULL
	 */
	trace_tcp_send_reset(sk, NULL);
}

/* Send a crossed SYN-ACK during socket establishment.
 * WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff *skb;

	skb = tcp_rtx_queue_head(sk);
	if (!skb || !(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
		pr_err("%s: wrong queue state\n", __func__);
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb;

			tcp_skb_tsorted_save(skb) {
				nskb = skb_copy(skb, GFP_ATOMIC);
			} tcp_skb_tsorted_restore(skb);
			if (!nskb)
				return -ENOMEM;
			INIT_LIST_HEAD(&nskb->tcp_tsorted_anchor);
			tcp_highest_sack_replace(sk, skb, nskb);
			tcp_rtx_queue_unlink_and_free(skb, sk);
			__skb_header_release(nskb);
			tcp_rbtree_insert(&sk->tcp_rtx_queue, nskb);
			sk_wmem_queued_add(sk, nskb->truesize);
			sk_mem_charge(sk, nskb->truesize);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ACK;
		tcp_ecn_send_synack(sk, skb);
	}
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

/**
 * tcp_make_synack - Allocate one skb and build a SYNACK packet.
 * @sk: listener socket
 * @dst: dst entry attached to the SYNACK. It is consumed and caller
 *       should not use it again.
 * @req: request_sock pointer
 * @foc: cookie for tcp fast open
 * @synack_type: Type of synack to prepare
 * @syn_skb: SYN packet just received.  It could be NULL for rtx case.
 */
// 分配一个skb，并且构建一个SYNACK包，用于建立连接
// tcp_make_synack用于构造一个SYN+ACK段，并初始化TCP首部及SKB中各字段的项，填入相应的选项，
// 如MSS、SACK、窗口扩大因子、时间戳等，然后将该段发送给对端。
// sk：为处理服务端连接过程的侦听控制块
// dst：为已获取到发送SYN+ACK到客户端的路由缓存项。
// req：为连接建立的连接请求块
struct sk_buff *tcp_make_synack(const struct sock *sk, struct dst_entry *dst,
				struct request_sock *req,
				struct tcp_fastopen_cookie *foc,
				enum tcp_synack_type synack_type,
				struct sk_buff *syn_skb)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_md5sig_key *md5 = NULL;
	struct tcp_out_options opts;
	struct sk_buff *skb;
	int tcp_header_size;
	struct tcphdr *th;
	int mss;
	u64 now;
	// 调用alloc_skb分配SKB
	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (unlikely(!skb)) {
		dst_release(dst);
		return NULL;
	}
	/* Reserve space for headers. */
	// 为MAC层、IP层、TCP层首部预留必要的空间
	skb_reserve(skb, MAX_TCP_HEADER);

	switch (synack_type) {
	case TCP_SYNACK_NORMAL:
		skb_set_owner_w(skb, req_to_sk(req));
		break;
	case TCP_SYNACK_COOKIE:
		/* Under synflood, we do not attach skb to a socket,
		 * to avoid false sharing.
		 */
		break;
	case TCP_SYNACK_FASTOPEN:
		/* sk is a const pointer, because we want to express multiple
		 * cpu might call us concurrently.
		 * sk->sk_wmem_alloc in an atomic, we can promote to rw.
		 */
		skb_set_owner_w(skb, (struct sock *)sk);
		break;
	}
	// 设置dst
	skb_dst_set(skb, dst);

	mss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	memset(&opts, 0, sizeof(opts));
	now = tcp_clock_ns();
#ifdef CONFIG_SYN_COOKIES
	if (unlikely(synack_type == TCP_SYNACK_COOKIE && ireq->tstamp_ok))
		skb_set_delivery_time(skb, cookie_init_timestamp(req, now),
				      true);
	else
#endif
	{
		skb_set_delivery_time(skb, now, true);
		if (!tcp_rsk(req)->snt_synack) /* Timestamp first SYNACK */
			tcp_rsk(req)->snt_synack = tcp_skb_timestamp_us(skb);
	}
	// 通过TCP MD5签名来保护BGP会话操作相关
#ifdef CONFIG_TCP_MD5SIG
	rcu_read_lock();
	md5 = tcp_rsk(req)->af_specific->req_md5_lookup(sk, req_to_sk(req));
#endif
	skb_set_hash(skb, tcp_rsk(req)->txhash, PKT_HASH_TYPE_L4);
	/* bpf program will be interested in the tcp_flags */
	TCP_SKB_CB(skb)->tcp_flags = TCPHDR_SYN | TCPHDR_ACK;
	// 得到tcp头部的长度
	tcp_header_size = tcp_synack_options(sk, req, mss, skb, &opts, md5,
					     foc, synack_type,
					     syn_skb) + sizeof(*th);
	
	// 初始化TCP首部中的各字段和SKB中的各项。
	// 在SKB中预留TCP首部空间
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	th = (struct tcphdr *)skb->data;
	// 将TCP首部清零
	memset(th, 0, sizeof(struct tcphdr));
	// 设置TCP首部中各字段，包括SYN、ACK、ECN标志位、源地址及目标地址。
	th->syn = 1;
	th->ack = 1;
	tcp_ecn_make_synack(req, th);
	th->source = htons(ireq->ir_num);
	th->dest = ireq->ir_rmt_port;

	skb->mark = ireq->ir_mark;
	skb->ip_summed = CHECKSUM_PARTIAL;
	// 设置TCP首部中的序号和确认序号。
	th->seq = htonl(tcp_rsk(req)->snt_isn);
	/* XXX data is queued and acked as is. No buffer/window check */
	th->ack_seq = htonl(tcp_rsk(req)->rcv_nxt);

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	//设置SYN+ACK段中的窗口大小
	th->window = htons(min(req->rsk_rcv_wnd, 65535U));
	// 写入TCP头选项
	tcp_options_write(th, NULL, &opts);
	th->doff = (tcp_header_size >> 2);
	__TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTSEGS);

#ifdef CONFIG_TCP_MD5SIG
	/* Okay, we have all we need - do the md5 hash if needed */
	if (md5)
		tcp_rsk(req)->af_specific->calc_md5_hash(opts.hash_location,
					       md5, req_to_sk(req), skb);
	rcu_read_unlock();
#endif

	bpf_skops_write_hdr_opt((struct sock *)sk, skb, req, syn_skb,
				synack_type, &opts);

	skb_set_delivery_time(skb, now, true);
	tcp_add_tx_delay(skb, tp);

	return skb;
}
EXPORT_SYMBOL(tcp_make_synack);

static void tcp_ca_dst_init(struct sock *sk, const struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_congestion_ops *ca;
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);

	if (ca_key == TCP_CA_UNSPEC)
		return;

	rcu_read_lock();
	ca = tcp_ca_find_key(ca_key);
	if (likely(ca && bpf_try_module_get(ca, ca->owner))) {
		bpf_module_put(icsk->icsk_ca_ops, icsk->icsk_ca_ops->owner);
		icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
		icsk->icsk_ca_ops = ca;
	}
	rcu_read_unlock();
}

/* Do all connect socket setups that can be done AF independent. */
static void tcp_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;
	u32 rcv_wnd;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr);
	if (sock_net(sk)->ipv4.sysctl_tcp_timestamps)
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk))
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_mtup_init(sk);
	tcp_sync_mss(sk, dst_mtu(dst));

	tcp_ca_dst_init(sk, dst);

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	tcp_initialize_rcv_mss(sk);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (tp->window_clamp > tcp_full_space(sk) || tp->window_clamp == 0))
		tp->window_clamp = tcp_full_space(sk);

	rcv_wnd = tcp_rwnd_init_bpf(sk);
	if (rcv_wnd == 0)
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);

	tcp_select_initial_window(sk, tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sock_net(sk)->ipv4.sysctl_tcp_window_scaling,
				  &rcv_wscale,
				  rcv_wnd);

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, 0);
	tcp_write_queue_purge(sk);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	WRITE_ONCE(tp->snd_nxt, tp->write_seq);

	if (likely(!tp->repair))
		tp->rcv_nxt = 0;
	else
		tp->rcv_tstamp = tcp_jiffies32;
	tp->rcv_wup = tp->rcv_nxt;
	WRITE_ONCE(tp->copied_seq, tp->rcv_nxt);

	inet_csk(sk)->icsk_rto = tcp_timeout_init(sk);
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);
}

static void tcp_connect_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	tcb->end_seq += skb->len;
	__skb_header_release(skb);
	sk_wmem_queued_add(sk, skb->truesize);
	sk_mem_charge(sk, skb->truesize);
	WRITE_ONCE(tp->write_seq, tcb->end_seq);
	tp->packets_out += tcp_skb_pcount(skb);
}

/* Build and send a SYN with data and (cached) Fast Open cookie. However,
 * queue a data-only packet after the regular SYN, such that regular SYNs
 * are retransmitted on timeouts. Also if the remote SYN-ACK acknowledges
 * only the SYN sequence, the data are retransmitted in the first ACK.
 * If cookie is not cached or other error occurs, falls back to send a
 * regular SYN with Fast Open cookie request option.
 */
static int tcp_send_syn_data(struct sock *sk, struct sk_buff *syn)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_request *fo = tp->fastopen_req;
	int space, err = 0;
	struct sk_buff *syn_data;

	tp->rx_opt.mss_clamp = tp->advmss;  /* If MSS is not cached */
	if (!tcp_fastopen_cookie_check(sk, &tp->rx_opt.mss_clamp, &fo->cookie))
		goto fallback;

	/* MSS for SYN-data is based on cached MSS and bounded by PMTU and
	 * user-MSS. Reserve maximum option space for middleboxes that add
	 * private TCP options. The cost is reduced data space in SYN :(
	 */
	tp->rx_opt.mss_clamp = tcp_mss_clamp(tp, tp->rx_opt.mss_clamp);
	/* Sync mss_cache after updating the mss_clamp */
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);

	space = __tcp_mtu_to_mss(sk, icsk->icsk_pmtu_cookie) -
		MAX_TCP_OPTION_SPACE;

	space = min_t(size_t, space, fo->size);

	/* limit to order-0 allocations */
	space = min_t(size_t, space, SKB_MAX_HEAD(MAX_TCP_HEADER));

	syn_data = tcp_stream_alloc_skb(sk, space, sk->sk_allocation, false);
	if (!syn_data)
		goto fallback;
	memcpy(syn_data->cb, syn->cb, sizeof(syn->cb));
	if (space) {
		int copied = copy_from_iter(skb_put(syn_data, space), space,
					    &fo->data->msg_iter);
		if (unlikely(!copied)) {
			tcp_skb_tsorted_anchor_cleanup(syn_data);
			kfree_skb(syn_data);
			goto fallback;
		}
		if (copied != space) {
			skb_trim(syn_data, copied);
			space = copied;
		}
		skb_zcopy_set(syn_data, fo->uarg, NULL);
	}
	/* No more data pending in inet_wait_for_connect() */
	if (space == fo->size)
		fo->data = NULL;
	fo->copied = space;

	tcp_connect_queue_skb(sk, syn_data);
	if (syn_data->len)
		tcp_chrono_start(sk, TCP_CHRONO_BUSY);

	err = tcp_transmit_skb(sk, syn_data, 1, sk->sk_allocation);

	skb_set_delivery_time(syn, syn_data->skb_mstamp_ns, true);

	/* Now full SYN+DATA was cloned and sent (or not),
	 * remove the SYN from the original skb (syn_data)
	 * we keep in write queue in case of a retransmit, as we
	 * also have the SYN packet (with no data) in the same queue.
	 */
	TCP_SKB_CB(syn_data)->seq++;
	TCP_SKB_CB(syn_data)->tcp_flags = TCPHDR_ACK | TCPHDR_PSH;
	if (!err) {
		tp->syn_data = (fo->copied > 0);
		tcp_rbtree_insert(&sk->tcp_rtx_queue, syn_data);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT);
		goto done;
	}

	/* data was not sent, put it in write_queue */
	__skb_queue_tail(&sk->sk_write_queue, syn_data);
	tp->packets_out -= tcp_skb_pcount(syn_data);

fallback:
	/* Send a regular SYN with Fast Open cookie request option */
	if (fo->cookie.len > 0)
		fo->cookie.len = 0;
	err = tcp_transmit_skb(sk, syn, 1, sk->sk_allocation);
	if (err)
		tp->syn_fastopen = 0;
done:
	fo->cookie.len = -1;  /* Exclude Fast Open option for SYN retries */
	return err;
}

/* Build a SYN and send it off. */
// 创建一个SYN包并发出去
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);
	// 计算路由，如果没有路由，则返回主机不可达的错误
	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	// 初始化TCP连接
	tcp_connect_init(sk);

	// 如果repair位置1，直接结束连接
	if (unlikely(tp->repair)) {
		tcp_finish_connect(sk, NULL);
		return 0;
	}

	// 分配一个SKB
	buff = tcp_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
	if (unlikely(!buff))
		return -ENOBUFS;

	// 初始化skb，并自增write_seq 的值
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
	// 设置时间戳
	tcp_mstamp_refresh(tp);
	tp->retrans_stamp = tcp_time_stamp(tp);
	// 将当前的SKB插入到发送队列中
	tcp_connect_queue_skb(sk, buff);
	// ECN (Explicit Congestion Notification,)
	// 支持显式拥塞控制
	tcp_ecn_send_syn(sk, buff);
	tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);

	/* Send off SYN; include data in Fast Open. */
	// 发送SYN包，并且考虑快速打开的情况（就是连接建立的同事发送数据）
	err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
	      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	// 我们在 tcp_transmit_skb() 调用之后更改 tp->snd_nxt为了使这个数据包被计入 tcpOutSegs
	// send next 下一个待发送字节的序列号
	WRITE_ONCE(tp->snd_nxt, tp->write_seq);
	tp->pushed_seq = tp->write_seq;
	// 这里tcp_send_head返回值为sk->sk_write_queue,也就是指向当前的将要发送的buf的位置
	buff = tcp_send_head(sk);
	// 修正snd_nxt和pushed_seq得值
	if (unlikely(buff)) {
		WRITE_ONCE(tp->snd_nxt, TCP_SKB_CB(buff)->seq);
		tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
	}
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	// 设置超时重传计时器
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}
EXPORT_SYMBOL(tcp_connect);

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int ato = icsk->icsk_ack.ato;
	unsigned long timeout;

	if (ato > TCP_DELACK_MIN) {
		const struct tcp_sock *tp = tcp_sk(sk);
		int max_ato = HZ / 2;

		if (inet_csk_in_pingpong_mode(sk) ||
		    (icsk->icsk_ack.pending & ICSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use inet_csk(sk)->icsk_rto here, use results of rtt measurements
		 * directly.
		 */
		if (tp->srtt_us) {
			int rtt = max_t(int, usecs_to_jiffies(tp->srtt_us >> 3),
					TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	ato = min_t(u32, ato, inet_csk(sk)->icsk_delack_max);

	/* Stay within the limit we were given */
	timeout = jiffies + ato;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer is about to expire, send ACK now. */
		if (time_before_eq(icsk->icsk_ack.timeout, jiffies + (ato >> 2))) {
			tcp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER;
	icsk->icsk_ack.timeout = timeout;
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout);
}

/* This routine sends an ack and also updates the window. */
// 该函数用于发送一个ack并且更新窗口
void __tcp_send_ack(struct sock *sk, u32 rcv_nxt)
{
	struct sk_buff *buff;

	/* If we have been reset, we may not send again. */
	// 如果TCP在CLOSE状态，就不发送了
	if (sk->sk_state == TCP_CLOSE)
		return;

	/* We are not putting this on the write queue, so
	 * tcp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	// 从ACK段分配一个SKB，如果分配失败则在启动延时确认定时器后返回。
	buff = alloc_skb(MAX_TCP_HEADER,
			 sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	if (unlikely(!buff)) {
		struct inet_connection_sock *icsk = inet_csk(sk);
		unsigned long delay;

		delay = TCP_DELACK_MAX << icsk->icsk_ack.retry;
		if (delay < TCP_RTO_MAX)
			icsk->icsk_ack.retry++;
		inet_csk_schedule_ack(sk);
		icsk->icsk_ack.ato = TCP_ATO_MIN;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK, delay, TCP_RTO_MAX);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	// 为TCP头和控制位保留空间
	skb_reserve(buff, MAX_TCP_HEADER);
	// 设置TCP序号和发送时间
	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPHDR_ACK);

	/* We do not want pure acks influencing TCP Small Queues or fq/pacing
	 * too much.
	 * SKB_TRUESIZE(max(1 .. 66, MAX_TCP_HEADER)) is unfortunately ~784
	 */
	skb_set_tcp_pure_ack(buff);

	/* Send it off, this clears delayed acks for us. */
	// 发送出去，并且清除延迟的确认
	__tcp_transmit_skb(sk, buff, 0, (__force gfp_t)0, rcv_nxt);
}
EXPORT_SYMBOL_GPL(__tcp_send_ack);

// 发送一个ACK，同时更新窗口
void tcp_send_ack(struct sock *sk)
{
	__tcp_send_ack(sk, tcp_sk(sk)->rcv_nxt);
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER,
			sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	if (!skb)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPHDR_ACK);
	NET_INC_STATS(sock_net(sk), mib);
	return tcp_transmit_skb(sk, skb, 0, (__force gfp_t)0);
}

/* Called from setsockopt( ... TCP_REPAIR ) */
void tcp_send_window_probe(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED) {
		tcp_sk(sk)->snd_wl1 = tcp_sk(sk)->rcv_nxt - 1;
		tcp_mstamp_refresh(tcp_sk(sk));
		tcp_xmit_probe_skb(sk, 0, LINUX_MIB_TCPWINPROBE);
	}
}

/* Initiate keepalive or window probe from timer. */
// 从计时器启动keepalive或窗口探测
int tcp_write_wakeup(struct sock *sk, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	// 如果传输控制块处于关闭状态，直接返回失败
	if (sk->sk_state == TCP_CLOSE)
		return -1;
	// 得到发送队列
	skb = tcp_send_head(sk);
	// 如果发送队列中有段需要发送，并且最先待发送得段至少有一部分在对端接收窗口内，
	// 那么可以直接利用该待发送得段来发送持续探测段。
	if (skb && before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		// 获取当前的MSS以及待分段的段长。分段得到的新段必须在对方接收窗口内，待分段的段长
		// 初始化为tp->snd_una + tp->snd_wnd -SKB.seq;
		unsigned int mss = tcp_current_mss(sk);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
		// 如果该段的序号已经大于pushed_seq，则需要更新pushed_seq
		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		// 如果分段的段长大于剩余等待发送数据，或者段长大于当前MSS，则对该段进行分段，
		// 分段段长取待分段段长与当前MSS两者中的最小值，以保证只发送一个段到对方。
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
			if (tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
					 skb, seg_size, mss, GFP_ATOMIC))
				return -1;
		} else if (!tcp_skb_pcount(skb))
			tcp_set_skb_tso_segs(skb, mss);

		// 将探测段发送出去，如果发送成功，则更新发送队首等标志。
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_event_new_data_sent(sk, skb);
		return err;
	} 
	// 如果发送队列为空，则构造并发送一个序号已确认、长度为零的段给对端。
	// 如果处于紧急模式，则多发送一个序号为SND.una的段给对端
	else {
		if (between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			tcp_xmit_probe_skb(sk, 1, mib);
		return tcp_xmit_probe_skb(sk, 0, mib);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
// 发生窗口探测超时。 如果窗口未关闭，则发送部分数据包，否则进行零探测。
void tcp_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	unsigned long timeout;
	int err;

	err = tcp_write_wakeup(sk, LINUX_MIB_TCPWINPROBE);

	if (tp->packets_out || tcp_write_queue_empty(sk)) {
		/* Cancel probe timer, if it is not required. */
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		icsk->icsk_probes_tstamp = 0;
		return;
	}

	icsk->icsk_probes_out++;
	if (err <= 0) {
		if (icsk->icsk_backoff < net->ipv4.sysctl_tcp_retries2)
			icsk->icsk_backoff++;
		timeout = tcp_probe0_when(sk, TCP_RTO_MAX);
	} else {
		/* If packet was not sent due to local congestion,
		 * Let senders fight for local resources conservatively.
		 */
		timeout = TCP_RESOURCE_PROBE_INTERVAL;
	}

	timeout = tcp_clamp_probe0_to_user_timeout(sk, timeout);
	tcp_reset_xmit_timer(sk, ICSK_TIME_PROBE0, timeout, TCP_RTO_MAX);
}

int tcp_rtx_synack(const struct sock *sk, struct request_sock *req)
{
	const struct tcp_request_sock_ops *af_ops = tcp_rsk(req)->af_specific;
	struct flowi fl;
	int res;

	/* Paired with WRITE_ONCE() in sock_setsockopt() */
	if (READ_ONCE(sk->sk_txrehash) == SOCK_TXREHASH_ENABLED)
		tcp_rsk(req)->txhash = net_tx_rndhash();
	res = af_ops->send_synack(sk, NULL, &fl, req, NULL, TCP_SYNACK_NORMAL,
				  NULL);
	if (!res) {
		TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
		if (unlikely(tcp_passive_fastopen(sk)))
			tcp_sk(sk)->total_retrans++;
		trace_tcp_retransmit_synack(sk, req);
	}
	return res;
}
EXPORT_SYMBOL(tcp_rtx_synack);
