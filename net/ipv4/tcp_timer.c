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

#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>

static u32 tcp_clamp_rto_to_user_timeout(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 elapsed, start_ts;
	s32 remaining;

	start_ts = tcp_sk(sk)->retrans_stamp;
	if (!icsk->icsk_user_timeout)
		return icsk->icsk_rto;
	elapsed = tcp_time_stamp(tcp_sk(sk)) - start_ts;
	remaining = icsk->icsk_user_timeout - elapsed;
	if (remaining <= 0)
		return 1; /* user timeout has passed; fire ASAP */

	return min_t(u32, icsk->icsk_rto, msecs_to_jiffies(remaining));
}

u32 tcp_clamp_probe0_to_user_timeout(const struct sock *sk, u32 when)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 remaining;
	s32 elapsed;

	if (!icsk->icsk_user_timeout || !icsk->icsk_probes_tstamp)
		return when;

	elapsed = tcp_jiffies32 - icsk->icsk_probes_tstamp;
	if (unlikely(elapsed < 0))
		elapsed = 0;
	remaining = msecs_to_jiffies(icsk->icsk_user_timeout) - elapsed;
	remaining = max_t(u32, remaining, TCP_TIMEOUT_MIN);

	return min_t(u32, remaining, when);
}

/**
 *  tcp_write_err() - close socket and save error info
 *  @sk:  The socket the error has appeared on.
 *
 *  Returns: Nothing (void)
 */

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk_error_report(sk);

	tcp_write_queue_purge(sk);
	tcp_done(sk);
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/**
 *  tcp_out_of_resources() - Close socket if out of resources
 *  @sk:        pointer to current socket
 *  @do_reset:  send a last packet with reset flag
 *
 *  Do not allow orphaned sockets to eat all our resources.
 *  This is direct violation of TCP specs, but it is required
 *  to prevent DoS attacks. It is called when a retransmission timeout
 *  or zero probe timeout occurs on orphaned socket.
 *
 *  Also close if our net namespace is exiting; in that case there is no
 *  hope of ever communicating again since all netns interfaces are already
 *  down (or about to be down), and we need to release our dst references,
 *  which have been moved to the netns loopback interface, so the namespace
 *  can finish exiting.  This condition is only possible if we are a kernel
 *  socket, as those do not hold references to the namespace.
 *
 *  Criteria is still not confirmed experimentally and may change.
 *  We kill the socket, if:
 *  1. If number of orphaned sockets exceeds an administratively configured
 *     limit.
 *  2. If we have strong memory pressure.
 *  3. If our net namespace is exiting.
 */
static int tcp_out_of_resources(struct sock *sk, bool do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_jiffies32 - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

	if (tcp_check_oom(sk, shift)) {
		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_jiffies32 - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = true;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}

	if (!check_net(sock_net(sk))) {
		/* Not possible to send reset; just close */
		tcp_done(sk);
		return 1;
	}

	return 0;
}

/**
 *  tcp_orphan_retries() - Returns maximal number of retries on an orphaned socket
 *  @sk:    Pointer to the current socket.
 *  @alive: bool, socket alive state
 */
static int tcp_orphan_retries(struct sock *sk, bool alive)
{
	int retries = sock_net(sk)->ipv4.sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	const struct net *net = sock_net(sk);
	int mss;

	/* Black hole detection */
	if (!net->ipv4.sysctl_tcp_mtu_probing)
		return;

	if (!icsk->icsk_mtup.enabled) {
		icsk->icsk_mtup.enabled = 1;
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
	} else {
		mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
		mss = min(net->ipv4.sysctl_tcp_base_mss, mss);
		mss = max(mss, net->ipv4.sysctl_tcp_mtu_probe_floor);
		mss = max(mss, net->ipv4.sysctl_tcp_min_snd_mss);
		icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
	}
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
}

static unsigned int tcp_model_timeout(struct sock *sk,
				      unsigned int boundary,
				      unsigned int rto_base)
{
	unsigned int linear_backoff_thresh, timeout;

	linear_backoff_thresh = ilog2(TCP_RTO_MAX / rto_base);
	if (boundary <= linear_backoff_thresh)
		timeout = ((2 << boundary) - 1) * rto_base;
	else
		timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
			(boundary - linear_backoff_thresh) * TCP_RTO_MAX;
	return jiffies_to_msecs(timeout);
}
/**
 *  retransmits_timed_out() - returns true if this connection has timed out
 *  @sk:       The current socket
 *  @boundary: max number of retransmissions
 *  @timeout:  A custom timeout value.
 *             If set to 0 the default timeout is calculated and used.
 *             Using TCP_RTO_MIN and the number of unsuccessful retransmits.
 *
 * The default "timeout" value this function can calculate and use
 * is equivalent to the timeout of a TCP Connection
 * after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN.
 */

static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  unsigned int timeout)
{
	unsigned int start_ts;

	if (!inet_csk(sk)->icsk_retransmits)
		return false;

	start_ts = tcp_sk(sk)->retrans_stamp;
	if (likely(timeout == 0)) {
		unsigned int rto_base = TCP_RTO_MIN;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			rto_base = tcp_timeout_init(sk);
		timeout = tcp_model_timeout(sk, boundary, rto_base);
	}

	return (s32)(tcp_time_stamp(tcp_sk(sk)) - start_ts - timeout) >= 0;
}

/* A write timeout has occurred. Process the after effects. */
// 当发生重传以后，需要检测当前的资源使用情况。
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	bool expired = false, do_reset;
	int retry_until;
	// 在建立连接阶段时
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		// 需要检测使用的路由缓存项，
		if (icsk->icsk_retransmits)
			__dst_negative_advice(sk);
		// 并获取重试次数的最大值
		retry_until = icsk->icsk_syn_retries ? : net->ipv4.sysctl_tcp_syn_retries;
		expired = icsk->icsk_retransmits >= retry_until;
	} else {
		// 系统启动路径MTU发现时，如果路径MTU发现的控制数据块中的开关没有开启，则将其开启，
		// 并根据PMTU同步MSS。否则，将当前路径MTU发现区间左端点的一半作为新区间左端点重新
		// 设定路径MTU的发现区间，并根据路径MTU同步MSS。

		// 如果重传次数达到sysctl_tcp_retries1时
		if (retransmits_timed_out(sk, net->ipv4.sysctl_tcp_retries1, 0)) {
			/* Black hole detection */
			// 则需要进行黑洞检测。
			tcp_mtu_probing(icsk, sk);
			// 完成黑洞检测后还需检测使用的路由缓存项。
			__dst_negative_advice(sk);
		}

		// 如果当前套接口已端口并即将关闭，则需要对当前使用的资源进行检测。
		// 当前的孤儿套接口数量达到tcp_max_orphans或者当前已使用内存达到
		// 硬件性能限制时，需要即刻关闭该套接口，这虽然不符合TCP的规范，但
		// 为了防止DOS攻击必须这么处理。
		retry_until = net->ipv4.sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
			const bool alive = icsk->icsk_rto < TCP_RTO_MAX;

			retry_until = tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				!retransmits_timed_out(sk, retry_until, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}
	// 检测重传次数是否达到建立连接重传上限，超时重传上限或确认连接异常期间重试上限三种上限之一
	if (!expired)
		expired = retransmits_timed_out(sk, retry_until,
						icsk->icsk_user_timeout);
	tcp_fastopen_active_detect_blackhole(sk, expired);

	if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RTO_CB_FLAG))
		tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RTO_CB,
				  icsk->icsk_retransmits,
				  icsk->icsk_rto, (int)expired);

	// 如果重传次数已经达到建立连接重传上限、超时重传上限或确认连接异常期间重试上限三种上限之一时，
	// 都必须关闭套接口，并且需要报告相应错误。
	if (expired) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}

	if (sk_rethink_txhash(sk)) {
		tp->timeout_rehash++;
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEOUTREHASH);
	}

	return 0;
}

/* Called with BH disabled */
void tcp_delack_timer_handler(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	// 回收缓存
	sk_mem_reclaim_partial(sk);
	// 如果TCP状态为CLOSE或者LISTEN，或者没有启动延时发送ACK定时器，则无需作进一步处理。
	if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)) ||
	    !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;
	// 如果超时时间还未到，则重新复位定时器，然后退出。
	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}
	// 检测完成后，正式进入延迟确认处理之前，需去掉ICSK_ACK_TIMER标记。
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;
	// 如果此时有ACK需要发送，则调用tcp_send_ack()函数发送ACK段，在发送ACK段之前
	// 先离开pingpong模式，并重新设定延时确认的估算值。
	if (inet_csk_ack_scheduled(sk)) {
		if (!inet_csk_in_pingpong_mode(sk)) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			inet_csk_exit_pingpong_mode(sk);
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}
		tcp_mstamp_refresh(tcp_sk(sk));
		tcp_send_ack(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}

out:
	if (tcp_under_memory_pressure(sk))
		sk_mem_reclaim(sk);
}


/**
 *  tcp_delack_timer() - The TCP delayed ACK timeout handler
 *  @t:  Pointer to the timer. (gets casted to struct sock *)
 *
 *  This function gets (indirectly) called when the kernel timer for a TCP packet
 *  of this socket expires. Calls tcp_delack_timer_handler() to do the actual work.
 *
 *  Returns: Nothing (void)
 */
// TCP延迟ACK超时处理程序
// 延时ACK定时器在TCP收到必须被确认但无需马上发出确认的段时设定，TCP在200m后发送确认响应，
// 如果在这200ms内，有数据要在该连接上发送，延时ACK响应就可以随数据一起发送回对端，称为
// 捎带确认。
static void tcp_delack_timer(struct timer_list *t)
{
	struct inet_connection_sock *icsk =
			from_timer(icsk, t, icsk_delack_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		tcp_delack_timer_handler(sk);
	} else {
		// 如果传输控制块已被用户进程锁定，则此时不能做处理，只能重新设置定时器超时时间，
		// 同时设置blocked标记。
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		/* deleguate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void tcp_probe_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb = tcp_send_head(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	if (tp->packets_out || !skb) {
		icsk->icsk_probes_out = 0;
		icsk->icsk_probes_tstamp = 0;
		return;
	}

	/* RFC 1122 4.2.2.17 requires the sender to stay open indefinitely as
	 * long as the receiver continues to respond probes. We support this by
	 * default and reset icsk_probes_out with incoming ACKs. But if the
	 * socket is orphaned or the user specifies TCP_USER_TIMEOUT, we
	 * kill the socket when the retry count and the time exceeds the
	 * corresponding system limit. We also implement similar policy when
	 * we use RTO to probe window in tcp_retransmit_timer().
	 */
	if (!icsk->icsk_probes_tstamp)
		icsk->icsk_probes_tstamp = tcp_jiffies32;
	else if (icsk->icsk_user_timeout &&
		 (s32)(tcp_jiffies32 - icsk->icsk_probes_tstamp) >=
		 msecs_to_jiffies(icsk->icsk_user_timeout))
		goto abort;

	max_probes = sock_net(sk)->ipv4.sysctl_tcp_retries2;
	if (sock_flag(sk, SOCK_DEAD)) {
		const bool alive = inet_csk_rto_backoff(icsk, TCP_RTO_MAX) < TCP_RTO_MAX;

		max_probes = tcp_orphan_retries(sk, alive);
		if (!alive && icsk->icsk_backoff >= max_probes)
			goto abort;
		if (tcp_out_of_resources(sk, true))
			return;
	}

	if (icsk->icsk_probes_out >= max_probes) {
abort:		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		tcp_send_probe0(sk);
	}
}

/*
 *	Timer for Fast Open socket to retransmit SYNACK. Note that the
 *	sk here is the child socket, not the parent (listener) socket.
 */
// 用于快速打开套接字重新传输 SYNACK 的计时器。 请注意，
// 这里的 sk 是子套接字，而不是父（侦听器）套接字。
static void tcp_fastopen_synack_timer(struct sock *sk, struct request_sock *req)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int max_retries = icsk->icsk_syn_retries ? :
	    sock_net(sk)->ipv4.sysctl_tcp_synack_retries + 1; /* add one more retry for fastopen */
	struct tcp_sock *tp = tcp_sk(sk);

	req->rsk_ops->syn_ack_timeout(req);

	if (req->num_timeout >= max_retries) {
		tcp_write_err(sk);
		return;
	}
	/* Lower cwnd after certain SYNACK timeout like tcp_init_transfer() */
	if (icsk->icsk_retransmits == 1)
		tcp_enter_loss(sk);
	/* XXX (TFO) - Unlike regular SYN-ACK retransmit, we ignore error
	 * returned from rtx_syn_ack() to make it more persistent like
	 * regular retransmit because if the child socket has been accepted
	 * it's not good to give up too easily.
	 */
	inet_rtx_syn_ack(sk, req);
	req->num_timeout++;
	icsk->icsk_retransmits++;
	if (!tp->retrans_stamp)
		tp->retrans_stamp = tcp_time_stamp(tp);
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
			  TCP_TIMEOUT_INIT << req->num_timeout, TCP_RTO_MAX);
}


/**
 *  tcp_retransmit_timer() - The TCP retransmit timeout handler
 *  @sk:  Pointer to the current socket.
 *
 *  This function gets called when the kernel timer for a TCP packet
 *  of this socket expires.
 *
 *  It handles retransmission, timer adjustment and other necessary measures.
 *
 *  Returns: Nothing (void)
 */
// TCP重传超时处理程序
void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock *req;
	struct sk_buff *skb;
	
	req = rcu_dereference_protected(tp->fastopen_rsk,
					lockdep_sock_is_held(sk));
	if (req) {
		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
			     sk->sk_state != TCP_FIN_WAIT1);
		// 用于快速打开套接字重新传输SYNACK的计时器
		tcp_fastopen_synack_timer(sk, req);
		/* Before we receive ACK to our SYN-ACK don't retransmit
		 * anything else (e.g., data or FIN segments).
		 */
		return;
	}
	// 如果此时从发送队列输出的段都已得到确认，则无需重传处理。
	if (!tp->packets_out)
		return;

	skb = tcp_rtx_queue_head(sk);
	if (WARN_ON_ONCE(!skb))
		return;

	tp->tlp_high_seq = 0;
	// 如果发送窗口已经关闭，套接口不在DEAD状态且TCP状态不处于连接过程中的情况。
	// 
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			net_dbg_ratelimited("Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
					    &inet->inet_daddr,
					    ntohs(inet->inet_dport),
					    inet->inet_num,
					    tp->snd_una, tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (sk->sk_family == AF_INET6) {
			net_dbg_ratelimited("Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
					    &sk->sk_v6_daddr,
					    ntohs(inet->inet_dport),
					    inet->inet_num,
					    tp->snd_una, tp->snd_nxt);
		}
#endif
		// 在重传的过程中如果超过重传超时上限TCP_RTO_MAX,还没有接收到对方的确认，
		// 则认为有错误发生，调用tcp_write_err()报告错误并关闭套接口，然后返回。
		if (tcp_jiffies32 - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
		// TCP进入拥塞控制的LOSS状态
		tcp_enter_loss(sk);
		// 重新传送重传队列中的第一个段。
		tcp_retransmit_skb(sk, skb, 1);
		// 由于发生了重传，传送控制块中目的路由项缓存需更新，因此将其清除。
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

	__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
	// 当发送重传之后，需要检测当前的资源使用情况和重传的次数。如果重传次数达到上限，
	// 则需要报告错误并强行关闭套接口。如果只是使用的资源达到使用的上限，则不进行此次重传。
	if (tcp_write_timeout(sk))
		goto out;
	// 如果重传次数为0，说明刚进入重传阶段，则根据不同的拥塞状态进行相关的数据统计。
	if (icsk->icsk_retransmits == 0) {
		int mib_idx = 0;

		if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else if ((icsk->icsk_ca_state == TCP_CA_Disorder) ||
			   tp->sacked_out) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		}
		if (mib_idx)
			__NET_INC_STATS(sock_net(sk), mib_idx);
	}
	// 调用tcp_enter_loss进入常规的RTO慢启动重传恢复阶段
	tcp_enter_loss(sk);
	// 递增累加重传次数icsk_retransmits
	icsk->icsk_retransmits++;
	// 如果发送重传队列上的第一个SKB失败，则复位重传定时器，等待下次重传。
	if (tcp_retransmit_skb(sk, tcp_rtx_queue_head(sk), 1) > 0) {
		/* Retransmission failed because of local congestion,
		 * Let senders fight for local resources conservatively.
		 */
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  TCP_RESOURCE_PROBE_INTERVAL,
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	// 递增指数退避算法指数icsk_backoff
	icsk->icsk_backoff++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || net->ipv4.sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);
	} else {
		/* Use normal (exponential) backoff */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
	// 完成重传以后，需重设重传超时时间，然后复位重传定时器，等待下次重传。
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  tcp_clamp_rto_to_user_timeout(sk), TCP_RTO_MAX);
	if (retransmits_timed_out(sk, net->ipv4.sysctl_tcp_retries1 + 1, 0))
		__sk_dst_reset(sk);

out:;
}

/* Called with bottom-half processing disabled.
   Called by tcp_write_timer() */
void tcp_write_timer_handler(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;
	// 如果是侦听或者关闭状态，或者未定义定时器事件，则无需处理
	if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)) ||
	    !icsk->icsk_pending)
		goto out;

	// 如果还未到定时器超时时间，则无需处理，重新设置定时器的下次的超时时间。
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}
	// 刷新TCP套接字的时钟
	tcp_mstamp_refresh(tcp_sk(sk));
	event = icsk->icsk_pending;
	// 由于重传定时器和持续定时器功能是共用了一个定时器实现的，因此需根据定时器事件
	// 来区分激活的是哪种定时器：如果event为ICSK_TIME_RETRANS，则调用tcp_retransmit_timer
	// 进行重传处理；如果为ICSK_TIME_PROBE0，则调用tcp_probe_timer进行持续定时器的处理。
	switch (event) {
	case ICSK_TIME_REO_TIMEOUT:
		tcp_rack_reo_timeout(sk);
		break;
	case ICSK_TIME_LOSS_PROBE:
		tcp_send_loss_probe(sk);
		break;
	case ICSK_TIME_RETRANS:
		icsk->icsk_pending = 0;
		tcp_retransmit_timer(sk);
		break;
	case ICSK_TIME_PROBE0:
		icsk->icsk_pending = 0;
		tcp_probe_timer(sk);
		break;
	}

out:
	sk_mem_reclaim(sk);
}

// 重传定时器在TCP发送数据时设定，如果定时器已超时而对端确认还没到，则TCP重传数据。
// 重传定时器的超时时间值是动态计算的，取决于TCP为该连接测量的往返时间以及该段已被重传的次数。
static void tcp_write_timer(struct timer_list *t)
{
	struct inet_connection_sock *icsk =
			from_timer(icsk, t, icsk_retransmit_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

	bh_lock_sock(sk);
	// 若传输控制块没被用户进程锁定，调用tcp_write_timer_handler
	if (!sock_owned_by_user(sk)) {
		tcp_write_timer_handler(sk);
	} else {
		// 若传输控制块被用户进程锁定，则只能稍后再试，因此重新设置定时器超时时间。
		/* delegate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_WRITE_TIMER_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

void tcp_syn_ack_timeout(const struct request_sock *req)
{
	struct net *net = read_pnet(&inet_rsk(req)->ireq_net);

	__NET_INC_STATS(net, LINUX_MIB_TCPTIMEOUTS);
}
EXPORT_SYMBOL(tcp_syn_ack_timeout);

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}
EXPORT_SYMBOL_GPL(tcp_set_keepalive);

// tcp_keepalive_timer实现了TCP中的三个定时器：连接建立定时器、保活定时器和FIN_WAIT_2定时器。
// 这是由于这三个定时器分别处于连接阶段、ESTABLISHED和FIN_WAIT_2三种状态，因为不必区分它们，只需
// 简单地通过当前的TCP状态就能判断当前执行的是何种定时器。
static void tcp_keepalive_timer (struct timer_list *t)
{
	// 通过计时器得到传输控制块
	struct sock *sk = from_timer(sk, t, sk_timer);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	// 如果传输控制块被用户进程锁定，则重新设定定时时间，0.05秒后再次激活
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}
	// 如果当前TCP状态为LISTEN,则说明出错了。。。
	if (sk->sk_state == TCP_LISTEN) {
		pr_err("Hmm... keepalive on a LISTEN ???\n");
		goto out;
	}
	// 刷新TCP套接字的时钟，确保值单调递增
	tcp_mstamp_refresh(tp);
	// 处于TCP_FIN_WAIT2且socket即将销毁，用作FIN_WAIT_2定时器
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		// 停留在TCP_FIN_WAIT2的停留时间>=0
		if (tp->linger2 >= 0) {
			// 获取TCP_FIN_WAIT2的剩余时间
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;
			// 如果还有剩余时间得调用TCP_FIN_WAIT2的定时器
			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
		// 发送rst
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}
	// 未启用保活，或者状态处于关闭，或者发送SYN状态，退出
	if (!sock_flag(sk, SOCK_KEEPOPEN) ||
	    ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)))
		goto out;
	
	// 获取设定的连接空闲时间
	elapsed = keepalive_time_when(tp);

	/* It is alive without keepalive 8) */
	// 有发送未确认的包或者还有待发送的包，不是空闲状态
	if (tp->packets_out || !tcp_write_queue_empty(sk))
		goto resched;
	// 从上次收到包到现在的空闲时间
	elapsed = keepalive_time_elapsed(tp);
	// 连接空闲时间超过设定值
	if (elapsed >= keepalive_time_when(tp)) {
		/* If the TCP_USER_TIMEOUT option is enabled, use that
		 * to determine when to timeout instead.
		 */
		// 设置了用户超时，空闲时间达到用户超时时间，已发送过探测
		// 未设置用户超时，探测次数达到了保活最大探测次数
		// 则发送rst关闭连接
		if ((icsk->icsk_user_timeout != 0 &&
		    elapsed >= msecs_to_jiffies(icsk->icsk_user_timeout) &&
		    icsk->icsk_probes_out > 0) ||
		    (icsk->icsk_user_timeout == 0 &&
		    icsk->icsk_probes_out >= keepalive_probes(tp))) {
			// 发送rst
			tcp_send_active_reset(sk, GFP_ATOMIC);
			// 关闭连接
			tcp_write_err(sk);
			goto out;
		}
		// 发送保活探测包
		if (tcp_write_wakeup(sk, LINUX_MIB_TCPKEEPALIVE) <= 0) {
			// 探测次数增加
			icsk->icsk_probes_out++;
			// 计算下一次探测时间
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			// 未超过空闲时间，则计算将要达到的空闲时间
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	sk_mem_reclaim(sk);

resched:
	// 重置定时器
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

static enum hrtimer_restart tcp_compressed_ack_kick(struct hrtimer *timer)
{
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, compressed_ack_timer);
	struct sock *sk = (struct sock *)tp;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		if (tp->compressed_ack) {
			/* Since we have to send one ack finally,
			 * subtract one from tp->compressed_ack to keep
			 * LINUX_MIB_TCPACKCOMPRESSED accurate.
			 */
			tp->compressed_ack--;
			tcp_send_ack(sk);
		}
	} else {
		if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED,
				      &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);

	sock_put(sk);

	return HRTIMER_NORESTART;
}
// 传输控制块定时器的初始化函数tcp_init_xmit_timers()在创建套接口、传输控制块时被调用，
// 并进而调用inet_csk_init_xmit_timers进行具体的初始化，
void tcp_init_xmit_timers(struct sock *sk)
{
	// 初始化TCP的tcp_write_timer，tcp_delack_timer和tcp_keepalive_timer
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
	hrtimer_init(&tcp_sk(sk)->pacing_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS_PINNED_SOFT);
	tcp_sk(sk)->pacing_timer.function = tcp_pace_kick;

	hrtimer_init(&tcp_sk(sk)->compressed_ack_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL_PINNED_SOFT);
	tcp_sk(sk)->compressed_ack_timer.function = tcp_compressed_ack_kick;
}
