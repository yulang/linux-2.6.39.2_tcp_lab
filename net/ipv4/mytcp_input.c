#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/kernel.h>
#include <net/dst.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ipsec.h>
#include <asm/unaligned.h>
#include <net/netdma.h>

/*
 * Handle the input skb in all states except ESTABLISHED & TIME_WAIT
 */
int mytcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
			  struct tcphdr *th, unsigned len)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int handled = 0, valid;

	tsk->rx_opt.saw_tstamp = 0;

	switch(sk->sk_state) {
		case TCP_LISTEN:
			/* it's in half-connection state, only handle SYN */
			if (th->ack)
				return 1; /* the function that calls this will send RST to the other end */

			if (th->rst)
				goto discard;

			if (th->syn) {
				/* here we handle the connection request */
				if (icsk->icsk_af_ops->conn_request(sk, skb) < 0)
					return 1;
				kfree_skb(skb);
				return 0;
			}

			goto discard;

		case TCP_CLOSE:
			goto discard;

		case TCP_SYN_SENT:
			/* wait for server's response */
			handled = mytcp_rcv_synsent_state_process(sk, skb, th, len);
			if (handled >= 0)
				return handled;

			mytcp_urg(sk, skb, th);
			__kfree_skb(skb);
			tcp_data_snd_check(sk); /* see if there's data to send */
			return 0;
	}
	valid = tcp_validate_incoming(sk, skb, th, 0);
	if (valid <= 0)
		return -valid;

	if (th->ack) {
		/* there might be state change */
		valid = mytcp_ack(sk, skb, FLAG_SLOWPATH) > 0;

		switch (sk->sk_state) {
			case TCP_SYN_RECV:
				if (valid == 0)
					return 1;
				else {
					tsk->copied_seq = tsk->rcv_nxt;
					smp_mb();

					tcp_set_state(sk, TCP_ESTABLISHED);
					sk->sk_state_change(sk);

					if (sk->sk_socket)
						/* static inline void sk_wake_async(struct sock *sk, int how, int band) */
						sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);

					tsk->snd_una = TCP_SKB_CB(skb)->ack_seq;
					tsk->snd_wnd = (ntohs(th->window)) << (tsk->rx_opt.snd_wscale);

					tcp_init_wl(tsk, TCP_SKB_CB(skb)->seq);
					tcp_ack_update_rtt(sk, 0, 0);
					if (tsk->rx_opt.tstamp_ok)
						tsk->advmss -= TCPOLEN_TSTAMP_ALIGNED;

					icsk->icsk_af_ops->rebuild_header(sk);
					tcp_init_metrics(sk);
					tcp_init_congestion_control(sk); /* YL: TO DO */

					tsk->lsndtime = tcp_time_stamp;

					tcp_mtup_init(sk);
					tcp_initialize_rcv_mss(sk);
					tcp_init_buffer_space(sk);
					tcp_fast_path_on(tp);
				}
				break;

			case TCP_FIN_WAIT1:
				/* go to FIN_WAIT2 */
				if (tsk->snd_una == tsk->write_seq) {
					tcp_set_state(sk, TCP_FIN_WAIT2);
					sk->sk_state |= SEND_SHUTDOWN;
					/* confrim route buff */
					dst_confirm(__sk_dst_get(sk));

					if (sock_flag(sk, SOCK_DEAD)) {
						int tmo;
						if (tsk->linger2 < 0 ||
					    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
					     after(TCP_SKB_CB(skb)->end_seq - th->fin, tsk->rcv_nxt))) {
						tcp_done(sk);
						NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
						return 1;
						}
						tmo = tcp_fin_time(sk);
						if (tmo > TCP_TIMEWAIT_LEN) {
							inet_csk_reset_keepalive_timer(sk, tmo - TCP_TIMEWAIT_LEN);
						} else if (th->fin || sock_owned_by_user(sk)) {
							inet_csk_reset_keepalive_timer(sk, tmo);
						} else {
							tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
							goto discard;
						}
					} else
						sk->sk_state_change(sk);
				}
				break;

			case TCP_CLOSING:
				if (tsk->snd_una == tsk->write_seq) {
					tcp_time_wait(sk, TCP_TIME_WAIT, 0);
					goto discard;
				}
				break;
			case TCP_LAST_ACK:
				if (tsk->snd_una == tsk->write_seq) {
					tcp_update_metrics(sk);
					tcp_done(sk);
					goto discard;
				}
				break;
		}
	} else
		goto discard;


discard:
		__kfree_skb(skb);
		return 0;

}
EXPORT_SYMBOL(mytcp_rcv_state_process);