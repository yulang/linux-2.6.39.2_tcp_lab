/* YL: my tcp implementation */

#include <linux/bottom_half.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/times.h>
#include <linux/slab.h>

#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/timewait_sock.h>
#include <net/xfrm.h>
#include <net/netdma.h>

#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>

void mytcp_init_trans_para(struct tcp_sock* tsk);

int mytcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{

}
EXPORT_SYMBOL(mytcp_v4_connect);

void mytcp_v4_err(struct sk_buff *icmp_skb, u32 info)
{
	/* YL: optional */
}

static void __mytcp_v4_send_check(struct sk_buff *skb,
				__be32 saddr, __be32 daddr)
{
	//__wsum csum_partial(const void *buff, int len, __wsum sum)

	struct tcphdr *tcphd = tcp_hdr(skb);
	__sum16 rst;

	if (skb->ip_summed == CHECKSUM_PARTIAL)
	{
		rst = ~mytcp_v4_check(skb->len, saddr, daddr); /* calculate pesudo header checksum */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);

	} else {
		/* calculate the checksum of the whole package */
		rst = mytcp_v4_check(skb->len, saddr, daddr, csum_partial(tcphd, tcphd->doff << 2, skb->csum));
	}

	tcphd->check = rst;
}

void mytcp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
	/*
		compute tcp checksum
		encapsulate __mytcp_v4_send_check
	*/
	struct inet_sock *insk = inet_sk(sk);
	__mytcp_v4_send_check(skb, inet->inet_saddr, inet->inet_daddr);

}
EXPORT_SYMBOL(mytcp_v4_send_check);

static void mytcp_v4_send_reset(struct sock *sk, struct sk_buff *skb)
{

}

static void mytcp_v4_send_ack(struct sk_buff *skb, u32 seq, u32 ack,
			    u32 win, u32 ts, int oif,
			    struct tcp_md5sig_key *key,
			    int reply_flags)
{

}

static void mytcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{

}

static void mytcp_v4_reqsk_send_ack(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req)
{

}

static int mytcp_v4_send_synack(struct sock *sk, struct dst_entry *dst,
			      struct request_sock *req,
			      struct request_values *rvp)
{

}

static int mytcp_v4_rtx_synack(struct sock *sk, struct request_sock *req,
			      struct request_values *rvp)
{

}

static void mytcp_v4_reqsk_destructor(struct request_sock *req)
{

}

struct request_sock_ops tcp_request_sock_ops __read_mostly = {
	/* YL: haven't changed the name & unsure about this structure*/

};

int mytcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{

}
EXPORT_SYMBOL(mytcp_v4_conn_request);

struct sock *mytcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{

}
EXPORT_SYMBOL(mytcp_v4_syn_recv_sock);

static struct sock *mytcp_v4_hnd_req(struct sock *sk, struct sk_buff *skb)
{

}

static __sum16 mytcp_v4_checksum_init(struct sk_buff *skb)
{
	//static inline __sum16 tcp_v4_check(int len, __be32 saddr,
	//			   __be32 daddr, __wsum base)
	//封装了校验和计算函数csum_tcpudp_magic，用于计算伪首部

	struct iphdr *iph = ip_hdr(skb);

	if (skb->ip_summed == CHECKSUM_COMPLETE)
	{
		/* if the checksum has been done, then only check the pseudo header */
		if (!mytcp_v4_check(skb->len, iph->saddr, iph->daddr, skb->csum))
		{
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			return 0;
		}
	}

	//__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
	//			   unsigned short len,
	//			   unsigned short proto,
	//			   __wsum sum)

	skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr, skb->len, IPPROTO_MYTCP,0);

	if (skb->len <= 76)
	{
		/* YL: if the skb is small enough, calculate the checksum of the whole packet */
		return __skb_checksum_complete(skb);
	}

	return 0;

}

int mytcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{

}
EXPORT_SYMBOL(mytcp_v4_do_rcv);

int mytcp_v4_rcv(struct sk_buff *skb)
{
	/* the overall handle function when receiving data */

	/*
	 *	bug: skb might be bad
	struct tcphdr *tcphd = tcp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	*/

	struct tcphdr *tcphd;
	struct iphdr *iphd;
	struct sock *sk; /* the owner sock of this SKB */
	struct net *net = dev_net(skb->dev);
	int rst = 0;

	if (skb->pkt_type != PACKET_HOST)
	{
		/* if the packet is not for local host, discard it. */
		goto discard_it;
	}
	TCP_INC_STATS_BH(net, TCP_MIB_INSEGS);

//static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
//moving the tail of skb head forward

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
	{
		goto discard_it;
	}

	tcphd = tcp_hdr(skb);

	if (tcphd->doff < sizeof(struct tcphdr) / 4)
	{
		goto bad_packet;
	}

	if (!pskb_may_pull(skb, tcphd->doff * 4))
	{
		goto discard_it;
	}

	/* then check the checksum of the pesudo header */
	/* YL: is it right? */
	if ((skb->ip_summed != CHECKSUM_UNNECESSARY) && (mytcp_v4_checksum_init(skb)))
	{
		goto bad_packet;
	}

	/* save the information in the tcp header to tcp private control block
	 * change the endian to local endian 
	 */

	 /*
	  *		struct tcp_skb_cb {
	  * 	__u32		seq;		
	  *		__u32		end_seq;	
	  *		__u32		when;		
	  *		__u8		flags;		
	  *		__u8		sacked;	
	  *		__u32		ack_seq;
	  *		}
	  */

	iphd = ip_hdr(skb);
	tcphd = tcp_hdr(skb);

	TCP_SKB_CB(skb)->seq = ntohl(tcphd->seq);
	/* only SYN, FIN and data consume seq */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + tcphd->syn + tcphd->fin + skb->len - tcphd->doff * 4; 
	TCP_SKB_CB(skb)->when = 0;
	TCP_SKB_CB(skb)->flags = iphd->tos;
	TCP_SKB_CB(skb)->sacked = 0;
	TCP_SKB_CB(skb)->ack_seq = ntohl(tcphd->ack_seq);

	/* look up owner sock in ehash or bhash */
	/*static inline struct sock *__inet_lookup_skb(struct inet_hashinfo *hashinfo,
	 *				     struct sk_buff *skb,
	 *				     const __be16 sport,
	 *				     const __be16 dport) */
	sk = __inet_lookup_skb(&tcp_hashinfo, skb, tcphd->source, tcphd->dest);

	if (!sk)
	{
		goto no_tcp_socket;
	}

	/* following codes begin to handle the received packet according to the sock state */
	if (sk->sk_state == TCP_TIME_WAIT)
	{
		goto do_time_wait;
	}

	if (inet_sk(sk)->min_ttl > iphd->ttl)
	{
		// min_ttl is a new member added in this version of kernel
		NET_INC_STATS_BH(net, LINUX_MIB_TCPMINTTLDROP);
		//goto discard_it;
		goto discard_and_release; /* we have got the sk, so it should be released while discarding the packet */
	}
	/* copied from original kernel */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_release;

	nf_reset(skb); /* init netfilter */
	if (sk_filter(sk, skb))
	{
		goto discard_and_release;
	}

	skb->dev = NULL;

	bh_lock_sock_nested(sk); /* lock sock */

	if (!sock_owned_by_user(sk))
	{
		if (!tcp_prequeue(sk, skb))
		{
			/* leave the DMA option */
			/* if the packet is not added to prequeue, call do_rcv to handle it */
			rst = mytcp_v4_do_rcv(sk, skb);
		}
	} else {
		sk_add_backlog(sk, skb);
	}

	bh_unlock_sock(sk);

	sock_put(sk);
	return rst;

	/* handle exceptions */

no_tcp_socket:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;
}

const struct inet_connection_sock_af_ops myipv4_specific = {
	/* YL: TO DO */
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.get_peer	   = tcp_v4_get_peer,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
	.bind_conflict	   = inet_csk_bind_conflict,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
};
EXPORT_SYMBOL(myipv4_specific);

static int mytcp_v4_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_sk(sk);
	struct tcp_sock *tsk = tcp_sk(sk);

	skb_queue_head_init(&tsk->out_of_order_queue);
	tcp_init_xmit_timers(sk);
	tcp_prequeue_init(tsk);

	icsk->icsk_rto = TCP_TIMEOUT_INIT; /* RFC 1122 */

	mytcp_init_trans_para(tsk);

	icsk->icsk_ca_ops = &mytcp_init_congestion_ops;

	sk->sk_state = TCP_CLOSE;

	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	icsk->icsk_af_ops = &myipv4_specific;
	icsk->icsk_sync_mss = tcp_sync_mss;	/* YL: TO DO */

	/************** copied from original kernel *******************/

#ifdef CONFIG_TCP_MD5SIG
	tsk->af_specific = &tcp_sock_ipv4_specific;
#endif

	/* TCP Cookie Transactions */
	if (sysctl_tcp_cookie_size > 0) {
		/* Default, cookies without s_data_payload. */
		tsk->cookie_values =
			kzalloc(sizeof(*tsk->cookie_values),
				sk->sk_allocation);
		if (tsk->cookie_values != NULL)
			kref_init(&tsk->cookie_values->kref);
	}

	/****************************************************************/

	/* YL: TO DO */
	sk->sk_sndbuf = sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_tcp_rmem[1];

	local_bh_disable();
	percpu_counter_inc(&tcp_sockets_allocated);
	local_bh_enable();
}

void mytcp_v4_destroy_sock(struct sock *sk)
{
	/* unfinished */
	struct tcp_sock *tsk = tcp_sk(sk);
	/* YL: TO DO */
	percpu_counter_dec(&tcp_sockets_allocated);

}
EXPORT_SYMBOL(mytcp_v4_destroy_sock);

struct proto mytcp_prot = {
	/* YL: TO DO */
	.name			= "MYTCP",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= tcp_v4_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.recvmsg		= tcp_recvmsg,
	.sendmsg		= tcp_sendmsg,
	.sendpage		= tcp_sendpage,
	.backlog_rcv		= tcp_v4_do_rcv,
	.hash			= inet_hash,
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcp_sock),
	.slab_flags		= SLAB_DESTROY_BY_RCU,
	.twsk_prot		= &tcp_timewait_sock_ops,
	.rsk_prot		= &tcp_request_sock_ops,
	.h.hashinfo		= &tcp_hashinfo,
	.no_autobind		= true,
#ifdef CONFIG_COMPAT
	.compat_setsockopt	= compat_tcp_setsockopt,
	.compat_getsockopt	= compat_tcp_getsockopt,
#endif
};
EXPORT_SYMBOL(mytcp_prot);

void mytcp_init_trans_para(struct tcp_sock* tsk)
{
	tsk->mdev = TCP_TIMEOUT_INIT;
	tsk->snd_cwnd = 2;
	tsk->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tsk->snd_cwnd_clamp = ~0;

	tsk->mss_cache = TCP_MSS_DEFAULT;
	tsk->reordering = sysctl_tcp_reordering;
}