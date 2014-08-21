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

}

void mytcp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{

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

}

int mytcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{

}
EXPORT_SYMBOL(mytcp_v4_do_rcv);

int mytcp_v4_rcv(struct sk_buff *skb)
{

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

}

void mytcp_v4_destroy_sock(struct sock *sk)
{

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

