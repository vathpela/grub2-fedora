/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/net.h>
#include <grub/net/ip.h>
#include <grub/net/tcp.h>
#include <grub/net/netbuff.h>
#include <grub/time.h>
#include <grub/priority_queue.h>

#define TCP_SYN_RETRANSMISSION_TIMEOUT GRUB_NET_INTERVAL
#define TCP_SYN_RETRANSMISSION_COUNT GRUB_NET_TRIES
#define TCP_RETRANSMISSION_TIMEOUT GRUB_NET_INTERVAL
#define TCP_RETRANSMISSION_COUNT GRUB_NET_TRIES

#define min(x, y) (((x) >= (y)) ? (x) : (y))

struct unacked
{
  struct unacked *next;
  struct unacked **prev;
  struct grub_net_buff *nb;
  grub_uint64_t last_try;
  int try_count;
};

enum
  {
    TCP_FIN = grub_cpu_to_be16_compile_time (0x01),
    TCP_SYN = grub_cpu_to_be16_compile_time (0x02),
    TCP_RST = grub_cpu_to_be16_compile_time (0x04),
    TCP_PSH = grub_cpu_to_be16_compile_time (0x08),
    TCP_ACK = grub_cpu_to_be16_compile_time (0x10),
    TCP_URG = grub_cpu_to_be16_compile_time (0x20),
  };

struct grub_net_tcp_socket
{
  struct grub_net_tcp_socket *next;
  struct grub_net_tcp_socket **prev;

  int established;
  int i_closed;
  int they_closed;
  int in_port;
  int out_port;
  int errors;
  int they_reseted;
  int i_reseted;
  int i_stall;
  int they_push;
  grub_uint32_t my_start_seq;
  grub_uint32_t my_cur_seq;
  grub_uint32_t their_start_seq;
  grub_uint32_t their_cur_seq;
  grub_uint16_t my_window;
  grub_uint8_t my_window_scale;
  grub_uint64_t their_window;
  grub_uint64_t last_ack_ms;
  grub_uint32_t queue_bytes;
  struct unacked *unack_first;
  struct unacked *unack_last;
  grub_err_t (*recv_hook) (grub_net_tcp_socket_t sock, struct grub_net_buff *nb,
			   void *recv);
  void (*error_hook) (grub_net_tcp_socket_t sock, void *recv);
  void (*fin_hook) (grub_net_tcp_socket_t sock, void *recv);
  void *hook_data;
  grub_net_network_level_address_t out_nla;
  grub_net_link_level_address_t ll_target_addr;
  struct grub_net_network_level_interface *inf;
  grub_net_packets_t packs;
  grub_priority_queue_t pq;
};

struct grub_net_tcp_listen
{
  struct grub_net_tcp_listen *next;
  struct grub_net_tcp_listen **prev;

  grub_uint16_t port;
  const struct grub_net_network_level_interface *inf;

  grub_err_t (*listen_hook) (grub_net_tcp_listen_t listen,
			     grub_net_tcp_socket_t sock,
			     void *data);
  void *hook_data;
};

struct tcphdr
{
  grub_uint16_t src;
  grub_uint16_t dst;
  grub_uint32_t seqnr;
  grub_uint32_t ack;
  grub_uint16_t flags;
  grub_uint16_t window;
  grub_uint16_t checksum;
  grub_uint16_t urgent;
} GRUB_PACKED;

struct tcp_opt
{
  grub_uint8_t kind;
  grub_uint8_t length;
} GRUB_PACKED;

struct tcp_scale_opt {
  grub_uint8_t kind;
  grub_uint8_t length;
  grub_uint8_t scale;
} GRUB_PACKED;

struct tcp_mss_opt
{
  grub_uint8_t kind;
  grub_uint8_t length;
  grub_uint16_t mss;
} GRUB_PACKED;

struct tcp_pseudohdr
{
  grub_uint32_t src;
  grub_uint32_t dst;
  grub_uint8_t zero;
  grub_uint8_t proto;
  grub_uint16_t tcp_length;
} GRUB_PACKED;

struct tcp6_pseudohdr
{
  grub_uint64_t src[2];
  grub_uint64_t dst[2];
  grub_uint32_t tcp_length;
  grub_uint8_t zero[3];
  grub_uint8_t proto;
} GRUB_PACKED;

static struct grub_net_tcp_socket *tcp_sockets;
static struct grub_net_tcp_listen *tcp_listens;

#define FOR_TCP_SOCKETS(var, next) FOR_LIST_ELEMENTS_SAFE (var, next, tcp_sockets)
#define FOR_TCP_LISTENS(var) FOR_LIST_ELEMENTS (var, tcp_listens)

#define tcplen(flags) ((grub_ssize_t)(grub_be_to_cpu16 (flags) >> 10))
#define tcpsize(size) grub_cpu_to_be16_compile_time((size) << 10)
#define pktlen(nb) ((grub_ssize_t)((nb)->tail - (nb)->data))
#define my_seq(sock, seqnr) ((seqnr) - ((sock)->my_start_seq))
#define their_seq(sock, seqnr) ((seqnr) - ((sock)->their_start_seq))
#define my_window(sock) ((sock)->my_window * (1 << ((sock)->my_window_scale)))

#define dbg(fmt, ...) ({grub_uint64_t _now = grub_get_time_ms(); grub_dprintf("tcp", "%lu.%lu " fmt, _now / 1000, _now % 1000, ## __VA_ARGS__);})

#define FOR_TCP_OPTIONS(tcph, opt)					    \
  for ((opt) = (struct tcp_opt *)(((char *)tcph) + sizeof (struct tcphdr)); \
       tcplen((tcph)->flags) > 20					    \
       && (char *)opt < (((char *)tcph) + tcplen((tcph)->flags)) ;	    \
       (opt) = (struct tcp_opt *)((char *)(opt) +			    \
				  ((opt)->kind == 1 ? 1 : ((opt)->length))))

static void
grub_net_tcp_flush_recv_queue (grub_net_tcp_socket_t sock);

static inline grub_uint64_t
minimum_window (grub_net_tcp_socket_t sock)
{
  return min(sock->inf->card->mtu, 1500)
         - GRUB_NET_OUR_IPV4_HEADER_SIZE
	 - sizeof (struct tcphdr);
}

static inline void
adjust_window (grub_net_tcp_socket_t sock, int howmuch)
{
  grub_uint64_t scale = 1 << sock->my_window_scale;
  grub_uint64_t window = sock->my_window;
  grub_int64_t scaled;
  grub_uint64_t maximum = 0x8000ULL * (1ULL << 48);
  grub_uint64_t minimum = minimum_window (sock);

  /* Add our modifier to the total */
  scaled = window * scale + howmuch;
  if ((grub_uint64_t)scaled > maximum)
    scaled = maximum;
  if (scaled < (grub_int64_t)minimum)
    scaled = minimum;

  /* and then compute a new window from that */
  for (scale = 0; scale < 0xff; scale++)
    if (scaled >> scale < 0xffff)
      break;
  window = scaled >> scale;

#if 0
  grub_dprintf ("tcp-window", "window: %u scale: %u\n", window, scale);
#endif
  if (scale != sock->my_window_scale || window != sock->my_window)
    {
      dbg ("rescaling (howmuch=%d) %u*%u (%x) -> %lu*%u (0x%lx)\n",
	   howmuch, sock->my_window, 1 << sock->my_window_scale,
	   sock->my_window * (1 << sock->my_window_scale),
	   window, 1 << scale, window * (1 << scale));
      sock->my_window_scale = scale;
      sock->my_window = window;
    }
}

static inline void
reset_window (grub_net_tcp_socket_t sock)
{
  grub_uint64_t scaled;
  sock->my_window_scale = 0;
  sock->my_window = 0;

  scaled = min(sock->inf->card->mtu, 1500)
	   - GRUB_NET_OUR_IPV4_HEADER_SIZE
	   - sizeof (struct tcphdr);
  scaled = scaled * 100;
  scaled = ALIGN_UP(scaled, 4096);
  adjust_window (sock, scaled);
  dbg ("Setting window to %u << %u = (%lu)\n",
       sock->my_window, sock->my_window_scale,
       (unsigned long)sock->my_window << sock->my_window_scale);
}

static grub_err_t
add_window_scale (struct grub_net_buff *nb,
		  struct tcphdr *tcph, grub_size_t *size, int scale_value)
{
  struct tcp_scale_opt *scale = (struct tcp_scale_opt *)((char *)tcph + *size);
  grub_err_t err;

  err = grub_netbuff_put (nb, sizeof (*scale));
  if (err)
    {
      grub_dprintf ("net", "error adding tcp window scale option\n");
      grub_netbuff_free (nb);
      return err;
    }

  scale->kind = 3;
  scale->length = sizeof (*scale);
  scale->scale = scale_value;
  *size += sizeof (*scale);
  return GRUB_ERR_NONE;
}

static grub_err_t
add_mss (grub_net_tcp_socket_t sock, struct grub_net_buff *nb,
	 struct tcphdr *tcph, grub_size_t *size)
{
  struct tcp_mss_opt *mss = (struct tcp_mss_opt *)((char *)tcph + *size);
  grub_err_t err;

  err = grub_netbuff_put (nb, sizeof (*mss));
  if (err)
    {
      grub_dprintf ("net", "error adding tcp mss option\n");
      grub_netbuff_free (nb);
      return err;
    }

  mss->kind = 2;
  mss->length = sizeof (*mss);
  mss->mss = grub_cpu_to_be16 (min(sock->inf->card->mtu, 1500)
			       - GRUB_NET_OUR_IPV4_HEADER_SIZE
			       - sizeof (struct tcphdr));
  *size += sizeof (*mss);
  return GRUB_ERR_NONE;
}

static grub_err_t
add_padding (struct grub_net_buff *nb,
	     struct tcphdr *tcph, grub_size_t *size)
{
  grub_uint8_t *end = (grub_uint8_t *)((char *)tcph + *size);
  grub_size_t end_size = 1;
  grub_err_t err;

  end_size = ALIGN_UP ((*size + 1), 4) - *size;

  err = grub_netbuff_put (nb, end_size);
  if (err)
    {
      grub_dprintf ("net", "error adding tcp mss option\n");
      grub_netbuff_free (nb);
      return err;
    }

  memset (end, 0, end_size);
  *size += end_size;
  return GRUB_ERR_NONE;
}

static void
destroy_pq (grub_net_tcp_socket_t sock)
{
  struct grub_net_buff **nb_p;
  while ((nb_p = grub_priority_queue_top (sock->pq)))
    {
      grub_netbuff_free (*nb_p);
      grub_priority_queue_pop (sock->pq);
    }

  grub_priority_queue_destroy (sock->pq);
}

static void
destroy_socket (grub_net_tcp_socket_t socket)
{
  struct unacked *unack, *next;

  for (unack = socket->unack_first; unack; unack = next)
    {
      next = unack->next;
      grub_netbuff_free (unack->nb);
      grub_free (unack);
    }

  socket->unack_first = NULL;
  socket->unack_last = NULL;

  grub_list_remove (GRUB_AS_LIST (socket));
  destroy_pq (socket);
  grub_free (socket);
}

grub_net_tcp_listen_t
grub_net_tcp_listen (grub_uint16_t port,
		     const struct grub_net_network_level_interface *inf,
		     grub_err_t (*listen_hook) (grub_net_tcp_listen_t listen,
						grub_net_tcp_socket_t sock,
						void *data),
		     void *hook_data)
{
  grub_net_tcp_listen_t ret;
  ret = grub_malloc (sizeof (*ret));
  if (!ret)
    return NULL;
  ret->listen_hook = listen_hook;
  ret->hook_data = hook_data;
  ret->port = port;
  ret->inf = inf;
  grub_list_push (GRUB_AS_LIST_P (&tcp_listens), GRUB_AS_LIST (ret));
  return ret;
}

void
grub_net_tcp_stop_listen (grub_net_tcp_listen_t listen)
{
  grub_list_remove (GRUB_AS_LIST (listen));
}

static inline void
tcp_socket_register (grub_net_tcp_socket_t sock)
{
  grub_list_push (GRUB_AS_LIST_P (&tcp_sockets),
		  GRUB_AS_LIST (sock));
}

static void
error (grub_net_tcp_socket_t sock)
{
  if (sock->error_hook)
    sock->error_hook (sock, sock->hook_data);

  destroy_socket (sock);
}

static grub_err_t
tcp_send (struct grub_net_buff *nb, grub_net_tcp_socket_t socket)
{
  grub_err_t err;
  grub_uint8_t *nbd;
  struct unacked *unack;
  struct tcphdr *tcph;
  grub_size_t size;

  tcph = (struct tcphdr *) nb->data;

  tcph->seqnr = grub_cpu_to_be32 (socket->my_cur_seq);
  size = pktlen (nb) - tcplen (tcph->flags);
  if (tcph->flags & TCP_FIN)
    size++;
  socket->my_cur_seq += size;
  tcph->src = grub_cpu_to_be16 (socket->in_port);
  tcph->dst = grub_cpu_to_be16 (socket->out_port);
  tcph->checksum = 0;
  tcph->checksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_TCP,
						   &socket->inf->address,
						   &socket->out_nla);
  nbd = nb->data;
  if (size)
    {
      unack = grub_malloc (sizeof (*unack));
      if (!unack)
	return grub_errno;

      unack->next = NULL;
      unack->nb = nb;
      unack->try_count = 1;
      unack->last_try = grub_get_time_ms ();
      if (!socket->unack_last)
	socket->unack_first = socket->unack_last = unack;
      else
	{
	  socket->unack_last->next = unack;
	  socket->unack_last = unack;
	}
    }

  err = grub_net_send_ip_packet (socket->inf, &(socket->out_nla),
				 &(socket->ll_target_addr), nb,
				 GRUB_NET_IP_TCP);
  if (err)
    return err;
  nb->data = nbd;
  if (!size)
    grub_netbuff_free (nb);
  return GRUB_ERR_NONE;
}

void
grub_net_tcp_close (grub_net_tcp_socket_t sock,
		    int discard_received)
{
  struct grub_net_buff *nb_fin;
  struct tcphdr *tcph_fin;
  grub_err_t err;

  if (discard_received != GRUB_NET_TCP_CONTINUE_RECEIVING)
    {
      sock->recv_hook = NULL;
      sock->error_hook = NULL;
      sock->fin_hook = NULL;
    }

  if (discard_received == GRUB_NET_TCP_ABORT)
    sock->i_reseted = 1;

  if (sock->i_closed)
    return;

  sock->i_closed = 1;

  nb_fin = grub_netbuff_alloc (sizeof (*tcph_fin)
			       + GRUB_NET_OUR_MAX_IP_HEADER_SIZE
			       + GRUB_NET_MAX_LINK_HEADER_SIZE);
  if (!nb_fin)
    return;
  err = grub_netbuff_reserve (nb_fin, GRUB_NET_OUR_MAX_IP_HEADER_SIZE
			       + GRUB_NET_MAX_LINK_HEADER_SIZE);
  if (err)
    {
      grub_netbuff_free (nb_fin);
      grub_dprintf ("net", "error closing socket\n");
      grub_errno = GRUB_ERR_NONE;
      return;
    }

  err = grub_netbuff_put (nb_fin, sizeof (*tcph_fin));
  if (err)
    {
      grub_netbuff_free (nb_fin);
      grub_dprintf ("net", "error closing socket\n");
      grub_errno = GRUB_ERR_NONE;
      return;
    }
  tcph_fin = (void *) nb_fin->data;
  tcph_fin->ack = grub_cpu_to_be32 (sock->their_cur_seq);
  tcph_fin->flags = tcpsize (sizeof *tcph_fin) | TCP_FIN | TCP_ACK;
  tcph_fin->window = grub_cpu_to_be16_compile_time (0);
  tcph_fin->window = grub_cpu_to_be16 (sock->my_window);
  tcph_fin->urgent = 0;
  err = tcp_send (nb_fin, sock);
  if (err)
    {
      grub_netbuff_free (nb_fin);
      grub_dprintf ("net", "error closing socket\n");
      grub_errno = GRUB_ERR_NONE;
    }
  return;
}

static void
ack_real (grub_net_tcp_socket_t sock, int res, int ack)
{
  struct grub_net_buff *nb_ack;
  struct tcphdr *tcph_ack;
  grub_size_t hdrsize = sizeof (*tcph_ack);
  grub_err_t err;

  nb_ack = grub_netbuff_alloc (hdrsize + 128);
  if (!nb_ack)
    return;
  err = grub_netbuff_reserve (nb_ack, 128);
  if (err)
    {
      grub_netbuff_free (nb_ack);
      grub_dprintf ("net", "error closing socket\n");
      grub_errno = GRUB_ERR_NONE;
      return;
    }

  err = grub_netbuff_put (nb_ack, hdrsize);
  if (err)
    {
      grub_netbuff_free (nb_ack);
error:
      grub_dprintf ("net", "error closing socket\n");
      grub_errno = GRUB_ERR_NONE;
      return;
    }
  tcph_ack = (void *) nb_ack->data;
  if (ack)
    {
      err = add_window_scale (nb_ack, tcph_ack, &hdrsize,
			      sock->my_window_scale);
      if (err)
	goto error;

      err = add_padding (nb_ack, tcph_ack, &hdrsize);
      if (err)
	goto error;
    }

  if (res)
    {
      tcph_ack->ack = grub_cpu_to_be32_compile_time (0);
      tcph_ack->flags = tcpsize (hdrsize) | TCP_RST;
      tcph_ack->window = grub_cpu_to_be16_compile_time (0);
      reset_window (sock);
      grub_net_tcp_flush_recv_queue (sock);
    }
  else
    {
      tcph_ack->ack = grub_cpu_to_be32 (sock->their_cur_seq);
      tcph_ack->flags = tcpsize (hdrsize) | TCP_ACK;
      if (sock->they_closed && !sock->i_closed)
	{
	  tcph_ack->flags |= TCP_FIN;
	  sock->i_closed;
	}
      tcph_ack->window = !sock->i_stall ? grub_cpu_to_be16 (sock->my_window)
	: 0;
    }
  tcph_ack->urgent = 0;
  tcph_ack->src = grub_cpu_to_be16 (sock->in_port);
  tcph_ack->dst = grub_cpu_to_be16 (sock->out_port);
  err = tcp_send (nb_ack, sock);
  if (err)
    {
      grub_dprintf ("net", "error acking socket\n");
      grub_errno = GRUB_ERR_NONE;
    }
}

static void
ack (grub_net_tcp_socket_t sock)
{
  sock->last_ack_ms = grub_get_time_ms ();
  ack_real (sock, 0, 1);
}

static void
reset (grub_net_tcp_socket_t sock, int ack)
{
  ack_real (sock, 1, ack);
}

void
grub_net_tcp_retransmit (void)
{
  grub_net_tcp_socket_t sock, next_sock;
  grub_uint64_t ctime = grub_get_time_ms ();
  grub_uint64_t limit_time = ctime - TCP_RETRANSMISSION_TIMEOUT;

  FOR_TCP_SOCKETS (sock, next_sock)
    {
      struct unacked *unack;
      for (unack = sock->unack_first; unack; unack = unack->next)
	{
	  struct tcphdr *tcph;
	  grub_uint8_t *nbd;
	  grub_err_t err;

	  if (unack->last_try > limit_time)
	    continue;

	  if (unack->try_count > TCP_RETRANSMISSION_COUNT)
	    {
	      error (sock);
	      break;
	    }
	  unack->try_count++;
	  unack->last_try = ctime;
	  nbd = unack->nb->data;
	  tcph = (struct tcphdr *) nbd;

	  if ((tcph->flags & TCP_ACK)
	      && tcph->ack != grub_cpu_to_be32 (sock->their_cur_seq))
	    {
	      dbg ("retransmitting previous ack %u\n",
		   grub_be_to_cpu32 (tcph->ack));
	      tcph->checksum = grub_net_ip_transport_checksum (unack->nb,
							       GRUB_NET_IP_TCP,
							       &sock->inf->address,
							       &sock->out_nla);
	    }

	  err = grub_net_send_ip_packet (sock->inf, &(sock->out_nla),
					 &(sock->ll_target_addr), unack->nb,
					 GRUB_NET_IP_TCP);
	  unack->nb->data = nbd;
	  if (err)
	    {
	      grub_dprintf ("net", "TCP retransmit failed: %s\n", grub_errmsg);
	      grub_errno = GRUB_ERR_NONE;
	    }
	}
    }
}

grub_uint16_t
grub_net_ip_transport_checksum (struct grub_net_buff *nb,
				grub_uint16_t proto,
				const grub_net_network_level_address_t *src,
				const grub_net_network_level_address_t *dst)
{
  grub_uint16_t a, b = 0;
  grub_uint32_t c;
  a = ~grub_be_to_cpu16 (grub_net_ip_chksum ((void *) nb->data, pktlen (nb)));

  switch (dst->type)
    {
    case GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4:
      {
	struct tcp_pseudohdr ph;
	ph.src = src->ipv4;
	ph.dst = dst->ipv4;
	ph.zero = 0;
	ph.tcp_length = grub_cpu_to_be16 (pktlen (nb));
	ph.proto = proto;
	b = ~grub_be_to_cpu16 (grub_net_ip_chksum ((void *) &ph, sizeof (ph)));
	break;
      }
    case GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6:
      {
	struct tcp6_pseudohdr ph;
	grub_memcpy (ph.src, src->ipv6, sizeof (ph.src));
	grub_memcpy (ph.dst, dst->ipv6, sizeof (ph.dst));
	grub_memset (ph.zero, 0, sizeof (ph.zero));
	ph.tcp_length = grub_cpu_to_be32 (pktlen (nb));
	ph.proto = proto;
	b = ~grub_be_to_cpu16 (grub_net_ip_chksum ((void *) &ph, sizeof (ph)));
	break;
      }
    case GRUB_NET_NETWORK_LEVEL_PROTOCOL_DHCP_RECV:
      b = 0;
      break;
    }
  c = (grub_uint32_t) a + (grub_uint32_t) b;
  if (c >= 0xffff)
    c -= 0xffff;
  return grub_cpu_to_be16 (~c);
}

/* FIXME: overflow. */
static int
cmp (const void *a__, const void *b__)
{
  struct grub_net_buff *a_ = *(struct grub_net_buff **) a__;
  struct grub_net_buff *b_ = *(struct grub_net_buff **) b__;
  struct tcphdr *a = (struct tcphdr *) a_->data;
  struct tcphdr *b = (struct tcphdr *) b_->data;
  /* We want the first elements to be on top.  */
  if (grub_be_to_cpu32 (a->seqnr) < grub_be_to_cpu32 (b->seqnr))
    return +1;
  if (grub_be_to_cpu32 (a->seqnr) > grub_be_to_cpu32 (b->seqnr))
    return -1;
  return 0;
}

grub_err_t
grub_net_tcp_accept (grub_net_tcp_socket_t sock,
		     grub_err_t (*recv_hook) (grub_net_tcp_socket_t sock,
					      struct grub_net_buff *nb,
					      void *data),
		     void (*error_hook) (grub_net_tcp_socket_t sock,
					 void *data),
		     void (*fin_hook) (grub_net_tcp_socket_t sock,
				       void *data),
		     void *hook_data)
{
  struct grub_net_buff *nb_ack;
  struct tcphdr *tcph;
  grub_size_t hdrsize = sizeof (*tcph);
  grub_err_t err;

  sock->recv_hook = recv_hook;
  sock->error_hook = error_hook;
  sock->fin_hook = fin_hook;
  sock->hook_data = hook_data;
  nb_ack = grub_netbuff_alloc (sizeof (*tcph)
			       + GRUB_NET_OUR_MAX_IP_HEADER_SIZE
			       + GRUB_NET_MAX_LINK_HEADER_SIZE);
  if (!nb_ack)
    return grub_errno;
  err = grub_netbuff_reserve (nb_ack, GRUB_NET_OUR_MAX_IP_HEADER_SIZE
			      + GRUB_NET_MAX_LINK_HEADER_SIZE);
  if (err)
    {
      grub_netbuff_free (nb_ack);
      return err;
    }

  err = grub_netbuff_put (nb_ack, hdrsize);
  if (err)
    {
error:
      grub_netbuff_free (nb_ack);
      return err;
    }
  tcph = (void *) nb_ack->data;
  err = add_mss (sock, nb_ack, tcph, &hdrsize);
  if (err)
    goto error;
  err = add_padding (nb_ack, tcph, &hdrsize);
  if (err)
    goto error;
  tcph->ack = grub_cpu_to_be32 (sock->their_cur_seq);
  tcph->flags = tcpsize (hdrsize) | TCP_SYN | TCP_ACK;
  tcph->window = grub_cpu_to_be16 (sock->my_window);
  tcph->urgent = 0;
  sock->established = 1;
  tcp_socket_register (sock);
  err = tcp_send (nb_ack, sock);
  if (err)
    return err;
  sock->my_cur_seq++;
  return GRUB_ERR_NONE;
}

static void
init_tcp_src_port (int *port)
{
  int new_port = *port;
  int shift = 12; // one page...

  /*
   * Try to randomize the port number.
   * I tried just doing grub_get_time_ms() a couple of times, and the numbers I
   * got were... disturbingly monotonic.  First couple of runs of
   * for (x = 0; x < 4; x++) {
   *   grub_millisleep(11);
   *   grub_printf("x: %x\n", grub_get_time_ms());
   * }
   * got me:
   * 0x77, 0x82, 0x8d, 0x98, 0xa3
   * 0x79, 0x84, 0x8f, 0x9a, 0xa5
   * and similar series, so basically all that's here is jitter, and not
   * enough of it to have good source port initialiation (or unique initial
   * sequence numbers...)
   *
   * So use grub_millisleep() to guarantee we've got some jitter in the
   * number, and then shift and or so the jitter is most of what we really
   * have.
   *
   * It's worth noting, this is on a virtual machine, and it appears the
   * clock source for grub_get_time_ms() doesn't often advance unless you
   * poll it, so basically it advances by however much we do
   * grub_millisleep().
   */
   while (new_port < 2 || new_port >= 65534)
    {
      int x, y, z;

      grub_millisleep (13);
      y = grub_get_time_ms ();
      grub_millisleep (37);
      z = grub_get_time_ms ();

      for (x = 0; x < 33; x++)
        {
          grub_millisleep (0x11);
          z = grub_get_time_ms ();
          if (x % 2)
	    continue;
          new_port = (new_port << 1) | (y & 0x1);
          y = z;
        }

      new_port &= 0xffff;
      grub_dprintf ("tcp", "initial source port %u\n", new_port);

      /* if we still don't have any number in range, just take the page number
       * of our socket...
       */
      while (new_port < 2 || new_port >= 65534)
	new_port = (grub_uint16_t)(((unsigned long long)port >> shift++) & 0xffff);
    }

  *port = new_port;
}

grub_net_tcp_socket_t
grub_net_tcp_open (char *server,
		   grub_uint16_t out_port,
		   grub_err_t (*recv_hook) (grub_net_tcp_socket_t sock,
					    struct grub_net_buff *nb,
					    void *data),
		   void (*error_hook) (grub_net_tcp_socket_t sock,
				       void *data),
		   void (*fin_hook) (grub_net_tcp_socket_t sock,
				     void *data),
		   void *hook_data)
{
  grub_err_t err;
  grub_net_network_level_address_t addr;
  struct grub_net_network_level_interface *inf;
  grub_net_network_level_address_t gateway;
  grub_net_tcp_socket_t socket;
  static grub_uint16_t in_port;
  struct grub_net_buff *nb;
  struct tcphdr *tcph;
  int i;
  grub_uint8_t *nbd;
  grub_net_link_level_address_t ll_target_addr;
  grub_size_t hdrsize = sizeof (*tcph);

  err = grub_net_resolve_address (server, &addr);
  if (err)
    return NULL;

  if (addr.type != GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4
      && addr.type != GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6)
    {
      grub_error (GRUB_ERR_BUG, "not an IP address");
      return NULL;
    }
 
  err = grub_net_route_address (addr, &gateway, &inf);
  if (err)
    return NULL;

  err = grub_net_link_layer_resolve (inf, &gateway, &ll_target_addr);
  if (err)
    return NULL;

  socket = grub_zalloc (sizeof (*socket));
  if (socket == NULL)
    return NULL; 

  if (in_port == 0)
    {
      init_tcp_src_port (&socket->in_port);
      in_port = socket->in_port;
    }
  else if (in_port == 65535)
    in_port = 2;
  socket->in_port = in_port++;
  grub_dprintf ("tcp", "new source port is %d\n", socket->in_port);

  socket->out_port = out_port;
  socket->inf = inf;
  socket->out_nla = addr;
  socket->ll_target_addr = ll_target_addr;
  socket->recv_hook = recv_hook;
  socket->error_hook = error_hook;
  socket->fin_hook = fin_hook;
  socket->hook_data = hook_data;

  nb = grub_netbuff_alloc (sizeof (*tcph) + 128);
  if (!nb)
    return NULL;
  err = grub_netbuff_reserve (nb, 128);
  if (err)
    {
      grub_netbuff_free (nb);
      return NULL;
    }

  err = grub_netbuff_put (nb, hdrsize);
  if (err)
    {
      grub_netbuff_free (nb);
      return NULL;
    }
  socket->pq = grub_priority_queue_new (sizeof (struct grub_net_buff *), cmp);
  if (!socket->pq)
    {
error:
      grub_netbuff_free (nb);
      return NULL;
    }

  tcph = (void *) nb->data;
  grub_memset(tcph, 0, sizeof (*tcph));
  socket->my_start_seq = grub_get_time_ms ();
  socket->my_cur_seq = socket->my_start_seq + 1;
  reset_window (socket);
  err = add_window_scale (nb, tcph, &hdrsize, socket->my_window_scale);
  if (err)
    goto error;
  err = add_mss (socket, nb, tcph, &hdrsize);
  if (err)
    goto error;
  err = add_padding (nb, tcph, &hdrsize);
  if (err)
    goto error;
  tcph->seqnr = grub_cpu_to_be32 (socket->my_start_seq);
  tcph->ack = grub_cpu_to_be32_compile_time (0);
  tcph->flags = tcpsize (hdrsize) | TCP_SYN;
  tcph->window = grub_cpu_to_be16 (socket->my_window);
  tcph->urgent = 0;
  tcph->src = grub_cpu_to_be16 (socket->in_port);
  tcph->dst = grub_cpu_to_be16 (socket->out_port);
  tcph->checksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_TCP,
						   &socket->inf->address,
						   &socket->out_nla);

  tcp_socket_register (socket);

  nbd = nb->data;
  for (i = 0; i < TCP_SYN_RETRANSMISSION_COUNT; i++)
    {
      int j;
      nb->data = nbd;
      err = grub_net_send_ip_packet (socket->inf, &(socket->out_nla), 
				     &(socket->ll_target_addr), nb,
				     GRUB_NET_IP_TCP);
      if (err)
	{
	  destroy_socket (socket);
	  grub_netbuff_free (nb);
	  return NULL;
	}
      for (j = 0; (j < TCP_SYN_RETRANSMISSION_TIMEOUT / 50 
		   && !socket->established); j++)
	grub_net_poll_cards (50, &socket->established);
      if (socket->established)
	break;
    }
  if (!socket->established)
    {
      if (socket->they_reseted)
	grub_error (GRUB_ERR_NET_PORT_CLOSED,
		    N_("connection refused"));
      else
	grub_error (GRUB_ERR_NET_NO_ANSWER,
		    N_("connection timeout"));
      destroy_socket (socket);
      grub_netbuff_free (nb);
      return NULL;
    }

  grub_netbuff_free (nb);
  return socket;
}

grub_err_t
grub_net_send_tcp_packet (const grub_net_tcp_socket_t socket,
			  struct grub_net_buff *nb, int push)
{
  struct tcphdr *tcph;
  grub_err_t err;
  grub_ssize_t fraglen;
  COMPILE_TIME_ASSERT (sizeof (struct tcphdr) == GRUB_NET_TCP_HEADER_SIZE);
  if (socket->out_nla.type == GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4)
    fraglen = (socket->inf->card->mtu - GRUB_NET_OUR_IPV4_HEADER_SIZE
	       - sizeof (*tcph));
  else
    fraglen = 1280 - GRUB_NET_OUR_IPV6_HEADER_SIZE;

  while (pktlen (nb) > fraglen)
    {
      struct grub_net_buff *nb2;

      nb2 = grub_netbuff_alloc (fraglen + sizeof (*tcph)
				+ GRUB_NET_OUR_MAX_IP_HEADER_SIZE
				+ GRUB_NET_MAX_LINK_HEADER_SIZE);
      if (!nb2)
	return grub_errno;
      err = grub_netbuff_reserve (nb2, GRUB_NET_MAX_LINK_HEADER_SIZE
				  + GRUB_NET_OUR_MAX_IP_HEADER_SIZE);
      if (err)
	return err;
      err = grub_netbuff_put (nb2, sizeof (*tcph));
      if (err)
	return err;

      tcph = (struct tcphdr *) nb2->data;
      tcph->ack = grub_cpu_to_be32 (socket->their_cur_seq);
      tcph->flags = tcpsize (sizeof *tcph) | TCP_ACK;
      tcph->window = !socket->i_stall ? grub_cpu_to_be16 (socket->my_window)
	: 0;
      tcph->urgent = 0;
      err = grub_netbuff_put (nb2, fraglen);
      if (err)
	return err;
      grub_memcpy (tcph + 1, nb->data, fraglen);
      err = grub_netbuff_pull (nb, fraglen);
      if (err)
	return err;

      dbg ("acking %u\n", their_seq(socket, socket->their_cur_seq));
      err = tcp_send (nb2, socket);
      if (err)
	return err;
    }

  err = grub_netbuff_push (nb, sizeof (*tcph));
  if (err)
    return err;

  dbg ("acking+push %u\n", their_seq (socket, socket->their_cur_seq));
  tcph = (struct tcphdr *) nb->data;
  tcph->ack = grub_cpu_to_be32 (socket->their_cur_seq);
  tcph->flags = tcpsize (sizeof *tcph) | TCP_ACK | (push ? TCP_PSH : 0);
  tcph->window = !socket->i_stall ? grub_cpu_to_be16 (socket->my_window) : 0;
  tcph->urgent = 0;
  return tcp_send (nb, socket);
}

static void
grub_net_tcp_flush_recv_queue (grub_net_tcp_socket_t sock)
{
  struct grub_net_buff **nb_top_p;

  while ((nb_top_p = grub_priority_queue_top (sock->pq)) != NULL)
    {
      struct grub_net_buff *nb_top = *nb_top_p;
      grub_netbuff_free (nb_top);
      grub_priority_queue_pop (sock->pq);
    }
}

static grub_err_t
grub_net_tcp_process_queue (grub_net_tcp_socket_t sock)
{
  struct grub_net_buff **nb_top_p;
  grub_err_t err = GRUB_ERR_NONE;
  int do_ack = 0;
  int just_closed = 0;

  while ((nb_top_p = grub_priority_queue_top (sock->pq)) != NULL)
    {
      struct grub_net_buff *nb_top = *nb_top_p;
      struct tcphdr *tcph;
      grub_uint32_t seqnr;
      grub_ssize_t len, hdrlen;

      tcph = (struct tcphdr *) nb_top->data;
      seqnr = grub_be_to_cpu32 (tcph->seqnr);
      hdrlen = tcplen (tcph->flags);
      len = pktlen (nb_top) - hdrlen;

      dbg ("processing nb with seqnr %u\n", their_seq (sock, seqnr));

      /* If we have seen this sequence already, just remove it */
      if (seqnr < sock->their_cur_seq)
	{
	  dbg ("Ignoring already acked packet %u\n", their_seq (sock, seqnr));
	  grub_netbuff_free (nb_top);
	  grub_priority_queue_pop (sock->pq);
	  sock->queue_bytes -= len;
	  continue;
	}

      /* If we've got an out-of-order packet, we need to re-ack to make sure
       * the sender is up to date, and our packet queue is invalid. */
      if (seqnr > sock->their_cur_seq)
	{
	  dbg ("OOO %u, expected %u moving on\n",
	       their_seq(sock, seqnr), their_seq(sock, sock->their_cur_seq));
	  do_ack = 1;
	  sock->queue_bytes -= len;
	  break;
	}

      /* If we called close and there's more data (not just empty ACKs and
       * whatnot), send a reset. */
      if (sock->i_reseted && len > 0)
	{
	  dbg ("i_reseted and there's %u bytes of data\n",
	       their_seq (sock, seqnr));
	  reset (sock, 0);
	}

      /* If we got here, we're actually consuming the packet, so it's safe to
       * remove it from our ingress queue. */
      grub_priority_queue_pop (sock->pq);
      sock->queue_bytes -= len;

      /* Eat the header.  If that somehow fails we have no hope of recovery,
       * so send a reset and get out of here. */
      err = grub_netbuff_pull (nb_top, hdrlen);
      if (err)
	{
	  dbg ("grub_netbuff_pull() failed: %d\n", err);
	  sock->i_reseted = 1;
	  reset (sock, 0);
	  break;
	}

      sock->their_cur_seq += len;
      dbg ("%u -> their_cur_seq\n", their_seq (sock, sock->their_cur_seq));
      adjust_window (sock, len);

      /* If we get a FIN it's over. */
      if (tcph->flags & TCP_FIN)
	{
	  if (!sock->i_closed)
	    sock->they_closed = 1;
	  just_closed = 1;
	  sock->their_cur_seq++;
	  dbg ("%u -> their_cur_seq\n", their_seq (sock, sock->their_cur_seq));
	  // XXX FIXME ack (sock);
	  // XXX FIXME do_ack = 1;
	  ack (sock);
	  do_ack = 0;
	}

      /* If there is data, puts packet in socket list. */
      if (len > 0)
	{
	  grub_net_put_packet (&sock->packs, nb_top);
	  do_ack = 1;
	}
      else
	grub_netbuff_free (nb_top);
    }

  /* If we got here, there's nothing we can process in the queue, and it's
   * all bad.  Flush it down the drain. */
  grub_net_tcp_flush_recv_queue (sock);

  if (do_ack)
    {
      dbg ("acking %u\n", their_seq (sock, sock->their_cur_seq));
      ack (sock);
    }

  /* Now feed our packet data to our real consumer. */
  while (sock->packs.first)
    {
      struct grub_net_buff *nb = sock->packs.first->nb;
      if (sock->recv_hook)
	sock->recv_hook (sock, sock->packs.first->nb, sock->hook_data);
      else
	grub_netbuff_free (nb);
      grub_net_remove_packet (sock->packs.first);
    }

  /* And if we closed, inform them of that as well. */
  if (sock->fin_hook && just_closed)
    sock->fin_hook (sock, sock->hook_data);

  return err;
}

static int
recv_pending (struct grub_net_network_level_interface *inf)
{
  int rc;

  rc = inf->card->driver->recv_pending (inf->card);
  if (rc < 1)
    return 0;
  return rc;
}

grub_err_t
grub_net_recv_tcp_packet (struct grub_net_buff *nb,
			  struct grub_net_network_level_interface *inf,
			  const grub_net_network_level_address_t *source)
{
  struct tcphdr *tcph;
  grub_net_tcp_socket_t sock, next_sock;
  grub_err_t err;
  grub_ssize_t len, hdrlen;

  /* Ignore broadcast.  */
  if (!inf)
    {
      grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }

  tcph = (struct tcphdr *) nb->data;
  hdrlen = tcplen (tcph->flags);
  len = pktlen (nb) - hdrlen;

  if (hdrlen < 5)
    {
      grub_dprintf ("net", "TCP header too short: %" PRIuGRUB_SIZE "\n",
		    hdrlen);
      grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }

  if (len < 0)
    {
      grub_dprintf ("net", "TCP packet too short: %" PRIuGRUB_SIZE "\n", len);
      grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }

  FOR_TCP_SOCKETS (sock, next_sock)
    {
      struct tcp_opt *opt;
      int fin = 0;
      if (!(grub_be_to_cpu16 (tcph->dst) == sock->in_port
	    && grub_be_to_cpu16 (tcph->src) == sock->out_port
	    && inf == sock->inf
	    && grub_net_addr_cmp (source, &sock->out_nla) == 0))
	continue;

      if (tcph->checksum)
	{
	  grub_uint16_t chk, expected;
	  chk = tcph->checksum;
	  tcph->checksum = 0;
	  expected = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_TCP,
						     &sock->out_nla,
						     &sock->inf->address);
	  if (expected != chk)
	    {
	      grub_dprintf ("net",
			    "Invalid TCP checksum. Expected %x, got %x\n",
			    grub_be_to_cpu16 (expected),
			    grub_be_to_cpu16 (chk));
	      grub_netbuff_free (nb);
	      return GRUB_ERR_NONE;
	    }
	  tcph->checksum = chk;
	}

      /* We do this here just to make the next debug log messages coherent */
      if (tcph->flags & TCP_SYN && tcph->flags & TCP_ACK && !sock->established)
	sock->their_start_seq = grub_be_to_cpu32 (tcph->seqnr);

      dbg ("ingress seq %u ack %u len=%ld\n",
	   their_seq (sock, grub_be_to_cpu32 (tcph->seqnr)),
	   my_seq (sock, grub_be_to_cpu32 (tcph->ack)), len);

      if (tcph->flags & TCP_SYN && tcph->flags & TCP_ACK && !sock->established)
	{
	  dbg ("their starting sequence is %u\n", sock->their_start_seq);
	  sock->their_cur_seq = sock->their_start_seq + 1;
	  dbg ("%u -> their_cur_seq\n", their_seq (sock, sock->their_cur_seq));
	  sock->established = 1;
	  ack (sock);
	}
      else if (tcph->flags & TCP_ACK && sock->i_closed && sock->they_closed)
	{
	  destroy_socket (sock);
	  grub_netbuff_free (nb);
	  return GRUB_ERR_NONE;
	}

      if (tcph->flags & TCP_PSH)
	sock->they_push = 1;

      FOR_TCP_OPTIONS (tcph, opt)
	{
	  struct tcp_scale_opt *scale;

	  dbg ("processing tcph (0x%016lx) option %u (0x%016lx)\n",
	       (unsigned long)tcph, opt->kind, (unsigned long)opt);

	  if (opt->kind != 3)
	    continue;

	  scale = (struct tcp_scale_opt *)opt;
	  sock->their_window = grub_be_to_cpu16 (tcph->window);
	  sock->their_window <<= scale->scale;
	  break;
	}

      if (tcph->flags & TCP_RST)
	{
	  sock->they_reseted = 1;
	  error (sock);
	  grub_netbuff_free (nb);
	  return GRUB_ERR_NONE;
	}

      /*
       * If we see an ACK here, we can get rid of our old unacked packets.
       */
      if (tcph->flags & TCP_ACK)
	{
	  struct unacked *unack, *next;
	  grub_uint32_t acked = grub_be_to_cpu32 (tcph->ack);

	  dbg ("looking for unacked packet %u\n", my_seq (sock, acked));
	  for (unack = sock->unack_first; unack; unack = next)
	    {
	      grub_uint32_t seqnr;
	      struct tcphdr *unack_tcph;

	      next = unack->next;
	      unack_tcph = (struct tcphdr *) unack->nb->data;
	      seqnr = grub_be_to_cpu32 (unack_tcph->seqnr);
	      seqnr += pktlen (unack->nb) - tcplen (unack_tcph->flags);

	      if (unack_tcph->flags & TCP_FIN)
		seqnr++;

	      if (seqnr > acked)
		break;

	      dbg ("freeing unack %u\n", my_seq (sock, acked));
	      grub_netbuff_free (unack->nb);
	      grub_free (unack);
	    }

	  sock->unack_first = unack;
	  if (!sock->unack_first)
	    sock->unack_last = NULL;
	}

      if (sock->i_reseted && len > 0)
	{
	  reset (sock, 0);
	}

      if ((tcph->flags & TCP_ACK && len > 0)
	  || !(tcph->flags & TCP_ACK)
	  || tcph->flags & TCP_FIN)
	{
	  if (tcph->flags & TCP_FIN)
	    fin = 1;
	  if (len > 0)
	    dbg ("adding %" PRIuGRUB_SIZE " to priority queue\n", len);
	  else if (tcph->flags & TCP_ACK || tcph->flags & TCP_FIN)
	    dbg ("adding %s packet to priority queue\n",
		    (tcph->flags & TCP_ACK) ?
		      (tcph->flags & TCP_FIN) ?
		        "ACK|FIN" : "ACK" : "FIN");

	  adjust_window (sock, -len);
	  err = grub_priority_queue_push (sock->pq, &nb);
	  if (err)
	    {
	      grub_dprintf ("tcp", "grub_priority_queue_push() returned %d\n",
			    err);
	      grub_netbuff_free (nb);
	      return err;
	    }
	  sock->queue_bytes += len;
	}
      else
	{
	  dbg ("not queueing empty packet.\n");
	}

      grub_uint64_t ms = grub_get_time_ms ();
      if (fin)
	dbg ("saw a FIN, processing queue\n");
      else if (sock->queue_bytes && sock->they_push)
	dbg ("they pushed, processing queue\n");
      else if (sock->queue_bytes && my_window (sock) < 0x500)
	dbg ("recv window low, processing queue (%d < 16384)\n",
	     my_window (sock));
      else if (my_window (sock) < 0x500)
	dbg ("recv window low (%d < 16384) but nothing in the queue?\n",
	     my_window (sock));
      else if (sock->queue_bytes && (ms - sock->last_ack_ms > 500))
	dbg ("timer expired; must process queue (%lu ms since last ack)\n",
	     ms - sock->last_ack_ms);
      else if (recv_pending (inf))
	{
	  dbg ("recv was pending; not processing queue\n");
	  return GRUB_ERR_NONE;
	}

      dbg ("processing queue\n");
      return grub_net_tcp_process_queue (sock);
    }

  /*
   * If it wasn't one of our outbound sockets, it must be one of our listens,
   * or a phantom.
   */
  if (tcph->flags & TCP_SYN)
    {
      grub_net_tcp_listen_t listen;

      FOR_TCP_LISTENS (listen)
	{
	  if (!(grub_be_to_cpu16 (tcph->dst) == listen->port
		&& (inf == listen->inf || listen->inf == NULL)))
	    continue;
	  sock = grub_zalloc (sizeof (*sock));
	  if (sock == NULL)
	    return grub_errno;

	  sock->out_port = grub_be_to_cpu16 (tcph->src);
	  sock->in_port = grub_be_to_cpu16 (tcph->dst);
	  sock->inf = inf;
	  sock->out_nla = *source;
	  sock->their_start_seq = grub_be_to_cpu32 (tcph->seqnr);
	  sock->their_cur_seq = sock->their_start_seq + 1;
	  sock->my_cur_seq = sock->my_start_seq = grub_get_time_ms ();
	  reset_window (sock);

	  sock->pq = grub_priority_queue_new (sizeof (struct grub_net_buff *),
					      cmp);
	  if (!sock->pq)
	    {
	      grub_netbuff_free (nb);
	      return grub_errno;
	    }

	  err = listen->listen_hook (listen, sock, listen->hook_data);

	  grub_netbuff_free (nb);
	  return err;
	}
    }
  grub_netbuff_free (nb);
  return GRUB_ERR_NONE;
}

void
grub_net_tcp_stall (grub_net_tcp_socket_t sock)
{
  if (sock->i_stall)
    return;
  sock->i_stall = 1;
  ack (sock);
}

void
grub_net_tcp_unstall (grub_net_tcp_socket_t sock)
{
  if (!sock->i_stall)
    return;
  sock->i_stall = 0;
  ack (sock);
}
