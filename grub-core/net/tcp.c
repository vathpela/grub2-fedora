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

#define TCP_FLAG_MASK grub_cpu_to_be16_compile_time (0x3f)

static const char * const tcp_flag_names[] =
{
  "FIN",
  "SYN",
  "RST",
  "PSH",
  "ACK",
  "URG",
  NULL
};

static char *
flags_str (grub_uint16_t flags)
{
  static char str[24];
  unsigned int i;
  int flag_values[] = { TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG };
  char *cur = &str[0];

  str[0] = '\0';
  for (i = 0; tcp_flag_names[i] != NULL; i++)
    {
      if (flags & flag_values[i])
	{
	  if (cur != str)
	    cur = grub_stpcpy (cur, "|");
	  cur = grub_stpcpy  (cur, tcp_flag_names[i]);
	}
    }

  return str;
}

enum tcp_states
{
  CLOSED,
  LISTEN,
  SYN_RCVD,
  SYN_SENT,
  ESTABLISHED,
  CLOSE_WAIT,
  LAST_ACK,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSING,
  TIME_WAIT,
  INVALID_STATE
};
typedef enum tcp_states tcp_state;

static const char * const tcp_state_names[] =
{
  [CLOSED] = "CLOSED",
  [LISTEN] = "LISTEN",
  [SYN_RCVD] = "SYN-RECEIVED",
  [SYN_SENT] = "SYN-SENT",
  [ESTABLISHED] = "ESTABLISHED",
  [CLOSE_WAIT] = "CLOSE-WAIT",
  [LAST_ACK] = "LAST-ACK",
  [FIN_WAIT_1] = "FIN-WAIT-1",
  [FIN_WAIT_2] = "FIN-WAIT-2",
  [CLOSING] = "CLOSING",
  [TIME_WAIT] = "TIME-WAIT",
};

struct tcp_state_transition
{
  tcp_state from;
  tcp_state to;
} tcp_state_transitions[] =
  {
    { CLOSED, SYN_SENT },
    { CLOSED, LISTEN },
    { SYN_SENT, CLOSED },
    { SYN_SENT, SYN_RCVD },
    { SYN_SENT, ESTABLISHED },
    { SYN_RCVD, CLOSED },
    { SYN_RCVD, ESTABLISHED },
    { SYN_RCVD, FIN_WAIT_1 },
    { ESTABLISHED, FIN_WAIT_1 },
    { ESTABLISHED, CLOSE_WAIT },
    { FIN_WAIT_1, FIN_WAIT_2 },
    { FIN_WAIT_1, CLOSING },
    { FIN_WAIT_1, TIME_WAIT },
    { CLOSE_WAIT, LAST_ACK },
    { FIN_WAIT_2, TIME_WAIT },
    { CLOSING, TIME_WAIT },
    { LAST_ACK, CLOSED },
    { TIME_WAIT, CLOSED },
    { INVALID_STATE, INVALID_STATE }
  };

struct tcp_segment
{
  int seq; /* SEG.SEQ - segment sequence number */
  int ack; /* SEG.ACK - segment acknowledgment number */
  int len; /* SEG.LEN - segment length */
  int wnd; /* SEG.WND - segment window */
  int up;  /* SEG.UP  - segment urgent pointer */
  int prc; /* SEG.PRC - segment precedence value */
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

struct grub_net_tcp_socket
{
  struct grub_net_tcp_socket *next;
  struct grub_net_tcp_socket **prev;

  grub_net_tcp_listen_t listen;

  tcp_state state;
  grub_uint16_t local_port;
  grub_uint16_t remote_port;

  struct {
      grub_uint32_t una; /* SND.UNA - send unacknowledged */
      grub_uint32_t nxt; /* SND.NXT - send next */
      grub_uint32_t wnd; /* SND.WND - send window */
      grub_uint32_t up;  /* SND.UG  - send urgent pointer */
      grub_uint32_t wl1; /* SND.WL1 - segment sequence number used for last
			    window update */
      grub_uint32_t wl2; /* SND.WL2 - segment acknowledgment number used for
			    last window update */
      grub_uint8_t sca;  /* SND.WND scale */
  } snd;
  grub_uint32_t iss;     /* ISS     - Initial send sequence number */
  struct {
      grub_uint32_t nxt; /* RCV.NXT - receive next */
      grub_uint32_t wnd; /* RCV.WND - receive window */
      grub_uint32_t up;  /* RCV.UP  - receive urgent pointer */
      grub_uint8_t sca;  /* RCV.WND scale */
  } rcv;
  grub_uint32_t irs;     /* IRS     - initial receive sequence number */

  struct tcp_segment seg;

  int i_closed;
  int they_closed;
  int errors;
  int they_reseted;
  int i_reseted;
  int i_stall;
  int they_push;
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
#define tcpflags(tcpp) ((tcpp)->flags & TCP_FLAG_MASK)
#define tcpsize(size) grub_cpu_to_be16_compile_time((size) << 10)
#define pktlen(nb) ((grub_ssize_t)((nb)->tail - (nb)->data))
#define my_seq(sock, seqnr) ((seqnr) - ((sock)->iss))
#define their_seq(sock, seqnr) ((seqnr) - ((sock)->irs))
#define my_window(sock) ((sock)->snd.wnd << ((sock)->snd.sca))

#define dbg(fmt, ...) ({grub_uint64_t _now = grub_get_time_ms(); grub_dprintf("tcp", "%lu.%lu " fmt, _now / 1000, _now % 1000, ## __VA_ARGS__);})

#define FOR_TCP_OPTIONS(tcph, opt)					    \
  for ((opt) = (struct tcp_opt *)(((char *)tcph) + sizeof (struct tcphdr)); \
       tcplen((tcph)->flags) > 20 && ((opt)->kind) != 0 ;		    \
       (opt) = (struct tcp_opt *)((char *)(opt) +			    \
				  ((opt)->kind == 1 ? 1 : ((opt)->length))))

static void
grub_net_tcp_flush_recv_queue (grub_net_tcp_socket_t sock);
static grub_err_t
grub_net_tcp_process_queue (grub_net_tcp_socket_t sock, int force_ack);

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
  grub_uint64_t scale = 1 << sock->snd.sca;
  grub_uint64_t window = sock->snd.wnd;
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
  if (scale != sock->snd.sca || window != sock->snd.wnd)
    {
      dbg ("rescaling (howmuch=%d) %u*%u (%x) -> %lu*%u (0x%lx)\n",
	   howmuch, sock->snd.wnd, 1 << sock->snd.sca,
	   sock->snd.wnd * (1 << sock->snd.sca),
	   window, 1 << scale, window * (1 << scale));
      sock->snd.sca = scale;
      sock->snd.wnd = window;
    }
}

static inline void
reset_window (grub_net_tcp_socket_t sock)
{
  grub_uint64_t scaled;
  sock->snd.sca = 0;
  sock->snd.wnd = 0;

  scaled = min(sock->inf->card->mtu, 1500)
	   - GRUB_NET_OUR_IPV4_HEADER_SIZE
	   - sizeof (struct tcphdr);
  scaled = scaled * 100;
  scaled = ALIGN_UP(scaled, 4096);
  adjust_window (sock, scaled);
  dbg ("Setting window to %u << %u = (%lu)\n",
       sock->snd.wnd, sock->snd.sca,
       (unsigned long)sock->snd.wnd << sock->snd.sca);
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

static grub_net_tcp_socket_t
new_socket (struct grub_net_network_level_interface *inf,
	    struct tcphdr *tcph,
	    const grub_net_network_level_address_t *source)
{
  grub_net_tcp_socket_t sock;

  sock = grub_zalloc (sizeof (*sock));
  if (sock == NULL)
    return NULL;

  sock->state = CLOSED;
  if (tcph)
    {
      sock->local_port = grub_be_to_cpu16 (tcph->src);
      sock->remote_port = grub_be_to_cpu16 (tcph->dst);
    }
  sock->inf = inf;
  sock->out_nla = *source;
  reset_window (sock);

  sock->pq = grub_priority_queue_new (sizeof (struct grub_net_buff *), cmp);
  if (!sock->pq)
    {
      grub_free (sock);
      return NULL;
    }

  return sock;
}

static grub_err_t
change_socket_state (grub_net_tcp_socket_t sock, tcp_state new_state)
{
  unsigned int i;
  const char *buf0, *buf1;
  char uintbuf0[11], uintbuf1[11];
  unsigned int state = (unsigned int)sock->state;

  for (i = 0; tcp_state_transitions[i].from != INVALID_STATE; i++)
    {
      if (tcp_state_transitions[i].from != sock->state)
	continue;
      if (tcp_state_transitions[i].to == new_state)
	{
	  grub_dprintf ("tcp", "%s -> %s\n",
			tcp_state_names[sock->state],
			tcp_state_names[new_state]);
	  sock->state = new_state;
	  return GRUB_ERR_NONE;
	}
    }

  if (state >= INVALID_STATE)
    {
      buf0 = uintbuf0;
      grub_snprintf (uintbuf0, 11, "%u", state);
    }
  else
    buf0 = tcp_state_names[state];

  if (new_state >= INVALID_STATE)
    {
      buf1 = uintbuf1;
      grub_snprintf (uintbuf1, 11, "%u", new_state);
    }
  else
    buf1 = tcp_state_names[new_state];

  grub_printf ("TCP: Invalid socket transition from %s to %s.  Closing.\n",
	       buf0, buf1);
  sock->state = CLOSED;
  return GRUB_ERR_BAD_ARGUMENT;
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

  tcph->seqnr = grub_cpu_to_be32 (socket->snd.nxt);
  size = pktlen (nb) - tcplen (tcph->flags);
  if (tcph->flags & TCP_FIN)
    size++;
  socket->snd.nxt += size;
  tcph->src = grub_cpu_to_be16 (socket->remote_port);
  tcph->dst = grub_cpu_to_be16 (socket->local_port);
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
  else
    grub_net_tcp_process_queue (sock, 0);

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
  tcph_fin->ack = grub_cpu_to_be32 (sock->rcv.nxt);
  tcph_fin->flags = tcpsize (sizeof *tcph_fin) | TCP_FIN | TCP_ACK;
  tcph_fin->window = grub_cpu_to_be16_compile_time (0);
  tcph_fin->window = grub_cpu_to_be16 (sock->snd.wnd);
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
			      sock->snd.sca);
      if (err)
	goto error;

      err = add_padding (nb_ack, tcph_ack, &hdrsize);
      if (err)
	goto error;

      sock->snd.una = sock->rcv.nxt;
      sock->last_ack_ms = grub_get_time_ms ();

      tcph_ack->window = !sock->i_stall ? grub_cpu_to_be16 (sock->snd.wnd)
	: 0;
    }
  else
    {
      tcph_ack->window = 0;
    }

  if (res)
    {
      tcph_ack->ack = grub_cpu_to_be32_compile_time (0);
      tcph_ack->flags = tcpsize (hdrsize) | TCP_RST
		        | (ack ? TCP_ACK : 0);
      reset_window (sock);
      grub_net_tcp_flush_recv_queue (sock);
    }
  else
    {
      tcph_ack->ack = grub_cpu_to_be32 (sock->rcv.nxt);
      tcph_ack->flags = tcpsize (hdrsize) | TCP_ACK;
      if (sock->they_closed && !sock->i_closed)
	{
	  tcph_ack->flags |= TCP_FIN;
	  sock->i_closed;
	}
    }

  tcph_ack->urgent = 0;
  tcph_ack->src = grub_cpu_to_be16 (sock->remote_port);
  tcph_ack->dst = grub_cpu_to_be16 (sock->local_port);
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
  grub_uint64_t now = grub_get_time_ms ();
  if (sock->rcv.nxt == sock->snd.una &&
      now - sock->last_ack_ms < 500 &&
      !(sock->i_closed || sock->they_closed))
    return;
  ack_real (sock, 0, 1);
}

static void
reset (grub_net_tcp_socket_t sock)
{
  int ack = 0;

  /* If it's closed, we ACK if they've sent an ACK */
  if (sock->i_closed || sock->they_closed)
    {
      if (!sock->rcv.nxt)
	ack = 1;
    }
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
	      && tcph->ack != grub_cpu_to_be32 (sock->rcv.nxt))
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
  tcph->ack = grub_cpu_to_be32 (sock->rcv.nxt);
  tcph->flags = tcpsize (hdrsize) | TCP_SYN | TCP_ACK;
  tcph->window = grub_cpu_to_be16 (sock->snd.wnd);
  tcph->urgent = 0;
  sock->state = ESTABLISHED;
  tcp_socket_register (sock);
  err = tcp_send (nb_ack, sock);
  if (err)
    return err;
  sock->snd.nxt++;
  return GRUB_ERR_NONE;
}

static void
init_tcp_src_port (grub_uint16_t *port)
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

static int
is_established (void *data)
{
  grub_net_tcp_socket_t sock = (grub_net_tcp_socket_t)data;

  return sock->state == ESTABLISHED;
}

grub_net_tcp_socket_t
grub_net_tcp_open (char *server,
		   grub_uint16_t local_port,
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
  static grub_uint16_t remote_port;
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

  if (remote_port == 0)
    {
      init_tcp_src_port (&socket->remote_port);
      remote_port = socket->remote_port;
    }
  else if (remote_port == 65535)
    remote_port = 2;

  socket = new_socket (inf, tcph, &addr);

  socket->remote_port = remote_port++;
  grub_dprintf ("tcp", "new source port is %d\n", socket->remote_port);

  socket->local_port = local_port;
  socket->ll_target_addr = ll_target_addr;
  socket->recv_hook = recv_hook;
  socket->error_hook = error_hook;
  socket->fin_hook = fin_hook;
  socket->hook_data = hook_data;
  socket->iss = grub_get_time_ms ();
  socket->snd.nxt = socket->iss + 1;

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
error:
      grub_netbuff_free (nb);
      return NULL;
    }

  tcph = (void *) nb->data;
  grub_memset(tcph, 0, sizeof (*tcph));

  err = add_window_scale (nb, tcph, &hdrsize, socket->snd.sca);
  if (err)
    goto error;

  err = add_mss (socket, nb, tcph, &hdrsize);
  if (err)
    goto error;

  err = add_padding (nb, tcph, &hdrsize);
  if (err)
    goto error;

  tcph->seqnr = grub_cpu_to_be32 (socket->iss);
  tcph->ack = grub_cpu_to_be32_compile_time (0);
  tcph->flags = tcpsize (hdrsize) | TCP_SYN;
  tcph->window = grub_cpu_to_be16 (socket->snd.wnd);
  tcph->urgent = 0;
  tcph->src = grub_cpu_to_be16 (socket->remote_port);
  tcph->dst = grub_cpu_to_be16 (socket->local_port);
  tcph->checksum = grub_net_ip_transport_checksum (nb, GRUB_NET_IP_TCP,
						   &socket->inf->address,
						   &socket->out_nla);
  tcp_socket_register (socket);
  change_socket_state (socket, SYN_SENT);

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
		   && socket->state != ESTABLISHED); j++)
	grub_net_poll_cards_cb (50, is_established, socket);
      if (socket->state == ESTABLISHED)
	break;
    }
  if (socket->state != ESTABLISHED)
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
      tcph->ack = grub_cpu_to_be32 (socket->rcv.nxt);
      tcph->flags = tcpsize (sizeof *tcph) | TCP_ACK;
      tcph->window = !socket->i_stall ? grub_cpu_to_be16 (socket->snd.wnd)
	: 0;
      tcph->urgent = 0;
      err = grub_netbuff_put (nb2, fraglen);
      if (err)
	return err;
      grub_memcpy (tcph + 1, nb->data, fraglen);
      err = grub_netbuff_pull (nb, fraglen);
      if (err)
	return err;

      dbg ("acking %u\n", their_seq(socket, socket->rcv.nxt));
      err = tcp_send (nb2, socket);
      if (err)
	return err;
    }

  err = grub_netbuff_push (nb, sizeof (*tcph));
  if (err)
    return err;

  dbg ("acking+push %u\n", their_seq (socket, socket->rcv.nxt));
  tcph = (struct tcphdr *) nb->data;
  tcph->ack = grub_cpu_to_be32 (socket->rcv.nxt);
  tcph->flags = tcpsize (sizeof *tcph) | TCP_ACK | (push ? TCP_PSH : 0);
  tcph->window = !socket->i_stall ? grub_cpu_to_be16 (socket->snd.wnd) : 0;
  tcph->urgent = 0;
  return tcp_send (nb, socket);
}

static void
prune_acks (grub_net_tcp_socket_t sock, struct tcphdr *tcph)
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

static int
recv_pending (struct grub_net_network_level_interface *inf)
{
  int rc;

  rc = inf->card->driver->recv_pending (inf->card);
  if (rc < 1)
    return 0;
  return rc;
}

static grub_err_t
grub_net_tcp_process_queue (grub_net_tcp_socket_t sock, int force_ack)
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
      int done;
      struct tcp_opt *opt;

      tcph = (struct tcphdr *) nb_top->data;
      seqnr = grub_be_to_cpu32 (tcph->seqnr);
      hdrlen = tcplen (tcph->flags);
      len = pktlen (nb_top) - hdrlen;

      dbg ("processing nb with seqnr %u\n", their_seq (sock, seqnr));

      if (force_ack)
	do_ack = 1;

      FOR_TCP_OPTIONS (tcph, opt)
	{
	  struct tcp_scale_opt *scale;

	  dbg ("processing tcph (0x%016lx) option %u (0x%016lx)\n",
	       (unsigned long)tcph, opt->kind, (unsigned long)opt);

	  if (opt->kind != 3)
	    continue;

	  scale = (struct tcp_scale_opt *)opt;
	  sock->rcv.wnd = grub_be_to_cpu16 (tcph->window);
	  sock->rcv.sca = scale->scale;
	  break;
	}

      grub_dprintf ("tcp", "packet flags %s for %s state\n",
		    flags_str (tcph->flags), tcp_state_names[sock->state]);
      switch (sock->state)
	{
	case CLOSED:
	  grub_dprintf ("tcp", "ignoring packet and reaping socket\n");
	  destroy_socket (sock);
	  return GRUB_ERR_NONE;
	case LISTEN:
	  grub_dprintf ("tcp", "unexpected listen\n");
	  break;
	case SYN_RCVD:
	  switch (tcph->flags)
	    {
	    case TCP_FIN:
	      change_socket_state (sock, CLOSE_WAIT);
	      sock->rcv.nxt++;
	      dbg ("%u -> rcv.nxt\n", their_seq (sock, sock->rcv.nxt));
	      do_ack = 1;
	      break;
	    case TCP_RST:
	      change_socket_state (sock, CLOSED);
	      break;
	    case TCP_ACK:
	      change_socket_state (sock, ESTABLISHED);
	      break;
	    }
	  break;
	case SYN_SENT:
	  switch (tcph->flags)
	    {
	    case TCP_SYN|TCP_ACK:
	      change_socket_state (sock, ESTABLISHED);
	      prune_acks (sock, tcph);
	      do_ack = 1;
	      break;
	    case TCP_SYN:
	      change_socket_state (sock, SYN_RCVD);
	      do_ack = 1;
	      break;
	    }
	  break;
	case ESTABLISHED:
	  switch (tcph->flags)
	    {
	    case TCP_FIN:
	      change_socket_state (sock, CLOSE_WAIT);
	      sock->rcv.nxt++;
	      dbg ("%u -> rcv.nxt\n", their_seq (sock, sock->rcv.nxt));
	      do_ack = 1;
	      break;
	    case TCP_ACK:
	      /* Get rid of our old unacked packets. */
	      prune_acks (sock, tcph);
	      if (len)
		{
		  dbg ("adding %" PRIuGRUB_SIZE " to priority queue\n", len);
		  adjust_window (sock, -len);
		  sock->queue_bytes += len;
		}
	      break;
	    }
	  break;
	case CLOSE_WAIT:
	  break;
	case LAST_ACK:
	  break;
	case FIN_WAIT_1:
	  break;
	case FIN_WAIT_2:
	  break;
	case CLOSING:
	  break;
	case TIME_WAIT:
	default: /* INVALID_STATE */
	  grub_dprintf ("tcp", "got a packet in invalid state?\n");
	}

      if (done)
	break;

      /* If we have seen this sequence already, just remove it */
      if (seqnr < sock->rcv.nxt)
	{
	  dbg ("Ignoring already acked packet %u\n", their_seq (sock, seqnr));
	  grub_netbuff_free (nb_top);
	  grub_priority_queue_pop (sock->pq);
	  sock->queue_bytes -= len;
	  continue;
	}

      /* If we've got an out-of-order packet, we need to re-ack to make sure
       * the sender is up to date, and our packet queue is invalid. */
      if (seqnr > sock->rcv.nxt)
	{
	  dbg ("OOO %u, expected %u moving on\n",
	       their_seq(sock, seqnr), their_seq(sock, sock->rcv.nxt));
	  if (their_seq (sock, seqnr) >> 4 >
	      their_seq (sock, sock->rcv.nxt))
	      reset (sock);
	  else
	    {
	      do_ack = 1;
	      sock->queue_bytes -= len;
	    }
	  break;
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
	  reset (sock);
	  break;
	}

      sock->rcv.nxt += len;
      dbg ("%u -> rcv.nxt\n", their_seq (sock, sock->rcv.nxt));
      adjust_window (sock, len);


      /* If this is near the end of the window, we need to ACK fast. */
#if 0
      if (sock->snd.una + sock->their_window + len
	  > sock->rcv.nxt)
	do_ack = 1;
      if (sock->snd.una + snd.wnd (sock) + len > sock->rcv.nxt)
	do_ack = 1;
#endif

      /* If there is data, puts packet in socket list. */
      if (len > 0)
	grub_net_put_packet (&sock->packs, nb_top);
      else
	grub_netbuff_free (nb_top);
    }


  /* If we got here, there's nothing we can process in the queue, and it's
   * all bad.  Flush it down the drain. */
  grub_net_tcp_flush_recv_queue (sock);

  if (do_ack)
    {
      dbg ("acking %u\n", their_seq (sock, sock->rcv.nxt));
      ack (sock);
      sock->they_push = 0;
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

static void
handle_listen (struct grub_net_buff *nb, struct tcphdr *tcph,
	       grub_net_tcp_socket_t listen_sock,
	       const grub_net_network_level_address_t *source)
{
  grub_net_tcp_socket_t sock;
  grub_uint16_t flags = tcpflags(tcph);
  grub_err_t err;

  grub_net_tcp_listen_t listen = listen_sock->listen;

  switch (tcph->flags)
    {
    case TCP_SYN:
      sock = new_socket (listen_sock->inf, tcph, source);
      if (!sock)
	{
	  grub_dprintf ("tcp", "new_socket returned %d\n", grub_errno);
	  grub_netbuff_free (nb);
	  return;
	}
      change_socket_state (sock, LISTEN);
      change_socket_state (sock, SYN_RCVD);

      sock->irs = grub_be_to_cpu32 (tcph->seqnr);
      sock->rcv.nxt = sock->irs + 1;

      sock->seg.seq = sock->iss = sock->irs + grub_get_time_ms ();

      err = listen->listen_hook (listen, sock, listen->hook_data);
      if (err)
	{
	  grub_netbuff_free (nb);
	  destroy_socket (sock);
	  return;
	}
      tcp_socket_register (sock);
      break;
    case TCP_RST:
      grub_netbuff_free (nb);
      return;
    default: /* XXX FIXME */
      grub_netbuff_free (nb);
      return;
    }
}

grub_err_t
grub_net_recv_tcp_packet (struct grub_net_buff *nb,
			  struct grub_net_network_level_interface *inf,
			  const grub_net_network_level_address_t *source)
{
  struct tcphdr *tcph;
  struct grub_net_tcp_socket sockbuf;
  grub_net_tcp_socket_t sock, next_sock;
  grub_err_t err;
  grub_ssize_t len, hdrlen;
  int force_ack;

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
      int push = 0, queue = 0;
      grub_net_tcp_listen_t listen;

      if (sock->state == CLOSED)
	{
	  grub_dprintf ("tcp", "reaping closed socket\n");
	  grub_netbuff_free (nb);
	  destroy_socket (sock);
	  continue;
	}

      if (!(grub_be_to_cpu16 (tcph->dst) == sock->remote_port
	    && grub_be_to_cpu16 (tcph->src) == sock->local_port
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

      grub_dprintf ("tcp", "packet flags %s for %s state\n",
		    flags_str (tcph->flags), tcp_state_names[sock->state]);
      switch (sock->state)
	{
	case CLOSED:
	  /* This shouldn't ever happen, because we reap these above */
	  break;
	case LISTEN:
	  FOR_TCP_LISTENS (listen)
	    {
	      if (!(grub_be_to_cpu16 (tcph->dst) == listen->port
		    && (inf == listen->inf || listen->inf == NULL)))
		continue;

	      handle_listen (nb, tcph, sock, source);
	    }
	  break;
	case SYN_RCVD:
	  if (tcpflags(tcph) == TCP_ACK)
	    sock->irs = grub_be_to_cpu32 (tcph->seqnr);
	  queue = 1;
	  break;
	case SYN_SENT:
	  /* We do this here just to make the next debug log messages
	   * coherent */
	  if (tcpflags(tcph) == (TCP_SYN|TCP_ACK))
	    sock->irs = grub_be_to_cpu32 (tcph->seqnr);
	  queue = 1;
	  break;
	case ESTABLISHED:
	  if (tcph->flags & TCP_PSH)
	    push = 1;
	  queue = 1;
	  break;
	case CLOSE_WAIT:
	case LAST_ACK:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSING:
	case TIME_WAIT:
	  queue = 1;
	  break;
	default: /* INVALID_STATE */
	  grub_dprintf ("tcp",
			"socket was in invalid state %d; destroying.\n",
			sock->state);
	  grub_netbuff_free (nb);
	  destroy_socket (sock);
	  return GRUB_ERR_NONE;
	}

      if (queue)
	{
	  dbg ("ingress seq %u ack %u len=%ld\n",
	       their_seq (sock, grub_be_to_cpu32 (tcph->seqnr)),
	       my_seq (sock, grub_be_to_cpu32 (tcph->ack)), len);

	  err = grub_priority_queue_push (sock->pq, &nb);
	  if (err)
	    {
	      grub_dprintf ("tcp", "grub_priority_queue_push() returned %d\n",
			    err);
	      grub_netbuff_free (nb);
	      return err;
	    }
	}

      force_ack = 1;
      if (push)
	dbg ("saw push; processing queue immediately\n");
      else if (recv_pending (inf))
	{
	  dbg ("recv was pending; not processing queue\n");
	  return GRUB_ERR_NONE;
	}
      else
	force_ack = 0;

      dbg ("processing queue\n");
      return grub_net_tcp_process_queue (sock, force_ack);
    }

  /* If this isn't an open socket, we send RST or RST|ACK depending on their
   * ack field, unless it's a RST packet, in which case we ignore it. */
  if (!(tcph->flags & TCP_RST))
    {
      memset (&sockbuf, 0, sizeof (sockbuf));
      sock = &sockbuf;
      sock->i_closed = 1;
      sock->they_closed = 1;
      sock->errors = 1;
      sock->i_reseted = 1;
      sock->remote_port = grub_be_to_cpu16 (tcph->src);
      sock->local_port = grub_be_to_cpu16 (tcph->dst);
      reset_window (sock);
      sock->rcv.nxt = grub_be_to_cpu32 (tcph->seqnr) + len;
      sock->snd.nxt = grub_be_to_cpu32 (tcph->ack);
      reset (sock);
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
