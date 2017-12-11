/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011,2017  Free Software Foundation, Inc.
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
#include <grub/backtrace.h>

#include "tcp.h"

struct grub_net_tcp_socket *tcp_sockets = NULL;

struct tcp_state_transition tcp_state_transitions[] =
  {
    { CLOSED, SYN_SENT },
    { CLOSED, SYN_RCVD },
    { CLOSED, LISTEN },
    { SYN_SENT, SYN_RCVD },
    { SYN_SENT, ESTABLISHED },
    { SYN_SENT, CLOSED },
    { SYN_RCVD, ESTABLISHED },
    { SYN_RCVD, FIN_WAIT_1 },
    { SYN_RCVD, CLOSED },
    { ESTABLISHED, FIN_WAIT_1 },
    { ESTABLISHED, CLOSE_WAIT },
    { ESTABLISHED, CLOSED },
    { FIN_WAIT_1, FIN_WAIT_2 },
    { FIN_WAIT_1, CLOSING },
    { FIN_WAIT_1, TIME_WAIT },
    { FIN_WAIT_1, CLOSED },
    { FIN_WAIT_2, TIME_WAIT },
    { FIN_WAIT_2, CLOSED },
    { CLOSE_WAIT, LAST_ACK },
    { CLOSE_WAIT, CLOSED },
    { CLOSING, TIME_WAIT },
    { CLOSING, CLOSED },
    { LAST_ACK, CLOSED },
    { TIME_WAIT, CLOSED },
    { INVALID_STATE, INVALID_STATE }
  };

const char * const tcp_state_names[] =
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
  [INVALID_STATE] = "INVALID",
};

const char * const tcp_flag_names[] =
{
  "FIN",
  "SYN",
  "RST",
  "PSH",
  "ACK",
  "URG",
  NULL
};

#define min(x, y) (((x) >= (y)) ? (x) : (y))

grub_uint64_t
minimum_window (grub_net_tcp_socket_t sock)
{
  return min(sock->inf->card->mtu, 1500)
         - GRUB_NET_OUR_IPV4_HEADER_SIZE
	 - sizeof (struct tcphdr);
}

void
adjust_window (grub_net_tcp_socket_t sock, struct tcp_segment *seg)
{
  grub_uint64_t scale = sock->snd.sca;
  grub_uint64_t window = sock->snd.wnd;
  grub_uint64_t scaled;
  grub_uint64_t maximum = 0x8000ULL * (1ULL << 48);
  grub_uint64_t minimum = minimum_window (sock);

  if (sock->snd.wl1 < seg->seq
      || (sock->snd.wl1 == seg->seq
	  && sock->snd.wl2 <= seg->ack))
    {
      sock->snd.wl1 = seg->seq;
      sock->snd.wl2 = seg->ack;

      scaled = seg->wnd;
      if (scaled > maximum)
	scaled = maximum;
      if (scaled < minimum)
	scaled = minimum;

      /* and then compute a new window from that */
      for (scale = 0; scale < 0xff; scale++)
	if (scaled >> scale < 0xffff)
	  break;
      window = scaled >> scale;

      if (scale != sock->snd.sca || window != sock->snd.wnd)
	{
	  dbgw ("%d rescaling %u*%u (%x) -> %lu*%u (0x%lx)\n", sock->local_port,
		sock->snd.wnd, 1 << sock->snd.sca,
		sock->snd.wnd * (1 << sock->snd.sca),
		window, 1 << scale, window * (1 << scale));
	  sock->snd.sca = scale;
	  sock->snd.wnd = window;
	}
    }
}

void
reset_window (grub_net_tcp_socket_t sock)
{
  grub_uint64_t scale = 1 << sock->snd.sca;
  grub_uint64_t window = sock->snd.wnd;
  grub_uint64_t scaled;
  grub_uint64_t maximum = 0x8000ULL * (1ULL << 48);
  grub_uint64_t minimum = minimum_window (sock);
  grub_uint64_t howmuch;

  sock->snd.sca = 0;
  sock->snd.wnd = 0;

  howmuch = min(sock->inf->card->mtu, 1500)
	   - GRUB_NET_OUR_IPV4_HEADER_SIZE
	   - sizeof (struct tcphdr);
  howmuch = howmuch * 100;
  howmuch = ALIGN_UP(howmuch, 4096);

  /* Add our modifier to the total */
  scaled = window * scale + howmuch;
  if (scaled > maximum)
    scaled = maximum;
  if (scaled < minimum)
    scaled = minimum;

  /* and then compute a new window from that */
  for (scale = 0; scale < 0xff; scale++)
    if (scaled >> scale < 0xffff)
      break;
  window = scaled >> scale;
  if (scale != sock->snd.sca || window != sock->snd.wnd)
    {
      sock->snd.sca = scale;
      sock->snd.wnd = window;

      dbgw ("%d setting window to %u << %u = (%lu)\n", sock->local_port,
	    sock->snd.wnd, sock->snd.sca,
	    (unsigned long)sock->snd.wnd << sock->snd.sca);
    }
}

void
grub_net_tcp_flush_recv_queue (grub_net_tcp_socket_t sock)
{
  struct grub_net_buff **nb_top_p;

  while ((nb_top_p = grub_priority_queue_top (sock->receive)) != NULL)
    {
      struct grub_net_buff *nb_top = *nb_top_p;
      grub_netbuff_free (nb_top);
      grub_priority_queue_pop (sock->receive);
    }
}

static int
seqcmp (const void *a__, const void *b__)
{
  struct grub_net_buff *a_ = *(struct grub_net_buff **) a__;
  struct grub_net_buff *b_ = *(struct grub_net_buff **) b__;
  struct tcphdr *a = (struct tcphdr *) a_->data;
  struct tcphdr *b = (struct tcphdr *) b_->data;

  /* We want the first elements to be on top.  */
  if (before (a->seqnr, b->seqnr))
    return +1;
  if (after (a->seqnr, b->seqnr))
    return -1;
  return 0;
}

grub_net_tcp_socket_t
new_socket (const struct grub_net_network_level_interface *inf,
	    const grub_net_network_level_address_t *source,
	    struct tcphdr *tcph, tcp_state state)
{
  grub_net_tcp_socket_t sock;

  sock = grub_zalloc (sizeof (*sock));
  if (sock == NULL)
    return NULL;

  sock->state = state;
  if (tcph)
    {
      sock->local_port = grub_be_to_cpu16 (tcph->src);
      sock->remote_port = grub_be_to_cpu16 (tcph->dst);
    }
  sock->inf = inf;
  sock->out_nla = *source;

  if (state != LISTEN)
    {
      sock->receive = grub_priority_queue_new (sizeof (struct grub_net_buff *), seqcmp);
      if (!sock->receive)
	{
	  grub_free (sock);
	  return NULL;
	}

      sock->retransmit = grub_priority_queue_new (sizeof (struct grub_net_buff *), seqcmp);
      if (!sock->retransmit)
	{
	  grub_priority_queue_destroy (sock->receive);
	  grub_free (sock);
	  return NULL;
	}
    }

  return sock;
}

void
destroy_socket (grub_net_tcp_socket_t sock)
{
  struct unacked *unack;
  struct grub_net_buff **nb_p;

  dbg ("%d destroying socket\n", sock->local_port);

  grub_list_remove (GRUB_AS_LIST (sock));

  while ((unack = grub_priority_queue_top (sock->retransmit)))
    {
      grub_netbuff_free (unack->nb);
      grub_priority_queue_pop (sock->retransmit);
    }

  grub_priority_queue_destroy (sock->retransmit);

  while ((nb_p = grub_priority_queue_top (sock->receive)))
    {
      grub_netbuff_free (*nb_p);
      grub_priority_queue_pop (sock->receive);
    }

  grub_priority_queue_destroy (sock->receive);

  grub_free (sock);
}

grub_err_t
tcp_socket_register (grub_net_tcp_socket_t sock)
{
  grub_net_tcp_socket_t this, next;

  FOR_TCP_SOCKETS(this, next)
    {
      if (this->local_port != sock->local_port)
	continue;

      switch (this->state)
	{
	case LISTEN:
	  if (sock->state == LISTEN)
	    return GRUB_ERR_WAIT;
	  continue;
	case CLOSED:
	  destroy_socket (this);
	  continue;
	default:
	  continue;
	}
    }
  grub_list_push (GRUB_AS_LIST_P (&tcp_sockets),
		  GRUB_AS_LIST (sock));
  return GRUB_ERR_NONE;
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
change_socket_state_real (grub_net_tcp_socket_t sock, tcp_state new_state,
			  const char * const file, int line)
{
  unsigned int i;
  const char *buf0, *buf1;
  char uintbuf0[11], uintbuf1[11];
  unsigned int state = (unsigned int)sock->state;
  int debug = grub_debug_enabled ("tcp");
  grub_err_t err;

  for (i = 0; tcp_state_transitions[i].from != INVALID_STATE; i++)
    {
      if (tcp_state_transitions[i].from != sock->state)
	continue;
      if (tcp_state_transitions[i].to == new_state)
	{
	  if (debug)
	    {
	      grub_uint64_t now = grub_get_time_ms ();
	      grub_printf ("%s:%d: %lu.%lu %d %s -> %s\n",
			   file, line, now / 1000, now % 1000,
			   sock->local_port,
			   tcp_state_names[sock->state],
			   tcp_state_names[new_state]);
	    }
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

  err = grub_error (GRUB_ERR_BUG,
		    N_("TCP: Invalid socket transition from %s to %s"),
		    buf0, buf1);
  grub_print_error ();
  grub_backtrace (0);
  sock->state = CLOSED;
  return err;
}

void
push_socket_data (grub_net_tcp_socket_t sock)
{
  while (sock->packs.first)
    {
      struct grub_net_buff *nb = sock->packs.first->nb;
      if (sock->recv_hook)
	sock->recv_hook (sock, sock->packs.first->nb, sock->hook_data);
      else
	grub_netbuff_free (nb);
      grub_net_remove_packet (sock->packs.first);
    }
}

grub_err_t
add_window_scale (struct grub_net_buff *nb,
		  struct tcphdr *tcph, grub_size_t *size, int scale_value)
{
  struct tcp_scale_opt *scale = (struct tcp_scale_opt *)((char *)tcph + *size);
  grub_err_t err;

  err = grub_netbuff_put (nb, sizeof (*scale));
  if (err)
    {
      grub_dprintf ("net", "error adding tcp window scale option: %m: %1m\n");
      return err;
    }

  scale->kind = 3;
  scale->length = sizeof (*scale);
  scale->scale = scale_value;
  *size += sizeof (*scale);
  return GRUB_ERR_NONE;
}

grub_err_t
add_mss (grub_net_tcp_socket_t sock, struct grub_net_buff *nb,
	 struct tcphdr *tcph, grub_size_t *size)
{
  struct tcp_mss_opt *mss = (struct tcp_mss_opt *)((char *)tcph + *size);
  grub_err_t err;

  err = grub_netbuff_put (nb, sizeof (*mss));
  if (err)
    {
      grub_dprintf ("net", "error adding tcp mss option: %m: %1m\n");
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

grub_err_t
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
      grub_dprintf ("net", "error adding tcp mss option: %m: %1m\n");
      return err;
    }

  memset (end, 0, end_size);
  *size += end_size;
  return GRUB_ERR_NONE;
}

void
error (grub_net_tcp_socket_t sock)
{
  if (sock->error_hook)
    sock->error_hook (sock, sock->hook_data);

  change_socket_state (sock, CLOSED);
}

int
reap_time_wait (grub_net_tcp_socket_t sock)
{
  if (sock->state == TIME_WAIT && grub_get_time_ms() > sock->time_wait)
    {
      dbg ("%d socket timer has expired, closing\n", sock->local_port);
      change_socket_state (sock, CLOSED);

      push_socket_data (sock);
      if (sock->fin_hook)
	sock->fin_hook (sock, sock->hook_data);
      return 1;
    }
  return 0;
}

int
destroy_closed (grub_net_tcp_socket_t sock)
{
  if (sock->state == CLOSED)
    {
      dbg ("%d reaping closed socket\n", sock->local_port);
      destroy_socket (sock);
      return 1;
    }
  return 0;
}

void
grub_net_tcp_stall (grub_net_tcp_socket_t sock)
{
  if (sock->i_stall)
    return;
  sock->i_stall = 1;
  ack (sock, 0);
}

void
grub_net_tcp_unstall (grub_net_tcp_socket_t sock)
{
  if (!sock->i_stall)
    return;
  sock->i_stall = 0;
  ack (sock, 0);
}

static int
is_closed (void *data)
{
  grub_net_tcp_socket_t sock = (grub_net_tcp_socket_t)data;

  return sock->state == CLOSED;
}

void
grub_net_tcp_close (grub_net_tcp_socket_t sock,
		    int discard_received)
{
  int do_ack = 0;
  tcp_state state = sock->state;

  switch (sock->state)
    {
    case CLOSED:
      return;
    case SYN_RCVD:
    case ESTABLISHED:
      do_ack = 1;
      state = FIN_WAIT_1;
      break;
    case CLOSE_WAIT:
      do_ack = 1;
      state = LAST_ACK;
      break;
    case LISTEN:
      destroy_socket (sock);
      return;
    default:
      state = CLOSED;
      break;
    }

  if (discard_received != GRUB_NET_TCP_CONTINUE_RECEIVING)
    {
      sock->recv_hook = NULL;
      sock->error_hook = NULL;
      sock->fin_hook = NULL;
    }
  else
    grub_net_tcp_process_queue (sock);

  if (sock->state != CLOSED)
    dbg ("%d closing from state %s\n", sock->local_port,
	 tcp_state_names[sock->state]);
  grub_backtrace(1);

  if (sock->state != state)
    change_socket_state (sock, state);

  if (do_ack)
    {
      dbg ("%d acking %u\n", sock->local_port, their_seq (sock, sock->rcv.nxt));
      ack (sock, 0);
      grub_net_poll_cards_cb (GRUB_NET_INTERVAL, is_closed, &sock->state);
    }
}
