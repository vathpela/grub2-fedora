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

static int
tcp (struct tcp_segment *seg, int *stop)
{
  grub_err_t err = GRUB_ERR_NONE;
  grub_uint16_t flags = tcpflags(seg->tcph);
  grub_net_tcp_socket_t sock = seg->sock;
  grub_size_t win_max, seg_end;
  int segment_okay = 1;

  //dbg ("%d iss:%u irs:%u\n", sock->local_port, sock->iss, sock->irs);
  dbgs ("%d %s queue %s seq:%u ack:%u len:%u\n", sock->local_port,
	tcp_state_names[sock->state], flags_str (flags),
	their_seq (sock, seg->seq), my_seq (sock, seg->ack), seg->len);

  win_max = sock->rcv.nxt + (sock->rcv.wnd << sock->rcv.sca);
  seg_end = seg->seq + seg->len;

  if (seg->seq < sock->rcv.nxt || seg->seq >= win_max
      || seg_end > win_max || seg_end < sock->rcv.nxt)
    {
      if (seg->seq < sock->rcv.nxt || seg->seq >= win_max)
	{
	dbgs ("%d ! %u <= %u < %u\n", sock->local_port,
	      their_seq (sock, sock->rcv.nxt),
	      their_seq (sock, seg->seq),
	      their_seq (sock, win_max));
	dbgs("%d seg->seq:%u sock->rcv.nxt:%u win_max:%lu\n", sock->local_port,
	     seg->seq, sock->rcv.nxt, win_max);
	}

      if (seg_end > win_max || seg_end < sock->rcv.nxt)
	dbgs ("%d ! %u <= %u < %u\n", sock->local_port,
	      their_seq (sock, sock->rcv.nxt),
	      their_seq (sock, seg_end),
	      their_seq (sock, win_max));

      segment_okay = 0;
    }

#if 0
  dbgs ("%d seg.seq:%u rcv.nxt:%u win_max:%u seg_end:%u ok:%d\n",
	sock->local_port,
	their_seq (sock, seg->seq),
	their_seq (sock, sock->rcv.nxt),
	their_seq (sock, win_max),
	their_seq (sock, seg_end),
	segment_okay);
#endif

  if (!segment_okay)
    {
      if (seg_end <= sock->rcv.nxt)
	{
	  adjust_recv_window (sock, seg->txtlen);
	  grub_priority_queue_pop (sock->receive);
	  return GRUB_ERR_NONE;
	}
      //dbg ("%d iss:%u irs:%u\n", sock->local_port, sock->iss, sock->irs);
      dbgs ("%d segment was not okay, sending a %s\n", sock->local_port,
	    seg->tcph->flags & TCP_RST ? "RST" : "ACK");
      if (seg->tcph->flags & TCP_RST)
	reset (sock);
      else
	ack (sock, sock->rcv.nxt);
      *stop = 1;
      return GRUB_ERR_NONE;
    }
  else if (seg->seq > sock->rcv.nxt)
    {
#if 0
      int x = sock->i_stall;
      sock->i_stall = 1;

      dbgs ("%d segment %u from the future, re-ACKing\n",
	    sock->local_port, their_seq (sock, seg->seq));
      ack (sock, sock->rcv.nxt);
      sock->i_stall = x;
#else
      dbgs ("%d segment %u from the future, re-queuing\n",
	    sock->local_port, their_seq (sock, seg->seq));
#endif
      *stop = 1;
      return GRUB_ERR_NONE;
    }

#if 0
  /* If we've got an out-of-order packet, we need to re-ack to make sure
   * the sender is up to date, and our packet queue is invalid. */
  if (sock->rcv.nxt && seqnr > sock->rcv.nxt)
    {
	dbg ("%d OOO %u, expected %u moving on\n", sock->local_port,
	   their_seq(sock, seqnr), their_seq(sock, sock->rcv.nxt));
	if (their_seq (sock, seqnr) >> 4 > their_seq (sock, sock->rcv.nxt))
	  reset (sock);
	else
	  {
	    sock->needs_ack = 1;
	  }
	continue;
    }
#endif
  switch (sock->state)
    {
    case CLOSED:
      return 0;
    case LISTEN:
      dbg ("%d unexpected listen\n", sock->local_port);
      grub_priority_queue_pop (sock->receive);
      return GRUB_ERR_NONE;
    case SYN_SENT:
      if ((flags & TCP_ACK)
	  && (seg->ack <= sock->iss || seg->ack > sock->snd.nxt))
	{
	  if (!(flags & TCP_RST))
	    {
	      grub_printf ("Bad ack in SYN_SENT, reseting\n");
	      reset (sock);
	    }
	  else
	    grub_priority_queue_pop (sock->receive);
	  return GRUB_ERR_NONE;
	}

      if (flags & TCP_RST)
	{
	  if (flags & TCP_ACK)
	    change_socket_state (sock, CLOSED);

	  grub_priority_queue_pop (sock->receive);
	  return GRUB_ERR_NONE;
	}

      if (flags & TCP_SYN)
	{
	  sock->irs = seg->seq;
	  sock->rcv.nxt = seg->seq + 1;
	  if (flags & TCP_ACK)
	    sock->snd.una = seg->ack;
	  dbg ("%d snd.nxt:%u rcv.nxt=%u snd.una=%u\n",
		sock->local_port, my_seq (sock, sock->snd.nxt),
		their_seq (sock, sock->rcv.nxt),
		my_seq (sock, sock->snd.una));
	  sock->needs_ack = 1;
	  if (sock->snd.una > sock->iss)
	    change_socket_state (sock, ESTABLISHED);
	  else
	    change_socket_state (sock, SYN_RCVD);
	}
      else
	{
	  dbg ("%d weird flags? %s (0x%x)\n", sock->local_port,
		 flags_str(flags), flags);
	}
      grub_priority_queue_pop (sock->receive);
      return GRUB_ERR_NONE;
    default:
      break;
    }

  if (flags & TCP_RST)
    {
      switch (sock->state)
	{
	case SYN_RCVD:
	  change_socket_state (sock, CLOSED);

	  /* If we got here, there's nothing we can process in the queue, and
	   * it's all bad.  Flush it down the drain. */
	  grub_net_tcp_flush_recv_queue (sock);
	  return GRUB_ERR_NONE;
	case ESTABLISHED:
	  /* fallthrough */
	case FIN_WAIT_1:
	  /* fallthrough */
	case FIN_WAIT_2:
	  /* fallthrough */
	case CLOSE_WAIT:
	  /* fallthrough */
	  change_socket_state (sock, CLOSED);
	  grub_printf ("Got RST in CLOSE_WAIT, closing.\n");
	  reset (sock);
	  return GRUB_ERR_NONE;
	case CLOSING:
	  /* fallthrough */
	case LAST_ACK:
	  /* fallthrough */
	case TIME_WAIT:
	  grub_priority_queue_pop (sock->receive);
	  change_socket_state (sock, CLOSED);
	  return GRUB_ERR_NONE;
	default:
	  break;
	}
    }

  if ((flags & TCP_SYN) && !(flags & TCP_ACK) && !(flags & TCP_RST))
    {
      change_socket_state (sock, CLOSED);
      grub_printf ("got an unexpected SYN without ACK or RST, reseting.\n");
      reset (sock);
      return GRUB_ERR_NONE;
    }

  if (flags & TCP_ACK)
    {
      switch (sock->state)
	{
	case SYN_RCVD:
	  if (sock->snd.una > seg->ack || seg->ack > sock->snd.nxt)
	    {
	      grub_printf ("got an ack from the future; reseting.\n");
	      reset (sock);
	      return GRUB_ERR_NONE;
	    }

	  change_socket_state (sock, ESTABLISHED);
	  return GRUB_ERR_NONE;
	case ESTABLISHED:
	  /* fallthrough */
	case FIN_WAIT_1:
	  /* fallthrough */
	case FIN_WAIT_2:
	  /* fallthrough */
	case CLOSE_WAIT:
	  /* fallthrough */
	case CLOSING:
	  if (previously_acked_segment (sock, seg))
	    {
	      dbg ("%d Ignoring already acked packet %u\n", sock->local_port,
		   their_seq (sock, seg->seq));
	      grub_priority_queue_pop (sock->receive);
	      return GRUB_ERR_NONE;
	    }

	  prune_acks (sock, seg);

	  if (sock->state == FIN_WAIT_1)
	    change_socket_state (sock, FIN_WAIT_2);
	  else if (sock->state == FIN_WAIT_2 && !grub_priority_queue_top (sock->retransmit))
	    sock->needs_ack = 1;
	  else if (sock->state == LAST_ACK)
	    change_socket_state (sock, CLOSED);
#if 0
	  grub_priority_queue_pop (sock->receive);
	  return GRUB_ERR_NONE;
#endif
	  break;
	case LAST_ACK:
	  change_socket_state (sock, CLOSED);
	  return GRUB_ERR_NONE;
	case TIME_WAIT:
	  grub_priority_queue_pop (sock->receive);
	  if (flags & TCP_FIN)
	    {
	      dbg ("%d acking %u\n", sock->local_port,
		   their_seq (sock, sock->rcv.nxt));
	      ack (sock, 0);
	      sock->needs_ack = 0;
	      change_socket_state (sock, CLOSED);

	      push_socket_data (sock);
	      if (sock->fin_hook)
		sock->fin_hook (sock, sock->hook_data);
	    }
	  return GRUB_ERR_NONE;
	default:
	  break;
	}
    }

  switch (sock->state)
    {
    case ESTABLISHED:
      /* fallthrough */
    case FIN_WAIT_1:
      /* fallthrough */
    case FIN_WAIT_2:
      /* If we got here, we're actually consuming the packet, so it's
       * safe to remove it from our ingress queue. */
      grub_priority_queue_pop (sock->receive);

      /* Eat the header.  If that somehow fails we have no hope of recovery, so
       * send a reset and get out of here. */
      err = grub_netbuff_pull (seg->nb, tcplen (seg->tcph->flags));
      if (err)
	{
	  grub_printf ("grub_netbuff_pull() failed: %m\n");
	  return GRUB_ERR_NONE;
	}

      if (flags & TCP_SYN && flags & TCP_ACK && !seg->txtlen)
	{
	  prune_acks (sock, seg);
	  sock->needs_ack = 1;
#if 0
	  dbg ("%d acking %u\n", sock->local_port,
	       their_seq (sock, sock->rcv.nxt));
	  ack (sock);
#endif
	}

      if (seg->txtlen)
	{
	  grub_size_t prefix = 0, txtlen = seg->txtlen;
	  if (seg->seq < sock->rcv.nxt)
	    {
	      prefix = sock->rcv.nxt - seg->seq;
	      txtlen -= prefix;
	      dbgs ("%d segment %u is %lu bytes before %u, eating\n",
		    sock->local_port,
		    their_seq (sock, seg->seq),
		    prefix,
		    their_seq (sock, sock->rcv.nxt));
	      grub_netbuff_pull (seg->nb, prefix);
	    }
	  sock->rcv.nxt += txtlen;
#if 0
	  if (sock->rcv.nxt > seg->seq - seg->wnd - seg->txtlen)
	    {
	      grub_printf ("iss:%u irs:%u rcv.nxt=%u seg.seq:%u-seg.wnd:%u-seg.txtlen:%u=%u ?\n",
			   sock->iss, sock->irs,
			   their_seq(sock, sock->rcv.nxt),
			   their_seq(sock, seg->seq),
			   seg->wnd,
			   seg->txtlen,
			   their_seq(sock, seg->seq + seg->txtlen));
	    }
#endif
	  dbgs ("%d snd.nxt:%u rcv.nxt=%u snd.una:%u\n",
		sock->local_port, my_seq (sock, sock->snd.nxt),
		their_seq (sock, sock->rcv.nxt),
		my_seq (sock, sock->snd.una));
	  adjust_send_window (sock, seg);
	  adjust_recv_window (sock, seg->txtlen);
	  sock->needs_ack = 1;
	  /* If there is data, puts packet in socket list. */
	  /* XXX we need to fix seg->nb up for segment overlap */
	  grub_net_put_packet (&sock->packs, seg->nb);
	  seg->nb = NULL;
	}
      break;
    case CLOSE_WAIT:
      /* fallthrough */
    case CLOSING:
      /* fallthrough */
    case LAST_ACK:
      /* fallthrough */
    case TIME_WAIT:
      grub_priority_queue_pop (sock->receive);
      return GRUB_ERR_NONE;
    default:
      break;
    }

  if (flags & TCP_FIN)
    {
      switch (sock->state)
	{
	case SYN_RCVD:
	  change_socket_state (sock, CLOSE_WAIT);
	  sock->rcv.nxt += 1;
	  sock->needs_ack = 1;
	  return GRUB_ERR_NONE;
	case ESTABLISHED:
	  change_socket_state (sock, FIN_WAIT_1);
	  sock->rcv.nxt += 1;
	  sock->needs_ack = 1;
	  return GRUB_ERR_NONE;
	case FIN_WAIT_1:
	  dbg ("%d seg->ack:%u snd.nxt:%u\n", sock->local_port,
	       their_seq (sock, seg->ack),
	       my_seq (sock, sock->snd.nxt));
	  if (seg->ack == sock->snd.nxt)
	    {
	      change_socket_state (sock, TIME_WAIT);
	      prune_acks (sock, seg);
	      sock->rcv.nxt += 1;
	      sock->time_wait = grub_get_time_ms () + (sock->ttl * 1000);
	      sock->needs_ack = 0;
	    }
	  return GRUB_ERR_NONE;
	case FIN_WAIT_2:
	  change_socket_state (sock, TIME_WAIT);
	  prune_acks (sock, seg);
	  sock->rcv.nxt += 1;
	  sock->time_wait = grub_get_time_ms () + (sock->ttl * 1000);
	  sock->needs_ack = 1;
	  return GRUB_ERR_NONE;
	case TIME_WAIT:
	  sock->rcv.nxt += 1;
	  sock->time_wait = grub_get_time_ms () + (sock->ttl * 1000);
	  return GRUB_ERR_NONE;
	default:
	  break;
	}
    }

  return GRUB_ERR_NONE;
}

/*
 * Nothing above here is ever allowed to do the following to the /received/
 * packet data:
 * - grub_netbuff_free()
 * - grub_priority_queue_pop() / grub_priority_queue_destroy()
 * - grub_list_remove(sock)
 * - grub_free (sock)
 */

static grub_err_t
process_one_queue (grub_net_tcp_socket_t sock, int nsegments)
{
  struct grub_net_buff **nb_top_p;
  grub_err_t err = GRUB_ERR_NONE;
  int just_closed = 0;
  int once = 1;
  grub_uint32_t seqnr = 0;

  while (nsegments-- && (nb_top_p = grub_priority_queue_top (sock->receive)) != NULL)
    {
      struct grub_net_buff *nb = *nb_top_p;
      struct tcphdr *tcph;
      struct tcp_opt *opt;
      struct tcp_segment seg;
      grub_uint16_t flags;
      int stop = 0;

      if (sock->state == CLOSED)
	{
	  grub_printf ("%d queue has stuff but socket is closed?\n",
		       sock->local_port);
	}

      if (once)
	{
	  once = 0;
	  dbgq ("%d processing queue\n", sock->local_port);
	}

      grub_memset (&seg, 0, sizeof (seg));

      seg.tcph = tcph = (struct tcphdr *) nb->data;
      seqnr = seg.seq = grub_be_to_cpu32 (tcph->seqnr);

      seg.len = seg.txtlen = pktlen (nb) - tcplen (tcph->flags);
      seg.nb = nb;

#if 0
      dbg ("%d processing nb with seqnr %u len %d\n",
	   sock->local_port, their_seq (sock, seg.seq), seg.len);
#endif

      flags = tcpflags(tcph);
      if (flags & TCP_ACK)
	seg.ack = grub_be_to_cpu32 (tcph->ack);
      if (flags & TCP_SYN)
	seg.len += 1;
      if (flags & TCP_FIN)
	seg.len += 1;

      seg.wnd = 0;
      FOR_TCP_OPTIONS (tcph, opt)
	{
	  struct tcp_scale_opt *scale;

	  dbgw ("%d processing tcph (0x%016lx) option %u\n",
	       sock->local_port, (unsigned long)tcph, opt->kind);

	  if (opt->kind != 3)
	    continue;

	  scale = (struct tcp_scale_opt *)opt;
	  seg.wnd = grub_be_to_cpu16 (tcph->window) << scale->scale;
	  sock->snd.sca = scale->scale;
	}
      if (seg.wnd == 0)
	seg.wnd = grub_be_to_cpu16 (tcph->window);

      adjust_send_window (sock, &seg);

      seg.sock = sock;

      if (sock->needs_retransmit)
	{
	  if (sock->retransmit)
	    {
	      grub_dprintf ("tcp", "retransmitting\n");
	      grub_net_tcp_socket_retransmit (sock);
	    }
	}

      err = tcp (&seg, &stop);
      if (err)
	{
	  grub_printf ("%d tcp() = %d (%m) %s\n", sock->local_port,
	       err, grub_errmsg);
	  change_socket_state (sock, CLOSED);
	  seg.nb = NULL;
	  break;
	}

      if (stop)
	break;

#if 0
      if (seg.txtlen == 0)
	{
	  grub_netbuff_free (seg.nb);
	  seg.nb = NULL;
	}
#endif

      if (sock->state == CLOSED)
	{
	  just_closed = 1;
	  break;
	}
    }

#if 0
  nb_top_p = grub_priority_queue_top (sock->receive);

  if (sock->rc
	{
	  struct grub_net_buff *nb = *nb_top_p;

	  if (sock->rcv.nxt < 
#endif

  if (sock->needs_ack)
    {
      dbgs ("%d acking %u (tcph says %u)\n", sock->local_port,
	    their_seq (sock, sock->rcv.nxt),
	    their_seq (sock, seqnr));
      ack (sock, 0);
    }

  /* Now feed our packet data to our real consumer. */
  push_socket_data (sock);

  /* And if we closed, inform them of that as well. */
  if (sock->fin_hook && just_closed)
    {
      sock->fin_hook (sock, sock->hook_data);
      destroy_socket (sock);
    }
  else
    reap_time_wait (sock);

  return err;
}

grub_err_t
grub_net_tcp_process_queue (grub_net_tcp_socket_t sock)
{
  grub_net_tcp_socket_t next_sock;
  int found = 0;

  if (sock == NULL || 0)
    {
      do
	{
	  FOR_TCP_SOCKETS (sock, next_sock)
	    {
	      process_one_queue (sock, 1);

	      if (grub_priority_queue_top (sock->receive))
		found = 1;
	    }
	} while (found);
    }
  else
    {
      process_one_queue (sock, ~0);

      if (grub_priority_queue_top (sock->receive))
	found = 1;
      else
	destroy_closed (sock);
    }

  return GRUB_ERR_NONE;
}

int
grub_net_tcp_socket_unacked (grub_net_tcp_socket_t sock)
{
  if (sock->receive || recv_pending (sock->inf))
    return 1;
  return 0;
}

void
grub_net_tcp_socket_ack (grub_net_tcp_socket_t sock)
{
  int done = 1;
  if (recv_pending (sock->inf))
    grub_net_poll_cards (10, &done);

  if (sock->receive)
    grub_net_tcp_process_queue (sock);
}

grub_err_t
grub_net_recv_tcp_packet (struct grub_net_buff *nb,
			  struct grub_net_network_level_interface *inf,
			  const grub_net_network_level_address_t *source,
			  grub_uint8_t ttl)
{
  struct tcphdr *tcph;
  grub_net_tcp_socket_t sock, next_sock;
  grub_err_t err;
  grub_ssize_t len, hdrlen;
#if 0
  static grub_net_tcp_socket_t prev;
#endif
  int received_packet = 0;

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
      int queue = 0;
      grub_uint16_t flags = tcpflags (tcph);
      struct tcp_segment seg;

      if (grub_be_to_cpu16 (tcph->dst) != sock->local_port)
	continue;

      if (sock->state == LISTEN && !(inf == sock->inf || sock->inf == NULL))
	continue;

      if (sock->state != LISTEN
	  && !(grub_be_to_cpu16 (tcph->src) == sock->remote_port
	       && inf == sock->inf
	       && grub_net_addr_cmp (source, &sock->out_nla) == 0))
	continue;

      received_packet = 1;

#if 0
      if (prev && prev != sock)
	{
	  if (grub_priority_queue_top (prev->receive) != NULL)
	    {
	      dbgq ("%d processing queue\n", prev->local_port);
	      err = grub_net_tcp_process_queue (prev);
	      if (err)
		grub_dprintf ("net", "%d error processing packet queue: %m\n",
			      prev->local_port);
	    }

	  reap_time_wait (prev);
	}
#endif

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

      sock->ttl = ttl;

      /* We do this here just to make the next debug log messages
       * coherent */
      if (sock->state == SYN_SENT && flags == (TCP_SYN|TCP_ACK))
	{
	  sock->rcv.nxt = sock->irs = grub_be_to_cpu32 (tcph->seqnr);
	  dbg ("%d snd.nxt:%u rcv.nxt=%u snd.una:%u irs=%u\n",
		sock->local_port, my_seq (sock, sock->snd.nxt),
		their_seq (sock, sock->rcv.nxt),
		my_seq (sock, sock->snd.una), sock->irs);
	}

      dbgq ("%d %s recv %s seq:%u ack:%u\n", sock->local_port,
	    tcp_state_names[sock->state], flags_str (flags),
	    their_seq (sock, grub_be_to_cpu32 (tcph->seqnr)),
	    my_seq (sock, grub_be_to_cpu32 (tcph->ack)));

      seg.seq = grub_be_to_cpu32 (tcph->seqnr);
      seg.len = seg.txtlen = pktlen (nb) - tcplen (tcph->flags);

      if (flags & TCP_PSH)
	{
	  sock->they_push = seg.seq;
	  tcph->flags &= ~TCP_PSH;
	  flags &= ~TCP_PSH;
	}

      if (flags & TCP_ACK)
	seg.ack = grub_be_to_cpu32 (tcph->ack);
      if (flags & TCP_SYN)
	seg.len += 1;
      if (flags & TCP_FIN)
	seg.len += 1;

#if 0
      FOR_TCP_OPTIONS (tcph, opt)
	{
	  struct tcp_scale_opt *scale;

	  dbgw ("%d processing tcph (0x%016lx) option %u\n",
	       sock->local_port, (unsigned long)tcph, opt->kind);

	  if (opt->kind != 3)
	    continue;

	  scale = (struct tcp_scale_opt *)opt;
#if 1
	  rcv_wnd = grub_be_to_cpu16 (tcph->window);
	  rcv_sca = scale->scale;
	}

      seg.wnd = rcv_wnd << rcv_sca;
#else
	  sock->rcv.wnd = grub_be_to_cpu16 (tcph->window);
	  sock->rcv.sca = scale->scale;
	}

      seg.wnd = sock->rcv.wnd << sock->rcv.sca;
#endif

      win_max = sock->rcv.nxt + seg.wnd;
      seg_end = seg.seq + seg.len;

      segment_okay = 1;
	    dbg ("%d ! %u <= %u < %u\n", sock->local_port,
		 their_seq (sock, sock->rcv.nxt),
		 their_seq (sock, seg.seq),
		 their_seq (sock, win_max));
	    dbg ("%d ! %u <= %u < %u\n", sock->local_port,
		 their_seq (sock, sock->rcv.nxt),
		 their_seq (sock, seg_end),
		 their_seq (sock, win_max));
      if (seg.seq < sock->rcv.nxt || seg.seq >= win_max
	  || seg_end > win_max || seg_end < sock->rcv.nxt)
	{
	  if (seg.seq < sock->rcv.nxt || seg.seq >= win_max)
	    dbg ("%d ! %u <= %u < %u\n", sock->local_port,
		 their_seq (sock, sock->rcv.nxt),
		 their_seq (sock, seg.seq),
		 their_seq (sock, win_max));

	  if (sock->rcv.nxt > seg_end || seg_end >= win_max)
	    dbg ("%d ! %u <= %u < %u\n", sock->local_port,
		 their_seq (sock, sock->rcv.nxt),
		 their_seq (sock, seg_end),
		 their_seq (sock, win_max));

	  if (!(flags & TCP_RST))
	    {
	      dbg ("%d ignoring bad segment %u, but sending an ACK\n",
		   sock->local_port, their_seq (sock, seg.seq));
	      ack (sock, seg.seq);

	      grub_net_tcp_process_queue (sock);
	    }
	  segment_okay = 0;
	}

#endif
      switch (sock->state)
	{
	case CLOSED:
	  /* This shouldn't ever happen, because we reap these above */
	  break;
	case LISTEN:
	  handle_listen (nb, tcph, sock, inf, source);
	  return GRUB_ERR_NONE;
	case SYN_RCVD:
	  if (tcpflags (tcph) == TCP_ACK)
	    {
	      dbg ("%d their starting sequence is %u\n",
		   sock->local_port, sock->irs);
	      sock->irs = grub_be_to_cpu32 (tcph->seqnr);
	      sock->rcv.nxt = sock->irs;
	      dbg ("%d snd.nxt:%u rcv.nxt=%u snd.una:%u\n",
		    sock->local_port, my_seq (sock, sock->snd.nxt),
		    their_seq (sock, sock->rcv.nxt),
		    my_seq (sock, sock->snd.una));
	    }
	  queue = 1;
	  break;
	case SYN_SENT:
	case ESTABLISHED:
	case CLOSE_WAIT:
	case LAST_ACK:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSING:
	case TIME_WAIT:
	  queue = 1;
	  break;
	default: /* INVALID_STATE */
	  grub_error (GRUB_ERR_BUG,
		      N_("socket on port %d was in invalid state %d"),
		      sock->local_port, sock->state);
	  destroy_socket (sock);
	  continue;
	}

      if (queue /* && segment_okay */)
	{
	  dbgs ("%d ingress seq %u ack %u len=%ld\n", sock->local_port,
		their_seq (sock, seg.seq), my_seq (sock, seg.ack), len);
	  adjust_recv_window (sock, -len);

	  err = grub_priority_queue_push (sock->receive, &nb);
	  if (err)
	    {
	      grub_dprintf ("tcp",
			    "grub_priority_queue_push(): %m %1m\n");
	      grub_netbuff_free (nb);
	      return err;
	    }
	}

      if (recv_pending (inf))
	{
	  dbgq ("%d recv was pending; not processing queue\n", sock->local_port);
	  return GRUB_ERR_NONE;
	}
      else if (sock->they_push || flags & TCP_FIN)
	{
	  dbgq ("%d saw push %u; processing queue now\n",
	       sock->local_port,
	       their_seq (sock, sock->rcv.nxt));
	  sock->needs_ack = 1;
	  err = grub_net_tcp_process_queue (sock);
	  if (err)
	    grub_dprintf ("net", "error processing packet queue: %m\n");
	  sock->they_push = 0;
	}
    }

  FOR_TCP_SOCKETS (sock, next_sock)
    {
      if (grub_priority_queue_top (sock->receive) != NULL)
	{
	  dbgq ("%d processing queue\n", sock->local_port);
	  err = process_one_queue (sock, ~0);
	  if (err)
	    grub_dprintf ("net", "error processing packet queue: %m\n");
	}

      if (grub_priority_queue_top (sock->receive) == NULL)
	  reap_time_wait (sock);

      if (grub_priority_queue_top (sock->receive) == NULL)
	  destroy_closed (sock);
    }

  if (received_packet)
    return GRUB_ERR_NONE;

  /* If this isn't an open socket, we send RST or RST|ACK depending on their
   * ack field, unless it's a RST packet, in which case we ignore it. */
  if (!(tcph->flags & TCP_RST))
    {
      sock = new_socket (inf, source, tcph, CLOSED);
      if (!sock)
	{
	  grub_netbuff_free (nb);
	  return grub_errno;
	}

      sock->local_port = grub_be_to_cpu16 (tcph->dst);
      sock->remote_port = grub_be_to_cpu16 (tcph->src);
      dbg ("%d unexpected packet; send one of our own.\n", sock->local_port);
      reset_window (sock);
      sock->irs = sock->rcv.nxt = grub_be_to_cpu32 (tcph->seqnr) + len;
      if (tcph->flags & TCP_ACK)
	sock->iss = sock->snd.nxt = grub_be_to_cpu32 (tcph->ack);
      else
	sock->iss = sock->snd.nxt = 0;
      sock->snd.una = sock->snd.nxt;
      sock->state = CLOSED;
      dbg ("%d snd.nxt=%u rcv.nxt=%u snd.una=%u\n", sock->local_port,
	    my_seq (sock, sock->snd.nxt),
	    their_seq (sock, sock->rcv.nxt),
	    my_seq (sock, sock->snd.una));
      dbg ("unsolicited packet for socket we don't have; ignoring.\n");
      //reset (sock);
    }

  grub_netbuff_free (nb);
  return GRUB_ERR_NONE;
}
