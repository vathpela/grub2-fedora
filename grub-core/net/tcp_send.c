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
  if (tcph->flags & TCP_FIN || tcph->flags & TCP_SYN)
    size++;
  socket->snd.nxt += size;
  dbgs ("%d snd.nxt=%u rcv.nxt:%u snd.una:%u\n", socket->local_port,
	my_seq (socket, socket->snd.nxt),
	their_seq (socket, socket->rcv.nxt),
	my_seq (socket, socket->snd.una));
  tcph->src = grub_cpu_to_be16 (socket->local_port);
  tcph->dst = grub_cpu_to_be16 (socket->remote_port);
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

      unack->nb = nb;
      unack->try_count = 1;
      unack->last_try = grub_get_time_ms ();
      grub_priority_queue_push (socket->retransmit, unack);
    }

  //dbg ("%d iss:%u irs:%u\n", socket->local_port, socket->iss, socket->irs);
  dbgs ("%d %s sending %s (seq:%u ack:%u)\n", socket->local_port,
       tcp_state_names[socket->state], flags_str (tcph->flags),
       my_seq (socket, grub_be_to_cpu32 (tcph->seqnr)),
       tcph->ack == 0 ? 0 : their_seq (socket, grub_be_to_cpu32 (tcph->ack)));

  err = grub_net_send_ip_packet (socket->inf, &(socket->out_nla),
				 &(socket->ll_target_addr), nb,
				 GRUB_NET_IP_TCP);
  if (err)
    return err;
  nb->data = nbd;
  if (!size)
    grub_netbuff_free (nb);
  if (socket->state == CLOSE_WAIT && tcpflags(tcph) == (TCP_ACK|TCP_FIN))
    change_socket_state(socket, LAST_ACK);
  return GRUB_ERR_NONE;
}

static grub_err_t
ack_real (grub_net_tcp_socket_t sock, int reset, grub_uint32_t resend)
{
  struct grub_net_buff *nb_ack;
  struct tcphdr *tcph_ack;
  grub_size_t hdrsize = sizeof (*tcph_ack);
  grub_err_t err;
  int ack = reset ? sock->needs_ack : 1;

  if (sock->state == FIN_WAIT_2 && !resend)
    return GRUB_ERR_NONE;

  nb_ack = grub_netbuff_alloc (hdrsize + 128);
  if (!nb_ack)
    return grub_errno;

  err = grub_netbuff_reserve (nb_ack, 128);
  if (err)
    {
      grub_netbuff_free (nb_ack);
      grub_dprintf ("net", "error closing socket: %m: %1m\n");
      return grub_errno;
    }

  err = grub_netbuff_put (nb_ack, hdrsize);
  if (err)
    {
error:
      grub_netbuff_free (nb_ack);
      grub_dprintf ("net", "error closing socket: %m: %1m\n");
      return grub_errno;
    }

#if 0
  if (reset && grub_priority_queue_top (sock->pq))
    ack = 1;
#endif

  tcph_ack = (void *) nb_ack->data;
  if (ack)
    {
      err = add_window_scale (nb_ack, tcph_ack, &hdrsize,
			      sock->rcv.sca);
      if (err)
	goto error;

      err = add_padding (nb_ack, tcph_ack, &hdrsize);
      if (err)
	goto error;

      sock->snd.una = sock->snd.nxt;
      dbgs ("%d snd.nxt:%u rcv.nxt:%u snd.una=%u\n", sock->local_port,
	    my_seq (sock, sock->snd.nxt),
	    their_seq (sock, sock->rcv.nxt),
	    my_seq (sock, sock->snd.una));

      tcph_ack->window = !sock->i_stall ? grub_cpu_to_be16 (sock->rcv.wnd)
	: 0;
    }
  else
    {
      tcph_ack->window = 0;
    }

  if (reset)
    {
      tcph_ack->ack = grub_cpu_to_be32_compile_time (0);
      tcph_ack->flags = tcpsize (hdrsize) | TCP_RST
		        | (ack ? TCP_ACK : 0);
      reset_window (sock);
    }
  else
    {
      if (resend)
	tcph_ack->ack = grub_cpu_to_be32 (resend);
      else
	tcph_ack->ack = grub_cpu_to_be32 (sock->rcv.nxt);
      tcph_ack->flags = tcpsize (hdrsize) | TCP_ACK;
      switch (sock->state)
	{
	case FIN_WAIT_1:
	case CLOSE_WAIT:
	  tcph_ack->flags |= TCP_FIN;
	  break;
	case SYN_RCVD:
	  tcph_ack->flags |= TCP_SYN;
	default:
	  break;
	}
    }

  tcph_ack->urgent = 0;
  tcph_ack->src = grub_cpu_to_be16 (sock->local_port);
  tcph_ack->dst = grub_cpu_to_be16 (sock->remote_port);
  err = tcp_send (nb_ack, sock);
  if (err)
    {
      grub_dprintf ("net", "error acking socket: %m: %1m\n");
      return err;
    }

  sock->needs_ack = 0;
  return err;
}

grub_err_t
ack (grub_net_tcp_socket_t sock, grub_uint32_t resend)
{
  if (sock->state == CLOSED)
    {
      sock->needs_ack = 0;
      return GRUB_ERR_NONE;
    }
  return ack_real (sock, 0, resend);
}

grub_err_t
reset (grub_net_tcp_socket_t sock)
{
  grub_err_t err;
  err = ack_real (sock, 1, 0);
  if (!err)
    grub_net_tcp_flush_recv_queue (sock);
  return err;
}

void
grub_net_tcp_socket_retransmit (grub_net_tcp_socket_t sock)
{
  grub_uint64_t ctime = grub_get_time_ms ();
  grub_uint64_t limit_time = ctime - TCP_RETRANSMISSION_TIMEOUT;
  struct unacked *unack;

  sock->needs_retransmit = 0;

  reap_time_wait (sock);

  if (destroy_closed (sock))
    return;

  if (grub_priority_queue_top (sock->retransmit)
      && recv_pending (sock->inf))
    {
      int stop = 1;
      grub_net_poll_cards (GRUB_NET_INTERVAL, &stop);
      return;
    }

  while ((unack = grub_priority_queue_top (sock->retransmit)))
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
	    && tcph->ack >= grub_cpu_to_be32 (sock->rcv.nxt))
	  {
	    dbg ("%d retransmitting previous ack %u\n", sock->local_port,
		 their_seq (sock, grub_be_to_cpu32 (tcph->ack)));
	    tcph->checksum = grub_net_ip_transport_checksum (
					  unack->nb, GRUB_NET_IP_TCP,
					  &sock->inf->address, &sock->out_nla);
	  }
	else
	  {
	    dbg ("%d retransmitting seq %u\n", sock->local_port,
		 my_seq (sock, grub_be_to_cpu32 (tcph->seqnr)));
	  }

	err = grub_net_send_ip_packet (sock->inf, &(sock->out_nla),
				       &(sock->ll_target_addr), unack->nb,
				       GRUB_NET_IP_TCP);
	unack->nb->data = nbd;
	if (err)
	  {
	    grub_dprintf ("net", "TCP retransmit failed: %m: %1m\n");
	    grub_errno = GRUB_ERR_NONE;
	  }
    }
}

void
grub_net_tcp_retransmit (void)
{
  grub_net_tcp_socket_t sock, next_sock;
  int once = 1;

  FOR_TCP_SOCKETS (sock, next_sock)
    {
      if (grub_priority_queue_top (sock->retransmit))
	{
	  if (once)
	    {
	      grub_dprintf ("net", "processing retransmits\n");
	      grub_debug_backtrace("net", 0);
	      once = 0;
	    }

	  grub_net_tcp_socket_retransmit (sock);
	}
    }
}

void
prune_acks (grub_net_tcp_socket_t sock, struct tcp_segment *seg)
{
  grub_uint32_t acked = seg->ack;
  struct unacked *unack;

  /* this means TCP_ACK was not set on the packet. */
  if (acked == 0)
    return;

  if (sock->snd.una >= seg->ack || seg->ack > sock->snd.nxt)
    return;

  if (acked >= sock->snd.una)
    dbg ("%d looking for unacked packet %u\n",
	 sock->local_port, my_seq (sock, acked));

  while ((unack = grub_priority_queue_top (sock->retransmit)))
    {
      grub_uint32_t seqnr;
      struct tcphdr *unack_tcph;

      unack_tcph = (struct tcphdr *) unack->nb->data;
      seqnr = grub_be_to_cpu32 (unack_tcph->seqnr);
      seqnr += pktlen (unack->nb) - tcplen (unack_tcph->flags);

      if (unack_tcph->flags & TCP_FIN)
	seqnr++;

      if (seqnr > acked)
	break;

      dbg ("%d freeing unack %u\n", sock->local_port, my_seq (sock, acked));
      grub_netbuff_free (unack->nb);
      grub_priority_queue_pop (sock->retransmit);
    }

  sock->snd.una = seg->ack;
  adjust_send_window (sock, seg);
}


grub_err_t
grub_net_send_tcp_packet (const grub_net_tcp_socket_t socket,
			  struct grub_net_buff *nb, int push)
{
  struct tcphdr *tcph;
  grub_err_t err;
  grub_size_t fraglen;
  COMPILE_TIME_ASSERT (sizeof (struct tcphdr) == GRUB_NET_TCP_HEADER_SIZE);

  if (socket->state != ESTABLISHED)
    {
      if (socket->state < 0 || socket->state > INVALID_STATE)
	socket->state = INVALID_STATE;

      return grub_error (GRUB_ERR_NET_PORT_CLOSED,
			 N_("Attempted to send on socket in %s state"),
			 tcp_state_names[socket->state]);
    }

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
      tcph->window = !socket->i_stall ? grub_cpu_to_be16 (socket->rcv.wnd)
	: 0;
      tcph->urgent = 0;
      err = grub_netbuff_put (nb2, fraglen);
      if (err)
	return err;
      grub_memcpy (tcph + 1, nb->data, fraglen);
      err = grub_netbuff_pull (nb, fraglen);
      if (err)
	return err;

      dbg ("%d acking %u\n",
	   socket->local_port, their_seq(socket, socket->rcv.nxt));
      err = tcp_send (nb2, socket);
      if (err)
	return err;
    }

  err = grub_netbuff_push (nb, sizeof (*tcph));
  if (err)
    return err;

  dbg ("%d acking+push %u\n",
       socket->local_port, their_seq (socket, socket->rcv.nxt));
  tcph = (struct tcphdr *) nb->data;
  tcph->ack = grub_cpu_to_be32 (socket->rcv.nxt);
  tcph->flags = tcpsize (sizeof *tcph) | TCP_ACK | (push ? TCP_PSH : 0);
  tcph->window = !socket->i_stall ? grub_cpu_to_be16 (socket->rcv.wnd) : 0;
  tcph->urgent = 0;
  return tcp_send (nb, socket);
}

static int
is_established_or_closed (void *data)
{
  grub_net_tcp_socket_t sock = (grub_net_tcp_socket_t)data;

  switch (sock->state)
    {
    case ESTABLISHED:
    case CLOSED:
      return 1;
    default:
      break;
    }

  return 0;
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
      dbg ("initial source port %u\n", new_port);

      /* if we still don't have any number in range, just take the page number
       * of our socket...
       */
      while (new_port < 2 || new_port >= 65534)
	new_port = (grub_uint16_t)
		   (((unsigned long long)port >> shift++) & 0xffff);
    }

  *port = new_port;
}

grub_net_tcp_socket_t
grub_net_tcp_open (char *server,
		   grub_uint16_t remote_port,
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
  grub_net_tcp_socket_t socket = NULL;
  static grub_uint16_t local_port;
  struct grub_net_buff *nb;
  struct tcphdr *tcph = NULL;
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
    {
      grub_printf("grub_net_route_address(): %m %1m\n");
      return NULL;
    }

  err = grub_net_link_layer_resolve (inf, &gateway, &ll_target_addr);
  if (err)
    {
      grub_printf("grub_net_link_layer_resolve(): %m :%1m\n");
      return NULL;
    }

  nb = grub_netbuff_alloc (sizeof (*tcph) + 128);
  if (!nb)
    {
      grub_printf("grub_netbuff_alloc(): %m: %1m\n");
      return NULL;
    }
  err = grub_netbuff_reserve (nb, 128);
  if (err)
    {
      grub_printf("grub_netbuff_reserve(): %m: %1m\n");
      grub_netbuff_free (nb);
      return NULL;
    }

  err = grub_netbuff_put (nb, hdrsize);
  if (err)
    {
      grub_printf("grub_netbuff_put(): %m: %1m\n");
      goto error;
    }

  tcph = (void *) nb->data;
  grub_memset(tcph, 0, sizeof (*tcph));

  socket = new_socket (inf, &addr, tcph, CLOSED);
  if (!socket)
    {
      grub_printf ("new_socket failed: %m: %1m\n");
      goto error;
    }

  if (local_port == 0)
    {
      init_tcp_src_port (&socket->local_port);
      local_port = socket->local_port;
    }
  else if (local_port == 65535)
    local_port = 2;

  if (addr.type != GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV4
      && addr.type != GRUB_NET_NETWORK_LEVEL_PROTOCOL_IPV6)
    {
      grub_error (GRUB_ERR_BUG, "not an IP address");
      return NULL;
    }

  socket->local_port = local_port++;
  socket->remote_port = remote_port;
  socket->ll_target_addr = ll_target_addr;
  socket->recv_hook = recv_hook;
  socket->error_hook = error_hook;
  socket->fin_hook = fin_hook;
  socket->hook_data = hook_data;
  socket->snd.una = socket->iss = grub_get_time_ms ();
  socket->snd.nxt = socket->iss + 1;
  dbgs ("%d snd.nxt=%u rcv.nxt:%u snd.una=%u iss=%u\n", socket->local_port,
	my_seq (socket, socket->snd.nxt),
	their_seq (socket, socket->rcv.nxt),
	my_seq (socket, socket->snd.una),
	socket->iss);

  reset_window (socket);

  err = add_window_scale (nb, tcph, &hdrsize, socket->rcv.sca);
  if (err)
    {
      grub_printf ("add_window_scale(): %m: %1m\n");
      goto error;
    }

  err = add_mss (socket, nb, tcph, &hdrsize);
  if (err)
    {
      grub_printf ("add_mss(): %m: %1m\n");
      goto error;
    }

  err = add_padding (nb, tcph, &hdrsize);
  if (err)
    {
      grub_printf ("add_padding(): %m: %1m\n");
      goto error;
    }

  tcph->seqnr = grub_cpu_to_be32 (socket->iss);
  tcph->ack = grub_cpu_to_be32_compile_time (0);
  tcph->flags = tcpsize (hdrsize) | TCP_SYN;
  tcph->window = grub_cpu_to_be16 (socket->rcv.wnd);
  tcph->urgent = 0;
  tcph->src = grub_cpu_to_be16 (socket->local_port);
  tcph->dst = grub_cpu_to_be16 (socket->remote_port);
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
	  grub_printf("%s:%d: grub_net_send_ip_packet(): %m: %1m\n", GRUB_FILE, __LINE__);
	  goto error;
	}

      err = GRUB_ERR_TIMEOUT;
      for (j = 0; j < TCP_SYN_RETRANSMISSION_TIMEOUT / 50
		      && !is_established_or_closed (socket); j++)
	grub_net_poll_cards_cb (50, is_established_or_closed, socket);

      if (is_established_or_closed (socket))
	{
	  err = GRUB_ERR_NONE;
	  break;
	}
    }

  if (err)
    {
      grub_printf("timeout\n");
      change_socket_state (socket, TIME_WAIT);
      socket->time_wait = grub_get_time_ms ()
	    - (TCP_SYN_RETRANSMISSION_COUNT * TCP_SYN_RETRANSMISSION_TIMEOUT);
      socket->ttl = socket->time_wait -1;
    }

  switch (socket->state)
    {
    case CLOSED:
      grub_error (GRUB_ERR_NET_PORT_CLOSED,
		  N_("connection refused"));
      goto error;
    case TIME_WAIT:
      grub_error (GRUB_ERR_NET_NO_ANSWER,
		    N_("connection timeout"));
      goto error;
    case ESTABLISHED:
      break;
    default:
      grub_error (GRUB_ERR_BUG, "Invalid TCP state during open");
      grub_backtrace (0);
      break;
    }

  grub_netbuff_free (nb);
  return socket;

error:
  reap_time_wait (socket);
  if (socket)
    destroy_socket (socket);
  grub_netbuff_free (nb);
  return NULL;
}
