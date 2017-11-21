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

grub_net_tcp_socket_t
grub_net_tcp_listen (grub_uint16_t port,
		     const struct grub_net_network_level_interface *inf,
		     const grub_net_network_level_address_t *source,
		     grub_net_tcp_listen_hook listen_hook,
		     void *hook_data)
{
  grub_net_tcp_socket_t sock;
  grub_err_t err;

  sock = new_socket (inf, NULL, NULL, LISTEN);
  if (!sock)
    return NULL;

  sock->listen_hook = listen_hook;
  sock->hook_data = hook_data;
  sock->local_port = port;
  sock->inf = inf;
  sock->out_nla = *source;
  change_socket_state (sock, LISTEN);
  err = tcp_socket_register (sock);
  if (err)
    {
      destroy_socket (sock);
      return NULL;
    }
  return sock;
}

void
grub_net_tcp_stop_listen (grub_net_tcp_socket_t listen)
{
  destroy_socket (listen);
}

void
handle_listen (struct grub_net_buff *nb, struct tcphdr *tcph,
	       grub_net_tcp_socket_t listen,
	       const struct grub_net_network_level_interface *inf,
	       const grub_net_network_level_address_t *source)
{
  grub_net_tcp_socket_t sock;
  grub_uint16_t flags = tcpflags (tcph);
  grub_err_t err;

  switch (flags)
    {
    case TCP_SYN:
      sock = new_socket (inf, source, tcph, CLOSED);
      if (!sock)
	{
	  grub_dprintf ("net", "new_socket returned %d (%m)\n", grub_errno);
	  grub_netbuff_free (nb);
	  return;
	}
      change_socket_state (sock, SYN_RCVD);

      sock->irs = grub_be_to_cpu32 (tcph->seqnr);
      sock->iss = sock->irs + grub_get_time_ms ();
      sock->rcv.nxt = sock->irs + 1;
      dbgs ("%d snd.nxt:%u rcv.nxt=%u snd.una:%u irs=%u\n",
	    sock->local_port, my_seq (sock, sock->snd.nxt),
	    their_seq (sock, sock->rcv.nxt),
	    my_seq (sock, sock->snd.una), sock->irs);
      reset_window (sock);

      err = listen->listen_hook (sock, listen->hook_data);
      if (err)
	{
	  grub_netbuff_free (nb);
	  destroy_socket (sock);
	  return;
	}
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
grub_net_tcp_accept (grub_net_tcp_socket_t sock,
		     grub_net_tcp_recv_hook recv_hook,
		     grub_net_tcp_error_hook error_hook,
		     grub_net_tcp_fin_hook fin_hook,
		     void *hook_data)
{
  grub_err_t err;

  sock->recv_hook = recv_hook;
  sock->error_hook = error_hook;
  sock->fin_hook = fin_hook;
  sock->hook_data = hook_data;

  err = ack (sock, 0);
  if (err)
    return err;

  change_socket_state (sock, ESTABLISHED);
  tcp_socket_register (sock);

  sock->snd.nxt++;
  dbgs ("%d snd.nxt=%u rcv.nxt:%u snd.una:%u\n", sock->local_port,
       my_seq (sock, sock->snd.nxt),
       their_seq (sock, sock->rcv.nxt),
       my_seq (sock, sock->snd.una));
  return GRUB_ERR_NONE;
}


