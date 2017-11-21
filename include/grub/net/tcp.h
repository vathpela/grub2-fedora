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

#ifndef GRUB_NET_TCP_HEADER
#define GRUB_NET_TCP_HEADER	1
#include <grub/types.h>
#include <grub/net.h>

struct grub_net_tcp_socket;
typedef struct grub_net_tcp_socket *grub_net_tcp_socket_t;

void grub_net_tcp_socket_retransmit (grub_net_tcp_socket_t sock);
int grub_net_tcp_socket_unacked (grub_net_tcp_socket_t sock);
void grub_net_tcp_socket_ack (grub_net_tcp_socket_t sock);

typedef grub_err_t (*grub_net_tcp_recv_hook) (grub_net_tcp_socket_t sock,
					      struct grub_net_buff *nb,
					      void *recv);
typedef void (*grub_net_tcp_error_hook) (grub_net_tcp_socket_t sock,
					 void *recv);
typedef void (*grub_net_tcp_fin_hook) (grub_net_tcp_socket_t sock, void *recv);
typedef grub_err_t (*grub_net_tcp_listen_hook) (grub_net_tcp_socket_t sock,
						void *data);

grub_net_tcp_socket_t
grub_net_tcp_open (char *server,
		   grub_uint16_t out_port,
		   grub_net_tcp_recv_hook recv_hook,
		   grub_net_tcp_error_hook error_hook,
		   grub_net_tcp_fin_hook fin_hook,
		   void *hook_data);
void
grub_net_tcp_socket_advise (grub_net_tcp_socket_t sock,
			    grub_size_t size);

grub_net_tcp_socket_t
grub_net_tcp_listen (grub_uint16_t port,
		     const struct grub_net_network_level_interface *inf,
		     const grub_net_network_level_address_t *source,
		     grub_net_tcp_listen_hook listen_hook,
		     void *hook_data);

void
grub_net_tcp_stop_listen (grub_net_tcp_socket_t socket);

grub_err_t
grub_net_send_tcp_packet (const grub_net_tcp_socket_t socket,
			  struct grub_net_buff *nb,
			  int push);

enum
  {
    GRUB_NET_TCP_CONTINUE_RECEIVING,
    GRUB_NET_TCP_DISCARD,
    GRUB_NET_TCP_ABORT
  };

void
grub_net_tcp_close (grub_net_tcp_socket_t sock, int discard_received);

grub_err_t
grub_net_tcp_accept (grub_net_tcp_socket_t sock,
		     grub_net_tcp_recv_hook recv_hook,
		     grub_net_tcp_error_hook error_hook,
		     grub_net_tcp_fin_hook fin_hook,
		     void *hook_data);

void
grub_net_tcp_stall (grub_net_tcp_socket_t sock);

void
grub_net_tcp_unstall (grub_net_tcp_socket_t sock);

#endif
