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

#ifndef GRUB_CORE_NET_TCP_PRIVATE_H
#define GRUB_CORE_NET_TCP_PRIVATE_H

#define TCP_SYN_RETRANSMISSION_TIMEOUT GRUB_NET_INTERVAL
#define TCP_SYN_RETRANSMISSION_COUNT GRUB_NET_TRIES
#define TCP_RETRANSMISSION_TIMEOUT GRUB_NET_INTERVAL
#define TCP_RETRANSMISSION_COUNT GRUB_NET_TRIES

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

extern const char * const tcp_flag_names[7];

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
extern const char * const tcp_state_names[INVALID_STATE+1];

struct tcp_state_transition
{
  tcp_state from;
  tcp_state to;
};
extern struct tcp_state_transition tcp_state_transitions[];

struct tcp_segment
{
  struct grub_net_tcp_socket *sock;
  grub_uint32_t seq; /* SEG.SEQ - segment sequence number */
  grub_uint32_t ack; /* SEG.ACK - segment acknowledgment number */
  grub_uint32_t len; /* SEG.LEN - segment length */
  grub_uint32_t wnd; /* SEG.WND - segment window */
  int up;  /* SEG.UP  - segment urgent pointer */
  int prc; /* SEG.PRC - segment precedence value */
  struct tcphdr *tcph;
  grub_uint32_t txtlen;
  struct grub_net_buff *nb;
};

struct unacked
{
  struct grub_net_buff *nb;
  grub_uint64_t last_try;
  int try_count;
};

struct grub_net_tcp_socket
{
  struct grub_net_tcp_socket *next;
  struct grub_net_tcp_socket **prev;

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

  grub_uint8_t ttl;
  grub_uint32_t time_wait;
  int needs_ack;
  int needs_retransmit;
  int i_stall;
  int they_push;

  grub_net_tcp_recv_hook recv_hook;
  grub_net_tcp_error_hook error_hook;
  grub_net_tcp_fin_hook fin_hook;
  grub_net_tcp_listen_hook listen_hook;

  void *hook_data;
  grub_net_network_level_address_t out_nla;
  grub_net_link_level_address_t ll_target_addr;
  const struct grub_net_network_level_interface *inf;
  grub_net_packets_t packs;
  grub_priority_queue_t receive;
  grub_priority_queue_t retransmit;
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

extern struct grub_net_tcp_socket *tcp_sockets;

#define FOR_TCP_SOCKETS(var, next) FOR_LIST_ELEMENTS_SAFE (var, next, tcp_sockets)

#define tcplen(flags) ((grub_size_t)(grub_be_to_cpu16 (flags) >> 10))
#define tcpflags(tcpp) ((tcpp)->flags & TCP_FLAG_MASK)
#define tcpsize(size) grub_cpu_to_be16_compile_time((size) << 10)
#define pktlen(nb) ((grub_size_t)((nb)->tail - (nb)->data))
#define my_seq(sock, seqnr) ((grub_uint32_t)\
			     (((grub_uint32_t)seqnr)\
			      - ((grub_uint32_t)((sock)->iss))))
#define their_seq(sock, seqnr) ((grub_uint32_t)\
				(((grub_uint32_t)seqnr)\
				 - ((grub_uint32_t)((sock)->irs))))
#define my_window(sock) ((sock)->snd.wnd << ((sock)->snd.sca))

#define dbg_helper(key, fmt, ...) ({grub_uint64_t _now = grub_get_time_ms(); grub_dprintf(key, "%lu.%lu " fmt, _now / 1000, _now % 1000, ## __VA_ARGS__);})
#define dbg(fmt, ...) dbg_helper ("tcp", fmt, ## __VA_ARGS__)
#define dbgs(fmt, ...) dbg_helper ("tcp-segment", fmt, ## __VA_ARGS__)
#define dbgw(fmt, ...) dbg_helper ("tcp-window", fmt, ## __VA_ARGS__)
#define dbgq(fmt, ...) dbg_helper ("tcp-queue", fmt, ## __VA_ARGS__)

#define FOR_TCP_OPTIONS(tcph, opt)					    \
  for ((opt) = (struct tcp_opt *)(((char *)tcph) + sizeof (struct tcphdr)); \
       tcplen((tcph)->flags) > 20					    \
       && (char *)opt < (((char *)tcph) + tcplen((tcph)->flags)) ;	    \
       (opt) = (struct tcp_opt *)((char *)(opt) +			    \
				  ((opt)->kind == 1 ? 1 : ((opt)->length))))

/* inline helpers here */
static inline char * __attribute__ ((__unused__))
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

static inline int __attribute__ ((__unused__))
recv_pending (const struct grub_net_network_level_interface *inf)
{
  int rc;

  rc = inf->card->driver->recv_pending (inf->card);
  if (rc < 1)
    return 0;
  return rc;
}

/* listen helpers */
extern void handle_listen (struct grub_net_buff *nb, struct tcphdr *tcph,
			   grub_net_tcp_socket_t listen_sock,
			   const struct grub_net_network_level_interface *inf,
			   const grub_net_network_level_address_t *source);
/* send helpers */
extern grub_err_t ack (grub_net_tcp_socket_t sock, grub_uint32_t resend);
extern grub_err_t reset (grub_net_tcp_socket_t sock);
extern void prune_acks (grub_net_tcp_socket_t sock, struct tcp_segment *seg);

/* recv helpers */
extern void push_socket_data (grub_net_tcp_socket_t sock);
extern void grub_net_tcp_flush_recv_queue (grub_net_tcp_socket_t sock);
extern grub_err_t grub_net_tcp_process_queue (grub_net_tcp_socket_t sock);

/* miscelanious tcp glue */
extern grub_net_tcp_socket_t new_socket (
			    const struct grub_net_network_level_interface *inf,
			    const grub_net_network_level_address_t *source,
			    struct tcphdr *tcph, tcp_state state);
extern void destroy_socket (grub_net_tcp_socket_t sock);
extern grub_err_t tcp_socket_register (grub_net_tcp_socket_t sock);
extern grub_err_t change_socket_state_real (grub_net_tcp_socket_t sock,
					    tcp_state new_state,
					    const char * const file, int line);
#define change_socket_state(sock, new_state) change_socket_state_real (sock, new_state, GRUB_FILE, __LINE__)

extern grub_uint64_t minimum_window (grub_net_tcp_socket_t sock);
extern void adjust_window (grub_net_tcp_socket_t sock, struct tcp_segment *seg);
extern void reset_window (grub_net_tcp_socket_t sock);
int reap_time_wait (grub_net_tcp_socket_t sock);
int destroy_closed (grub_net_tcp_socket_t sock);
void error (grub_net_tcp_socket_t sock);

/* tcp options */
extern grub_err_t add_window_scale (struct grub_net_buff *nb,
				    struct tcphdr *tcph, grub_size_t *size,
				    int scale_value);
extern grub_err_t add_mss (grub_net_tcp_socket_t sock,
			   struct grub_net_buff *nb,
			   struct tcphdr *tcph, grub_size_t *size);
extern grub_err_t add_padding (struct grub_net_buff *nb,
			       struct tcphdr *tcph, grub_size_t *size);

static inline int __attribute__ ((__unused__))
before(grub_uint32_t seq1, grub_uint32_t seq2)
{
  /* if one of these has overflowed and the other hasn't, casting to the
   * signed type will cause the one that has not yet overflowed to be
   * negative, unless they're 2^31 apart, in which case one will be rejected
   * for being outside the segment window anyway. */
  return (grub_int32_t)(seq1-seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int
between(grub_uint32_t seq1, grub_uint32_t seq2, grub_uint32_t seq3)
{
  return seq3 - seq2 >= seq1 - seq2;
}

static inline int __attribute__ ((__unused__))
previously_acked_segment (grub_net_tcp_socket_t sock, struct tcp_segment *seg)
{
  /* If we have seen this sequence already, just remove it */
  if (before(seg->ack, sock->snd.una))
    return 1;

  return 0;
}

#endif /* !GRUB_CORE_NET_TCP_PRIVATE_H */
