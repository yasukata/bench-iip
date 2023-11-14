/*
 *
 * Copyright 2023 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <assert.h>

#include <arpa/inet.h>

#include <numa.h>

#define __iip_memcpy	memcpy
#define __iip_memset	memset
#define __iip_memcmp	memcmp
#define __iip_memmove	memmove
#define __iip_assert	assert

#include "iip/main.c"

static uint16_t helper_ip4_get_connection_affinity(uint16_t, uint32_t, uint16_t, uint32_t, uint16_t, void *);

#define NOW() \
	({ \
		struct timespec __ts; \
		assert(!clock_gettime(CLOCK_REALTIME, &__ts)); \
		(__ts.tv_sec * 1000000000UL + __ts.tv_nsec); \
	}) \

#define MAX_THREAD (256)

#define NUM_MONITOR_LATENCY_RECORD (5000000UL)

struct thread_data {
	void *workspace;
	void *pkt_payload;
	uint8_t app_state;
	uint8_t close_state;
	uint8_t should_stop;
	struct {
		struct tcp_opaque *conn_list[1U << 16];
		uint16_t conn_list_cnt;
		uint8_t used_port_bm[0xffff / 8];
	} tcp;
	struct {
		uint8_t idx;
		struct {
			uint64_t rx_pkt;
			uint64_t tx_pkt;
			uint64_t rx_bytes;
			uint64_t tx_bytes;
		} counter[2];
		struct {
			uint64_t cnt;
			uint64_t val[NUM_MONITOR_LATENCY_RECORD];
		} latency;
	} monitor;
	uint64_t prev_arp;
};

struct tcp_opaque {
	void *handle;
	uint8_t sent;
	uint64_t prev_sent; /* for pacing */
	struct {
		uint64_t ts;
	} monitor;
};

static uint8_t __app_close_posted = 0;

static _Atomic uint64_t __app_active_conn = 0;
static uint16_t __app_tcp_port_affinty_map[0xffff];
static uint64_t __app_dbg_prev_print = 0;
static struct thread_data *__app_td[MAX_THREAD] = { 0 };

static uint32_t __app_remote_ip4_addr_be = 0;
static uint16_t __app_l4_port_be = 0;
static uint8_t __app_remote_mac[6] = { 0 };
static uint32_t __app_payload_len = 0;
static const char *__app_msg = NULL;
static uint32_t __app_concurrency = 1;
static uint8_t __app_proto_id = 6; /* tcp */
static uint8_t __app_mode = 1;
static uint8_t __app_io_depth = 1;
static uint64_t __app_pacing_pps = 0;
static uint64_t __app_duration = 0;
static uint64_t __app_start_time = 0;
static uint64_t __rx_pps_prev[2] = { 0 }, __rx_bytes_prev[2] = { 0 }, __tx_pps_prev[2] = { 0 }, __tx_bytes_prev[2] = { 0 };

static uint64_t __app_latency_cnt = 0;
static uint64_t *__app_latency_val = NULL;

static uint8_t __app_should_stop(void *opaque)
{
	void **opaque_array = (void *) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[1];
	return td->should_stop;
}

static void __tcp_send_content(void *handle, struct tcp_opaque *to, void *opaque)
{
	void **opaque_array = (void *) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		{
			void *m;
			assert(td->pkt_payload);
			assert((m = iip_ops_pkt_clone(td->pkt_payload, opaque)) != NULL);
			if (__app_pacing_pps) {
				to->prev_sent = NOW();
				to->sent = 1;
			}
			if (__app_mode == 1 /* ping-pong */)
				to->monitor.ts = NOW();
			assert(!iip_tcp_send(td->workspace, handle, m, opaque));
			__app_td[iip_ops_util_core()]->monitor.counter[__app_td[iip_ops_util_core()]->monitor.idx].tx_bytes += __app_payload_len;
			__app_td[iip_ops_util_core()]->monitor.counter[__app_td[iip_ops_util_core()]->monitor.idx].tx_pkt++;
		}
	}
}

#define MAX_PORT_CNT (1024)

static void __app_loop(uint8_t mac[], uint32_t ip4_be, uint32_t *next_us, void *opaque)
{
	void **opaque_array = (void *) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		switch (td->app_state) {
		case 0:
			if (__app_remote_ip4_addr_be) {
				if (!iip_ops_util_core()) {
					{ /* get port affinity map */
						printf("getting affinity map for %u ports ...", MAX_PORT_CNT); fflush(stdout);
						uint16_t i;
						for (i = 0; i < MAX_PORT_CNT; i++) {
							uint16_t port = helper_ip4_get_connection_affinity(6 /* tcp */,
											ip4_be, htons(i),
											__app_remote_ip4_addr_be, __app_l4_port_be,
											opaque);
							if (port != UINT16_MAX)
								__app_tcp_port_affinty_map[i] = port;
							else {
								assert(!i);
								printf("RSS not supported\n");
								__app_tcp_port_affinty_map[i] = 0;
								break;
							}
						}
						printf("ok\n");
					}
				}
				td->app_state = 1;
			} else
				td->app_state = 3;
			break;
		case 1:
			{
				uint32_t macsum = 0;
				{
					uint8_t i;
					for (i = 0; i < 6; i++)
						macsum += __app_remote_mac[i];
				}
				if (macsum)
					td->app_state = 2;
				else if (!iip_ops_util_core()) {
					uint64_t now = NOW();
					if (1000000000UL < (now - td->prev_arp)) {
						printf("sending arp request ...\n");
						iip_arp_request(td->workspace, mac, ip4_be, __app_remote_ip4_addr_be, opaque);
						td->prev_arp = now;
					}
				}
			}
			break;
		case 2:
			{
				uint16_t i;
				for (i = 0; i < __app_concurrency; i++) {
					uint16_t j;
					for (j = 1 /* minimum local port number */; j < 0xffff; j++) {
						if (__app_tcp_port_affinty_map[j] == iip_ops_util_core()) {
							if (!(td->tcp.used_port_bm[j >> 3] & (1 << (j & 7)))) {
								td->tcp.used_port_bm[j >> 3] |= (1 << (j & 7));
								switch (__app_proto_id) {
								case 6:
									{
										printf("%u: try connect to %hhu.%hhu.%hhu.%hhu:%u (local %u)\n",
												iip_ops_util_core(),
												(uint8_t)((__app_remote_ip4_addr_be >>  0) & 0xff),
												(uint8_t)((__app_remote_ip4_addr_be >>  8) & 0xff),
												(uint8_t)((__app_remote_ip4_addr_be >> 16) & 0xff),
												(uint8_t)((__app_remote_ip4_addr_be >> 24) & 0xff),
												ntohs(__app_l4_port_be), j);
										assert(!iip_tcp_connect(td->workspace,
													mac, ip4_be, htons(j),
													__app_remote_mac, __app_remote_ip4_addr_be, __app_l4_port_be,
													opaque));
									}
									break;
								case 17:
									{
										void *m;
										assert(td->pkt_payload);
										assert((m = iip_ops_pkt_clone(td->pkt_payload, opaque)) != NULL);;
										printf("%u: send first udp packet to %hhu.%hhu.%hhu.%hhu:%u (local %u)\n",
												iip_ops_util_core(),
												(uint8_t)((__app_remote_ip4_addr_be >>  0) & 0xff),
												(uint8_t)((__app_remote_ip4_addr_be >>  8) & 0xff),
												(uint8_t)((__app_remote_ip4_addr_be >> 16) & 0xff),
												(uint8_t)((__app_remote_ip4_addr_be >> 24) & 0xff),
												ntohs(__app_l4_port_be), j);
										{
											uint16_t k;
											for (k = 0; k < __app_io_depth; k++) {
												assert(!iip_udp_send(td->workspace,
															mac, ip4_be, htons(j),
															__app_remote_mac, __app_remote_ip4_addr_be, __app_l4_port_be,
															m, opaque));
											}
										}
									}
									break;
								default:
									assert(0);
									break;
								}
																break;
							}
						}
					}
				}
				td->app_state = 3;
				__app_start_time = NOW();
			}
			break;
		case 3:
			if (__app_pacing_pps) {
				if (td->tcp.conn_list_cnt) {
					uint16_t i;
					for (i = 0; i < td->tcp.conn_list_cnt; i++) {
						if (!td->tcp.conn_list[i]->sent) {
							if ((1000000000UL / __app_pacing_pps) < NOW() - td->tcp.conn_list[i]->prev_sent)
								__tcp_send_content(td->tcp.conn_list[i]->handle, td->tcp.conn_list[i], opaque);
						}
					}
				}
			}
		default:
			break;
		}
	}
	if (!iip_ops_util_core()) {
		uint64_t now = NOW();
		if (1000000000UL < now - __app_dbg_prev_print) {
			{
				uint16_t i;
				for (i = 0; i < MAX_THREAD; i++) {
					if (__app_td[i]) {
						if (__app_td[i]->monitor.idx)
							__app_td[i]->monitor.idx = 0;
						else
							__app_td[i]->monitor.idx = 1;
					}
				}
			}
			{
				uint64_t rx_bytes = 0, rx_pkt = 0, tx_bytes = 0, tx_pkt = 0;
				{
					uint16_t i;
					for (i = 0; i < MAX_THREAD; i++) {
						if (__app_td[i]) {
							uint8_t idx = (__app_td[i]->monitor.idx ? 0 : 1);
							if (__app_td[i]->monitor.counter[idx].rx_pkt || __app_td[i]->monitor.counter[idx].tx_pkt) {
								printf("[%u] payload: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
										i,
										__app_td[i]->monitor.counter[idx].rx_bytes / 125000UL,
										__app_td[i]->monitor.counter[idx].rx_pkt,
										__app_td[i]->monitor.counter[idx].tx_bytes / 125000UL,
										__app_td[i]->monitor.counter[idx].tx_pkt
										);
								rx_bytes += __app_td[i]->monitor.counter[idx].rx_bytes;
								tx_bytes += __app_td[i]->monitor.counter[idx].tx_bytes;
								rx_pkt += __app_td[i]->monitor.counter[idx].rx_pkt;
								tx_pkt += __app_td[i]->monitor.counter[idx].tx_pkt;
							}
							memset(&__app_td[i]->monitor.counter[idx], 0, sizeof(__app_td[i]->monitor.counter[idx]));
						}
					}
				}
				__rx_pps_prev[0] = __rx_pps_prev[1];
				__rx_pps_prev[1] = rx_pkt;
				__rx_bytes_prev[0] = __rx_bytes_prev[1];
				__rx_bytes_prev[1] = rx_bytes;
				__tx_pps_prev[0] = __tx_pps_prev[1];
				__tx_pps_prev[1] = tx_pkt;
				__tx_bytes_prev[0] = __tx_bytes_prev[1];
				__tx_bytes_prev[1] = tx_bytes;
				printf("paylaod total: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
						rx_bytes / 125000UL,
						rx_pkt,
						tx_bytes / 125000UL,
						tx_pkt
					  );
			}
			__app_dbg_prev_print = now;
		}
		*next_us = (__app_dbg_prev_print + 1000000000U - now) / 1000U;
	} else
		*next_us = 1000000U;
	if (!iip_ops_util_core()) {
		if (!__app_close_posted && __app_duration && __app_start_time) {
			if (__app_start_time + __app_duration * 1000000000UL < NOW()) {
				printf("%lu sec has passed, now stopping the program ...\n", __app_duration);
				signal(SIGINT, SIG_DFL);
				__app_close_posted = 1;
			}
		}
	}
	{
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		if (__app_close_posted) {
			switch (td->close_state) {
				case 0:
					printf("close requested\n");
					if (__app_remote_ip4_addr_be && !iip_ops_util_core()) {
						assert((__app_latency_val = numa_alloc_local(NUM_MONITOR_LATENCY_RECORD * MAX_THREAD)) != NULL);
						{
							uint16_t i;
							for (i = 0; i < MAX_THREAD; i++) {
								if (__app_td[i]) {
									uint64_t cnt = __app_td[i]->monitor.latency.cnt;
									asm volatile ("" ::: "memory");
									if (NUM_MONITOR_LATENCY_RECORD < cnt)
										cnt = NUM_MONITOR_LATENCY_RECORD;
									memcpy(&__app_latency_val[__app_latency_cnt],
											__app_td[i]->monitor.latency.val,
											sizeof(__app_td[i]->monitor.latency.val[0]) * cnt);
									__app_latency_cnt += cnt;
								}
							}
						}
					}
					{
						if (td->tcp.conn_list_cnt) {
							uint16_t i;
							for (i = 0; i < td->tcp.conn_list_cnt; i++)
								iip_tcp_close(td->workspace, td->tcp.conn_list[i]->handle, opaque);
						} else
							td->should_stop = 1;
					}
					td->close_state = 1;
					break;
				case 1:
					break;
				default:
					break;
			}
		}
	}
}

static void *__app_thread_init(void *workspace, void *opaque)
{
	struct thread_data *td;
	assert((td = numa_alloc_local(sizeof(struct thread_data))) != NULL);
	memset(td, 0, sizeof(struct thread_data));
	td->workspace = workspace;
	if (__app_payload_len) {
		assert((td->pkt_payload = iip_ops_pkt_alloc(opaque)) != NULL);
		/* TODO: check max packet length */
		if (__app_msg) {
			memcpy(iip_ops_pkt_get_data(td->pkt_payload, opaque), __app_msg, strlen(__app_msg));
			iip_ops_pkt_set_len(td->pkt_payload, strlen(__app_msg), opaque);
		} else {
			iip_ops_pkt_set_len(td->pkt_payload, __app_payload_len, opaque);
		}
	}
	__app_td[iip_ops_util_core()] = td;
	return td;
}

static void iip_ops_arp_reply(void *_mem __attribute__((unused)), void *m, void *opaque)
{
	struct iip_arp_hdr *arph = (struct iip_arp_hdr *)((uintptr_t) iip_ops_pkt_get_data(m, opaque) + 14);
	printf("arp reply: %u.%u.%u.%u at %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
			arph->ip_sender[0],
			arph->ip_sender[1],
			arph->ip_sender[2],
			arph->ip_sender[3],
			arph->mac_sender[0],
			arph->mac_sender[1],
			arph->mac_sender[2],
			arph->mac_sender[3],
			arph->mac_sender[4],
			arph->mac_sender[5]
	      );
	if (arph->ip_sender[0] == (uint8_t)((__app_remote_ip4_addr_be >>  0) & 0xff) &&
			arph->ip_sender[1] == (uint8_t)((__app_remote_ip4_addr_be >>  8) & 0xff) &&
			arph->ip_sender[2] == (uint8_t)((__app_remote_ip4_addr_be >> 16) & 0xff) &&
			arph->ip_sender[3] == (uint8_t)((__app_remote_ip4_addr_be >> 24) & 0xff))
		memcpy(__app_remote_mac, arph->mac_sender, 6);
}

static void iip_ops_icmp_reply(void *_mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused)))
{
	printf("received icmp reply\n");
}

static uint8_t iip_ops_tcp_accept(void *mem __attribute__((unused)), void *m, void *opaque)
{
	if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be == __app_l4_port_be)
		return 1;
	else
		return 0;
}

static void *iip_ops_tcp_accepted(void *mem __attribute__((unused)), void *handle, void *m __attribute__((unused)), void *opaque)
{
	struct tcp_opaque *to = (struct tcp_opaque *) numa_alloc_local(sizeof(struct tcp_opaque));
	assert(to);
	memset(to, 0, sizeof(struct tcp_opaque));
	to->handle = handle;
	printf("[%u] accept new connection (%lu)\n", iip_ops_util_core(), ++__app_active_conn);
	{
		void **opaque_array = (void *) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		td->tcp.conn_list[td->tcp.conn_list_cnt++] = to;
	}
	return (void *) to;
}

static void *iip_ops_tcp_connected(void *mem __attribute__((unused)), void *handle, void *m __attribute__((unused)), void *opaque)
{
	void **opaque_array = (void *) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		printf("[%u] connected (%lu)\n", iip_ops_util_core(), ++__app_active_conn);
		{
			struct tcp_opaque *to = numa_alloc_local(sizeof(struct tcp_opaque)); /* TODO: finer-grained allocation */
			assert(to);
			memset(to, 0, sizeof(struct tcp_opaque));
			to->handle = handle;
			td->tcp.conn_list[td->tcp.conn_list_cnt++] = to;
			{
				uint16_t k;
				for (k = 0; k < __app_io_depth; k++)
					__tcp_send_content(handle, to, opaque);
			}
			return (void *) to;
		}
	}
}

static void iip_ops_tcp_payload(void *mem, void *handle, void *m,
				void *tcp_opaque,
				void *opaque)
{
	{
		void **opaque_array = (void *) opaque;
		{
			struct thread_data *td = (struct thread_data *) opaque_array[1];
			{
				uint8_t idx = td->monitor.idx;
				asm volatile ("" ::: "memory");
				td->monitor.counter[idx].rx_bytes += PB_TCP_PAYLOAD_LEN(iip_ops_pkt_get_data(m, opaque));
				td->monitor.counter[idx].rx_pkt++;
			}
		}
	}

	iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);

	switch (__app_mode) {
	case 1: /* ping-pong */
		if (__app_remote_ip4_addr_be && ((struct tcp_opaque *) tcp_opaque)->monitor.ts) {
			void **opaque_array = (void *) opaque;
			{
				struct thread_data *td = (struct thread_data *) opaque_array[1];
				{
					uint64_t now = NOW();
					td->monitor.latency.val[td->monitor.latency.cnt++ % NUM_MONITOR_LATENCY_RECORD] = now - ((struct tcp_opaque *) tcp_opaque)->monitor.ts;
					((struct tcp_opaque *) tcp_opaque)->monitor.ts = now;
				}
			}
		}
		if (__app_pacing_pps)
			((struct tcp_opaque *) tcp_opaque)->sent = 0;
		else
			__tcp_send_content(handle, tcp_opaque, opaque);
		break;
	case 2: /* burst */
		break;
	default:
		assert(0);
		break;
	}
}

static void iip_ops_tcp_acked(void *mem __attribute__((unused)),
			      void *handle,
			      void *m __attribute__((unused)),
			      void *tcp_opaque,
			      void *opaque)
{
	if (__app_remote_ip4_addr_be) { /* client */
		switch (__app_mode) {
		case 1: /* ping-pong */
			break;
		case 2: /* burst */
			if (__app_pacing_pps)
				((struct tcp_opaque *) tcp_opaque)->sent = 0;
			else
				__tcp_send_content(handle, tcp_opaque, opaque);
			break;
		default:
			assert(0);
			break;
		}
	}
}

static void iip_ops_tcp_closed(void *handle __attribute__((unused)), void *tcp_opaque, void *opaque)
{
	void **opaque_array = (void *) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		{
			uint16_t i;
			for (i = 0; i < td->tcp.conn_list_cnt; i++) {
				if (tcp_opaque == td->tcp.conn_list[i]) {
					td->tcp.conn_list[i] = td->tcp.conn_list[--td->tcp.conn_list_cnt];
					numa_free(tcp_opaque, sizeof(struct tcp_opaque));
					break;
				}
			}
		}
		if (td->close_state == 1 && !td->tcp.conn_list_cnt)
			td->should_stop = 1;
	}
	{
		uint64_t conn_cnt = --__app_active_conn;
		printf("tcp connection closed (%lu)\n", conn_cnt);
	}
}

static void iip_ops_udp_payload(void *mem __attribute__((unused)), void *m, void *opaque)
{
	void **opaque_array = (void *) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[1];
		{
			void *_m;
			assert(td->pkt_payload);
			assert((_m = iip_ops_pkt_clone(td->pkt_payload, opaque)) != NULL);
			assert(!iip_udp_send(td->workspace,
						PB_ETH(iip_ops_pkt_get_data(m, opaque))->dst,
						PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be,
						PB_UDP(iip_ops_pkt_get_data(m, opaque))->dst_be,
						PB_ETH(iip_ops_pkt_get_data(m, opaque))->src,
						PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be,
						PB_UDP(iip_ops_pkt_get_data(m, opaque))->src_be,
						_m, opaque));
			td->monitor.counter[td->monitor.idx].tx_bytes += __app_payload_len;
			td->monitor.counter[td->monitor.idx].tx_pkt++;
		}
		td->monitor.counter[td->monitor.idx].rx_bytes += PB_UDP_PAYLOAD_LEN(iip_ops_pkt_get_data(m, opaque));
		td->monitor.counter[td->monitor.idx].rx_pkt++;
	}
}

static void sig_h(int sig __attribute__((unused)))
{
	__app_close_posted = 1;
	signal(SIGINT, SIG_DFL);
}

static void __app_init(int argc, char *const *argv)
{
	{ /* parse arguments */
		int ch, cnt = 0;
		while ((ch = getopt(argc, argv, "c:d:g:l:m:n:p:r:s:t:")) != -1) {
			cnt += 2;
			switch (ch) {
			case 'c':
				__app_concurrency = atoi(optarg);
				break;
			case 'd':
				__app_io_depth = atoi(optarg);
				break;
			case 'g':
				__app_mode = atoi(optarg);
				assert(0 < __app_mode && __app_mode <= 2);
				break;
			case 'l':
				assert(!__app_msg);
				__app_payload_len = atoi(optarg);
				break;
			case 'm':
				assert(!__app_payload_len);
				__app_msg = optarg;
				__app_payload_len = strlen(__app_msg);
				break;
			case 'n':
				__app_proto_id = atoi(optarg);
				switch (__app_proto_id) {
				case 6:
				case 17:
					break;
				default:
					assert(0);
					break;
				}
				break;
			case 'p':
				__app_l4_port_be = htons(atoi(optarg));
				break;
			case 'r':
				__app_pacing_pps = strtol(optarg, NULL, 10);
				break;
			case 's':
				assert(inet_pton(AF_INET, optarg, &__app_remote_ip4_addr_be) == 1);
				break;
			case 't':
				__app_duration = strtol(optarg, NULL, 10);
				break;
			default:
				assert(0);
				break;
			}
		}
		argc -= cnt;
		argv += cnt - 1;
	}

	assert(__app_l4_port_be);

	if (__app_remote_ip4_addr_be) {
		switch (__app_mode) {
		case 1: /* ping-pong */
			printf("client: ping-pong mode\n");
			break;
		case 2: /* burst */
			printf("client: burst mode\n");
			break;
		default:
			assert(0);
			break;
		}
		assert(__app_payload_len);
		assert(__app_concurrency);
		if (__app_pacing_pps)
			assert(__app_io_depth == 1);
		printf("client: connect to %u.%u.%u.%u:%u with concurrency %u, io-depth %u, pacing %lu rps, duration %lu sec\n",
				(__app_remote_ip4_addr_be >>  0) & 0x0ff,
				(__app_remote_ip4_addr_be >>  8) & 0x0ff,
				(__app_remote_ip4_addr_be >> 16) & 0x0ff,
				(__app_remote_ip4_addr_be >> 24) & 0x0ff,
				ntohs(__app_l4_port_be),
				__app_concurrency,
				__app_io_depth,
				__app_pacing_pps,
				__app_duration);
	} else {
		assert(!__app_pacing_pps);
		switch (__app_mode) {
		case 1: /* ping-pong */
			printf("server: ping-pong mode\n");
			assert(__app_payload_len);
			break;
		case 2: /* burst (ignore) */
			printf("server: burst mode (just ignore incoming data)\n");
			break;
		default:
			assert(0);
			break;
		}
		printf("server listens on %u\n", ntohs(__app_l4_port_be));
	}

	signal(SIGINT, sig_h);
}

#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S

static int qsort_uint64_cmp(const void *a, const void *b)
{
	if (*((uint64_t *) a) == *((uint64_t *) b))
		return 0;
	else if (*((uint64_t *) a) < *((uint64_t *) b))
		return -1;
	else
		return 1;
}

int main(int argc, char *const *argv)
{
	int ret = __iosub_main(argc, argv);
	if (!iip_ops_util_core() && __app_latency_val) {
		static uint64_t l_50th, l_90th, l_99th, l_999th;
		printf("calculating latency ...\n");
		qsort(__app_latency_val, __app_latency_cnt, sizeof(__app_td[0]->monitor.latency.val[0]), qsort_uint64_cmp);
		if (2 < __app_latency_cnt)
			l_50th = __app_latency_val[__app_latency_cnt / 2];
		if (100 <= __app_latency_cnt) {
			l_90th = __app_latency_val[(__app_latency_cnt / 10) * 9];
			l_99th = __app_latency_val[(__app_latency_cnt / 100) * 99];
		}
		if (1000 <= __app_latency_cnt)
			l_999th = __app_latency_val[(__app_latency_cnt / 1000) * 999];
		numa_free(__app_latency_val, NUM_MONITOR_LATENCY_RECORD * MAX_THREAD);
		{
			char b50th[256], *p50th = b50th, b90th[256], *p90th = b90th, b99th[256], *p99th = b99th, b999th[256], *p999th = b999th;
			if (l_50th)
				snprintf(b50th, sizeof(b50th), "50%%-ile %lu", l_50th);
			else
				snprintf(b50th, sizeof(b50th), "50%%-ile -");
			if (l_90th)
				snprintf(b90th, sizeof(b90th), "90%%-ile %lu", l_90th);
			else
				snprintf(b90th, sizeof(b90th), "90%%-ile -");
			if (l_99th)
				snprintf(b99th, sizeof(b99th), "99%%-ile %lu", l_99th);
			else
				snprintf(b99th, sizeof(b99th), "99%%-ile -");
			if (l_999th)
				snprintf(b999th, sizeof(b999th), "99.9%%-ile %lu", l_999th);
			else
				snprintf(b999th, sizeof(b999th), "99.9%%-ile -");
			printf("latency in ns (%lu samples): %s, %s, %s, %s\n",
					__app_latency_cnt, p50th, p90th, p99th, p999th);
		}
		printf("throughput rx %lu bps (%lu pps), tx %lu bps (%lu pps)\n",
				__rx_bytes_prev[0] * 8,
				__rx_pps_prev[0],
				__tx_bytes_prev[0] * 8,
				__tx_pps_prev[0]
		      );
		numa_free(__app_latency_val, NUM_MONITOR_LATENCY_RECORD * MAX_THREAD);
	}
	return ret;
}
