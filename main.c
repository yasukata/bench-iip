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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <assert.h>

#include <arpa/inet.h>

#if defined(__linux__)
#include <numa.h>
#define mem_alloc_local	numa_alloc_local
#define mem_free	numa_free
#elif defined(__FreeBSD__)
#include <sys/socket.h> /* AF_INET */
static void *mem_alloc_local(size_t len)
{
	return malloc(len);
}

static void mem_free(void *ptr, size_t len)
{
	free(ptr);
	{
		(void) len;
	}
}
#endif

#define __iip_memcpy	memcpy
#define __iip_memset	memset
#define __iip_memcmp	memcmp
#define __iip_memmove	memmove
#define __iip_assert	assert

static uint8_t verbose_level = 0;

#ifndef IIP_OPS_DEBUG_PRINTF
static void __debug_printf(const char *format, ...)
{
	if (verbose_level) {
		va_list v;
		va_start(v, format);
		vprintf(format, v);
		va_end(v);
		fflush(stdout);
	}
}
#define IIP_OPS_DEBUG_PRINTF __debug_printf
#endif

#include "iip/main.c"

#if !defined(APP_IIP_OPS_UTIL_NOW_NS_NONE)
static void iip_ops_util_now_ns(uint32_t t[3], void *opaque)
{
	struct timespec ts;
	assert(!clock_gettime(CLOCK_REALTIME, &ts));
	t[0] = (ts.tv_sec >> 32) & 0xffffffff;
	t[1] = (ts.tv_sec >>  0) & 0xffffffff;
	t[2] = ts.tv_nsec;
	{ /* unused */
		(void) opaque;
	}
}
#endif

static uint16_t helper_ip4_get_connection_affinity(uint16_t, uint32_t, uint16_t, uint32_t, uint16_t, void *);

static uint64_t BENCH_IIP_NOW(void *opaque)
{
	uint32_t t[3];
	iip_ops_util_now_ns(t, opaque);
	return (((uint64_t) t[0] << 32) + (uint64_t) t[1]) * 1000000000UL + (uint64_t) t[2];
}

#define MAX_THREAD (256)
#define MAX_PAYLOAD_LEN (63488)

#define MAX_PAYLOAD_PKT_CNT (2048)

#define NUM_MONITOR_LATENCY_RECORD (5000000UL)

#ifndef __APP_PRINTF
#define __APP_PRINTF printf
#endif

struct thread_data {
	uint16_t core_id;
	void *workspace;
	struct {
		uint16_t cnt;
		void *pkt[MAX_PAYLOAD_PKT_CNT];
	} payload;
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
	uint16_t cur;
	uint16_t sent;
	uint64_t prev_sent; /* for pacing */
	struct {
		uint64_t ts;
	} monitor;
};

static uint8_t __app_close_posted = 0;
static uint8_t __app_remote_stop_handled = 0;

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
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	return td->should_stop;
}

static void __tcp_send_content(void *handle, struct tcp_opaque *to, uint16_t cur, uint16_t cnt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			uint32_t l = 0;
			{
				uint16_t i;
				for (i = 0; i < cnt; i++) {
					void *m;
					assert((m = iip_ops_pkt_clone(td->payload.pkt[cur], opaque)) != NULL);
					l += iip_ops_pkt_get_len(m, opaque);
					if (++cur == td->payload.cnt)
						cur = 0;
					assert(!iip_tcp_send(td->workspace, handle, m, opaque));
				}
			}
			if (__app_pacing_pps) {
				to->prev_sent = BENCH_IIP_NOW(opaque);
				to->sent += cnt;
			}
			if (__app_mode == 1 /* ping-pong */)
				to->monitor.ts = BENCH_IIP_NOW(opaque);
			td->monitor.counter[td->monitor.idx].tx_bytes += l;
			td->monitor.counter[td->monitor.idx].tx_pkt += cnt;
		}
	}
}

#define MAX_PORT_CNT (1024)

static void __app_loop(uint8_t mac[], uint32_t ip4_be, uint32_t *next_us, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		switch (td->app_state) {
		case 0:
			if (__app_remote_ip4_addr_be) {
				if (!td->core_id) {
					{ /* get port affinity map */
						__APP_PRINTF("getting affinity map for %u ports ...", MAX_PORT_CNT); fflush(stdout);
						{
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
									__APP_PRINTF("RSS not supported\n"); fflush(stdout);
									__app_tcp_port_affinty_map[i] = 0;
									break;
								}
							}
						}
						__APP_PRINTF("ok\n"); fflush(stdout);
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
				else if (!td->core_id) {
					uint64_t now = BENCH_IIP_NOW(opaque);
					if (1000000000UL < (now - td->prev_arp)) {
						IIP_OPS_DEBUG_PRINTF("sending arp request ... to %u.%u.%u.%u\n",
								(__app_remote_ip4_addr_be >>  0) & 0xff,
								(__app_remote_ip4_addr_be >>  8) & 0xff,
								(__app_remote_ip4_addr_be >> 16) & 0xff,
								(__app_remote_ip4_addr_be >> 24) & 0xff);
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
						if (__app_tcp_port_affinty_map[j] == td->core_id) {
							if (!(td->tcp.used_port_bm[j >> 3] & (1 << (j & 7)))) {
								td->tcp.used_port_bm[j >> 3] |= (1 << (j & 7));
								switch (__app_proto_id) {
								case 6:
									{
										IIP_OPS_DEBUG_PRINTF("%u: try connect to %hhu.%hhu.%hhu.%hhu:%u (local %u)\n",
												td->core_id,
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
										assert((m = iip_ops_pkt_clone(td->payload.pkt[0], opaque)) != NULL);;
										IIP_OPS_DEBUG_PRINTF("%u: send first udp packet to %hhu.%hhu.%hhu.%hhu:%u (local %u)\n",
												td->core_id,
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
			}
			break;
		case 3:
			if (__app_pacing_pps) {
				if (td->tcp.conn_list_cnt) {
					uint16_t i;
					for (i = 0; i < td->tcp.conn_list_cnt; i++) {
						if (td->tcp.conn_list[i]->sent != td->payload.cnt) {
							if ((1000000000UL / __app_pacing_pps) < BENCH_IIP_NOW(opaque) - td->tcp.conn_list[i]->prev_sent) {
								__tcp_send_content(td->tcp.conn_list[i]->handle, td->tcp.conn_list[i], td->tcp.conn_list[i]->cur, td->payload.cnt - td->tcp.conn_list[i]->sent, opaque);
								if (++td->tcp.conn_list[i]->cur == td->payload.cnt)
									td->tcp.conn_list[i]->cur = 0;
							}
						}
					}
				}
			}
		default:
			break;
		}
		if (!__app_close_posted && !td->core_id) {
			uint64_t now = BENCH_IIP_NOW(opaque);
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
									__APP_PRINTF("[%u] payload: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
											i,
											__app_td[i]->monitor.counter[idx].rx_bytes / 125000UL,
											__app_td[i]->monitor.counter[idx].rx_pkt,
											__app_td[i]->monitor.counter[idx].tx_bytes / 125000UL,
											__app_td[i]->monitor.counter[idx].tx_pkt
											); fflush(stdout);
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
					__APP_PRINTF("paylaod total: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
							rx_bytes / 125000UL,
							rx_pkt,
							tx_bytes / 125000UL,
							tx_pkt
						  ); fflush(stdout);
				}
				__app_dbg_prev_print = now;
			}
			*next_us = (__app_dbg_prev_print + 1000000000U - now) / 1000U;
		} else
			*next_us = 1000000U;
		if (!td->core_id) {
			if (!__app_close_posted && __app_duration && __app_start_time) {
				if (__app_start_time + __app_duration * 1000000000UL < BENCH_IIP_NOW(opaque)) {
					{
						time_t t = time(NULL);
						struct tm lt;
						localtime_r(&t, &lt);
						__APP_PRINTF("%04u-%02u-%02u %02u:%02u:%02u : %lu sec has passed, now stopping the program ...\n",
								lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
								lt.tm_hour, lt.tm_min, lt.tm_sec,
								__app_duration); fflush(stdout);
					}
					{
						uint16_t i;
						for (i = MAX_PORT_CNT; i < MAX_PORT_CNT + MAX_PORT_CNT; i++) {
							if (td->core_id == helper_ip4_get_connection_affinity(6 /* tcp */,
										ip4_be, htons(i),
										__app_remote_ip4_addr_be, htons(50000 /* remote shutdown */),
										opaque)) {
								__APP_PRINTF("send stop request to the remote host (local port %u)\n", i); fflush(stdout);
								assert(!iip_tcp_connect(__app_td[td->core_id]->workspace,
											mac, ip4_be, htons(i),
											__app_remote_mac, __app_remote_ip4_addr_be, htons(50000 /* remote shutdown */),
											opaque));
								break;
							}
						}
						assert(i != MAX_PORT_CNT + MAX_PORT_CNT);
					}
					signal(SIGINT, SIG_DFL);
					__app_close_posted = 1;
				}
			}
		}
		if (__app_close_posted) {
			switch (td->close_state) {
				case 0:
					if (__app_remote_ip4_addr_be && !td->core_id) {
						if (!__app_remote_stop_handled)
							break;
					}
					if (!td->core_id) {
						time_t t = time(NULL);
						struct tm lt;
						localtime_r(&t, &lt);
						__APP_PRINTF("%04u-%02u-%02u %02u:%02u:%02u : close requested\n",
								lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
								lt.tm_hour, lt.tm_min, lt.tm_sec); fflush(stdout);
					}
					if (__app_remote_ip4_addr_be && !td->core_id) {
						assert((__app_latency_val = (uint64_t *) mem_alloc_local(NUM_MONITOR_LATENCY_RECORD * MAX_THREAD)) != NULL);
						{
							uint16_t i;
							for (i = 0; i < MAX_THREAD; i++) {
								if (__app_td[i]) {
									uint64_t cnt = __app_td[i]->monitor.latency.cnt;
									__asm__ volatile ("" ::: "memory");
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

static void *__app_thread_init(void *workspace, uint16_t core_id, void *opaque)
{
	struct thread_data *td;
	assert((td = (struct thread_data *) mem_alloc_local(sizeof(struct thread_data))) != NULL);
	memset(td, 0, sizeof(struct thread_data));
	td->core_id = core_id;
	td->workspace = workspace;
	if (__app_payload_len) {
		uint32_t l = 0;
		while (l != __app_payload_len) {
			assert((td->payload.pkt[td->payload.cnt] = iip_ops_pkt_alloc(opaque)) != NULL);
			{
				uint16_t _l = (__app_payload_len - l < MAX_PAYLOAD_LEN ? __app_payload_len - l : MAX_PAYLOAD_LEN);
				if (__app_msg)
					memcpy(iip_ops_pkt_get_data(td->payload.pkt[td->payload.cnt], opaque), &__app_msg[l], _l);
				iip_ops_pkt_set_len(td->payload.pkt[td->payload.cnt], _l, opaque);
				l += _l;
			}
			td->payload.cnt++;
			assert(td->payload.cnt < MAX_PAYLOAD_PKT_CNT);
		}
	}
	__app_td[td->core_id] = td;
	return td;
}

static void iip_ops_arp_reply(void *_mem __attribute__((unused)), void *m, void *opaque)
{
	IIP_OPS_DEBUG_PRINTF("arp reply: %u.%u.%u.%u at %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[0],
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[1],
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[2],
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[3],
			PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque))[0],
			PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque))[1],
			PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque))[2],
			PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque))[3],
			PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque))[4],
			PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque))[5]
	      );
	if (PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[0] == (uint8_t)((__app_remote_ip4_addr_be >>  0) & 0xff) &&
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[1] == (uint8_t)((__app_remote_ip4_addr_be >>  8) & 0xff) &&
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[2] == (uint8_t)((__app_remote_ip4_addr_be >> 16) & 0xff) &&
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[3] == (uint8_t)((__app_remote_ip4_addr_be >> 24) & 0xff))
		memcpy(__app_remote_mac, PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque)), 6);
}

static void iip_ops_icmp_reply(void *_mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused)))
{
	IIP_OPS_DEBUG_PRINTF("received icmp reply from %u.%u.%u.%u\n",
			(PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be >>  0) & 0xff,
			(PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be >>  8) & 0xff,
			(PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be >> 16) & 0xff,
			(PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be >> 24) & 0xff);
}

static uint8_t iip_ops_tcp_accept(void *mem __attribute__((unused)), void *m, void *opaque)
{
	if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be == htons(50000)) /* to remote shutdown */
		return 1;
	if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be == __app_l4_port_be)
		return 1;
	else
		return 0;
}

static void *iip_ops_tcp_accepted(void *mem __attribute__((unused)), void *handle, void *m, void *opaque)
{
	struct tcp_opaque *to = (struct tcp_opaque *) mem_alloc_local(sizeof(struct tcp_opaque));
	assert(to);
	memset(to, 0, sizeof(struct tcp_opaque));
	to->handle = handle;
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		IIP_OPS_DEBUG_PRINTF("[%u] accept new connection (%lu)\n", td->core_id, ++__app_active_conn);
	}
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		td->tcp.conn_list[td->tcp.conn_list_cnt++] = to;
	}
	if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be == htons(50000 /* remote shutdown */)) {
		time_t t = time(NULL);
		struct tm lt;
		localtime_r(&t, &lt);
		__APP_PRINTF("%04u-%02u-%02u %02u:%02u:%02u : close requested via network\n",
				lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
				lt.tm_hour, lt.tm_min, lt.tm_sec); fflush(stdout);
		__app_close_posted = 1;
		signal(SIGINT, SIG_DFL);
	}
	return (void *) to;
}

static void *iip_ops_tcp_connected(void *mem __attribute__((unused)), void *handle, void *m __attribute__((unused)), void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		IIP_OPS_DEBUG_PRINTF("[%u] connected (%lu)\n", td->core_id, ++__app_active_conn);
		if (!__app_start_time)
			__app_start_time = BENCH_IIP_NOW(opaque);
		{
			struct tcp_opaque *to = (struct tcp_opaque *) mem_alloc_local(sizeof(struct tcp_opaque)); /* TODO: finer-grained allocation */
			assert(to);
			memset(to, 0, sizeof(struct tcp_opaque));
			to->handle = handle;
			td->tcp.conn_list[td->tcp.conn_list_cnt++] = to;
			if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be == htons(50000 /* remote shutdown */)) {
				__APP_PRINTF("remote stop request is handled\n");
				__app_remote_stop_handled = 1;
			} else {
				uint16_t i;
				for (i = 0; i < __app_io_depth; i++) {
					__tcp_send_content(handle, to, to->cur, 1, opaque);
					if (++to->cur == td->payload.cnt)
						to->cur = 0;
				}
			}
			return (void *) to;
		}
	}
}

static void iip_ops_tcp_payload(void *mem, void *handle, void *m,
				void *tcp_opaque,
				void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			uint8_t idx = td->monitor.idx;
			__asm__ volatile ("" ::: "memory");
			td->monitor.counter[idx].rx_bytes += PB_TCP_PAYLOAD_LEN(iip_ops_pkt_get_data(m, opaque));
			td->monitor.counter[idx].rx_pkt++;
		}
		switch (__app_mode) {
		case 1: /* ping-pong */
			if (__app_remote_ip4_addr_be && ((struct tcp_opaque *) tcp_opaque)->monitor.ts) {
				void **opaque_array = (void **) opaque;
				{
					struct thread_data *td = (struct thread_data *) opaque_array[2];
					{
						uint64_t now = BENCH_IIP_NOW(opaque);
						td->monitor.latency.val[td->monitor.latency.cnt++ % NUM_MONITOR_LATENCY_RECORD] = now - ((struct tcp_opaque *) tcp_opaque)->monitor.ts;
						((struct tcp_opaque *) tcp_opaque)->monitor.ts = now;
					}
				}
			}
			if (__app_pacing_pps)
				((struct tcp_opaque *) tcp_opaque)->sent--;
			else
				__tcp_send_content(handle, (struct tcp_opaque *) tcp_opaque, 0, td->payload.cnt, opaque);
			break;
		case 2: /* burst */
			break;
		default:
			assert(0);
			break;
		}
	}
	iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);
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
				((struct tcp_opaque *) tcp_opaque)->sent--;
			else {
				__tcp_send_content(handle, (struct tcp_opaque *) tcp_opaque, ((struct tcp_opaque *) tcp_opaque)->cur, 1, opaque);
				{
					void **opaque_array = (void **) opaque;
					struct thread_data *td = (struct thread_data *) opaque_array[2];
					{
						if (++((struct tcp_opaque *) tcp_opaque)->cur == td->payload.cnt)
							((struct tcp_opaque *) tcp_opaque)->cur = 0;
					}
				}
			}
			break;
		default:
			assert(0);
			break;
		}
	}
}

static void iip_ops_tcp_closed(void *handle __attribute__((unused)), void *tcp_opaque, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			uint16_t i;
			for (i = 0; i < td->tcp.conn_list_cnt; i++) {
				if (tcp_opaque == td->tcp.conn_list[i]) {
					td->tcp.conn_list[i] = td->tcp.conn_list[--td->tcp.conn_list_cnt];
					mem_free(tcp_opaque, sizeof(struct tcp_opaque));
					break;
				}
			}
		}
		if (td->close_state == 1 && !td->tcp.conn_list_cnt)
			td->should_stop = 1;
	}
	IIP_OPS_DEBUG_PRINTF("tcp connection closed (%lu)\n", --__app_active_conn);
}

static void iip_ops_udp_payload(void *mem __attribute__((unused)), void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			void *_m;
			assert((_m = iip_ops_pkt_clone(td->payload.pkt[0], opaque)) != NULL);
			assert(!iip_udp_send(td->workspace,
						iip_ops_l2_hdr_dst_ptr(m, opaque),
						PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be,
						PB_UDP(iip_ops_pkt_get_data(m, opaque))->dst_be,
						iip_ops_l2_hdr_src_ptr(m, opaque),
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
	__app_remote_stop_handled = 1;
	signal(SIGINT, SIG_DFL);
}

static void __app_exit(void *app_global_opaque)
{
	(void) app_global_opaque;
	if (__app_latency_val) {
		static uint64_t l_50th, l_90th, l_99th, l_999th;
		__APP_PRINTF("calculating latency for %lu samples ...\n", __app_latency_cnt); fflush(stdout);
		qsort(__app_latency_val, __app_latency_cnt, sizeof(__app_td[0]->monitor.latency.val[0]), qsort_uint64_cmp);
		if (2 < __app_latency_cnt)
			l_50th = __app_latency_val[__app_latency_cnt / 2];
		if (100 <= __app_latency_cnt) {
			l_90th = __app_latency_val[(__app_latency_cnt / 10) * 9];
			l_99th = __app_latency_val[(__app_latency_cnt / 100) * 99];
		}
		if (1000 <= __app_latency_cnt)
			l_999th = __app_latency_val[(__app_latency_cnt / 1000) * 999];
		mem_free(__app_latency_val, NUM_MONITOR_LATENCY_RECORD * MAX_THREAD);
		{
			char b50th[256], *p50th = b50th, b90th[256], *p90th = b90th, b99th[256], *p99th = b99th, b999th[256], *p999th = b999th;
			if (l_50th)
				snprintf(b50th, sizeof(b50th), "50%%-ile %lu ns", l_50th);
			else
				snprintf(b50th, sizeof(b50th), "50%%-ile -");
			if (l_90th)
				snprintf(b90th, sizeof(b90th), "90%%-ile %lu ns", l_90th);
			else
				snprintf(b90th, sizeof(b90th), "90%%-ile -");
			if (l_99th)
				snprintf(b99th, sizeof(b99th), "99%%-ile %lu ns", l_99th);
			else
				snprintf(b99th, sizeof(b99th), "99%%-ile -");
			if (l_999th)
				snprintf(b999th, sizeof(b999th), "99.9%%-ile %lu ns", l_999th);
			else
				snprintf(b999th, sizeof(b999th), "99.9%%-ile -");
			__APP_PRINTF("throughput rx %lu bps %lu pps, tx %lu bps %lu pps, latency %s %s %s %s\n",
					__rx_bytes_prev[0] * 8,
					__rx_pps_prev[0],
					__tx_bytes_prev[0] * 8,
					__tx_pps_prev[0],
					p50th, p90th, p99th, p999th
				    ); fflush(stdout);
		}
	}
}

static void *__app_init(int argc, char *const *argv)
{
	{ /* parse arguments */
		int ch, cnt = 0;
		while ((ch = getopt(argc, argv, "c:d:g:l:m:n:p:r:s:t:v:")) != -1) {
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
			case 'v':
				verbose_level = atoi(optarg);
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
	assert(__app_l4_port_be != htons(50000 /* remote shut down */));

	if (__app_mode == 1) { /* ping-pong mode only accepts data fit in a packet */
		assert(__app_payload_len < MAX_PAYLOAD_LEN);
	}

	if (__app_proto_id == 17) { /* udp mode only accepts data fit in a packet */
		assert(__app_payload_len < MAX_PAYLOAD_LEN);
	}

	if (__app_remote_ip4_addr_be) {
		switch (__app_mode) {
		case 1: /* ping-pong */
			__APP_PRINTF("client: ping-pong mode\n"); fflush(stdout);
			break;
		case 2: /* burst */
			__APP_PRINTF("client: burst mode\n"); fflush(stdout);
			break;
		default:
			assert(0);
			break;
		}
		assert(__app_payload_len);
		assert(__app_concurrency);
		if (__app_pacing_pps)
			assert(__app_io_depth == 1);
		__APP_PRINTF("client: connect to %u.%u.%u.%u:%u with concurrency %u, data len %u, io-depth %u, pacing %lu rps, duration %lu sec\n",
				(__app_remote_ip4_addr_be >>  0) & 0x0ff,
				(__app_remote_ip4_addr_be >>  8) & 0x0ff,
				(__app_remote_ip4_addr_be >> 16) & 0x0ff,
				(__app_remote_ip4_addr_be >> 24) & 0x0ff,
				ntohs(__app_l4_port_be),
				__app_concurrency,
				__app_payload_len,
				__app_io_depth,
				__app_pacing_pps,
				__app_duration); fflush(stdout);
	} else {
		assert(!__app_pacing_pps);
		switch (__app_mode) {
		case 1: /* ping-pong */
			__APP_PRINTF("server: ping-pong mode\n"); fflush(stdout);
			assert(__app_payload_len);
			break;
		case 2: /* burst (ignore) */
			__APP_PRINTF("server: burst mode (just ignore incoming data)\n"); fflush(stdout);
			break;
		default:
			assert(0);
			break;
		}
		__APP_PRINTF("server listens on %u, data len %u\n", ntohs(__app_l4_port_be), __app_payload_len); fflush(stdout);
	}

	signal(SIGINT, sig_h);

	return NULL;
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
	int ret = 0;
	ret = __iosub_main(argc, argv);
	return ret;
}
