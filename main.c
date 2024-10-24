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

#ifdef __cplusplus
#include <atomic>
#endif

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

#ifndef IIP_MAIN_C
#define IIP_MAIN_C "iip/main.c"
#endif

#include IIP_MAIN_C

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

#ifndef MAX_THREAD
#define MAX_THREAD (256)
#endif
#ifndef MAX_PAYLOAD_LEN
#define MAX_PAYLOAD_LEN (63488)
#endif

#ifndef MAX_PAYLOAD_PKT_CNT
#define MAX_PAYLOAD_PKT_CNT (2048)
#endif

#ifndef NUM_MONITOR_LATENCY_RECORD
#define NUM_MONITOR_LATENCY_RECORD (5000000UL)
#endif

#ifndef __APP_PRINTF
#define __APP_PRINTF printf
#endif

struct thread_data {
	uint16_t core_id;
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

struct app_data {
#ifdef __cplusplus
	std::atomic<uint64_t> active_conn;
#else
	_Atomic uint64_t active_conn;
#endif
	uint16_t tcpudp_port_affinty_map[0xffff];
	uint64_t dbg_prev_print;
	struct thread_data *tds[MAX_THREAD];
	uint32_t remote_ip4_addr_be;
	uint16_t l4_port_be;
	uint8_t remote_mac[6];
	uint32_t payload_len;
	const char *app_msg;
	uint32_t concurrency;
	uint8_t proto_id;
	uint8_t app_mode;
	uint16_t io_depth;
	uint64_t pacing_pps;
	uint64_t duration;
	uint64_t start_time;
	uint64_t rx_pps_prev[2];
	uint64_t rx_bytes_prev[2];
	uint64_t tx_pps_prev[2];
	uint64_t tx_bytes_prev[2];
	uint64_t latency_cnt;
	uint64_t *latency_val;
};

static uint8_t __app_should_stop(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	return td->should_stop;
}

static void __tcp_send_content(void *mem, void *handle, struct tcp_opaque *to, uint16_t cur, uint16_t cnt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct app_data *ad = (struct app_data *) opaque_array[1];
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
					assert(!iip_tcp_send(mem, handle, m, (i == cnt - 1 ? 0x08U /* PSH */ : 0), opaque));
				}
			}
			if (ad->pacing_pps) {
				to->prev_sent = BENCH_IIP_NOW(opaque);
				to->sent += cnt;
			}
			if (ad->app_mode == 1 /* ping-pong */)
				to->monitor.ts = BENCH_IIP_NOW(opaque);
			td->monitor.counter[td->monitor.idx].tx_bytes += l;
			td->monitor.counter[td->monitor.idx].tx_pkt += cnt;
		}
	}
}

#ifndef MAX_PORT_CNT
#define MAX_PORT_CNT (1024)
#endif

static void __app_loop(void *mem, uint8_t mac[], uint32_t ip4_be, uint32_t *next_us, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct app_data *ad = (struct app_data *) opaque_array[1];
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		switch (td->app_state) {
		case 0:
			if (ad->remote_ip4_addr_be) {
				if (!td->core_id) {
					{ /* get port affinity map */
						__APP_PRINTF("getting affinity map for %u ports ...", MAX_PORT_CNT); fflush(stdout);
						{
							uint16_t i;
							for (i = 0; i < MAX_PORT_CNT; i++) {
								uint16_t port = helper_ip4_get_connection_affinity(ad->proto_id,
										ip4_be, htons(i),
										ad->remote_ip4_addr_be, ad->l4_port_be,
										opaque);
								if (port != UINT16_MAX)
									ad->tcpudp_port_affinty_map[i] = port;
								else {
									assert(!i);
									__APP_PRINTF("RSS not supported\n"); fflush(stdout);
									ad->tcpudp_port_affinty_map[i] = 0;
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
						macsum += ad->remote_mac[i];
				}
				if (macsum)
					td->app_state = 2;
				else if (!td->core_id) {
					uint64_t now = BENCH_IIP_NOW(opaque);
					if (1000000000UL < (now - td->prev_arp)) {
						IIP_OPS_DEBUG_PRINTF("sending arp request ... to %u.%u.%u.%u\n",
								(ad->remote_ip4_addr_be >>  0) & 0xff,
								(ad->remote_ip4_addr_be >>  8) & 0xff,
								(ad->remote_ip4_addr_be >> 16) & 0xff,
								(ad->remote_ip4_addr_be >> 24) & 0xff);
						iip_arp_request(mem, mac, ip4_be, ad->remote_ip4_addr_be, opaque);
						td->prev_arp = now;
					}
				}
			}
			break;
		case 2:
			{
				uint16_t i;
				for (i = 0; i < ad->concurrency; i++) {
					uint16_t j;
					for (j = 1 /* minimum local port number */; j < 0xffff; j++) {
						if (ad->tcpudp_port_affinty_map[j] == td->core_id) {
							if (!(td->tcp.used_port_bm[j >> 3] & (1 << (j & 7)))) {
								td->tcp.used_port_bm[j >> 3] |= (1 << (j & 7));
								switch (ad->proto_id) {
								case 6:
									{
										IIP_OPS_DEBUG_PRINTF("%u: try connect to %hhu.%hhu.%hhu.%hhu:%u (local %u)\n",
												td->core_id,
												(uint8_t)((ad->remote_ip4_addr_be >>  0) & 0xff),
												(uint8_t)((ad->remote_ip4_addr_be >>  8) & 0xff),
												(uint8_t)((ad->remote_ip4_addr_be >> 16) & 0xff),
												(uint8_t)((ad->remote_ip4_addr_be >> 24) & 0xff),
												ntohs(ad->l4_port_be), j);
										assert(!iip_tcp_connect(mem,
													mac, ip4_be, htons(j),
													ad->remote_mac, ad->remote_ip4_addr_be, ad->l4_port_be,
													opaque));
									}
									break;
								case 17:
									{
										void *m;
										assert((m = iip_ops_pkt_clone(td->payload.pkt[0], opaque)) != NULL);;
										IIP_OPS_DEBUG_PRINTF("%u: send first udp packet to %hhu.%hhu.%hhu.%hhu:%u (local %u)\n",
												td->core_id,
												(uint8_t)((ad->remote_ip4_addr_be >>  0) & 0xff),
												(uint8_t)((ad->remote_ip4_addr_be >>  8) & 0xff),
												(uint8_t)((ad->remote_ip4_addr_be >> 16) & 0xff),
												(uint8_t)((ad->remote_ip4_addr_be >> 24) & 0xff),
												ntohs(ad->l4_port_be), j);
										{
											uint16_t k;
											for (k = 0; k < ad->io_depth; k++) {
												assert(!iip_udp_send(mem,
															mac, ip4_be, htons(j),
															ad->remote_mac, ad->remote_ip4_addr_be, ad->l4_port_be,
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
			if (ad->pacing_pps) {
				if (td->tcp.conn_list_cnt) {
					uint16_t i;
					for (i = 0; i < td->tcp.conn_list_cnt; i++) {
						if (td->tcp.conn_list[i]->sent != td->payload.cnt) {
							if ((1000000000UL / ad->pacing_pps) < BENCH_IIP_NOW(opaque) - td->tcp.conn_list[i]->prev_sent) {
								__tcp_send_content(mem, td->tcp.conn_list[i]->handle, td->tcp.conn_list[i], td->tcp.conn_list[i]->cur, td->payload.cnt - td->tcp.conn_list[i]->sent, opaque);
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
			if (1000000000UL < now - ad->dbg_prev_print) {
				{
					uint16_t i;
					for (i = 0; i < MAX_THREAD; i++) {
						if (ad->tds[i]) {
							if (ad->tds[i]->monitor.idx)
								ad->tds[i]->monitor.idx = 0;
							else
								ad->tds[i]->monitor.idx = 1;
						}
					}
				}
				{
					uint64_t rx_bytes = 0, rx_pkt = 0, tx_bytes = 0, tx_pkt = 0;
					{
						uint16_t i;
						for (i = 0; i < MAX_THREAD; i++) {
							if (ad->tds[i]) {
								uint8_t idx = (ad->tds[i]->monitor.idx ? 0 : 1);
								if (ad->tds[i]->monitor.counter[idx].rx_pkt || ad->tds[i]->monitor.counter[idx].tx_pkt) {
									__APP_PRINTF("[%u] payload: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
											i,
											ad->tds[i]->monitor.counter[idx].rx_bytes / 125000UL,
											ad->tds[i]->monitor.counter[idx].rx_pkt,
											ad->tds[i]->monitor.counter[idx].tx_bytes / 125000UL,
											ad->tds[i]->monitor.counter[idx].tx_pkt
											); fflush(stdout);
									rx_bytes += ad->tds[i]->monitor.counter[idx].rx_bytes;
									tx_bytes += ad->tds[i]->monitor.counter[idx].tx_bytes;
									rx_pkt += ad->tds[i]->monitor.counter[idx].rx_pkt;
									tx_pkt += ad->tds[i]->monitor.counter[idx].tx_pkt;
								}
								memset(&ad->tds[i]->monitor.counter[idx], 0, sizeof(ad->tds[i]->monitor.counter[idx]));
							}
						}
					}
					ad->rx_pps_prev[0] = ad->rx_pps_prev[1];
					ad->rx_pps_prev[1] = rx_pkt;
					ad->rx_bytes_prev[0] = ad->rx_bytes_prev[1];
					ad->rx_bytes_prev[1] = rx_bytes;
					ad->tx_pps_prev[0] = ad->tx_pps_prev[1];
					ad->tx_pps_prev[1] = tx_pkt;
					ad->tx_bytes_prev[0] = ad->tx_bytes_prev[1];
					ad->tx_bytes_prev[1] = tx_bytes;
					__APP_PRINTF("paylaod total: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
							rx_bytes / 125000UL,
							rx_pkt,
							tx_bytes / 125000UL,
							tx_pkt
						  ); fflush(stdout);
				}
				ad->dbg_prev_print = now;
			}
			*next_us = (ad->dbg_prev_print + 1000000000U - now) / 1000U;
		} else
			*next_us = 1000000U;
		if (!td->core_id) {
			if (!__app_close_posted && ad->duration && ad->start_time) {
				if (ad->start_time + ad->duration * 1000000000UL < BENCH_IIP_NOW(opaque)) {
					{
						time_t t = time(NULL);
						struct tm lt;
						localtime_r(&t, &lt);
						__APP_PRINTF("%04u-%02u-%02u %02u:%02u:%02u : %lu sec has passed, now stopping the program ...\n",
								lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
								lt.tm_hour, lt.tm_min, lt.tm_sec,
								ad->duration); fflush(stdout);
					}
					{
						uint16_t i;
						for (i = MAX_PORT_CNT; i < MAX_PORT_CNT + MAX_PORT_CNT; i++) {
							if (td->core_id == helper_ip4_get_connection_affinity(6 /* tcp */,
										ip4_be, htons(i),
										ad->remote_ip4_addr_be, htons(50000 /* remote shutdown */),
										opaque)) {
								__APP_PRINTF("send stop request to the remote host (local port %u)\n", i); fflush(stdout);
								assert(!iip_tcp_connect(mem,
											mac, ip4_be, htons(i),
											ad->remote_mac, ad->remote_ip4_addr_be, htons(50000 /* remote shutdown */),
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
					if (ad->remote_ip4_addr_be && !td->core_id) {
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
					if (ad->remote_ip4_addr_be && !td->core_id) {
						assert((ad->latency_val = (uint64_t *) mem_alloc_local(NUM_MONITOR_LATENCY_RECORD * MAX_THREAD)) != NULL);
						{
							uint16_t i;
							for (i = 0; i < MAX_THREAD; i++) {
								if (ad->tds[i]) {
									uint64_t cnt = ad->tds[i]->monitor.latency.cnt;
									__asm__ volatile ("" ::: "memory");
									if (NUM_MONITOR_LATENCY_RECORD < cnt)
										cnt = NUM_MONITOR_LATENCY_RECORD;
									memcpy(&ad->latency_val[ad->latency_cnt],
											ad->tds[i]->monitor.latency.val,
											sizeof(ad->tds[i]->monitor.latency.val[0]) * cnt);
									ad->latency_cnt += cnt;
								}
							}
						}
					}
					{
						if (td->tcp.conn_list_cnt) {
							uint16_t i;
							for (i = 0; i < td->tcp.conn_list_cnt; i++)
								iip_tcp_close(mem, td->tcp.conn_list[i]->handle, opaque);
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
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	struct thread_data *td;
	assert((td = (struct thread_data *) mem_alloc_local(sizeof(struct thread_data))) != NULL);
	memset(td, 0, sizeof(struct thread_data));
	td->core_id = core_id;
	if (ad->payload_len) {
		uint32_t l = 0;
		while (l != ad->payload_len) {
			assert((td->payload.pkt[td->payload.cnt] = iip_ops_pkt_alloc(opaque)) != NULL);
			{
				uint16_t _l = (ad->payload_len - l < MAX_PAYLOAD_LEN ? ad->payload_len - l : MAX_PAYLOAD_LEN);
				if (ad->app_msg)
					memcpy(iip_ops_pkt_get_data(td->payload.pkt[td->payload.cnt], opaque), &ad->app_msg[l], _l);
				iip_ops_pkt_set_len(td->payload.pkt[td->payload.cnt], _l, opaque);
				l += _l;
			}
			td->payload.cnt++;
			assert(td->payload.cnt < MAX_PAYLOAD_PKT_CNT);
		}
	}
	ad->tds[td->core_id] = td;
	return td;
	{ /* unused */
		(void) workspace;
	}
}

static void iip_ops_arp_reply(void *_mem __attribute__((unused)), void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
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
	if (PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[0] == (uint8_t)((ad->remote_ip4_addr_be >>  0) & 0xff) &&
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[1] == (uint8_t)((ad->remote_ip4_addr_be >>  8) & 0xff) &&
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[2] == (uint8_t)((ad->remote_ip4_addr_be >> 16) & 0xff) &&
			PB_ARP_IP_SENDER(iip_ops_pkt_get_data(m, opaque))[3] == (uint8_t)((ad->remote_ip4_addr_be >> 24) & 0xff))
		memcpy(ad->remote_mac, PB_ARP_HW_SENDER(iip_ops_pkt_get_data(m, opaque)), 6);
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
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be == htons(50000)) /* to remote shutdown */
		return 1;
	if (PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be == ad->l4_port_be)
		return 1;
	else
		return 0;
}

static void *iip_ops_tcp_accepted(void *mem __attribute__((unused)), void *handle, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	struct tcp_opaque *to = (struct tcp_opaque *) mem_alloc_local(sizeof(struct tcp_opaque));
	assert(to);
	memset(to, 0, sizeof(struct tcp_opaque));
	to->handle = handle;
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		IIP_OPS_DEBUG_PRINTF("[%u] accept new connection (%lu)\n", td->core_id, ++ad->active_conn);
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

static void *iip_ops_tcp_connected(void *mem, void *handle, void *m __attribute__((unused)), void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct app_data *ad = (struct app_data *) opaque_array[1];
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		IIP_OPS_DEBUG_PRINTF("[%u] connected (%lu)\n", td->core_id, ++ad->active_conn);
		if (!ad->start_time)
			ad->start_time = BENCH_IIP_NOW(opaque);
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
				for (i = 0; i < ad->io_depth; i++) {
					__tcp_send_content(mem, handle, to, to->cur, 1, opaque);
					if (++to->cur == td->payload.cnt)
						to->cur = 0;
				}
			}
			return (void *) to;
		}
	}
}

static void iip_ops_tcp_payload(void *mem, void *handle, void *m,
				void *tcp_opaque, uint16_t head_off, uint16_t tail_off,
				void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct app_data *ad = (struct app_data *) opaque_array[1];
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			uint8_t idx = td->monitor.idx;
			__asm__ volatile ("" ::: "memory");
			td->monitor.counter[idx].rx_bytes += PB_TCP_PAYLOAD_LEN(iip_ops_pkt_get_data(m, opaque)) - head_off - tail_off;
			td->monitor.counter[idx].rx_pkt++;
		}
		switch (ad->app_mode) {
		case 1: /* ping-pong */
			if (ad->remote_ip4_addr_be && ((struct tcp_opaque *) tcp_opaque)->monitor.ts) {
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
			if (ad->pacing_pps)
				((struct tcp_opaque *) tcp_opaque)->sent--;
			else
				__tcp_send_content(mem, handle, (struct tcp_opaque *) tcp_opaque, 0, td->payload.cnt, opaque);
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
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	if (ad->remote_ip4_addr_be) { /* client */
		switch (ad->app_mode) {
		case 1: /* ping-pong */
			break;
		case 2: /* burst */
			if (ad->pacing_pps)
				((struct tcp_opaque *) tcp_opaque)->sent--;
			else {
				__tcp_send_content(mem, handle, (struct tcp_opaque *) tcp_opaque, ((struct tcp_opaque *) tcp_opaque)->cur, 1, opaque);
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

static void iip_ops_tcp_closed(void *handle __attribute__((unused)),
			       uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			       uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			       void *tcp_opaque, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
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
	IIP_OPS_DEBUG_PRINTF("tcp connection closed (%lu)\n", --ad->active_conn);
	{ /* unused */
		(void) local_mac;
		(void) local_ip4_be;
		(void) local_port_be;
		(void) peer_mac;
		(void) peer_ip4_be;
		(void) peer_port_be;
	}
}

static void iip_ops_udp_payload(void *mem, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	{
		struct app_data *ad = (struct app_data *) opaque_array[1];
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			void *_m;
			assert((_m = iip_ops_pkt_clone(td->payload.pkt[0], opaque)) != NULL);
			assert(!iip_udp_send(mem,
						iip_ops_l2_hdr_dst_ptr(m, opaque),
						PB_IP4(iip_ops_pkt_get_data(m, opaque))->dst_be,
						PB_UDP(iip_ops_pkt_get_data(m, opaque))->dst_be,
						iip_ops_l2_hdr_src_ptr(m, opaque),
						PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be,
						PB_UDP(iip_ops_pkt_get_data(m, opaque))->src_be,
						_m, opaque));
			td->monitor.counter[td->monitor.idx].tx_bytes += ad->payload_len;
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

static int qsort_uint64_cmp(const void *a, const void *b)
{
	if (*((uint64_t *) a) == *((uint64_t *) b))
		return 0;
	else if (*((uint64_t *) a) < *((uint64_t *) b))
		return -1;
	else
		return 1;
}

static void __app_exit(void *app_global_opaque)
{
	struct app_data *ad = (struct app_data *) app_global_opaque;
	if (ad->latency_val) {
		static uint64_t l_50th, l_90th, l_99th, l_999th;
		__APP_PRINTF("calculating latency for %lu samples ...\n", ad->latency_cnt); fflush(stdout);
		qsort(ad->latency_val, ad->latency_cnt, sizeof(ad->tds[0]->monitor.latency.val[0]), qsort_uint64_cmp);
		if (2 < ad->latency_cnt)
			l_50th = ad->latency_val[ad->latency_cnt / 2];
		if (100 <= ad->latency_cnt) {
			l_90th = ad->latency_val[(ad->latency_cnt / 10) * 9];
			l_99th = ad->latency_val[(ad->latency_cnt / 100) * 99];
		}
		if (1000 <= ad->latency_cnt)
			l_999th = ad->latency_val[(ad->latency_cnt / 1000) * 999];
		mem_free(ad->latency_val, NUM_MONITOR_LATENCY_RECORD * MAX_THREAD);
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
					ad->rx_bytes_prev[0] * 8,
					ad->rx_pps_prev[0],
					ad->tx_bytes_prev[0] * 8,
					ad->tx_pps_prev[0],
					p50th, p90th, p99th, p999th
			      ); fflush(stdout);
		}
	}
	mem_free(app_global_opaque, sizeof(struct app_data));
}

static void *__app_init(int argc, char *const *argv)
{
	struct app_data *ad = (struct app_data *) mem_alloc_local(sizeof(struct app_data));
	assert(ad);

	ad->concurrency = 1;
	ad->proto_id = 6; /* tcp */
	ad->app_mode = 1;
	ad->io_depth = 1;

	{ /* parse arguments */
		int ch, cnt = 0;
		while ((ch = getopt(argc, argv, "c:d:g:l:m:n:p:r:s:t:v:")) != -1) {
			cnt += 2;
			switch (ch) {
			case 'c':
				ad->concurrency = atoi(optarg);
				break;
			case 'd':
				ad->io_depth = atoi(optarg);
				break;
			case 'g':
				ad->app_mode = atoi(optarg);
				assert(0 < ad->app_mode && ad->app_mode <= 2);
				break;
			case 'l':
				assert(!ad->app_msg);
				ad->payload_len = atoi(optarg);
				break;
			case 'm':
				assert(!ad->payload_len);
				ad->app_msg = optarg;
				ad->payload_len = strlen(ad->app_msg);
				break;
			case 'n':
				ad->proto_id = atoi(optarg);
				switch (ad->proto_id) {
				case 6:
				case 17:
					break;
				default:
					assert(0);
					break;
				}
				break;
			case 'p':
				ad->l4_port_be = htons(atoi(optarg));
				break;
			case 'r':
				ad->pacing_pps = strtol(optarg, NULL, 10);
				break;
			case 's':
				assert(inet_pton(AF_INET, optarg, &ad->remote_ip4_addr_be) == 1);
				break;
			case 't':
				ad->duration = strtol(optarg, NULL, 10);
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

	assert(ad->l4_port_be);
	assert(ad->l4_port_be != htons(50000 /* remote shut down */));

	if (ad->app_mode == 1) { /* ping-pong mode only accepts data fit in a packet */
		assert(ad->payload_len < MAX_PAYLOAD_LEN);
	}

	if (ad->proto_id == 17) { /* udp mode only accepts data fit in a packet */
		assert(ad->payload_len < MAX_PAYLOAD_LEN);
	}

	if (ad->remote_ip4_addr_be) {
		switch (ad->app_mode) {
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
		assert(ad->payload_len);
		assert(ad->concurrency);
		if (ad->pacing_pps)
			assert(ad->io_depth == 1);
		__APP_PRINTF("client: connect to %u.%u.%u.%u:%u with concurrency %u, data len %u, io-depth %u, pacing %lu rps, duration %lu sec\n",
				(ad->remote_ip4_addr_be >>  0) & 0x0ff,
				(ad->remote_ip4_addr_be >>  8) & 0x0ff,
				(ad->remote_ip4_addr_be >> 16) & 0x0ff,
				(ad->remote_ip4_addr_be >> 24) & 0x0ff,
				ntohs(ad->l4_port_be),
				ad->concurrency,
				ad->payload_len,
				ad->io_depth,
				ad->pacing_pps,
				ad->duration); fflush(stdout);
	} else {
		assert(!ad->pacing_pps);
		switch (ad->app_mode) {
		case 1: /* ping-pong */
			__APP_PRINTF("server: ping-pong mode\n"); fflush(stdout);
			assert(ad->payload_len);
			break;
		case 2: /* burst (ignore) */
			__APP_PRINTF("server: burst mode (just ignore incoming data)\n"); fflush(stdout);
			break;
		default:
			assert(0);
			break;
		}
		__APP_PRINTF("server listens on %u, data len %u\n", ntohs(ad->l4_port_be), ad->payload_len); fflush(stdout);
	}

	signal(SIGINT, sig_h);

	return (void *) ad;
}

#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S

int main(int argc, char *const *argv)
{
	int ret = 0;
	ret = __iosub_main(argc, argv);
	return ret;
}
