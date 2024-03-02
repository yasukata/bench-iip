# bench-iip: a benchmark tool for the iip TCP/IP stack

This is the benchmark tool of the [iip TCP/IP stack](https://github.com/yasukata/iip).

**WARNING: Several commands described in this README need the root permission (sudo). So, please conduct the following procedure only when you understand what you are doing. The authors will not bear any responsibility if the implementations, provided by the authors, cause any problems.**

## build

Please first download the source code of this repository.

```
git clone https://github.com/yasukata/bench-iip.git
```

Afterward, please enter the ```bench-iip``` directory.

```
cd bench-iip
```

Then, please download the source code of iip and the I/O backend.

```
git clone https://github.com/yasukata/iip.git
```

```
git clone https://github.com/yasukata/iip-dpdk.git
```

Please type the following command to build the application.

```
IOSUB_DIR=./iip-dpdk make
```

The command above will download the source code of DPDK and compile it with the files in this repository, ```./iip``` and ```./iip-dpdk```.

The DPDK source code will be downloaded at ```./iip-dpdk/dpdk/dpdk-VERSION.tar.xz```, and after the compilation, it will be installed in  ```./iip-dpdk/dpdk/install```.

So, the DPDK installation itself does not require the root permission (while we need the root permission to run this benchmark tool using DPDK).

For details, please refer to [https://github.com/yasukata/iip-dpdk/blob/master/build.mk](https://github.com/yasukata/iip-dpdk/blob/master/build.mk).

After the compilation finishes, we supposedly see an application file named ```a.out```.

## setup

Before starting to run the benchmark tool, we need to setup huge pages for DPDK.

The following command configures 2GB of huge pages with the 2MB granurality.

NOTE: If your system already has huge pages, you do not need to execute the following command.

```
sudo ./iip-dpdk/dpdk/dpdk-23.07/usertools/dpdk-hugepages.py -p 2M -r 2G
```

## run

For quick testing, please use the following command to launch this benchmark tool as the server; this program works as a client when the argument specifies the remote server address by ```-s```, otherwise, it works as a server.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -l 0 --proc-type=primary --file-prefix=pmd1 --vdev=net_tap,iface=tap001 --no-pci -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```

Now, the benchnark tool has started.

Please open another console (terminal), and please type the following commands to associate the tap device made by DPDK with a Linux bridge.

```
sudo brctl addbr br000
```
```
sudo ifconfig br000 10.100.0.10 up
```
```
sudo brctl addif br000 tap001
```

Then, let's first try the ```ping``` command to communicate with the benchmark tool server; supposedly, we will get replies.

```
ping 10.100.0.20
```

Afterward, let's try ```telnet```.

```
telnet 10.100.0.20 10000
```

Please type ```GET ``` in the telnet console; then, we will get the following output (this is specified by the command above).

```
HTTP/1.1 200 OK
Content-Length: 2
Connection: keep-alive

AA
```

You can exit from ```telnet``` by pressing the ```]``` button and the Ctrl button, and enter ```q```, like as follows.

```
Escape character is '^]'.
^]
telnet> q
Connection closed.
```

## command options

The options of this benchmark tool consist of three sections divided by ```--```: 1) the first is for DPDK (passed to ```rte_eal_init```), 2) the second is for the application-specific DPDK setting, and 3) the last is for the benchmark tool.

### 1st section: for DPDK

In the example above,
- ```-l 0``` specifies the CPU core to be used, this time is CPU core 0
- ```--proc-type=primary``` specifies proc type (maybe not necessary)
- ```--file-prefix=pmd1``` is for the namespace issue (maybe not necessary)
- ```--vdev=net_tap,iface=tap001``` is for associating a newly created tap device named ```tap001``` with DPDK.
- ```--no-pci``` requests DPDK not to lookup PCI NIC devices.

### 2nd section: for the application-specific DPDK setting

- ```-a```: specify the IP address for a DPDK port; the format is PORT_NUM,IP_ADDR (e.g., 0,10.100.0.10 configures 10.100.0.10 for port0)
- ```-e```: specify the max timeout value (in millisecond) passed to epoll_wait; when 0 is specified, the interrupt-based mode is not activated and epoll_wait will not be called (default value is 0)

### 3rd section: for the benchmark tool

- ```-c```: concurrency (for the client mode)
- ```-d```: io depth (for the client mode)
- ```-g```: mode (1: ping-pong, 2: burst); in the burst mode, a TCP client send data when it receives a TCP ack, and a TCP server ignores incoming data.
- ```-l```: payload length (if ```-m``` is not specified)
- ```-m```: a string to be sent as the payload
- ```-n```: protocol number, either 6 (TCP) or 17 (UDP) (for the client mode) : default is TCP
- ```-p```: the server port (to listen on for the server mode, to connect to for the client mode)
- ```-r```: targeted throughput rate (requests/sec) for each thread (for the client mode)
- ```-s```: the server IP address to be connected (for the client mode)
- ```-t```: duration of the experiment in second (0 means infinite)

## using a physical NIC

The command above uses the tap device, a virtual network interface, primarily for quick testing.

If you have an extra physical NIC, that is not used, you can test this benchmark tool with the unused extra physical NIC.

**NOTE: It is not recommended to use your primary physical NIC for testing this benchmark tool because this benchmark tool fully occupies the physical NIC and you will lose connections to other hosts previously established over it.**

Before starting the physical NIC setting, please remove ```br000``` that is made in the previous experiment using the tap device.

```
sudo ifconfig br000 down
```

```
sudo brctl delbr br000
```

### bind a physical NIC with vfio-pci

To use DPDK, we need to associate a physical NIC with a driver named ```vfio-pci```.

**NOTE: you do not need to go through this step if you use Mellanox NICs; please note that here we list the commands just to show how to use NICs from other vendors.**

First, please type the following command.

```
./iip-dpdk/dpdk/dpdk-23.07/usertools/dpdk-devbind.py -s
```

Supposedly, we will see this kind of output.

```
Network devices using kernel driver
===================================
0000:17:00.0 'MT28800 Family [ConnectX-5 Ex] 1019' if=enp23s0f0np0 drv=mlx5_core unused=
0000:17:00.1 'MT28800 Family [ConnectX-5 Ex] 1019' if=enp23s0f1np1 drv=mlx5_core unused=
```

In this example, we bind a NIC identified by the PCI id ```0000:17:00.0``` by the following command.

```
sudo ./iip-dpdk/dpdk/dpdk-23.07/usertools/dpdk-devbind.py -b vfio-pci 0000:17:00.0
```

### launch the benchmark tool

The following executes the benchmark tool as the server and binds it with the NIC 0000:17:00.0.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```

The following runs the benchnark tool as the client using the NIC 0000:17:00.0.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 1
```

## rough numbers

Here, we show some rough numbers obtained from this benchmark tool.

### machines

Two machines having the same configuration.

- CPU: Two of 16-core Intel(R) Xeon(R) Gold 6326 CPU @ 2.90GHz (32 cores in total)
- NIC: Mellanox ConnectX-5 100 Gbps NIC (the NICs of the two machines are directly connected via a cable)
- OS: Linux 6.2

### version

- iip: e423db4bee7c75d028a5f5ae0cb3a4a249caa940
- iip-dpdk: b493a944c13135c38766003606e14d51ca61fc71
- bench-iip: a93f859d2ca35a93b8891cba14f9d8d2eacea17f

### multi-core server performance

- client (iip and DPDK)

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p $((10000+$cnt)) -g 1 -l 1 -t 5 -c $(($cnt == 0 ? 1 : $cnt)) 2>&1 | tee -a ./result.txt; cnt=$(($cnt+2)); done
```

- server (iip and DPDK)

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-$(($cnt == 0 ? 0 : $(($cnt-1)))) --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p $((10000+$cnt)) -g 1 -l 1; cnt=$(($cnt+2)); done
```

<details>
<summary>please click here to show the changes made for disabling zero-copy mode</summary>

```iip-dpdk/main.c```

```diff
--- a/main.c
+++ b/main.c
@@ -684,6 +684,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok (max lro pkt size %u)\n", nic_conf[portid].rxmode.max_lro_pkt_size);
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("TX multi-seg: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
@@ -691,6 +692,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX IPv4 checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
```
</details>

<details>
<summary>please click here to show the changes made for disabling the checksum offload feature of the NIC</summary>

```iip-dpdk/main.c```

```diff
--- a/main.c
+++ b/main.c
@@ -669,6 +669,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok (nic feature %lx udp-rss-all %lx)\n", dev_info.flow_type_rss_offloads, RTE_ETH_RSS_TCP);
                                                } else printf("no\n"); /* TODO: software-based RSS */
                                        }
+#if 0
                                        {
                                                printf("RX checksum: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
@@ -676,6 +677,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("RX LRO: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
@@ -691,6 +693,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("TX IPv4 checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
@@ -705,6 +708,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX TCP TSO: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
```

</details>

- server (Linux)

<details>

<summary>please click here to show the code of the program</summary>

```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <numa.h>

#define MAX_CORE (256)

static unsigned int should_stop = 0;
static unsigned int mode = 0;
static unsigned short payload_len = 1;
static char payload_buf[0xffff] = { 0 };

struct monitor_data {
	unsigned short idx;
	struct {
		unsigned long rx_cnt;
		unsigned long tx_cnt;
		unsigned long rx_bytes;
		unsigned long tx_bytes;
	} counter[2];
};

static struct monitor_data *monitor[MAX_CORE] = { 0 };

static void sig_h(int s __attribute__((unused)))
{
	should_stop = 1;
	signal(SIGINT, SIG_DFL);
}

static void *server_thread(void *data)
{
	printf("core %lu : server fd %lu\n", (((unsigned long) data) & 0xffffffff), (((unsigned long) data) >> 32));
	{
		cpu_set_t c;
		CPU_ZERO(&c);
		CPU_SET((((unsigned long) data) & 0xffffffff), &c);
		pthread_setaffinity_np(pthread_self(), sizeof(c), &c);
	}
	{
		struct monitor_data *mon;
		assert((mon = numa_alloc_local(sizeof(struct monitor_data))) != NULL);
		memset(mon, 0, sizeof(struct monitor_data));
		monitor[(((unsigned long) data) & 0xffffffff)] = mon;
		{
			int epfd;

			assert((epfd = epoll_create1(EPOLL_CLOEXEC)) != -1);

			{
				struct epoll_event ev = {
					.events = EPOLLIN,
					.data.fd = (((unsigned long) data) >> 32),
				};
				assert(!epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev));
			}

			while (!should_stop) {
				struct epoll_event ev[64];
				int nfd = epoll_wait(epfd, ev, 64, 100);
				{
					int i;
					for (i = 0; i < nfd; i++) {
						if ((unsigned long) ev[i].data.fd == (((unsigned long) data) >> 32)) {
							while (1) {
								struct sockaddr_in sin;
								socklen_t addrlen;
								{
									struct epoll_event _ev = {
										.events = EPOLLIN,
										.data.fd = accept(ev[i].data.fd, (struct sockaddr *) &sin, &addrlen),
									};
									if (_ev.data.fd == -1) {
										assert(errno == EAGAIN);
										break;
									}
									assert(!epoll_ctl(epfd, EPOLL_CTL_ADD, _ev.data.fd, &_ev));
								}
							}
						} else {
							char buf[0x10000];
							ssize_t rx = read(ev[i].data.fd, buf, sizeof(buf));
							if (rx <= 0)
								close(ev[i].data.fd);
							else {
								mon->counter[mon->idx].rx_bytes += rx;
								mon->counter[mon->idx].rx_cnt++;
								if (mode == 1 /* ping-pong */) {
									assert(write(ev[i].data.fd, payload_buf, payload_len) == payload_len);
									mon->counter[mon->idx].tx_bytes += payload_len;
									mon->counter[mon->idx].tx_cnt++;
								}
							}
						}
					}
				}
			}
			close(epfd);
		}
		numa_free(mon, sizeof(struct monitor_data));
	}

	pthread_exit(NULL);
}

static void *remote_stop_thread(void *data)
{
	int *ready = (int *) data, fd;

	assert((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1);
	{
		int v = 1;
		assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)));
	}
	{
		int v = 1;
		assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)));
	}
	{
		int v = 1;
		assert(!ioctl(fd, FIONBIO, &v));
	}
	{
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
			.sin_port = htons(50000 /* remote shutdown */),
		};
		assert(!bind(fd, (struct sockaddr *) &sin, sizeof(sin)));
	}
	assert(!listen(fd, SOMAXCONN));

	asm volatile ("" ::: "memory");

	*ready = 1;

	while (!should_stop) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		{
			struct timeval tv = { .tv_sec = 1, };
			if (0 < select(fd + 1, &fds, NULL, NULL, &tv)) {
				struct sockaddr_in sin;
				socklen_t addrlen;
				{
					int newfd = accept(fd, (struct sockaddr *) &sin, &addrlen);
					if (0 < newfd)
						close(newfd);
					printf("close requested\n");
				}
				sig_h(0);
			}
		}
	}

	close(fd);

	pthread_exit(NULL);
}

int main(int argc, char *const *argv)
{
	unsigned short port = 0, num_cores = 0, core_list[MAX_CORE] = { 0 };
	pthread_t remote_stop_th;

	{
		int ready = 0;
		assert(!pthread_create(&remote_stop_th, NULL, remote_stop_thread, &ready));
		while (!ready) usleep(10000);
	}

	{
		int ch;
		while ((ch = getopt(argc, argv, "c:g:l:p:")) != -1) {
			switch (ch) {
			case 'c':
				{
					ssize_t num_comma = 0, num_hyphen = 0;
					{
						size_t i;
						for (i = 0; i < strlen(optarg); i++) {
							switch (optarg[i]) {
							case ',':
								num_comma++;
								break;
							case '-':
								num_hyphen++;
								break;
							}
						}
					}
					if (num_hyphen) {
						assert(num_hyphen == 1);
						assert(!num_comma);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i;
								for (i = 0; i < strlen(optarg); i++) {
									if (m[i] == '-') {
										m[i] = '\0';
										break;
									}
								}
								assert(i != strlen(optarg) - 1 && i != strlen(optarg));
								{
									uint16_t from = atoi(&m[0]), to = atoi(&m[i + 1]);
									assert(from <= to);
									{
										uint16_t j, k;
										for (j = 0, k = from; k <= to; j++, k++)
											core_list[j] = k;
										num_cores = j;
									}
								}
							}
							free(m);
						}
					} else if (num_comma) {
						assert(num_comma + 1 < MAX_CORE);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i, j, k;
								for (i = 0, j = 0, k = 0; i < strlen(optarg) + 1; i++) {
									if (i == strlen(optarg) || m[i] == ',') {
										m[i] = '\0';
										if (j != i)
											core_list[k++] = atoi(&m[j]);
										j = i + 1;
									}
									if (i == strlen(optarg))
										break;
								}
								assert(k);
								num_cores = k;
							}
							free(m);
						}
					} else {
						core_list[0] = atoi(optarg);
						num_cores = 1;
					}
				}
				break;
			case 'g':
				mode = atoi(optarg);
				break;
			case 'l':
				payload_len = atoi(optarg);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			default:
				assert(0);
				break;
			}
		}
	}

	if (!num_cores) {
		printf("please specify cores : -c\n");
		exit(0);
	}

	if (!port) {
		printf("please specify port number : -p\n");
		exit(0);
	}

	printf("start server with %u cores: ", num_cores);
	{
		uint16_t i;
		for (i = 0; i < num_cores; i++)
			printf("%u ", core_list[i]);
	}
	printf("\n");
	printf("listen on port %u\n", port);
	printf("payload len %u\n", payload_len);
	fflush(stdout);

	switch (mode) {
	case 1:
	case 2:
		break;
	default:
		printf("please specify a mode 1 ping-pong 2 burst : -g\n");
		exit(0);
		break;
	}

	{
		int fd;

		assert((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1);
		{
			int v = 1;
			assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)));
		}
		{
			int v = 1;
			assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)));
		}
		{
			int v = 1;
			assert(!setsockopt(fd, SOL_TCP, TCP_NODELAY, &v, sizeof(v)));
		}
		{
			int v = 1;
			assert(!ioctl(fd, FIONBIO, &v));
		}
		{
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_addr.s_addr = htonl(INADDR_ANY),
				.sin_port = htons(port),
			};
			assert(!bind(fd, (struct sockaddr *) &sin, sizeof(sin)));
		}
		assert(!listen(fd, SOMAXCONN));

		signal(SIGINT, sig_h);

		{
			pthread_t *th;
			assert((th = calloc(num_cores, sizeof(pthread_t))) != NULL);
			{
				unsigned short i;
				for (i = 0; i < num_cores; i++)
					assert(!pthread_create(&th[i], NULL, server_thread, (void *)(((unsigned long) fd << 32) | ((unsigned long) core_list[i] & 0xffffffff))));
			}
			while (!should_stop) {
				{
					unsigned short i;
					for (i = 0; i < num_cores; i++) {
						if (monitor[i]) {
							if (monitor[i]->idx)
								monitor[i]->idx = 0;
							else
								monitor[i]->idx = 1;
						}
					}
				}
				{
					unsigned long rx_bytes = 0, rx_cnt = 0, tx_bytes = 0, tx_cnt = 0;
					{
						unsigned short i;
						for (i = 0; i < num_cores; i++) {
							if (monitor[i]) {
								unsigned short idx = (monitor[i]->idx ? 0 : 1);
								if (monitor[i]->counter[idx].rx_cnt || monitor[i]->counter[idx].tx_cnt) {
									printf("[%u] payload: rx %lu Mbps (%lu read), tx %lu Mbps (%lu write)\n",
											i,
											monitor[i]->counter[idx].rx_bytes / 125000UL,
											monitor[i]->counter[idx].rx_cnt,
											monitor[i]->counter[idx].tx_bytes / 125000UL,
											monitor[i]->counter[idx].tx_cnt
									      ); fflush(stdout);
									rx_bytes += monitor[i]->counter[idx].rx_bytes;
									tx_bytes += monitor[i]->counter[idx].tx_bytes;
									rx_cnt += monitor[i]->counter[idx].rx_cnt;
									tx_cnt += monitor[i]->counter[idx].tx_cnt;
								}
								memset(&monitor[i]->counter[idx], 0, sizeof(monitor[i]->counter[idx]));
							}
						}
					}
					printf("paylaod total: rx %lu Mbps (%lu pps), tx %lu Mbps (%lu pps)\n",
							rx_bytes / 125000UL,
							rx_cnt,
							tx_bytes / 125000UL,
							tx_cnt
					      ); fflush(stdout);
				}
				sleep(1);
			}
			{
				unsigned short i;
				for (i = 0; i < num_cores; i++)
					assert(!pthread_join(th[i], NULL));
			}
			free(th);
		}

		close(fd);
	}

	pthread_join(remote_stop_th, NULL);

	printf("done.\n");

	return 0;
}
```

</details>

The following compiles the program above (```program_above.c```) and generates an executable file ```app```.

```
gcc -Werror -Wextra -Wall -O3 program_above.c -lpthread -lnuma -o app
```

Then, the following executes the compiled program ```app```.

```
ulimit -n unlimited; cnt=0; while [ $cnt -le 32 ]; do ./app -p $((10000+$cnt)) -c 0-$(($cnt == 0 ? 0 : $(($cnt-1)))) -g 1 -l 1; cnt=$(($cnt+2)); done
```

- results:

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/multicore/throughput.svg" width="500px">

### 32-core server latency

- client (iip and DPDK)

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 5 -c $(($cnt == 0 ? 1 : $cnt)) -d 1 -l 1 2>&1 | tee -a ./result.txt; cnt=$(($cnt+2)); done
```

- server (iip and DPDK)

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 1 -l 1; cnt=$(($cnt+2)); done
```

- server (Linux)

```
ulimit -n unlimited; cnt=0; while [ $cnt -le 32 ]; do ./app -p 10000 -c 0-31 -g 1 -l 1; cnt=$(($cnt+2)); done
```

- results:

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/multicore/latency.svg" width="500px">

### bulk transfer

- receiver

```
cnt=0; while [ $cnt -le 20 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 2; cnt=$(($cnt+1)); done
```

- sender

```
cnt=0; while [ $cnt -le 20 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 2 -t 5 -c 1 -d 3 -l $((63488+63488*$cnt*32)) 1 2>&1 | tee -a ./result.txt; cnt=$(($cnt+1)); done
```

- note

<details>

<summary>changes made to disable zero-copy transmission on the sender side</summary>

```diff
--- a/main.c
+++ b/main.c
@@ -684,6 +684,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok (max lro pkt size %u)\n", nic_conf[portid].rxmode.max_lro_pkt_size);
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("TX multi-seg: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
@@ -691,6 +692,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX IPv4 checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
```

</details>

<details>

<summary>changes made to disable TSO on the sender side</summary>

```diff
--- a/main.c
+++ b/main.c
@@ -39,7 +39,7 @@
 #include <rte_bus_pci.h>
 #include <rte_thash.h>
 
-#define NUM_RX_DESC (128)
+#define NUM_RX_DESC (2048)
 #define NUM_TX_DESC NUM_RX_DESC
 #define NUM_NETSTACK_PB (8192)
 #define NUM_NETSTACK_TCP_CONN (512)
@@ -705,6 +705,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("TX TCP TSO: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
@@ -712,6 +713,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX UDP checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
```

</details>

<details>

<summary>changes made to disable TSO and checksum offload on the sender side</summary>

```diff
--- a/main.c
+++ b/main.c
@@ -39,7 +39,7 @@
 #include <rte_bus_pci.h>
 #include <rte_thash.h>
 
-#define NUM_RX_DESC (128)
+#define NUM_RX_DESC (2048)
 #define NUM_TX_DESC NUM_RX_DESC
 #define NUM_NETSTACK_PB (8192)
 #define NUM_NETSTACK_TCP_CONN (512)
@@ -669,6 +669,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok (nic feature %lx udp-rss-all %lx)\n", dev_info.flow_type_rss_offloads, RTE_ETH_RSS_TCP);
                                                } else printf("no\n"); /* TODO: software-based RSS */
                                        }
+#if 0
                                        {
                                                printf("RX checksum: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
@@ -676,6 +677,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("RX LRO: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
@@ -691,6 +693,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("TX IPv4 checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
@@ -712,6 +715,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX UDP checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
```

</details>

<details>

<summary>changes made to disable LRO on the receiver side</summary>

```diff
--- a/main.c
+++ b/main.c
@@ -676,6 +676,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("RX LRO: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
@@ -684,6 +685,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok (max lro pkt size %u)\n", nic_conf[portid].rxmode.max_lro_pkt_size);
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX multi-seg: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
```

</details>

<details>

<summary>changes made to disable checksum offload on the receiver side</summary>

```diff
--- a/main.c
+++ b/main.c
@@ -669,6 +669,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok (nic feature %lx udp-rss-all %lx)\n", dev_info.flow_type_rss_offloads, RTE_ETH_RSS_TCP);
                                                } else printf("no\n"); /* TODO: software-based RSS */
                                        }
+#if 0
                                        {
                                                printf("RX checksum: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
@@ -676,6 +677,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("RX LRO: ");
                                                if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_LRO) {
@@ -691,6 +693,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#if 0
                                        {
                                                printf("TX IPv4 checksum: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
@@ -705,6 +708,7 @@ static int __iosub_main(int argc, char *const *argv)
                                                        printf("ok\n");
                                                } else printf("no\n");
                                        }
+#endif
                                        {
                                                printf("TX TCP TSO: ");
                                                if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
```

</details>

- results:

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/bulk/large.svg" width="500px">

## separate threads for networking and app logic

Potentially, there are three CPU core assignment models which we call ***split***, ***merge***, and ***unified***, respectively.

- The split model runs the networking logic and the application logic on two different threads, and dedicates a CPU core to each of the threads.
- The merge model runs the networking logic and the application logic on two different threads similarly to the first model, but executes the two threads on the same CPU core.
- The unified model executes the networking and application logic on the same thread.

The following program instantiates sub threads, besides the threads launched by an I/O subsystem such as DPDK, to execute the application logic implemented in bench-iip for testing the split and merge models.

Please save the following program as ```bench-iip/sub/main.c```.

<details>

<summary>please click here to show the program</summary>

```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define __app_exit	    __o__app_exit
#define __app_should_stop   __o__app_should_stop
#define __app_loop	    __o__app_loop
#define __app_thread_init   __o__app_thread_init
#define __app_init	    __o__app_init

#pragma push_macro("IOSUB_MAIN_C")
#undef IOSUB_MAIN_C
#define IOSUB_MAIN_C pthread.h

static int __iosub_main(int argc, char *const *argv);

#define IIP_MAIN_C "./iip_main.c"

#include "../main.c"

#undef IOSUB_MAIN_C
#pragma pop_macro("IOSUB_MAIN_C")

#undef __app_init
#undef __app_thread_init
#undef __app_loop
#undef __app_should_stop
#undef __app_exit

#undef iip_ops_pkt_alloc
#undef iip_ops_pkt_free
#undef iip_ops_pkt_get_data
#undef iip_ops_pkt_get_len
#undef iip_ops_pkt_set_len
#undef iip_ops_pkt_increment_head
#undef iip_ops_pkt_decrement_tail
#undef iip_ops_pkt_clone
#undef iip_ops_pkt_scatter_gather_chain_append
#undef iip_ops_pkt_scatter_gather_chain_get_next

#undef iip_ops_arp_reply
#undef iip_ops_icmp_reply
#undef iip_ops_tcp_accept
#undef iip_ops_tcp_accepted
#undef iip_ops_tcp_connected
#undef iip_ops_tcp_payload
#undef iip_ops_tcp_acked
#undef iip_ops_tcp_closed
#undef iip_ops_udp_payload

#include <stdatomic.h>
#include <sys/poll.h>
#include <pthread.h>

#define SUB_MAX_CORE (128)
#define NUM_OP_SLOT (512)

enum {
	OP_ARP_REPLY = 1,
	OP_ICMP_REPLY,
	OP_TCP_ACCEPT,
	OP_TCP_ACCEPTED,
	OP_TCP_CONNECTED,
	OP_TCP_PAYLOAD,
	OP_TCP_ACKED,
	OP_TCP_CLOSED,
	OP_UDP_PAYLOAD,
	DO_ARP_REQUEST,
	DO_TCP_SEND,
	DO_TCP_CLOSE,
#if 0
	DO_TCP_RXBUF_CONSUMED,
#endif
	DO_TCP_CONNECT,
	DO_UDP_SEND,
};

#define SUB_READY	(1U << 1)
#define SUB_SHOULD_STOP	(1U << 2)

struct sub_data {
	void *workspace;
	void *opaque_array[5];
	volatile uint16_t flags;
	uint16_t th_id;
	uint16_t core_id;
	pthread_t th;
	uint8_t mac[IIP_CONF_L2ADDR_LEN_MAX];
	uint32_t ip4_be;
	uint32_t op_batch_cnt;
	uint32_t wait_time_ms;
	int pipe_fd[2];
	struct {
		volatile uint16_t head;
		uint16_t cur;
		volatile uint16_t tail;
		uint16_t tail_cache;
		struct {
			uint64_t op;
			uint64_t arg[9];
			uint8_t mac[2][IIP_CONF_L2ADDR_LEN_MAX];
		} slot[NUM_OP_SLOT];
	} opq[2];
};

struct sub_app_global_data {
	uint16_t num_cores;
	uint16_t num_io_threads; /* XXX: this is not great but needed to avoid adding an interface to io subsystems */
	void *app_global_opaque;
	struct sub_data sd[SUB_MAX_CORE];
};

static uint16_t iip_udp_send(void *_mem,
			     uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			     uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			     void *pkt, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_data *sd = (struct sub_data *) opaque_array[4];
	uint16_t c = sd->opq[1].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
		sd->opq[1].tail_cache = atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[1].tail); }
		}
	}
	sd->opq[1].slot[c].op = DO_UDP_SEND;
	sd->opq[1].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[0].slot[c].arg[1] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[0], local_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[1].slot[c].arg[2] = (uint64_t) local_ip4_be;
	sd->opq[1].slot[c].arg[3] = (uint64_t) local_port_be;
	sd->opq[0].slot[c].arg[4] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[1], peer_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[1].slot[c].arg[5] = (uint64_t) peer_ip4_be;
	sd->opq[1].slot[c].arg[6] = (uint64_t) peer_port_be;
	sd->opq[1].slot[c].arg[7] = (uint64_t) pkt;
	sd->opq[1].slot[c].arg[8] = 0; /* opaque */
	c = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[1].head <= sd->opq[1].cur ? sd->opq[1].cur - sd->opq[1].head : NUM_OP_SLOT + sd->opq[1].head - sd->opq[1].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
	}
	return 0; /* XXX: assuming always 0 is returned */
}

static uint16_t iip_tcp_connect(void *_mem,
				uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
				void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_data *sd = (struct sub_data *) opaque_array[4];
	uint16_t c = sd->opq[1].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
		sd->opq[1].tail_cache = atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[1].tail); }
		}
	}
	sd->opq[1].slot[c].op = DO_TCP_CONNECT;
	sd->opq[1].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[0].slot[c].arg[1] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[0], local_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[1].slot[c].arg[2] = (uint64_t) local_ip4_be;
	sd->opq[1].slot[c].arg[3] = (uint64_t) local_port_be;
	sd->opq[0].slot[c].arg[4] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[1], peer_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[1].slot[c].arg[5] = (uint64_t) peer_ip4_be;
	sd->opq[1].slot[c].arg[6] = (uint64_t) peer_port_be;
	sd->opq[1].slot[c].arg[7] = 0; /* opaque */
	c = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[1].head <= sd->opq[1].cur ? sd->opq[1].cur - sd->opq[1].head : NUM_OP_SLOT + sd->opq[1].head - sd->opq[1].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
	}
	return 0; /* XXX: assuming always 0 is returned */
}

static void iip_tcp_rxbuf_consumed(void *_mem, void *_handle, uint16_t cnt, void *opaque)
{
#if 0
	void **opaque_array = (void **) opaque;
	struct sub_data *sd = (struct sub_data *) opaque_array[4];
	uint16_t c = sd->opq[1].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
		sd->opq[1].tail_cache = atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[1].tail); }
		}
	}
	sd->opq[1].slot[c].op = DO_TCP_RXBUF_CONSUMED;
	sd->opq[1].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[1].slot[c].arg[1] = (uint64_t) _handle;
	sd->opq[1].slot[c].arg[2] = (uint64_t) cnt;
	sd->opq[1].slot[c].arg[3] = 0; /* opaque */
	c = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[1].head <= sd->opq[1].cur ? sd->opq[1].cur - sd->opq[1].head : NUM_OP_SLOT + sd->opq[1].head - sd->opq[1].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
	}
#endif
	{
		(void) _mem;
		(void) _handle;
		(void) cnt;
		(void) opaque;
	}
}

static uint16_t iip_tcp_close(void *_mem, void *_handle, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_data *sd = (struct sub_data *) opaque_array[4];
	uint16_t c = sd->opq[1].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
		sd->opq[1].tail_cache = atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[1].tail); }
		}
	}
	sd->opq[1].slot[c].op = DO_TCP_CLOSE;
	sd->opq[1].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[1].slot[c].arg[1] = (uint64_t) _handle;
	sd->opq[1].slot[c].arg[2] = 0; /* opaque */
	sd->opq[1].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[1].head <= sd->opq[1].cur ? sd->opq[1].cur - sd->opq[1].head : NUM_OP_SLOT + sd->opq[1].head - sd->opq[1].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
	}
	return 0; /* XXX: assuming always 0 is returned */
}

static uint16_t iip_tcp_send(void *_mem, void *_handle, void *pkt, uint16_t tcp_flags, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_data *sd = (struct sub_data *) opaque_array[4];
	uint16_t c = sd->opq[1].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
		sd->opq[1].tail_cache = atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[1].tail); }
		}
	}
	sd->opq[1].slot[c].op = DO_TCP_SEND;
	sd->opq[1].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[1].slot[c].arg[1] = (uint64_t) _handle;
	sd->opq[1].slot[c].arg[2] = (uint64_t) pkt;
	sd->opq[1].slot[c].arg[3] = (uint64_t) tcp_flags;
	sd->opq[1].slot[c].arg[4] = 0; /* opaque */
	sd->opq[1].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[1].head <= sd->opq[1].cur ? sd->opq[1].cur - sd->opq[1].head : NUM_OP_SLOT + sd->opq[1].head - sd->opq[1].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
	}
	return 0; /* XXX: assuming always 0 is returned */
}

static void iip_arp_request(void *_mem,
			    uint8_t local_mac[],
			    uint32_t local_ip4_be,
			    uint32_t target_ip4_be,
			    void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_data *sd = (struct sub_data *) opaque_array[4];
	uint16_t c = sd->opq[1].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
		sd->opq[1].tail_cache = atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[1].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[1].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[1].tail); }
		}
	}
	sd->opq[1].slot[c].op = DO_ARP_REQUEST;
	sd->opq[1].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[0].slot[c].arg[1] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[0], local_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[1].slot[c].arg[2] = (uint64_t) local_ip4_be;
	sd->opq[1].slot[c].arg[3] = (uint64_t) target_ip4_be;
	sd->opq[1].slot[c].arg[4] = 0; /* opaque */
	sd->opq[1].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[1].head <= sd->opq[1].cur ? sd->opq[1].cur - sd->opq[1].head : NUM_OP_SLOT + sd->opq[1].head - sd->opq[1].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
	}
}

static void *app_sub_thread(void *data)
{
	struct sub_data *sd = (struct sub_data *) data;
	while (!(sd->flags & SUB_READY)) { }
	IIP_OPS_DEBUG_PRINTF("start sub thread %u on core %u\n", sd->th_id, sd->core_id);
	{
		sd->opaque_array[1] = (void *) ((struct sub_app_global_data *) sd->opaque_array[3])->app_global_opaque;
		sd->opaque_array[2] = __o__app_thread_init(NULL, sd->th_id, sd->opaque_array);
	}
	if (sd->wait_time_ms) {
		struct sched_param sp;
		sp.sched_priority = 1;
		__iip_assert(!pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp));
	}
	while (!(sd->flags & SUB_SHOULD_STOP)) {
		uint32_t next_us = sd->wait_time_ms * 1000;
		{
			uint16_t h = atomic_load_explicit(&sd->opq[0].head, memory_order_acquire), t = sd->opq[0].tail;
			while (h != t) {
				switch (sd->opq[0].slot[t].op) {
				case OP_ARP_REPLY:
					__o_iip_ops_arp_reply((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[1], sd->opaque_array);
					break;
				case OP_ICMP_REPLY:
					__o_iip_ops_arp_reply((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[1], sd->opaque_array);
					break;
				case OP_TCP_ACCEPT:
					sd->opq[0].slot[t].op = (uint64_t) __o_iip_ops_tcp_accept((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[1], sd->opaque_array);
					break;
				case OP_TCP_ACCEPTED:
					sd->opq[0].slot[t].op = (uint64_t) __o_iip_ops_tcp_accepted((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2], (void *) sd->opq[0].slot[t].arg[3]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[2], sd->opaque_array);
					break;
				case OP_TCP_CONNECTED:
					sd->opq[0].slot[t].op = (uint64_t) __o_iip_ops_tcp_connected((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2], (void *) sd->opq[0].slot[t].arg[3]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[2], sd->opaque_array);
					break;
				case OP_TCP_PAYLOAD:
					__o_iip_ops_tcp_payload((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2], (void *) sd->opq[0].slot[t].arg[3], sd->opq[0].slot[t].arg[4], sd->opq[0].slot[t].arg[5], (void *) sd->opq[0].slot[t].arg[6]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[2], sd->opaque_array);
					break;
				case OP_TCP_ACKED:
					__o_iip_ops_tcp_acked((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2], (void *) sd->opq[0].slot[t].arg[3], (void *) sd->opq[0].slot[t].arg[4]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[2], sd->opaque_array);
					break;
				case OP_TCP_CLOSED:
					__o_iip_ops_tcp_closed((void *) sd->opq[0].slot[t].arg[0], (void *) sd->opq[0].slot[t].mac[0], sd->opq[0].slot[t].arg[2], sd->opq[0].slot[t].arg[3], (void *) sd->opq[0].slot[t].mac[1], sd->opq[0].slot[t].arg[5], sd->opq[0].slot[t].arg[6], (void *) sd->opq[0].slot[t].arg[7], (void *) sd->opq[0].slot[t].arg[8]);
					break;
				case OP_UDP_PAYLOAD:
					__o_iip_ops_udp_payload((void *) sd->opq[0].slot[t].arg[0], (void *) (void *) sd->opq[0].slot[t].arg[1], (void *) sd->opq[0].slot[t].arg[2]);
					iip_ops_pkt_free((void *) sd->opq[0].slot[t].arg[1], sd->opaque_array);
					break;
				default:
					assert(0);
					break;
				}
				t = (t == NUM_OP_SLOT - 1 ? 0 : t + 1);
			}
			if (t != sd->opq[0].tail) {
				__asm__ volatile("" ::: "memory");
				atomic_store_explicit(&sd->opq[0].tail, t, memory_order_release);
			}
			if (sd->opq[1].head != sd->opq[1].cur) {
				__asm__ volatile("" ::: "memory");
				atomic_store_explicit(&sd->opq[1].head, sd->opq[1].cur, memory_order_release);
			}
		}
		{
			uint32_t _next_us;
			__o__app_loop(sd->workspace, sd->mac, sd->ip4_be, &_next_us, sd->opaque_array);
			if (_next_us < next_us)
				next_us = _next_us;
		}
		if (next_us) {
			struct pollfd pollfd = {
				.fd = sd->pipe_fd[0],
				.events = POLLIN,
			};
			assert(poll(&pollfd, 1, (next_us / 1000)) != -1);
			if (pollfd.revents & POLLIN) {
				char b;
				__iip_assert(read(sd->pipe_fd[0], &b, 1) == 1);
			}
		}
	}
	pthread_exit(NULL);
}

static void iip_ops_arp_reply(void *_mem, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_ARP_REPLY;
	sd->opq[0].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[1]);
	sd->opq[0].slot[c].arg[2] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[0].head <= sd->opq[0].cur ? sd->opq[0].cur - sd->opq[0].head : NUM_OP_SLOT + sd->opq[0].head - sd->opq[0].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
		if (sd->wait_time_ms) {
			char b = 0;
			__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
		}
	}
}

static void iip_ops_icmp_reply(void *_mem, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_ICMP_REPLY;
	sd->opq[0].slot[c].arg[0] = (uint64_t) _mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[1]);
	sd->opq[0].slot[c].arg[2] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[0].head <= sd->opq[0].cur ? sd->opq[0].cur - sd->opq[0].head : NUM_OP_SLOT + sd->opq[0].head - sd->opq[0].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
		if (sd->wait_time_ms) {
			char b = 0;
			__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
		}
	}
}

static uint8_t iip_ops_tcp_accept(void *mem, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_TCP_ACCEPT;
	sd->opq[0].slot[c].arg[0] = (uint64_t) mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[1]);
	sd->opq[0].slot[c].arg[2] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	__asm__ volatile("" ::: "memory");
	atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
	if (sd->wait_time_ms) {
		char b = 0;
		__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
	}
	while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) != atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { } /* wait until app sets result */
	return (uint8_t) sd->opq[0].slot[c].op;
}

static void *iip_ops_tcp_accepted(void *mem, void *handle, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_TCP_ACCEPTED;
	sd->opq[0].slot[c].arg[0] = (uint64_t) mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) handle;
	sd->opq[0].slot[c].arg[2] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[2]);
	sd->opq[0].slot[c].arg[3] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	__asm__ volatile("" ::: "memory");
	atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
	if (sd->wait_time_ms) {
		char b = 0;
		__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
	}
	while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) != atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { } /* wait until app sets result */
	return (void *) sd->opq[0].slot[c].op;
}

static void *iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_TCP_CONNECTED;
	sd->opq[0].slot[c].arg[0] = (uint64_t) mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) handle;
	sd->opq[0].slot[c].arg[2] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[2]);
	sd->opq[0].slot[c].arg[3] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	__asm__ volatile("" ::: "memory");
	atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
	if (sd->wait_time_ms) {
		char b = 0;
		__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
	}
	while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) != atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { } /* wait until app sets result */
	return (void *) sd->opq[0].slot[c].op;
}

static void iip_ops_tcp_payload(void *mem, void *handle, void *m,
				void *tcp_opaque, uint16_t head_off, uint16_t tail_off,
				void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_TCP_PAYLOAD;
	sd->opq[0].slot[c].arg[0] = (uint64_t) mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) handle;
	sd->opq[0].slot[c].arg[2] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[2]);
	sd->opq[0].slot[c].arg[3] = (uint64_t) tcp_opaque;
	sd->opq[0].slot[c].arg[4] = (uint64_t) head_off;
	sd->opq[0].slot[c].arg[5] = (uint64_t) tail_off;
	sd->opq[0].slot[c].arg[6] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[0].head <= sd->opq[0].cur ? sd->opq[0].cur - sd->opq[0].head : NUM_OP_SLOT + sd->opq[0].head - sd->opq[0].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
		if (sd->wait_time_ms) {
			char b = 0;
			__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
		}
	}
	__o_iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);
}

static void iip_ops_tcp_acked(void *mem,
			      void *handle,
			      void *m,
			      void *tcp_opaque,
			      void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_TCP_ACKED;
	sd->opq[0].slot[c].arg[0] = (uint64_t) mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) handle;
	sd->opq[0].slot[c].arg[2] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[2]);
	sd->opq[0].slot[c].arg[3] = (uint64_t) tcp_opaque;
	sd->opq[0].slot[c].arg[4] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[0].head <= sd->opq[0].cur ? sd->opq[0].cur - sd->opq[0].head : NUM_OP_SLOT + sd->opq[0].head - sd->opq[0].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
		if (sd->wait_time_ms) {
			char b = 0;
			__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
		}
	}
}

static void iip_ops_tcp_closed(void *handle,
			       uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			       uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			       void *tcp_opaque, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((peer_ip4_be + peer_port_be + local_port_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_TCP_CLOSED;
	sd->opq[0].slot[c].arg[0] = (uint64_t) handle;
	sd->opq[0].slot[c].arg[1] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[0], local_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[0].slot[c].arg[2] = local_ip4_be;
	sd->opq[0].slot[c].arg[3] = local_port_be;
	sd->opq[0].slot[c].arg[4] = 0;
	__iip_memcpy(sd->opq[0].slot[c].mac[1], peer_mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
	sd->opq[0].slot[c].arg[5] = peer_ip4_be;
	sd->opq[0].slot[c].arg[6] = peer_port_be;
	sd->opq[0].slot[c].arg[7] = (uint64_t) tcp_opaque;
	sd->opq[0].slot[c].arg[8] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[0].head <= sd->opq[0].cur ? sd->opq[0].cur - sd->opq[0].head : NUM_OP_SLOT + sd->opq[0].head - sd->opq[0].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
		if (sd->wait_time_ms) {
			char b = 0;
			__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
		}
	}
}

static void iip_ops_udp_payload(void *mem, void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	struct sub_data *sd = &sa->sd[((PB_IP4(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->src_be + PB_TCP(iip_ops_pkt_get_data(m, opaque))->dst_be) % (sa->num_cores / sa->num_io_threads)) * (sa->num_cores / sa->num_io_threads) + core_id];
	uint16_t c = sd->opq[0].cur;
	if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
		sd->opq[0].tail_cache = atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire);
		if ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == sd->opq[0].tail_cache) {
			__asm__ volatile ("" ::: "memory");
			atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
			while ((c == NUM_OP_SLOT - 1 ? 0 : c + 1) == atomic_load_explicit(&sd->opq[0].tail, memory_order_acquire)) { IIP_OPS_DEBUG_PRINTF("%u waiting %u %u\n", __LINE__, c, sd->opq[0].tail); }
		}
	}
	sd->opq[0].slot[c].op = OP_UDP_PAYLOAD;
	sd->opq[0].slot[c].arg[0] = (uint64_t) mem;
	sd->opq[0].slot[c].arg[1] = (uint64_t) iip_ops_pkt_clone(m, opaque);
	__iip_assert(sd->opq[0].slot[c].arg[1]);
	sd->opq[0].slot[c].arg[2] = (uint64_t) sd->opaque_array;
	sd->opq[0].cur = (c == NUM_OP_SLOT - 1 ? 0 : c + 1);
	if (sd->op_batch_cnt <= (uint32_t)(sd->opq[0].head <= sd->opq[0].cur ? sd->opq[0].cur - sd->opq[0].head : NUM_OP_SLOT + sd->opq[0].head - sd->opq[0].cur)) {
		__asm__ volatile ("" ::: "memory");
		atomic_store_explicit(&sd->opq[0].head, sd->opq[0].cur, memory_order_release);
		if (sd->wait_time_ms) {
			char b = 0;
			__iip_assert(write(sd->pipe_fd[1], &b, 1) == 1);
		}
	}
}

static void __app_loop(void *mem, uint8_t mac[], uint32_t ip4_be, uint32_t *next_us, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = opaque_array[1];
	uint16_t core_id = (uint16_t)(uintptr_t) opaque_array[2];
	if (!(sa->sd[core_id].flags & SUB_READY)) {
		uint16_t i;
		for (i = 0; i < sa->num_cores; i++) {
			if (core_id == i % sa->num_io_threads) {
				__iip_memcpy(sa->sd[i].mac, mac, IIP_CONF_L2ADDR_LEN_MAX /* FIXME */);
				sa->sd[i].ip4_be = ip4_be;
			}
		}
		__asm__ volatile("" ::: "memory");
		for (i = 0; i < sa->num_cores; i++) {
			if (core_id == i % sa->num_io_threads)
				sa->sd[i].flags |= SUB_READY;
		}
	}
	{
		uint16_t i;
		for (i = 0; i < sa->num_cores; i++) {
			if (core_id == i % sa->num_io_threads) {
				uint16_t h = atomic_load_explicit(&sa->sd[i].opq[1].head, memory_order_acquire), t = sa->sd[i].opq[1].tail;
				while (h != t) {
					switch (sa->sd[i].opq[1].slot[t].op) {
					case DO_ARP_REQUEST:
						__o_iip_arp_request((void *) sa->sd[i].opq[1].slot[t].arg[0], (void *) sa->sd[i].opq[1].slot[t].mac[0], sa->sd[i].opq[1].slot[t].arg[2], sa->sd[i].opq[1].slot[t].arg[3], opaque);
						break;
					case DO_TCP_SEND:
						sa->sd[i].opq[1].slot[t].op = __o_iip_tcp_send((void *) sa->sd[i].opq[1].slot[t].arg[0], (void *) sa->sd[i].opq[1].slot[t].arg[1], (void *) sa->sd[i].opq[1].slot[t].arg[2], sa->sd[i].opq[1].slot[t].arg[3], opaque);
						break;
					case DO_TCP_CLOSE:
						sa->sd[i].opq[1].slot[t].op = __o_iip_tcp_close((void *) sa->sd[i].opq[1].slot[t].arg[0], (void *) sa->sd[i].opq[1].slot[t].arg[1], opaque);
						break;
#if 0
					case DO_TCP_RXBUF_CONSUMED:
						__o_iip_tcp_rxbuf_consumed((void *) sa->sd[i].opq[1].slot[t].arg[0], (void *) sa->sd[i].opq[1].slot[t].arg[1], sa->sd[i].opq[1].slot[t].arg[2], opaque);
						break;
#endif
					case DO_TCP_CONNECT:
						sa->sd[i].opq[1].slot[t].op = __o_iip_tcp_connect((void *) sa->sd[i].opq[1].slot[t].arg[0], (void *) sa->sd[i].opq[1].slot[t].mac[0], sa->sd[i].opq[1].slot[t].arg[2], sa->sd[i].opq[1].slot[t].arg[3], (void *) sa->sd[i].opq[1].slot[t].mac[1], sa->sd[i].opq[1].slot[t].arg[5], sa->sd[i].opq[1].slot[t].arg[6], opaque);
						break;
					case DO_UDP_SEND:
						sa->sd[i].opq[1].slot[t].op = __o_iip_udp_send((void *) sa->sd[i].opq[1].slot[t].arg[0], (void *) sa->sd[i].opq[1].slot[t].mac[0], sa->sd[i].opq[1].slot[t].arg[2], sa->sd[i].opq[1].slot[t].arg[3], (void *) sa->sd[i].opq[1].slot[t].mac[1], sa->sd[i].opq[1].slot[t].arg[5], sa->sd[i].opq[1].slot[t].arg[6], (void *) sa->sd[i].opq[1].slot[t].arg[7], opaque);
						break;
					default:
						assert(0);
						break;
					}
					t = (t == NUM_OP_SLOT - 1 ? 0 : t + 1);
				}
				if (t != sa->sd[i].opq[1].tail) {
					__asm__ volatile("" ::: "memory");
					atomic_store_explicit(&sa->sd[i].opq[1].tail, t, memory_order_release);
				}
				if (sa->sd[i].opq[0].head != sa->sd[i].opq[0].cur) {
					__asm__ volatile("" ::: "memory");
					atomic_store_explicit(&sa->sd[i].opq[0].head, sa->sd[i].opq[0].cur, memory_order_release);
					if (sa->sd[i].wait_time_ms) {
						char b = 0;
						__iip_assert(write(sa->sd[i].pipe_fd[1], &b, 1) == 1);
					}
				}
			}
		}
	}
	*next_us = 100;
	{ /* unused */
		(void) mem;
	}
}

static void __app_exit(void *app_global_opaque)
{
	if (app_global_opaque) {
		struct sub_app_global_data *sa = (struct sub_app_global_data *) app_global_opaque;
		{
			uint16_t i;
			for (i = 0; i < sa->num_cores; i++)
				sa->sd[i].flags |= SUB_SHOULD_STOP;
		}
		{
			uint16_t i;
			for (i = 0; i < sa->num_cores; i++)
				__iip_assert(!pthread_join(sa->sd[i].th, NULL));
		}
		if (sa->app_global_opaque)
			__o__app_exit(sa->app_global_opaque);
		mem_free(app_global_opaque, sizeof(struct sub_app_global_data));
	}
}

static uint8_t __app_should_stop(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = (struct sub_app_global_data *) opaque_array[1];
	if (sa->sd[0].opaque_array[2])
		return __o__app_should_stop(sa->sd[0].opaque_array);
	else
		return 0;
}

static void *__app_thread_init(void *workspace, uint16_t core_id, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct sub_app_global_data *sa = (struct sub_app_global_data *) opaque_array[1];
	{
		uint16_t i;
		for (i = 0; i < sa->num_cores; i++) {
			if (core_id == i % sa->num_io_threads) {
				sa->sd[i].workspace = workspace;
				sa->sd[i].opaque_array[0] = opaque_array[0]; /* FIXME: this assumes that io subsystems pay attention to thread-safety while they do not */
			}
		}
	}
	return (void *)((uintptr_t) core_id);
}

static void *__app_init(int argc, char *const *argv)
{
	struct sub_app_global_data *sa = (struct sub_app_global_data *) mem_alloc_local(sizeof(struct sub_app_global_data));
	memset(sa, 0, sizeof(struct sub_app_global_data));
	sa->app_global_opaque = __o__app_init(argc, argv);
	{ /* parse arguments */
		int ch;
		while ((ch = getopt(argc, argv, "b:c:e:n:")) != -1) {
			switch (ch) {
			case 'b':
				sa->sd[0].op_batch_cnt = atoi(optarg);
				break;
			case 'c':
				{
					ssize_t num_comma = 0, num_hyphen = 0;
					{
						size_t i;
						for (i = 0; i < strlen(optarg); i++) {
							switch (optarg[i]) {
								case ',':
									num_comma++;
									break;
								case '-':
									num_hyphen++;
									break;
							}
						}
					}
					if (num_hyphen) {
						assert(num_hyphen == 1);
						assert(!num_comma);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i;
								for (i = 0; i < strlen(optarg); i++) {
									if (m[i] == '-') {
										m[i] = '\0';
										break;
									}
								}
								assert(i != strlen(optarg) - 1 && i != strlen(optarg));
								{
									uint16_t from = atoi(&m[0]), to = atoi(&m[i + 1]);
									assert(from <= to);
									{
										uint16_t j, k;
										for (j = 0, k = from; k <= to; j++, k++)
											sa->sd[j].core_id = k;
										sa->num_cores = j;
									}
								}
							}
							free(m);
						}
					} else if (num_comma) {
						assert(num_comma + 1 < SUB_MAX_CORE);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i, j, k;
								for (i = 0, j = 0, k = 0; i < strlen(optarg) + 1; i++) {
									if (i == strlen(optarg) || m[i] == ',') {
										m[i] = '\0';
										if (j != i)
											sa->sd[k++].core_id = atoi(&m[j]);
										j = i + 1;
									}
									if (i == strlen(optarg))
										break;
								}
								assert(k);
								sa->num_cores = k;
							}
							free(m);
						}
					} else {
						sa->sd[0].core_id = atoi(optarg);
						sa->num_cores = 1;
					}
				}
				break;
			case 'e':
				sa->sd[0].wait_time_ms = atoi(optarg);
				break;
			case 'n':
				sa->num_io_threads = atoi(optarg);
				break;
			default:
				assert(0);
				break;
			}
		}
	}
	__iip_assert(sa->num_cores);
	__iip_assert(sa->num_io_threads);
	__iip_assert(sa->num_io_threads <= sa->num_cores);
	__iip_assert(sa->sd[0].op_batch_cnt);
	{
		uint16_t i;
		for (i = 0; i < sa->num_cores; i++) {
			sa->sd[i].th_id = i;
			sa->sd[i].opaque_array[3] = (void *) sa;
			sa->sd[i].opaque_array[4] = (void *) &sa->sd[i];
			sa->sd[i].op_batch_cnt = sa->sd[0].op_batch_cnt;
			sa->sd[i].wait_time_ms = sa->sd[0].wait_time_ms;
			if (sa->sd[i].wait_time_ms)
				__iip_assert(!pipe(sa->sd[i].pipe_fd));
			__iip_assert(!pthread_create(&sa->sd[i].th, NULL, app_sub_thread, &sa->sd[i]));
			{
				cpu_set_t cs;
				CPU_ZERO(&cs);
				CPU_SET(sa->sd[i].core_id, &cs);
				__iip_assert(!pthread_setaffinity_np(sa->sd[i].th, sizeof(cs), &cs));
			}
		}
	}
	return sa;
}

#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S
```

</details>

Please save the following program as ```bench-iip/sub/iip_main.c```.

<details>

<summary>please click here to show the program</summary>

```c
#define iip_udp_send		__o_iip_udp_send
#define iip_tcp_connect		__o_iip_tcp_connect
#define iip_tcp_rxbuf_consumed	__o_iip_tcp_rxbuf_consumed
#define iip_tcp_close		__o_iip_tcp_close
#define iip_tcp_send		__o_iip_tcp_send
#define iip_arp_request		__o_iip_arp_request

#include "../iip/main.c"

#undef iip_udp_send
#undef iip_tcp_connect
#undef iip_tcp_rxbuf_consumed
#undef iip_tcp_close
#undef iip_tcp_send
#undef iip_arp_request

static uint16_t iip_udp_send(void *_mem,
			     uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			     uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			     void *pkt, void *opaque);
static uint16_t iip_tcp_connect(void *_mem,
				uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
				uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
				void *opaque);
static void iip_tcp_rxbuf_consumed(void *_mem, void *_handle, uint16_t cnt, void *opaque);
static uint16_t iip_tcp_close(void *_mem, void *_handle, void *opaque);
static uint16_t iip_tcp_send(void *_mem, void *_handle, void *pkt, uint16_t tcp_flags, void *opaque);
static void iip_arp_request(void *_mem,
			    uint8_t local_mac[],
			    uint32_t local_ip4_be,
			    uint32_t target_ip4_be,
			    void *opaque);

#define iip_ops_arp_reply			    __o_iip_ops_arp_reply
#define iip_ops_icmp_reply	    		    __o_iip_ops_icmp_reply
#define iip_ops_tcp_accept	    		    __o_iip_ops_tcp_accept
#define iip_ops_tcp_accepted	    		    __o_iip_ops_tcp_accepted
#define iip_ops_tcp_connected	    		    __o_iip_ops_tcp_connected
#define iip_ops_tcp_payload	    		    __o_iip_ops_tcp_payload
#define iip_ops_tcp_acked	    		    __o_iip_ops_tcp_acked
#define iip_ops_tcp_closed	    		    __o_iip_ops_tcp_closed
#define iip_ops_udp_payload	    		    __o_iip_ops_udp_payload
```

</details>

In ```bench-iip/sub```, please type the following command to generate a file ```bench-iip/sub/a.out```.

```
IOSUB_DIR=../iip-dpdk make -f ../Makefile
```

The generated file can be executed by the following commands.

```
sudo LD_LIBRARY_PATH=../iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 1 -l 1 -v 1 -- -c 1 -n 1
```

The specification in the last section ```-c 1 -n 1``` means the sub thread uses CPU core 1 (```-c 1```) to execute the application logic, and tells that there is 1 I/O (DPDK) thread (```-n 1```); the number of I/O (DPDK) thread is specified by ```-l 0``` in the first section.

Note: for this thread separation program and particularly for request-response workloads, the following change in ```iip/main.c``` (e423db4bee7c75d028a5f5ae0cb3a4a249caa940) omits the code to immediately transmit an ack packet for received data, and leads to better performance; This change usually does not imporove performance for bulk transfer workloads.

<details>

<summary>please click here to show the change</summary>

```diff
--- a/main.c
+++ b/main.c
@@ -3242,10 +3242,12 @@ static uint16_t iip_run(void *_mem, uint8_t mac[], uint32_t ip4_be, void *pkt[],
                                                                _next_us = _next_us_tmp;
                                                }
                                        }
+#if 0
                                        if (!conn->head[3][0]) {
                                                if ((__iip_ntohl(conn->ack_seq_be) != conn->ack_seq_sent)) /* we got payload, but ack is not pushed by the app */
                                                        __iip_tcp_push(s, conn, NULL, 0, 1, 0, 0, 0, NULL, opaque);
                                        }
+#endif
                                        if (conn->do_ack_cnt) { /* push ack telling rx misses */
                                                struct pb *queue[2] = { 0 };
                                                if (conn->sack_ok && conn->head[4][1]) {
```

</details>

- The command for the benchmark client.

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-$(($cnt == 0 ? 0 : $(($cnt-1)))) --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 5 -c 1 -d 1 -l 1 2>&1 | tee -a ./result.txt; cnt=$(($cnt+2)); done
```

- The command for the benchmark server with the split model.

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./sub/a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 1 -l 1 -- -b 1 -c 2 -n 1; cnt=$(($cnt+2)); done
```

- The command for the benchmark server with the merge model.

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./sub/a.out -n 2 -l 0-1 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 1 -l 1 -- -b 32 -c 0-1 -n 2 -e 100; cnt=$(($cnt+2)); done
```

- The command for the benchmark server with the unified model.

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-1 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 1 -l 1; cnt=$(($cnt+2)); done
```

- results:

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/multicore/models.svg" width="500px">

## performance numbers of other TCP/IP stacks

We show rough performance numbers of other TCP/IP stacks.

**CAUTION: Please note that it is impossible to conduct a fair comparison among TCP/IP stacks having different implementations, properties, and features. What we show here is an apples-to-oranges comparison, in other words, the results shown here do not indicate the superiority of the TCP/IP stack implementations.**

We run benchmarks with the following TCP/IP stack implementations.

- Linux
- lwIP: [paper](https://www.usenix.org/conference/mobisys2003/full-tcpip-8-bit-architectures), [web page](https://www.nongnu.org/lwip)
- Seastar: [web page](https://seastar.io/), [GitHub](https://github.com/scylladb/seastar)
- F-Stack: [web page](https://www.f-stack.org/), [GitHub](https://github.com/F-Stack/f-stack)
- TAS: [paper](https://dl.acm.org/doi/10.1145/3302424.3303985), [GitHub](https://github.com/tcp-acceleration-service/tas)
- Caladan: [paper](https://www.usenix.org/conference/osdi20/presentation/fried), [GitHub](https://github.com/shenango/caladan)

We run a simple TCP ping-pong workload that exchanges a 1-byte TCP message; for the benchmark server programs, we use example programs in the publicly available repositories of the TCP/IP stack implementations, and we use the bench-iip program as the client.

We use the same machines [described above](#machines); one machine is for the server, and the other machine runs the client that is the bench-iip program.

The server and client programs communicate over the 100 Gbps Mellanox NICs.

### 1 CPU core server

***client (iip)***

- bench-iip: 4e98b9af786299ec44f79b2bf67c046a301075bd
- iip: 0da3100f108f786d923e41acd84b6614082a72be
- iip-dpdk: 9fd10fd9410dbc43ab487784f4cb72300199354b
- Linux kernel 6.2 (Ubuntu 22.04)

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 0 -c 1 -d 1 -l 1
```

***Linux setup***

- Linux kernel 6.2 (Ubuntu 22.04)
- We use the same server implementation shown [above](#multi-core-server-performance).

command to launch the benchmark server

```
./app -c 0 -g 1 -l 1 -p 10000
```

***lwIP setup***

- https://github.com/yasukata/tinyhttpd-lwip-dpdk
- a3e1ea3d3917554573024483fb159b73e8bc3aa5
- Linux kernel 6.2 (Ubuntu 22.04)

<details>

<summary>please click here to see changes made for this test</summary>

We change the program to always reply "A".

```diff
--- a/main.c
+++ b/main.c
@@ -132,13 +132,11 @@ static err_t tcp_recv_handler(void *arg, struct tcp_pcb *tpcb,
        if (!arg) { /* server mode */
                char buf[4] = { 0 };
                pbuf_copy_partial(p, buf, 3, 0);
-               if (!strncmp(buf, "GET", 3)) {
                        io_stat[0]++;
                        io_stat[2] += httpdatalen;
                        assert(tcp_sndbuf(tpcb) >= httpdatalen);
                        assert(tcp_write(tpcb, httpbuf, httpdatalen, TCP_WRITE_FLAG_COPY) == ERR_OK);
                        assert(tcp_output(tpcb) == ERR_OK);
-               }
        } else { /* client mode */
                struct http_response *r = (struct http_response *) arg;
                assert(p->tot_len < (sizeof(r->buf) - r->cur));
@@ -385,7 +383,7 @@ int main(int argc, char *const *argv)
                        assert((content = (char *) malloc(content_len + 1)) != NULL);
                        memset(content, 'A', content_len);
                        content[content_len] = '\0';
-                       httpdatalen = snprintf(httpbuf, buflen, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nConnection: keep-alive\r\n\r\n%s", content_len, content);
+                       httpdatalen = snprintf(httpbuf, buflen, "A");
                        free(content);
                        printf("http data length: %lu bytes\n", httpdatalen);
                }
```

</details>

command to launch the benchmark server

```
sudo LD_LIBRARY_PATH=./dpdk/install/lib/x86_64-linux-gnu ./app -l 0 --proc-type=primary --file-prefix=pmd1 --allow=0000:17:00.0 -- -a 10.100.0.20 -g 10.100.0.10 -m 255.255.255.0 -l 1 -p 10000
```

***Seastar setup***

- https://github.com/scylladb/seastar.git
- 10b7d604d1f5037a733879d8d171d4405faebbe9
- Linux kernel 6.2 (Ubuntu 22.04)

<details>

<summary>please click here to see changes made for this test</summary>

A build-relevant file is changed to involve the mlx5 driver.

```diff
--- a/cmake/Finddpdk.cmake
+++ b/cmake/Finddpdk.cmake
@@ -25,6 +25,7 @@ find_path (dpdk_INCLUDE_DIR
   PATH_SUFFIXES dpdk)
 
 find_library (dpdk_PMD_VMXNET3_UIO_LIBRARY rte_pmd_vmxnet3_uio)
+find_library (dpdk_PMD_MLX5_LIBRARY rte_pmd_mlx5)
 find_library (dpdk_PMD_I40E_LIBRARY rte_pmd_i40e)
 find_library (dpdk_PMD_IXGBE_LIBRARY rte_pmd_ixgbe)
 find_library (dpdk_PMD_E1000_LIBRARY rte_pmd_e1000)
@@ -58,6 +59,7 @@ include (FindPackageHandleStandardArgs)
 set (dpdk_REQUIRED
   dpdk_INCLUDE_DIR
   dpdk_PMD_VMXNET3_UIO_LIBRARY
+  dpdk_PMD_MLX5_LIBRARY
   dpdk_PMD_I40E_LIBRARY
   dpdk_PMD_IXGBE_LIBRARY
   dpdk_PMD_E1000_LIBRARY
@@ -113,6 +115,7 @@ if (dpdk_FOUND AND NOT (TARGET dpdk::dpdk))
     ${dpdk_PMD_ENA_LIBRARY}
     ${dpdk_PMD_ENIC_LIBRARY}
     ${dpdk_PMD_QEDE_LIBRARY}
+       ${dpdk_PMD_MLX5_LIBRARY}
     ${dpdk_PMD_I40E_LIBRARY}
     ${dpdk_PMD_IXGBE_LIBRARY}
     ${dpdk_PMD_NFP_LIBRARY}
@@ -146,6 +149,17 @@ if (dpdk_FOUND AND NOT (TARGET dpdk::dpdk))
       IMPORTED_LOCATION ${dpdk_PMD_VMXNET3_UIO_LIBRARY}
       INTERFACE_INCLUDE_DIRECTORIES ${dpdk_INCLUDE_DIR})
 
+  #
+  # pmd_mlx5
+  #
+
+  add_library (dpdk::pmd_mlx5 UNKNOWN IMPORTED)
+
+  set_target_properties (dpdk::pmd_mlx5
+    PROPERTIES
+      IMPORTED_LOCATION ${dpdk_PMD_MLX5_LIBRARY}
+      INTERFACE_INCLUDE_DIRECTORIES ${dpdk_INCLUDE_DIR})
+
   #
   # pmd_i40e
   #
@@ -468,6 +482,7 @@ if (dpdk_FOUND AND NOT (TARGET dpdk::dpdk))
     dpdk::pmd_ena
     dpdk::pmd_enic
     dpdk::pmd_qede
+    dpdk::pmd_mlx5
     dpdk::pmd_i40e
     dpdk::pmd_ixgbe
     dpdk::pmd_nfp
```

We modify the memcached application to use it as a simple TCP ping-pong server; after the change, the server always return "A" to a TCP message without running the memcached-specific event handler.

```diff
--- a/apps/memcached/memcache.cc
+++ b/apps/memcached/memcache.cc
@@ -1042,6 +1042,13 @@ class ascii_protocol {
     }
 
     future<> handle(input_stream<char>& in, output_stream<char>& out) {
+               return in.read().then([this, &out] (temporary_buffer<char> buf) -> future<> {
+                               if (!buf.empty())
+                                       return out.write("A");
+                               else
+                                       return make_ready_future<>();
+               });
+
         _parser.init();
         return in.consume(_parser).then([this, &out] () -> future<> {
             switch (_parser._state) {
```

In the file ```build/release/build.ninja```, ```-libverbs -lmlx5 -lmnl``` has to be added to ```LINK_LIBRARIES``` like as follows.

```
#############################################
# Link the executable apps/memcached/memcached

build apps/memcached/memcached: CXX_EXECUTABLE_LINKER__app_memcached_RelWithDebInfo apps/memcached/CMakeFiles/app_memcached.dir/memcache.cc.o | libseastar.a /usr/lib/x86_64-linux-gnu/libboost_program_options.so /usr/lib/x86_64-linux-gnu/libboost_thread.so /usr/lib/x86_64-linux-gnu/libboost_chrono.so /usr/lib/x86_64-linux-gnu/libboost_date_time.so /usr/lib/x86_64-linux-gnu/libboost_atomic.so /usr/lib/x86_64-linux-gnu/libcares.so /usr/lib/x86_64-linux-gnu/libcryptopp.so /usr/lib/x86_64-linux-gnu/libfmt.so.8.1.1 /usr/lib/x86_64-linux-gnu/liblz4.so /usr/lib/x86_64-linux-gnu/libgnutls.so /usr/lib/x86_64-linux-gnu/libsctp.so /usr/lib/x86_64-linux-gnu/libyaml-cpp.so _cooking/installed/lib/librte_cfgfile.a _cooking/installed/lib/librte_cmdline.a _cooking/installed/lib/librte_ethdev.a _cooking/installed/lib/librte_hash.a _cooking/installed/lib/librte_mbuf.a _cooking/installed/lib/librte_eal.a _cooking/installed/lib/librte_kvargs.a _cooking/installed/lib/librte_mempool.a _cooking/installed/lib/librte_mempool_ring.a _cooking/installed/lib/librte_pmd_bnxt.a _cooking/installed/lib/librte_pmd_cxgbe.a _cooking/installed/lib/librte_pmd_e1000.a _cooking/installed/lib/librte_pmd_ena.a _cooking/installed/lib/librte_pmd_enic.a _cooking/installed/lib/librte_pmd_qede.a _cooking/installed/lib/librte_pmd_mlx5.a _cooking/installed/lib/librte_pmd_i40e.a _cooking/installed/lib/librte_pmd_ixgbe.a _cooking/installed/lib/librte_pmd_nfp.a _cooking/installed/lib/librte_pmd_ring.a _cooking/installed/lib/librte_pmd_vmxnet3_uio.a _cooking/installed/lib/librte_ring.a _cooking/installed/lib/librte_net.a _cooking/installed/lib/librte_timer.a _cooking/installed/lib/librte_pci.a _cooking/installed/lib/librte_bus_pci.a _cooking/installed/lib/librte_bus_vdev.a _cooking/installed/lib/librte_pmd_fm10k.a _cooking/installed/lib/librte_pmd_sfc_efx.a /usr/lib/x86_64-linux-gnu/libhwloc.so /usr/lib/x86_64-linux-gnu/liburing.so /usr/lib/x86_64-linux-gnu/libnuma.so || apps/memcached/app_memcached_ascii libseastar.a
  FLAGS = -O2 -g -DNDEBUG
  #LINK_LIBRARIES = libseastar.a  /usr/lib/x86_64-linux-gnu/libboost_program_options.so  /usr/lib/x86_64-linux-gnu/libboost_thread.so  /usr/lib/x86_64-linux-gnu/libboost_chrono.so  /usr/lib/x86_64-linux-gnu/libboost_date_time.so  /usr/lib/x86_64-linux-gnu/libboost_atomic.so  /usr/lib/x86_64-linux-gnu/libcares.so  /usr/lib/x86_64-linux-gnu/libcryptopp.so  /usr/lib/x86_64-linux-gnu/libfmt.so.8.1.1  -Wl,--as-needed  /usr/lib/x86_64-linux-gnu/liblz4.so  -ldl  /usr/lib/x86_64-linux-gnu/libgnutls.so  -latomic  /usr/lib/x86_64-linux-gnu/libsctp.so  /usr/lib/x86_64-linux-gnu/libyaml-cpp.so  _cooking/installed/lib/librte_cfgfile.a  _cooking/installed/lib/librte_cmdline.a  _cooking/installed/lib/librte_ethdev.a  _cooking/installed/lib/librte_hash.a  _cooking/installed/lib/librte_mbuf.a  _cooking/installed/lib/librte_eal.a  _cooking/installed/lib/librte_kvargs.a  _cooking/installed/lib/librte_mempool.a  _cooking/installed/lib/librte_mempool_ring.a  _cooking/installed/lib/librte_pmd_bnxt.a  _cooking/installed/lib/librte_pmd_cxgbe.a  _cooking/installed/lib/librte_pmd_e1000.a  _cooking/installed/lib/librte_pmd_ena.a  _cooking/installed/lib/librte_pmd_enic.a  _cooking/installed/lib/librte_pmd_qede.a  _cooking/installed/lib/librte_pmd_mlx5.a  _cooking/installed/lib/librte_pmd_i40e.a  _cooking/installed/lib/librte_pmd_ixgbe.a  _cooking/installed/lib/librte_pmd_nfp.a  _cooking/installed/lib/librte_pmd_ring.a  _cooking/installed/lib/librte_pmd_vmxnet3_uio.a  _cooking/installed/lib/librte_ring.a  _cooking/installed/lib/librte_net.a  _cooking/installed/lib/librte_timer.a  _cooking/installed/lib/librte_pci.a  _cooking/installed/lib/librte_bus_pci.a  _cooking/installed/lib/librte_bus_vdev.a  _cooking/installed/lib/librte_pmd_fm10k.a  _cooking/installed/lib/librte_pmd_sfc_efx.a  /usr/lib/x86_64-linux-gnu/libhwloc.so  /usr/lib/x86_64-linux-gnu/liburing.so  /usr/lib/x86_64-linux-gnu/libnuma.so
  LINK_LIBRARIES = libseastar.a  /usr/lib/x86_64-linux-gnu/libboost_program_options.so  /usr/lib/x86_64-linux-gnu/libboost_thread.so  /usr/lib/x86_64-linux-gnu/libboost_chrono.so  /usr/lib/x86_64-linux-gnu/libboost_date_time.so  /usr/lib/x86_64-linux-gnu/libboost_atomic.so  /usr/lib/x86_64-linux-gnu/libcares.so  /usr/lib/x86_64-linux-gnu/libcryptopp.so  /usr/lib/x86_64-linux-gnu/libfmt.so.8.1.1  -Wl,--as-needed  /usr/lib/x86_64-linux-gnu/liblz4.so  -ldl  -libverbs -lmlx5 -lmnl  /usr/lib/x86_64-linux-gnu/libgnutls.so  -latomic  /usr/lib/x86_64-linux-gnu/libsctp.so  /usr/lib/x86_64-linux-gnu/libyaml-cpp.so  _cooking/installed/lib/librte_cfgfile.a  _cooking/installed/lib/librte_cmdline.a  _cooking/installed/lib/librte_ethdev.a  _cooking/installed/lib/librte_hash.a  _cooking/installed/lib/librte_mbuf.a  _cooking/installed/lib/librte_eal.a  _cooking/installed/lib/librte_kvargs.a  _cooking/installed/lib/librte_mempool.a  _cooking/installed/lib/librte_mempool_ring.a  _cooking/installed/lib/librte_pmd_bnxt.a  _cooking/installed/lib/librte_pmd_cxgbe.a  _cooking/installed/lib/librte_pmd_e1000.a  _cooking/installed/lib/librte_pmd_ena.a  _cooking/installed/lib/librte_pmd_enic.a  _cooking/installed/lib/librte_pmd_qede.a  _cooking/installed/lib/librte_pmd_mlx5.a  _cooking/installed/lib/librte_pmd_i40e.a  _cooking/installed/lib/librte_pmd_ixgbe.a  _cooking/installed/lib/librte_pmd_nfp.a  _cooking/installed/lib/librte_pmd_ring.a  _cooking/installed/lib/librte_pmd_vmxnet3_uio.a  _cooking/installed/lib/librte_ring.a  _cooking/installed/lib/librte_net.a  _cooking/installed/lib/librte_timer.a  _cooking/installed/lib/librte_pci.a  _cooking/installed/lib/librte_bus_pci.a  _cooking/installed/lib/librte_bus_vdev.a  _cooking/installed/lib/librte_pmd_fm10k.a  _cooking/installed/lib/librte_pmd_sfc_efx.a  /usr/lib/x86_64-linux-gnu/libhwloc.so  /usr/lib/x86_64-linux-gnu/liburing.so  /usr/lib/x86_64-linux-gnu/libnuma.so
  OBJECT_DIR = apps/memcached/CMakeFiles/app_memcached.dir
  POST_BUILD = :
  PRE_LINK = :
  TARGET_FILE = apps/memcached/memcached
  TARGET_PDB = memcached.dbg
```

</details>

command to launch the benchmark server

```
build/release/apps/memcached/memcached --network-stack native --dpdk-pmd --dhcp 0 --host-ipv4-addr 10.100.0.20 --netmask-ipv4-addr 255.255.255.0 --collectd 0 --smp 1 --port 10000
```

***F-Stack setup***

- https://github.com/F-Stack/f-stack.git
- 81b0219b097156693e6061ce215dc79687ef7f92
- Linux kernel 6.2 (Ubuntu 22.04)

<details>

<summary>please click here to see changes made for this test</summary>

The following is the change made to the configuration file.

```diff
--- a/config.ini
+++ b/config.ini
@@ -33,13 +33,14 @@ idle_sleep=0
 # if set 0, means send pkts immediately.
 # if set >100, will dealy 100 us.
 # unit: microseconds
-pkt_tx_delay=100
+pkt_tx_delay=0

 # use symmetric Receive-side Scaling(RSS) key, default: disabled.
 symmetric_rss=0

 # PCI device enable list.
 # And driver options
+allow=17:00.0
 #allow=02:00.0
 # for multiple PCI devices
 #allow=02:00.0,03:00.0
@@ -85,10 +86,10 @@ savepath=.
 # Port config section
 # Correspond to dpdk.port_list's index: port0, port1...
 [port0]
-addr=192.168.1.2
+addr=10.100.0.20
 netmask=255.255.255.0
-broadcast=192.168.1.255
-gateway=192.168.1.1
+broadcast=10.100.0.255
+gateway=10.100.0.10
 # set interface name, Optional parameter.
 #if_name=eno7
```

We changed an HTTP-server like example to always return "A" to incoming TCP messages.

```diff
--- a/example/main.c
+++ b/example/main.c
@@ -26,37 +26,7 @@ int sockfd;
 int sockfd6;
 #endif

-char html[] =
-"HTTP/1.1 200 OK\r\n"
-"Server: F-Stack\r\n"
-"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
-"Content-Type: text/html\r\n"
-"Content-Length: 438\r\n"
-"Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
-"Connection: keep-alive\r\n"
-"Accept-Ranges: bytes\r\n"
-"\r\n"
-"<!DOCTYPE html>\r\n"
-"<html>\r\n"
-"<head>\r\n"
-"<title>Welcome to F-Stack!</title>\r\n"
-"<style>\r\n"
-"    body {  \r\n"
-"        width: 35em;\r\n"
-"        margin: 0 auto; \r\n"
-"        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
-"    }\r\n"
-"</style>\r\n"
-"</head>\r\n"
-"<body>\r\n"
-"<h1>Welcome to F-Stack!</h1>\r\n"
-"\r\n"
-"<p>For online documentation and support please refer to\r\n"
-"<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
-"\r\n"
-"<p><em>Thank you for using F-Stack.</em></p>\r\n"
-"</body>\r\n"
-"</html>";
+char html[] = "A";
 
 int loop(void *arg)
 {
@@ -143,7 +113,7 @@ int main(int argc, char * argv[])
     struct sockaddr_in my_addr;
     bzero(&my_addr, sizeof(my_addr));
     my_addr.sin_family = AF_INET;
-    my_addr.sin_port = htons(80);
+    my_addr.sin_port = htons(10000);
     my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
```

</details>

command to launch the benchmark server

```
./example/helloworld
```

***TAS setup***

- https://github.com/tcp-acceleration-service/tas.git
- d3926baf6ad65211dc724206a8420715eb5ab645
- Linux kernel 6.2 (Ubuntu 22.04)

<details>

<summary>please click here to see changes made for this test</summary>

We remove ```-Werror``` and manipulate several path settings to pass the compilation.

```diff
--- a/Makefile
+++ b/Makefile
@@ -5,15 +5,15 @@

 CPPFLAGS += -Iinclude/
 CPPFLAGS += $(EXTRA_CPPFLAGS)
-CFLAGS += -std=gnu99 -O3 -g -Wall -Werror -march=native -fno-omit-frame-pointer
+CFLAGS += -std=gnu99 -O3 -g -Wall -march=native -fno-omit-frame-pointer
 CFLAGS += $(EXTRA_CFLAGS)
 CFLAGS_SHARED += $(CFLAGS) -fPIC
 LDFLAGS += -pthread -g
 LDFLAGS += $(EXTRA_LDFLAGS)
-LDLIBS += -lm -lpthread -lrt -ldl
+LDLIBS += -lm -lpthread -lrt -ldl -lrte_kvargs
 LDLIBS += $(EXTRA_LDLIBS)

-PREFIX ?= /usr/local
+PREFIX ?= $(HOME)/dpdk-inst
 SBINDIR ?= $(PREFIX)/sbin
 LIBDIR ?= $(PREFIX)/lib
 INCDIR ?= $(PREFIX)/include
@@ -23,13 +23,13 @@ INCDIR ?= $(PREFIX)/include
 # DPDK configuration

 # Prefix for dpdk
-RTE_SDK ?= /usr/
+RTE_SDK ?= $(HOME)/dpdk-inst
 # mpdts to compile
-DPDK_PMDS ?= ixgbe i40e tap virtio
+DPDK_PMDS ?= ixgbe i40e tap virtio mlx5

 DPDK_CPPFLAGS += -I$(RTE_SDK)/include -I$(RTE_SDK)/include/dpdk \
-  -I$(RTE_SDK)/include/x86_64-linux-gnu/dpdk/
-DPDK_LDFLAGS+= -L$(RTE_SDK)/lib/
+  -I$(RTE_SDK)/include/x86_64-linux-gnu/dpdk/ -I$(RTE_SDK)/include/
+DPDK_LDFLAGS+= -L$(RTE_SDK)/lib/ -L/root/dpdk-inst/lib/x86_64-linux-gnu
 DPDK_LDLIBS+= \
   -Wl,--whole-archive \
    $(addprefix -lrte_pmd_,$(DPDK_PMDS)) \
```

We replace ```pthread_yield``` with ```sched_yield``` because the compiler suggested.

```diff
--- a/lib/sockets/interpose.c
+++ b/lib/sockets/interpose.c
@@ -779,7 +779,7 @@ static inline void ensure_init(void)
       init_done = 1;
     } else {
       while (init_done == 0) {
-        pthread_yield();
+        sched_yield();
       }
       MEM_BARRIER();
     }
```

```diff
--- a/lib/sockets/libc.c
+++ b/lib/sockets/libc.c
@@ -150,7 +150,7 @@ static inline void ensure_init(void)
       init_done = 1;
     } else {
       while (init_done == 0) {
-        pthread_yield();
+        sched_yield();
       }
       MEM_BARRIER();
     }
```

</details>

command to launch the service process of TAS

```
LD_LIBRARY_PATH=$HOME/dpdk-inst/lib/x86_64-linux-gnu ./tas/tas --ip-addr=10.100.0.20/24 --fp-cores-max=1
```

command to launch the benchmark server

```
./tests/bench_ll_echo 10000 1 64 128
```

***Caladan setup***

- https://github.com/shenango/caladan.git
- 1ab795053531dacf6bde366471a4439ae72313c4
- Linux kernel 5.15 (Ubuntu 22.04)

<details>

<summary>please click here to see changes made for this test</summary>

```diff
--- a/apps/synthetic/src/main.rs
+++ b/apps/synthetic/src/main.rs
@@ -1,4 +1,4 @@
-#![feature(integer_atomics)]
+//#![feature(integer_atomics)]
 #![feature(nll)]
 #![feature(test)]
 #[macro_use]
```

We changed the build config file to include the mlx5 NIC driver.

The directpath optimization ```CONFIG_DIRECTPATH``` is not activated.

```diff
--- a/build/config
+++ b/build/config
@@ -1,7 +1,7 @@
 # build configuration options (set to y for "yes", n for "no")
 
 # Enable Mellanox ConnectX-4,5 NIC Support
-CONFIG_MLX5=n
+CONFIG_MLX5=y
 # Enable Mellanox ConnectX-3 NIC Support
 CONFIG_MLX4=n
 # Enable SPDK NVMe support
```

The configuration file is edited as follows.

```diff
--- a/server.config
+++ b/server.config
@@ -1,7 +1,6 @@
-# an example runtime config file
-host_addr 192.168.1.3
+host_addr 10.100.0.20
 host_netmask 255.255.255.0
-host_gateway 192.168.1.1
-runtime_kthreads 4
-runtime_guaranteed_kthreads 4
+host_gateway 10.100.0.10
+runtime_kthreads 1
+runtime_guaranteed_kthreads 1
 runtime_priority lc
```

We change the port number that the servers listens on.

```diff
--- a/tests/netperf.c
+++ b/tests/netperf.c
@@ -14,7 +14,7 @@
 #include <runtime/sync.h>
 #include <runtime/tcp.h>
 
-#define NETPERF_PORT   8000
+#define NETPERF_PORT   10000
 
 /* experiment parameters */
 static struct netaddr raddr;
```

</details>

command to launch the process for Caladan's IOKernel

```
./iokerneld simple noht
```

command to launch the benchmark server

```
./tests/netperf ./server.config SERVER 1 10.100.0.20 0 1 1
```

***iip setup***

- bench-iip: 4e98b9af786299ec44f79b2bf67c046a301075bd
- iip: 0da3100f108f786d923e41acd84b6614082a72be
- iip-dpdk: 9fd10fd9410dbc43ab487784f4cb72300199354b
- Linux kernel 6.2 (Ubuntu 22.04)

command to launch the benchmark server

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -l 1
```

***result***

| system | throughput (requests/sec) | 99th percentile latency (us) |
| ------------- | ------------- | ------------- |
| Linux | 255872 | 160.381 |
| lwIP | 2330425 | 14.188 |
| Seastar | 1135152 | 30.286 |
| F-Stack | 1368221 | 23.884 |
| TAS | 1628830 | 26.794 |
| Caladan | 2427353 | 17.263 |
| iip | 2894734 | 15.314 |

***note***

For this benchmark, TAS uses three CPU cores and Caladan uses two CPU cores; TAS needs two extra CPU cores for its service process, and Caladan requires a dedicated CPU core for its scheduler. The other cases use one CPU core.

### 8 CPU core server

***client (iip)***

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 0 -c 8 -d 1 -l 1
```

***Linux setup***

```
./app -c 0-7 -g 1 -l 1 -p 10000
```

***Seastar setup***

```
build/release/apps/memcached/memcached --network-stack native --dpdk-pmd --dhcp 0 --host-ipv4-addr 10.100.0.20 --netmask-ipv4-addr 255.255.255.0 --collectd 0 --smp 8 --port 10000
```

***Caladan setup***

The file ```server.config``` is changed so that ```runtime_kthreads``` will be 8.

<details>

<summary>please click here to see the configuration used for this test</summary>

```
host_addr 10.100.0.20
host_netmask 255.255.255.0
host_gateway 10.100.0.10
runtime_kthreads 8
runtime_guaranteed_kthreads 8
runtime_priority lc
```

</details>

command to launch the benchmark server

```
./tests/netperf ./server.config SERVER 0 10.100.0.20 0 1 1
```

***iip setup***

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-7 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -l 1
```

***result***

| system | throughput (requests/sec) | 99th percentile latency (us) |
| ------------- | ------------- | ------------- |
| Linux | 1891960 | 304.695 |
| Seastar | 8837323 | 39.769 |
| Caladan | 9997752 | 50.033 |
| iip | 22040945 | 16.538 |

***note***

Caladan uses 9 CPU cores for this benchmark (Caladan requires a dedicated CPU core for its scheduler), and the other cases use 8 CPU cores.

### 32 CPU core server

***client (iip)***

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 0 -c 32 -d 1 -l 1
```

***Linux setup***

```
./app -c 0-31 -g 1 -l 1 -p 10000
```

***Seastar setup***

```
build/release/apps/memcached/memcached --network-stack native --dpdk-pmd --dhcp 0 --host-ipv4-addr 10.100.0.20 --netmask-ipv4-addr 255.255.255.0 --collectd 0 --smp 32 --port 10000
```

***iip setup***

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -l 1
```

***result***

| system | throughput (requests/sec) | 99th percentile latency (us) |
| ------------- | ------------- | ------------- |
| Linux | 4809453 | 528.557 |
| Seastar | 29381169 | 53.341 |
| iip | 71007462 | 21.247 |

***note***

In our environment, 14 was the maximum number specified for ```runtime_kthreads```.

<details>

<summary>please click here to see the configuration used for this test</summary>

```
host_addr 10.100.0.20
host_netmask 255.255.255.0
host_gateway 10.100.0.10
runtime_kthreads 14
runtime_guaranteed_kthreads 14
runtime_priority lc
```

</details>

The client is launched by the following command.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 0 -c 14 -d 1 -l 1
```

Caladan's throughput with this 14 ```runtime_kthreads``` setup was  9708941 requests/sec and its 99th percentile latency was 72.881 us.

# appendix

## cache statistics

We can have cache-relevant statistics by, in another console/terminal, executing the following command during the benchmark execution.

```
sudo pqos -m all:0-31 2>&1 | tee -a pqos-output.txt
```

The following extracts, from the entire pqos output, the result for the second that is two seconds before the benchmark execution completes:

for 32 cores

```
ta=(`cat result.txt|grep "sec has passed"|awk '{ print $2 }'`); for i in ${ta[@]}; do tac pqos-output.txt|grep -v NOTE|grep -v CAT|grep -v CORE|awk -v timestr="$i" 'BEGIN{ pcnt = 0; } { num = match($0, timestr); if (0 < num) { pcnt = 1; }; if (0 < pcnt && pcnt < 67) { if (34 < pcnt) { print $n; }; pcnt += 1; }; }'; done
```

for CPU core 0

```
ta=(`cat result.txt|grep "sec has passed"|awk '{ print $2 }'`); for i in ${ta[@]}; do tac pqos-output.txt|grep -v NOTE|grep -v CAT|grep -v CORE|awk -v timestr="$i" 'BEGIN{ pcnt = 0; } { num = match($0, timestr); if (0 < num) { pcnt = 1; }; if (0 < pcnt && pcnt < 67) { if (34 < pcnt) { print $n; }; pcnt += 1; }; }'|sort|awk '{ if (NR == 1) { print $n; exit } }'; done
```

get average of 32 cores

```
numcore=1; ta=(`cat result.txt|grep "sec has passed"|awk '{ print $2 }'`); for i in ${ta[@]}; do tac pqos-output.txt|grep -v NOTE|grep -v CAT|grep -v CORE|awk -v timestr="$i" -v numcore=$numcore 'BEGIN{ pcnt = 0; ipc = 0; missk = 0; util = 0; } { num = match($0, timestr); if (0 < num) { pcnt = 1; }; if (0 < pcnt && pcnt < 67) { if (34 + (32 - numcore) < pcnt) { ipc += $2; missk += $3; util += $4; }; pcnt += 1; }; } END{ print ipc / numcore ", " missk /numcore ", " util / numcore }'; numcore=$(($numcore+1)); done
```

## AF_XDP-based backend

This bench-iip program should work with an [AF_XDP-based backend](https://github.com/yasukata/iip-af_xdp).

### build with the AF_XDP-based backend

Please first download the files of [bench-iip](https://github.com/yasukata/bench-iip) and [iip](https://github.com/yasukata/iip) by the following commands; these are the same as the ones described in the [build section](#build), therefore, if you already have them, you do not need to execute these commands.

```
git clone https://github.com/yasukata/bench-iip.git
```

```
cd bench-iip
```

```
git clone https://github.com/yasukata/iip.git
```

From here, the procedure is specific for the AF_XDP-based backend and not described in the [build section](#build).

Please download the code of the [AF_XDP-based backend](https://github.com/yasukata/iip-af_xdp) by the following command; please note that this we assume we are in the directory ```bench-iip``` by the command ```cd bench-iip``` above.

```
git clone https://github.com/yasukata/iip-af_xdp.git
```

If you already have a compiled binary for the DPDK-based backend, please clean the directory by the following command.

```
IOSUB_DIR=./iip-dpdk make clean
```

Then, the following command will generate the bench-iip application named by ```a.out``` whose packet I/O is performed by AF_XDP.

```
IOSUB_DIR=./iip-af_xdp make
```

### run the benchmark with the AF_XDP-based backend

Please turn on a network interface to be used for the AF_XDP-based backend and assign an IP address to it; the following example command turns on a physical NIC named ```enp23s0f0np0``` and assigns ```10.100.0.20/24``` to it.

```
sudo ifconfig enp23s0f0np0 10.100.0.20 netmask 255.255.255.0 up
```

To run the program with the behavior equivalent to the one shown in the [run section](#run), please type the following command.

```
sudo ethtool -L enp23s0f0np0 combined 1; sudo ./a.out -l 0 -i enp23s0f0np0 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```

The launched program will use ```10.100.0.20/24``` as its IP address and listen on TCP port 10000 for serving the specified HTTP message, and supposedly, you will see the same behavior if you try the ```ping``` and ```telnet``` tests shown in the [run section](#run) from another machine reachable to the ```enp23s0f0np0``` interface.

### command options for the AF_XDP-based backend

The arguments for ```a.out``` are divided into two sections by ```--``` and the first part is passed to the AF_XDP-based backend and the second part is processed by the bench-iip program.

The first part of the arguments are:
- ```-l```: specification for CPU cores to be used, and its syntax is the same as the ```-l``` option for the DPDK-based backend
- ```-i```: specification for a network interface to be used

The second part of the arguments are the same as the one shown in the [previous section](#3rd-section-for-the-benchmark-tool).

One important point in the command above is to use ```ethtool``` to configure the number of NIC queues to be the same as the number of CPU cores used by the bench-iip program that is specified through the ```-l``` option; this is necessary because this benchmark program uses one CPU core to monitor one NIC queue. Therefore, if you use, for example, two CPU cores by specifying ```-l 0-1```, please ```sudo ethtool -L enp23s0f0np0 combined 2``` beforehand.

## netmap-based backend

### download source code necessary for the netmap-based backend

Please first download the files of [bench-iip](https://github.com/yasukata/bench-iip) and [iip](https://github.com/yasukata/iip) by the following commands; these are the same as the ones described in the [build section](#build), therefore, if you already have them, you do not need to execute these commands.

```
git clone https://github.com/yasukata/bench-iip.git
```

```
cd bench-iip
```

```
git clone https://github.com/yasukata/iip.git
```

From here, the procedure is specific for the netmap-based backend and not described in the [build section](#build).

Please download the code of the [netmap-based backend](https://github.com/yasukata/iip-netmap) by the following command; please note that this we assume we are in the directory ```bench-iip``` by the command ```cd bench-iip``` above.

```
git clone https://github.com/yasukata/iip-netmap.git
```

### netmap preparation necessary on Linux

This part is specific to Linux environments; to use netmap on Linux, we need to build its source code and install it and this step is not necessary on FreeBSD.

Please enter the iip-netmap directory.

```
cd iip-netmap
```

Please download the netmap source code by the following command.

```
git clone https://github.com/luigirizzo/netmap.git
```

Then, please enter the downloaded netmap directory.

```
cd netmap
```

To build netmap on Linux, we should have Linux kernel headers; you could install them using the following commands.

```
sudo apt install linux-headers-`uname -r`
```

Please type the following command to execute ```configure``` of netmap. Please note that here we specify ```--drivers=``` to skip building NIC device drivers having netmap-specific patches; if you plan to use physical NICs, you need to specify the names of drivers for the physical NICs shown in ```driver_avail``` of ```netmap/LINUX/configure``` for ```--drivers=``` or if you remove the ``````--drivers``` option, the netmap build tool will try to build all possible NIC drivers.

```
./configure --drivers=
```

Afterward, pleae type ```make``` to generate a kernel module named ```netmap.ko```.

```
make
```

Then, the following command will install the netmap kernel module.

```
sudo insmod netmap.ko
```

Please get back to ```bench-iip``` directory.

```
cd ../../
```

**WARNING**: If you plan to use netmap with physical NICs, you need to replace the currently loaded device drivers for the physical NICs with the ones having netmap-specific changes. This part is a little bit complicated and, in the worst case, you may lose network reachability to the machine where you try to install netmap because of the NIC device driver module deletion. For details, please refer to the instruction provided from the official netmap repository at https://github.com/luigirizzo/netmap/blob/master/LINUX/README.md#how-to-load-netmap-in-your-system , and please try it **at your own risk**.

### build with the netmap-based backend

If you already have a compiled binary for the DPDK-based backend, please clean the directory by the following command.

```
IOSUB_DIR=./iip-dpdk make clean
```

Then, the following command will generate the bench-iip application named by ```a.out``` whose packet I/O is performed by netmap.

```
IOSUB_DIR=./iip-netmap make
```

### run the benchmark with the netmap-based backend

The example here uses netmap-specific virtual ports rather than physical NICs for simplicity.

The following command runs, on CPU core 0, a server program which has a virtual port named ```if20``` which is associated with a virtual switch named ```vale0```, and the virtual port's MAC address is aa:bb:cc:dd:ee:ff and IP address is 10.100.0.20 respectively and it listens on TCP port 10000 and serves an HTTP content.

```
sudo ./a.out -a aa:bb:cc:dd:ee:ff,10.100.0.20 -l 0 -i vale0:if20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```

Please open another terminal/console on the same machine executed the command above, and please type the following command; it runs, on CPU core 1, a client program which has a virtual port named ```if10``` which is associated with a virtual switch named ```vale0```, and the virtual port's MAC address is 11:22:33:44:55:66 and IP address is 10.100.0.10 respectively and it triest to connect to TCP port 10000 of 10.100.0.20 and sends ```GET ``` to fetch the HTTP data through 1 TCP connection.

```
sudo ./a.out -a 11:22:33:44:55:66,10.100.0.10 -l 1 -i vale0:if10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 1
```

### command options for the netmap-based backend

The arguments for ```a.out``` are divided into two sections by ```--``` and the first part is passed to the netmap-based backend and the second part is processed by the bench-iip program.

The first part of the arguments are:
- ```-a```: specification for MAC and IP addresses (for example, ```-a aa:bb:cc:dd:ee:ff,10.100.0.20``` specifies aa:bb:cc:dd:ee:ff for the MAC address and 10.100.0.20 for the IP address)
- ```-l```: specification for CPU cores to be used, and its syntax is the same as the ```-l``` option for the DPDK-based backend
- ```-i```: specification for a network interface to be used

The second part of the arguments are the same as the one shown in the [previous section](#3rd-section-for-the-benchmark-tool).

## compilation test

The following commands are to see the dependencies introduced by ```main.c``` in this repository.

```
mkdir ./iip-iostub
```

The content of ```iip-iostub/main.c```.

<details>

<summary>please click here to show the program</summary>

```c
static uint16_t helper_ip4_get_connection_affinity(uint16_t protocol, uint32_t local_ip4_be, uint16_t local_port_be, uint32_t peer_ip4_be, uint16_t peer_port_be, void *opaque)
{
	return 0;
	{ /* unused */
		(void) protocol;
		(void) local_ip4_be;
		(void) local_port_be;
		(void) peer_ip4_be;
		(void) peer_port_be;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	return 0;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint8_t *iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	return NULL;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint8_t *iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	return NULL;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint8_t iip_ops_l2_skip(void *pkt, void *opaque)
{
	return 0;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	return 0;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint16_t iip_ops_l2_addr_len(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_l2_broadcast_addr(uint8_t bc_mac[], void *opaque)
{
	{ /* unused */
		(void) bc_mac;
		(void) opaque;
	}
}

static void iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be, void *opaque)
{
	{ /* unused */
		(void) pkt;
		(void) src;
		(void) dst;
		(void) ethertype_be;
		(void) opaque;
	}
}

static uint8_t iip_ops_arp_lhw(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_arp_lproto(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void *iip_ops_pkt_alloc(void *opaque)
{
	return NULL;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_pkt_free(void *pkt, void *opaque)
{
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static void *iip_ops_pkt_get_data(void *pkt, void *opaque)
{
	return NULL;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static uint16_t iip_ops_pkt_get_len(void *pkt, void *opaque)
{
	return 0;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static void iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque)
{
	{ /* unused */
		(void) pkt;
		(void) len;
		(void) opaque;
	}
}

static void iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque)
{
	{ /* unused */
		(void) pkt;
		(void) len;
		(void) opaque;
	}
}

static void iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque)
{
	{ /* unused */
		(void) pkt;
		(void) len;
		(void) opaque;
	}
}

static void *iip_ops_pkt_clone(void *pkt, void *opaque)
{
	return NULL;
	{ /* unused */
		(void) pkt;
		(void) opaque;
	}
}

static void iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque)
{
	{ /* unused */
		(void) pkt_head;
		(void) pkt_tail;
		(void) opaque;
	}
}

static void *iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque)
{
	return NULL;
	{ /* unused */
		(void) pkt_head;
		(void) opaque;
	}
}

static void iip_ops_l2_flush(void *opaque)
{
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_l2_push(void *_m, void *opaque)
{
	{ /* unused */
		(void) _m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque)
{
	return 0;
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static uint8_t iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
{
	return 0;
	{ /* unused */
		(void) opaque;
	}
}

static void iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque)
{
	{ /* unused */
		(void) m;
		(void) opaque;
	}
}

static int __iosub_main(int argc, char *const *argv)
{
	return 0;
	{ /* unused */
		(void) argc;
		(void) argv;
	}
	{ /* unused */
		(void) __app_init;
		(void) __app_thread_init;
		(void) __app_loop;
		(void) __app_should_stop;
		(void) __app_exit;
	}
	{ /* unused */
		(void) iip_run;
		(void) iip_udp_send;
		(void) iip_tcp_connect;
		(void) iip_tcp_rxbuf_consumed;
		(void) iip_tcp_close;
		(void) iip_tcp_send;
		(void) iip_arp_request;
		(void) iip_add_tcp_conn;
		(void) iip_add_pb;
		(void) iip_tcp_conn_size;
		(void) iip_pb_size;
		(void) iip_workspace_size;
	}
}
```

</details>

The content of ```iip-iostub/build.mk```.

<details>

<summary>please click here to show the program</summary>

```Makefile
CFLAGS += -pedantic

OSNAME = $(shell uname -s)
ifeq ($(OSNAME),Linux)
CFLAGS += -D_POSIX_C_SOURCE=200112L -std=c17
else ifeq ($(OSNAME),FreeBSD)
CFLAGS += -std=c17
endif
```

</details>

Supposedly, we will have ```a.out``` by the following command.

```
IOSUB_DIR=./iip-iostub make
```

Note that ```a.out``` generated with ```IOSUB_DIR=./iip-iostub``` is does not work; it is just for the compilation test.
