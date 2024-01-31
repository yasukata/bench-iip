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

### multi-core server performance

- client (iip and DPDK)

```
cnt=0; while [ $cnt -le 31 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -l 1 -t 5 -c $(($cnt+1)) 2>&1 | tee -a ./result.txt; cnt=$(($cnt+1)); done
```

- server (iip and DPDK)

```
cnt=0; while [ $cnt -le 31 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-$cnt --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 1 -l 1; cnt=$(($cnt+1)); done
```

- server (Linux)

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

The following compiles the program above (```program_above.c```) and generates an executable file ```app```.

```
gcc -Werror -Wextra -Wall -O3 program_above.c -lpthread -lnuma -o app
```

Then, the following executes the compiled program ```app```.

```
ulimit -n unlimited; cnt=0; while [ $cnt -le 31 ]; do ./app -p 10000 -c 0-$cnt -g 1 -l 1; cnt=$(($cnt+1)); done
```

- results:

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/multicore/throughput.svg" width="500px">

### 32-core server latency

- client (iip and DPDK)

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 5 -c $(($cnt == 0 ? 1 : $cnt)) -d 1 -l 1 2>&1 | tee -a ./result.txt; cnt=$(($cnt+2)); don
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

In the "all" case, the tx side leverages NIC offloading features for TSO and checksum along with zero-copy transmission, and the rx side activates the NIC offloading features of LRO and checksum.
For the "w/o TSO" and "w/o TSO + w/o TX TCP checksum" cases, the tx side sets 2048 to the queue length.

- results:

<img src="https://raw.githubusercontent.com/yasukata/img/master/iip/bulk/large.svg" width="500px">

### cache statistics

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

# appendix

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

The content of ```iip-iostub/build.mk```.

```Makefile
CFLAGS += -pedantic

OSNAME = $(shell uname -s)
ifeq ($(OSNAME),Linux)
CFLAGS += -D_POSIX_C_SOURCE=200112L -std=c17
else ifeq ($(OSNAME),FreeBSD)
CFLAGS += -std=c17
endif
```

Supposedly, we will have ```a.out``` by the following command.

```
IOSUB_DIR=./iip-iostub make
```

Note that ```a.out``` generated with ```IOSUB_DIR=./iip-iostub``` is does not work; it is just for the compilation test.
