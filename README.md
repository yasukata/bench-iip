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
IOSUB_MK=./iip-dpdk/build.mk make
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

### 3rd section: for the benchmark tool

- ```-c```: concurrency (for the client mode)
- ```-m```: a string to be sent as the payload
- ```-n```: protocol number, either 6 (TCP) or 17 (UDP) (for the client mode) : default is TCP
- ```-p```: the server port (to listen on for the server mode, to connect to for the client mode)
- ```-s```: the server IP address to be connected (for the client mode)

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

Here, we show some rough numbers obtained from this benchmark tool and comparison with the following server program based on the Linux kernel TCP/IP stack.

```c
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

static size_t httpdatalen = 0;
static char *httpbuf = NULL;

static unsigned int should_stop = 0;

static void sig_h(int s __attribute__((unused)))
{
	should_stop = 1;
	signal(SIGINT, SIG_DFL);
}

static void *server_thread(void *data)
{
	int epfd;

	assert((epfd = epoll_create1(EPOLL_CLOEXEC)) != -1);

	{
		struct epoll_event ev = {
			.events = EPOLLIN,
			.data.fd = (unsigned long) data,
		};
		assert(!epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev));
	}

	while (!should_stop) {
		struct epoll_event ev[64];
		int nfd = epoll_wait(epfd, ev, 64, 100);
		{
			int i;
			for (i = 0; i < nfd; i++) {
				if (ev[i].data.fd == (unsigned long) data) {
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
							printf("%lx: accept %d\n", pthread_self(), _ev.data.fd);
						}
					}
				} else {
					char buf[0x1000];
					ssize_t rx = read(ev[i].data.fd, buf, sizeof(buf));
					if (rx <= 0) {
						printf("%lx: close %d\n", pthread_self(), ev[i].data.fd);
						close(ev[i].data.fd);
					} else {
						if (!strncmp(buf, "GET", 3))
							assert(write(ev[i].data.fd, httpbuf, httpdatalen) == httpdatalen);
					}
				}
			}
		}
	}

	close(epfd);

	pthread_exit(NULL);
}

int main(int argc, char *const *argv)
{
	unsigned short port = 0, num_thread = 0;
	unsigned int content_len = 1;

	{
		int ch;
		while ((ch = getopt(argc, argv, "l:p:t:")) != -1) {
			switch (ch) {
				case 'l':
					content_len = atoi(optarg);
					break;
				case 'p':
					port = atoi(optarg);
					break;
				case 't':
					num_thread = atoi(optarg);
					break;
				default:
					assert(0);
					break;
			}
		}
	}

	if (!port) {
		printf("please specify port number : -p\n");
		exit(0);
	}

	if (!num_thread) {
		printf("please specify number of threads : -t\n");
		exit(0);
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
			size_t buflen = content_len + 256 /* for http hdr */;
			char *content;
			assert((httpbuf = (char *) malloc(buflen)) != NULL);
			assert((content = (char *) malloc(content_len + 1)) != NULL);
			memset(content, 'A', content_len);
			content[content_len] = '\0';
			httpdatalen = snprintf(httpbuf, buflen, "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s",
					content_len, content);
			free(content);
			printf("http data length: %lu bytes\n", httpdatalen);
		}

		{
			pthread_t *th;
			assert((th = calloc(num_thread, sizeof(pthread_t))) != NULL);
			{
				unsigned short i;
				for (i = 0; i < num_thread; i++) {
					assert(!pthread_create(&th[i], NULL, server_thread, (void *)((unsigned long) fd)));
				}
			}
			{
				unsigned short i;
				for (i = 0; i < num_thread; i++)
					assert(!pthread_join(th[i], NULL));
			}
			free(th);
		}

		close(fd);
	}

	printf("Done\n");

	return 0;
}
```

## machines

Two machines having the same configuration.

- CPU: Two of 16-core Intel(R) Xeon(R) Gold 6326 CPU @ 2.90GHz (32 cores in total)
- NIC: Mellanox ConnectX-5 100 Gbps NIC (the NICs of the two machines are directly connected via a cable)
- OS: Linux 6.2

## commands

We compile the program above with:
```
gcc -O3 program_above.c -lpthread -o app
```

The server program (above) with the Linux TCP/IP stack

1 CPU core
```
./app -p 10000 -l 2 -t 1
```
2 CPU cores
```
./app -p 10000 -l 2 -t 2
```
4 CPU cores
```
./app -p 10000 -l 2 -t 4
```
8 CPU cores
```
./app -p 10000 -l 2 -t 8
```
16 CPU cores
```
./app -p 10000 -l 2 -t 16
```
32 CPU cores
```
./app -p 10000 -l 2 -t 32
```

iip benchmark server

1 CPU core
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```
2 CPU cores
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-1 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```
4 CPU cores
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-3 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```
8 CPU cores
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-7 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```
16 CPU cores
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-15 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```
32 CPU cores
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```

iip benchmark client (used for both Linux TCP/IP and iip servers)

for the 1 CPU core server
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-15 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 1
```
for the 2 CPU core server
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 1
```
for the 4 CPU core server
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 2
```
for the 8 CPU core server
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 4
```
for the 16 CPU core server
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 8
```
for the 32 CPU core server
```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -m "GET " -c 16
```

Essentially, on the server side, each CPU core will serve 16 of persistent concurrent connections.

## results

The following table shows the requests per second results for the Linux TCP/IP and iip cases along with different number of server CPU cores.

| number of CPU cores | Linux TCP/IP |   iip    |
|---------------------|--------------|----------|
|  1                  |       256960 |  1996518 |
|  2                  |       494979 |  3777021 |
|  4                  |      1069769 |  7542078 |
|  8                  |      1683952 | 14698990 |
| 16                  |      2987447 | 17208917 |
| 32                  |      4643684 | 17586849 |

