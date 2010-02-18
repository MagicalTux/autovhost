#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include "buf.h"

#define max(a,b) (a>b?a:b)

bool opt_do_fork = false;
bool do_quit = false;
const char *opt_socket = NULL;
const char *opt_target = NULL;

void print_help(const char *myname) {
	fprintf(stderr, "Usage: %s -s /path/to/sock -t target_server_ip [-f]\n", myname);
}

int main(int argc, char *argv[]) {
	while(1) {
		int op = getopt(argc, argv, "s:t:fh");
		if (op == -1) break;
		switch(op) {
			case 'h':
				print_help(argv[0]);
				return 0;
			case 'f':
				opt_do_fork = true;
				break;
			case 's':
				opt_socket = optarg;
				break;
			case 't':
				opt_target = optarg;
				break;
			case '?':
			case ':':
			default:
				print_help(argv[0]);
				return 1;
		}
	}

	if ((opt_socket == NULL) || (opt_target == NULL)) {
		print_help(argv[0]);
		return 2;
	}

	unlink(opt_socket);
	
	int sock;
	int transmit = 0;
	int transmit_status = 0; // "need connection"
	time_t transmit_cnx = 0;

	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
		return 3;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, opt_socket);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
		close(sock);
		return 4;
	}
	chmod(opt_socket, 0777);

	BUF_DEFINE(mainbuf);

	fd_set rfd;
	fd_set wfd;
	FD_ZERO(&rfd);
	FD_ZERO(&wfd);

	while(!do_quit) {
		switch(transmit_status) {
			case 0: // "not connected"
			{
				FD_CLR(transmit, &wfd);
				if (transmit_cnx > time(NULL)) break;

				if (transmit != 0) close(transmit);

				FD_ZERO(&wfd);

				// need to establish a connection
				if ((transmit = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
					fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
					transmit_cnx = time(NULL)+30;
					break;
				}

				struct sockaddr_in tx_addr;
				memset(&tx_addr, 0, sizeof(tx_addr));
				tx_addr.sin_family = AF_INET;
				if (inet_aton(opt_target, &tx_addr.sin_addr) == -1) {
					perror("inet_aton");
					return 7;
				}
				tx_addr.sin_port = htons(11547);

				if (fcntl(transmit, F_SETFL, O_NONBLOCK) == -1) {
					perror("fcntl");
				}

				int res = connect(transmit, (struct sockaddr *)&tx_addr, sizeof(tx_addr));
				if (res == 0) {
					transmit_status = 2; // established
					fprintf(stderr, "Connected to %s\n", opt_target);
					if (!BUF_EMPTY(mainbuf)) FD_SET(transmit, &wfd);
					break;
				} else if (errno == EINPROGRESS) {
					transmit_status = 1; // waiting for connection
					transmit_cnx = time(NULL);
					FD_SET(transmit, &wfd);
					fprintf(stderr, "Connecting to %s\n", opt_target);
					break;
				} else {
					fprintf(stderr, "Failed to connect socket: %s\n", strerror(errno));
					transmit_cnx = time(NULL)+30;
					break;
				}
			}
			case 1:
				FD_SET(transmit, &wfd); // waiting for connection
			case 2:
				if (BUF_EMPTY(mainbuf)) {
					FD_CLR(transmit, &wfd);
				} else {
					FD_SET(transmit, &wfd);
				}
		}

		struct timeval tv;
		memset(&tv, 0, sizeof(tv));
		tv.tv_sec = 5;
		FD_SET(sock, &rfd);

		int res = select(max(sock,transmit)+1, &rfd, &wfd, NULL, &tv);
		if (res == -1) {
			fprintf(stderr, "FATAL: something REALLY BAD: %s!\n", strerror(errno));
			return 5;
		}
		if ((transmit_status == 1) && (transmit_cnx < (time(NULL) - 30))) {
			fprintf(stderr, "Connection timeout while connecting to server. Waiting 60 secs before reconnect.\n");
			close(transmit);
			transmit = 0;
			transmit_cnx = time(NULL)+60;
			transmit_status = 0;
		}
		if (res == 0) continue;
		if (FD_ISSET(sock, &rfd)) {
			char buf[65535];
			res = recv(sock, &buf, 65535, MSG_DONTWAIT);
			if (res == -1) {
				fprintf(stderr, "Packet reception failed: %s\n", strerror(errno));
				continue;
			}
			if (res == 0) continue;
			// append to our main buffer
			BUF_APPEND(mainbuf, &buf, res);
		}
		if (FD_ISSET(transmit, &wfd)) {
			switch(transmit_status) {
				case 1:
				{
					// check for connection status
					int error = EINVAL;
					socklen_t error_len = sizeof(error);
					if (getsockopt(transmit, SOL_SOCKET, SO_ERROR, &error, &error_len) == -1) error = errno;
					if (error == 0) {
						transmit_status = 2;
						fprintf(stderr, "Connection established\n");
						break;
					}
					fprintf(stderr, "Failed to connect to socket: %s\n", strerror(error));
					close(transmit);
					transmit = 0;
					transmit_status = 0;
					transmit_cnx = time(NULL)+30;
					break;
				}
				case 2:
					BUF_WRITE(transmit, mainbuf);
					break;
			}
		}
	}

	return 0;
}

