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

#include "buf.h"

bool opt_do_fork = false;
bool do_quit = false;
const char *opt_socket = NULL;

void print_help(const char *myname) {
	fprintf(stderr, "Usage: %s -s /path/to/sock [-f]\n", myname);
}

int main(int argc, char *argv[]) {
	while(1) {
		int op = getopt(argc, argv, "s:fh");
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
			case '?':
			case ':':
			default:
				print_help(argv[0]);
				return 1;
		}
	}

	if (opt_socket == NULL) {
		print_help(argv[0]);
		return 2;
	}

	unlink(opt_socket);
	
	int sock;

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
	FD_ZERO(&rfd);
	while(!do_quit) {
		struct timeval tv;
		tv.tv_sec = 5;
		FD_SET(sock, &rfd);
		int res = select(sock+1, &rfd, NULL, NULL, &tv);
		if (res == -1) {
			fprintf(stderr, "FATAL: something REALLY BAD: %s!\n", strerror(errno));
			return 5;
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
	}

#if 0
	int real_len = strlen(n.buf);
	int slen = sendto(sock, n.buf, real_len, 0, &addr, sizeof(addr));

	if (slen == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to send log: %s", strerror(errno));
		close(sock);
		return DECLINED;
	}
#endif

	return 0;
}

