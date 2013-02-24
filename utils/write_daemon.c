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
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>

#define max(a,b) (a>b?a:b)

bool do_quit = false;
bool opt_do_fork = false;
bool opt_use_stderr = false;
const char *opt_socket = NULL;
const char *opt_target = NULL;

void print_help(const char *myname) {
	fprintf(stderr, "Usage: %s -s /path/to/sock -t /path/to/file_prefix [-f] [-e]\n", myname);
}

void msg_log(int pri, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	if (opt_use_stderr) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		vsyslog(pri, fmt, ap);
	}
	va_end(ap);
}

int main(int argc, char *argv[]) {
	while(1) {
		int op = getopt(argc, argv, "s:t:feh");
		if (op == -1) break;
		switch(op) {
			case 'h':
				print_help(argv[0]);
				return 0;
			case 'f':
				opt_do_fork = true;
				break;
			case 'e':
				opt_use_stderr = true;
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
	int transmit = -1;
	time_t write_stamp = time(NULL);

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

	signal(SIGPIPE, SIG_IGN);

	if (opt_do_fork) {
		int pid = fork();
		if (pid > 0) { // parent
			fprintf(stderr, "Forked child pid %d\n", pid);
			return 0;
		}
		if (pid == 0) {
			setsid();
		}
	}

	if (!opt_use_stderr)
		openlog("autovhost_log", LOG_CONS, LOG_DAEMON);

	fd_set rfd;
	fd_set wfd;
	FD_ZERO(&rfd);
	FD_ZERO(&wfd);

	while(!do_quit) {
		struct timeval tv;
		memset(&tv, 0, sizeof(tv));
		tv.tv_sec = 5;

		FD_SET(sock, &rfd);
		int res = select(sock+1, &rfd, &wfd, NULL, &tv);
		if (res == -1) {
			msg_log(LOG_ALERT, "FATAL: something REALLY BAD: %s!", strerror(errno));
			return 5;
		}

		if (res == 0) {
			if (write_stamp < (time(NULL)-3600)) {
				do_quit = true; // 1 hour without data, stop here
			}
			continue;
		}

		if (FD_ISSET(sock, &rfd)) {
			char buf[65536];
			res = recv(sock, &buf, 65535, 0); //MSG_DONTWAIT);
			if (write_stamp < (time(NULL)-60)) {
				write_stamp = time(NULL);
				if (transmit != -1) {
					close(transmit);
					transmit = -1;
				}
			}
			if (res == -1) {
				msg_log(LOG_WARNING, "Packet reception failed: %s", strerror(errno));
				continue;
			}
			if (res == 0) continue;
			// append to file
			buf[res] = '\n'; // add a linebreak
			if (transmit == -1) {
				// need to open a new file
				char filename[PATH_MAX];
				memset(&filename, 0, PATH_MAX);
				snprintf(filename, PATH_MAX-1, "%s_%ld.log", opt_target, time(NULL));
				transmit = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0777);
				if (transmit == -1) {
					msg_log(LOG_ALERT, "Failed to open output: %s", strerror(errno));
					return 6;
				}
			}
			int wres = write(transmit, buf, res+1); // write as many bytes we could read + 1
			if (wres == -1) {
				msg_log(LOG_ALERT, "Failed to write to file: %s", strerror(errno));
				return 4;
			}
			if (wres != res+1) {
				msg_log(LOG_ALERT, "Failed to write to file");
				return 5;
			}
		}
	}

	return 0;
}

