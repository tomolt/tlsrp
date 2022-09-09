/* See LICENSE file for copyright and license details. */
#include <sys/socket.h>
#include <sys/un.h>

#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>

#include "util.h"
#include "config.h"
#include "arg.h"

#define BACKLOG 10
#define TIMEOUT 1000
#define SERVER 0
#define CLIENT 1

typedef int (*attach_func)(int, const struct sockaddr *, socklen_t);

char *argv0;

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-u backpath | -p backport [-h backhost]] [-U frontpath | -P frontport [-H fronthost]] -a ca_path -r cert_path -k key_path\n", argv0);
}

static int
networksocket(const char *host, const char *port, attach_func attach)
{
	int fd = -1;
	struct addrinfo *results = NULL, *rp = NULL;
	struct addrinfo hints = { .ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM};

	int err;
	if ((err = getaddrinfo(host, port, &hints, &results)) != 0)
		die("dobind: getaddrinfo: %s", gai_strerror(err));

	for (rp = results; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;

		if (attach(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;

		close(fd);
	}

	if (!rp) die("failed to create network socket:");

	free(results);
	return fd;
}

static int
unixsocket(const char *path, attach_func attach)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	if (!memccpy(addr.sun_path, path, '\0', sizeof addr.sun_path))
		die("unix socket path too long:");

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		die("failed to create unix socket at %s:", path);

	if (attach(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0)
		die("failed to attach to unix socket at %s:", path);

	return fd;
}

static int
serve(int serverfd, int clientfd, struct tls *clientconn)
{
	struct pollfd pfd[] = {
		{serverfd, POLLIN | POLLOUT, 0},
		{clientfd, POLLIN | POLLOUT, 0}
	};

	char clibuf[BUFSIZ] = {0};
	char serbuf[BUFSIZ] = {0};

	char *cliptr = NULL, *serptr = NULL;

	ssize_t clicount = 0, sercount = 0;
	ssize_t written = 0;

	while (poll(pfd, 2, TIMEOUT) != 0) {
		if ((pfd[CLIENT].revents | pfd[SERVER].revents) & POLLNVAL)
			return -1;

		if ((pfd[CLIENT].revents & POLLIN) && clicount == 0) {
			clicount = tls_read(clientconn, clibuf, BUFSIZ);
			if (clicount == -1) {
				tdie(clientconn, "client read failed:");
				return -2;
			} else if (clicount == TLS_WANT_POLLIN) {
				pfd[CLIENT].events = POLLIN;
			} else if (clicount == TLS_WANT_POLLOUT) {
				pfd[CLIENT].events = POLLOUT;
			} else {
				cliptr = clibuf;
			}
		}

		if ((pfd[SERVER].revents & POLLIN) && sercount == 0) {
			sercount = read(serverfd, serbuf, BUFSIZ);
			if (sercount == -1) {
				die("server read failed:");
				return -3;
			}
			serptr = serbuf;
		}

		if ((pfd[SERVER].revents & POLLOUT) && clicount > 0) {
			written = write(serverfd, cliptr, clicount);
			if (written == -1)
				die("failed to write:");
			clicount -= written;
			cliptr += written;
		}

		if ((pfd[CLIENT].revents & POLLOUT) && sercount > 0) {
			written = tls_write(clientconn, serptr, sercount);
			if (written == -1)
				tdie(clientconn, "failed tls_write:");
			else if (written == TLS_WANT_POLLIN) {
				pfd[CLIENT].events = POLLIN;
			} else if (written == TLS_WANT_POLLOUT) {
				pfd[CLIENT].events = POLLOUT;
			} else {
				sercount -= written;
				serptr += written;
			}
		}

		if ((pfd[CLIENT].revents | pfd[SERVER].revents) & POLLHUP)
			if (clicount == 0 && sercount == 0)
				break;

		if ((pfd[CLIENT].revents | pfd[SERVER].revents) & POLLERR)
			break;
	}
	return 0;
}

int 
main(int argc, char* argv[])
{
	int serverfd = 0, clientfd = 0, bindfd = 0;
	struct sockaddr_storage client_sa = {0};
	struct tls_config *config;
	struct tls *toclient, *conn;
	socklen_t client_sa_len = 0;
	char *backpath = NULL,
	     *frontpath = NULL,
	     *backhost  = NULL,
	     *fronthost  = NULL,
	     *backport = NULL,
	     *frontport = NULL,
	     *ca_path = NULL,
	     *cert_path = NULL,
	     *key_path = NULL;

	ARGBEGIN {
	case 'a':
		ca_path = EARGF(usage());
		break;
	case 'h':
		backhost = EARGF(usage());
		break;
	case 'H':
		fronthost = EARGF(usage());
		break;
	case 'k':
		key_path = EARGF(usage());
		break;
	case 'p':
		backport = EARGF(usage());
		break;
	case 'P':
		frontport = EARGF(usage());
		break;
	case 'r':
		cert_path = EARGF(usage());
		break;
	case 'u':
		backpath = EARGF(usage());
		break;
	case 'U':
		frontpath = EARGF(usage());
		break;
	case 'v':
		printf("%s " VERSION "\n", argv0);
		exit(0);
		break;
	case '?':
		usage();
		exit(0);
		break;
	default:
		usage();
		exit(1);
	} ARGEND

	if ((backpath && backhost) || !(backpath || backport))
		die("can only serve on unix socket xor network socket");

	if ((frontpath && fronthost) || !(frontpath || frontport))
		die("can only receive on unix socket xor network socket");

	if (!ca_path || !cert_path || !key_path)
		die("must provide ca_path, cert_path and key_path");

	if ((config = tls_config_new()) == NULL)
		tcdie(config, "failed to get tls config:");

	if (tls_config_set_protocols(config, protocols) == -1)
		tcdie(config, "failed to set protocols:");

	if (tls_config_set_ciphers(config, ciphers) == -1)
		tcdie(config, "failed to set ciphers:");

	if (tls_config_set_dheparams(config, dheparams) == -1)
		tcdie(config, "failed to set dheparams:");

	if (tls_config_set_ecdhecurves(config, ecdhecurves) == -1)
		tcdie(config, "failed to set ecdhecurves:");

	if (tls_config_set_ca_file(config, ca_path) == -1)
		tcdie(config, "failed to load ca file:");

	if (tls_config_set_cert_file(config, cert_path) == -1)
		tcdie(config, "failed to load cert file:");

	if (tls_config_set_key_file(config, key_path) == -1)
		tcdie(config, "failed to load key file:");

	if ((toclient = tls_server()) == NULL)
		die("failed to create server context");

	if ((tls_configure(toclient, config)) == -1)
		tdie(toclient, "failed to configure server:");

	tls_config_free(config);

	if (frontpath)
		bindfd = unixsocket(frontpath, bind);
	else
		bindfd = networksocket(fronthost, frontport, bind);

	if (listen(bindfd, BACKLOG) == -1) {
		close(bindfd);
		die("could not start listen:");
	}

	pid_t pid;

	while (1) {
		if ((clientfd = accept(bindfd, (struct sockaddr*) &client_sa, 
						&client_sa_len)) == -1) {
			warn("could not accept connection:");
			continue;
		}

		switch ((pid = fork())) {
		case 0:
			if (backpath)
				serverfd = unixsocket(backpath, connect);
			else
				serverfd = networksocket(backhost, backport, connect);

			if (tls_accept_socket(toclient, &conn, clientfd) == -1) {
				warn("tls_accept_socket: %s", tls_error(toclient));
				goto tlsfail;
			}

			if (serverfd)
				serve(serverfd, clientfd, conn);

			tls_close(conn);
tlsfail:
			close(serverfd);
			close(clientfd);
			close(bindfd);
			exit(0);
			break;
		case -1:
			warn("fork:");
			/* fallthrough */
		default:
			close(clientfd);
		}
	}
}

