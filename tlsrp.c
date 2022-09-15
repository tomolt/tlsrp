/* See LICENSE file for copyright and license details. */
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>

#include "util.h"
#include "config.h"
#include "arg.h"


typedef int (*attach_func)(int, const struct sockaddr *, socklen_t);

#define OK    0x0
#define FIN   0x1
#define RESET 0x2

struct conn {
	struct tls *tls;
	char *data; /* to be sent over this connection */
	size_t length; /* of data */
	int fin;
	int inevent;
	int outevent;
};

char *argv0;

char *cafile;
char *certfile;
char *keyfile;

char *backpath;
char *backhost;
char *backport;

char *frontpath;
char *fronthost;
char *frontport;

struct conn   *conns;
struct pollfd *pfds;
int            numconns;
int            capconns;

volatile int interrupted;
volatile int reconfplease;

static int
moreconns(void)
{
	/* TODO overflow checks */
	void *mem;
	int newcap = capconns ? 2 * capconns : 16;
	
	/* TODO reallocarray() */
	mem = realloc(conns, newcap * sizeof *conns);
	if (!mem) {
		warn("insufficient memory");
		return -1;
	}
	conns = mem;

	mem = realloc(pfds, (1+2*newcap) * sizeof *pfds);
	if (!mem) {
		warn("insufficient memory");
		return -1;
	}
	pfds = mem;

	capconns = newcap;
	return 0;
}

static int
addconn(void)
{
	void *mem;
	int id;

	if (numconns + 1 > capconns) {
		if (moreconns() < 0) return -1;
	}

	if (!(mem = malloc(BUFSIZ))) {
		warn("insufficient memory");
		return -1;
	}

	id = numconns++;

	memset(&conns[id], 0, sizeof *conns);
	conns[id].data = mem;
	conns[id].inevent = POLLIN;
	conns[id].outevent = POLLOUT;

	pfds[1+id].fd = -1;
	pfds[1+id].events = POLLIN;
	pfds[1+id].revents = 0;

	return id;
}

static void
delconn(size_t id)
{
	free(conns[id].data);
	if (conns[id].tls) {
		tls_close(conns[id].tls);
		tls_free(conns[id].tls);
	}
	if (pfds[1+id].fd >= 0) close(pfds[1+id].fd);

	--numconns;
	conns[id] = conns[numconns];
	pfds[1+id] = pfds[1+numconns];
}

static int
networksocket(const char *host, const char *port, attach_func attach)
{
	int fd = -1;
	struct addrinfo *results = NULL, *rp = NULL;
	struct addrinfo hints = { .ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM };

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

	freeaddrinfo(results);
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
establishlink(int bindfd, struct tls *bindtls)
{
	struct sockaddr_storage client_sa = { 0 };
	socklen_t client_sa_len = 0;
	int clid, svid;

	if ((clid = addconn()) < 0) goto fail;
	if ((svid = addconn()) < 0) goto fail;

	pfds[1+clid].fd = accept(bindfd,
		(struct sockaddr *)&client_sa,
		&client_sa_len);
	if (pfds[1+clid].fd < 0) goto fail;

	if (tls_accept_socket(bindtls, &conns[clid].tls, pfds[1+clid].fd) < 0) {
		warn("tls_accept_socket(): %s", tls_error(bindtls));
		goto fail;
	}

	pfds[1+svid].fd = backpath ? unixsocket(backpath, connect) :
		networksocket(backhost, backport, connect);
	if (pfds[1+svid].fd < 0) goto fail;

	return 0;

fail:
	/* needs to be inverse order of creation :/ */
	if (svid >= 0) delconn(svid);
	if (clid >= 0) delconn(clid);
	return -1;
}

static int
readtls(int id, char *out, size_t *outlen)
{
	ssize_t ret = tls_read(conns[id].tls,
		out + *outlen, BUFSIZ - *outlen);
	switch (ret) {
	case -1:
		warn("tls_read(): %s", tls_error(conns[id].tls));
		return RESET;
	case TLS_WANT_POLLIN:
		conns[id].inevent = POLLIN;
		return OK;
	case TLS_WANT_POLLOUT:
		conns[id].inevent = POLLOUT;
		return OK;
	case 0:
		return FIN;
	default:
		*outlen += ret;
		conns[id].inevent = POLLIN;
		return OK;
	}
}

static int
writetls(int id)
{
	ssize_t ret = tls_write(conns[id].tls,
		conns[id].data, conns[id].length);
	switch (ret) {
	case -1:
		warn("tls_write(): %s", tls_error(conns[id].tls));
		return RESET;
	case TLS_WANT_POLLIN:
		conns[id].outevent = POLLIN;
		return OK;
	case TLS_WANT_POLLOUT:
		conns[id].outevent = POLLOUT;
		return OK;
	case 0:
		return FIN;
	default:
		conns[id].length -= ret;
		memmove(conns[id].data, conns[id].data + ret,
			conns[id].length);
		conns[id].outevent = POLLOUT;
		return OK;
	}
}

static int
readraw(int id, char *out, size_t *outlen)
{
	for (;;) {
		ssize_t ret = read(pfds[1+id].fd,
			out + *outlen, BUFSIZ - *outlen);
		if (ret > 0) {
			*outlen += ret;
			return OK;
		}
		if (!ret) return FIN;
		if (errno == EINTR) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return OK;
			warn("read():");
			return RESET;
		}
	}
}

static int
writeraw(int id)
{
	for (;;) {
		ssize_t ret = write(pfds[1+id].fd,
			conns[id].data,
			conns[id].length);
		if (ret > 0) {
			conns[id].length -= ret;
			memmove(conns[id].data, conns[id].data + ret,
				conns[id].length);
			return OK;
		}
		if (errno != EINTR) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return OK;
			warn("write():");
			return RESET;
		}
	}
}

static int
serve(int id, char *out, size_t *outlen)
{
	int revents = pfds[1+id].revents;
	int status = OK;

	if (revents & POLLNVAL) return RESET;

	if (!conns[id].fin && (revents & POLLIN) && *outlen < BUFSIZ) {
		status |= (conns[id].tls ? readtls : readraw)(id, out, outlen);
		if (status & FIN) conns[id].fin = 1;
		if (status & RESET) return status;
	}

	if ((revents & POLLOUT) && conns[id].length > 0) {
		status |= (conns[id].tls ? writetls : writeraw)(id);
		if (status & RESET) return status;
	}

	return status;
}

static void
chooseevents(int id, size_t outlen)
{
	pfds[1+id].events = (outlen < BUFSIZ/2 ? conns[id].inevent : 0) |
		(conns[id].length > 0 ? conns[id].outevent : 0);
}

static void
handlesignal(int signal)
{
	switch (signal) {
	case SIGINT:
		interrupted = 1;
		break;
	case SIGHUP:
		reconfplease = 1;
		break;
	}
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-u backpath | -p backport [-h backhost]]"
	                " [-U frontpath | -P frontport [-H fronthost]]"
	                " ca-file cert-file key-file\n", argv0);
}

static void
reconfigure(struct tls *bindtls)
{
	struct tls_config *config;

	if (!(config = tls_config_new()))
		tcdie(config, "failed to get tls config:");

	if (tls_config_set_protocols(config, protocols) < 0)
		tcdie(config, "failed to set protocols:");
	if (tls_config_set_ciphers(config, ciphers) < 0)
		tcdie(config, "failed to set ciphers:");
	if (tls_config_set_dheparams(config, dheparams) < 0)
		tcdie(config, "failed to set dheparams:");
	if (tls_config_set_ecdhecurves(config, ecdhecurves) < 0)
		tcdie(config, "failed to set ecdhecurves:");
	if (tls_config_set_ca_file(config, cafile) < 0)
		tcdie(config, "failed to load ca file:");
	if (tls_config_set_cert_file(config, certfile) < 0)
		tcdie(config, "failed to load cert file:");
	if (tls_config_set_key_file(config, keyfile) < 0)
		tcdie(config, "failed to load key file:");

	if ((tls_configure(bindtls, config)) < 0)
		tdie(bindtls, "failed to configure server:");

	tls_config_free(config);
}

int 
main(int argc, char **argv)
{
	struct sigaction action = { 0 };
	int bindfd = 0;
	struct tls *bindtls;
	int status, cmd;
	int id;

	action.sa_handler = handlesignal;
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);

	ARGBEGIN {
	case 'h': backhost  = EARGF(usage()); break;
	case 'H': fronthost = EARGF(usage()); break;
	case 'p': backport  = EARGF(usage()); break;
	case 'P': frontport = EARGF(usage()); break;
	case 'u': backpath  = EARGF(usage()); break;
	case 'U': frontpath = EARGF(usage()); break;
	case 'v':
		printf("%s %s\n", argv0, VERSION);
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
	if (argc != 3) {
		usage();
		exit(1);
	}
	cafile   = *argv++;
	certfile = *argv++;
	keyfile  = *argv++;

	if ((backpath && backhost) || !(backpath || backport))
		die("can only serve on unix socket xor network socket");
	if ((frontpath && fronthost) || !(frontpath || frontport))
		die("can only receive on unix socket xor network socket");

	if (!(bindtls = tls_server()))
		die("failed to create server context");
	reconfigure(bindtls);

	bindfd = frontpath ? unixsocket(frontpath, bind) :
		networksocket(fronthost, frontport, bind);

	pfds = calloc(1, sizeof *pfds);
	pfds[0].fd = bindfd;
	pfds[0].events = POLLIN;

	if (listen(bindfd, BACKLOG) < 0)
		die("cannot listen on socket:");

	while (!interrupted) {
		if (reconfplease) {
			fprintf(stderr, "Received interrupt. Reconfiguring.\n");
			tls_reset(bindtls);
			reconfigure(bindtls);
			reconfplease = 0;
		}
		/* If a signal occurs right before poll(), it will have to
		 * wait until the next I/O takes place. This is a bug, but
		 * fixing it might not be worth the effort. */
		status = poll(pfds, 1+numconns, -1);
		if (!status) continue;
		if (status < 0) {
			if (errno == EINTR) continue;
			warn("poll():");
			continue;
		}

		if (pfds[0].revents) {
			status--;
			establishlink(bindfd, bindtls);
		}

		for (id = 0; id < numconns && status; id++) {
			if (!pfds[1+id].revents) continue;
			status--;
			cmd = serve(id, conns[id^1].data, &conns[id^1].length);
			chooseevents(id, conns[id^1].length);
			chooseevents(id^1, conns[id].length);
			if ((cmd & FIN) && !conns[id^1].tls) {
				shutdown(pfds[1+(id^1)].fd, SHUT_WR);
			}
			if (cmd & RESET) {
				delconn(id|1);
				delconn(id&~1);
				id -= 2;
			}
		}
	}

	fprintf(stderr, "Received interrupt. Exiting.\n");

	while (numconns) {
		delconn(numconns-1);
	}
	free(conns);
	free(pfds);
	tls_close(bindtls);
	tls_free(bindtls);
	close(bindfd);
}

