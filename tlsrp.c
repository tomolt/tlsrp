/* See LICENSE file for copyright and license details. */
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
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

/* get lvalue of the pollfd for the server of the connection with index id */
#define SVPFD(id) (pfds[2*(id)+1])
/* get lvalue of the pollfd for the client of the connection with index id */
#define CLPFD(id) (pfds[2*(id)+2])

typedef int (*attach_func)(int, const struct sockaddr *, socklen_t);

struct buffer {
	size_t length;
	char  *data;
};

struct conn {
	struct buffer sv2cl;
	struct buffer cl2sv;
	struct tls *tls;
	int clinevt;
	int cloutevt;
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
size_t         numconns;
size_t         capconns;

static int
moreconns(void)
{
	void *mem;
	capconns = capconns ? 2 * capconns : 16;
	/* TODO reallocarray() */
	mem = realloc(conns,
		capconns * sizeof *conns +
		(1+2*capconns) * sizeof *pfds);
	if (!mem) {
		warn("insufficient memory");
		return -1;
	}
	conns = mem;
	pfds = (void *)&conns[capconns];
	return 0;
}

static int
addconn(size_t *idptr)
{
	size_t id;
	void *mem;

	if (numconns + 1 > capconns) {
		if (moreconns() < 0) return -1;
	}

	if (!(mem = malloc(2 * BUFSIZ))) {
		warn("insufficient memory");
		return -1;
	}

	id = numconns++;

	conns[id].sv2cl.length = 0;
	conns[id].sv2cl.data = mem;
	conns[id].cl2sv.length = 0;
	conns[id].cl2sv.data = (char *)mem + BUFSIZ;
	conns[id].tls = NULL;
	conns[id].clinevt = POLLIN;
	conns[id].cloutevt = POLLOUT;

	SVPFD(id).fd = -1;
	SVPFD(id).events = POLLIN | POLLOUT;
	CLPFD(id).fd = -1;
	CLPFD(id).events = POLLIN | POLLOUT;

	*idptr = id;
	return 0;
}

static void
delconn(size_t id)
{
	/* sv2cl & cl2sv are allocated as one block, so only free() the first one! */
	free(conns[id].sv2cl.data);
	if (conns[id].tls) {
		tls_close(conns[id].tls);
		tls_free(conns[id].tls);
	}
	if (SVPFD(id).fd >= 0) close(SVPFD(id).fd);
	if (CLPFD(id).fd >= 0) close(CLPFD(id).fd);

	--numconns;
	conns[id] = conns[numconns];
	SVPFD(id) = SVPFD(numconns);
	CLPFD(id) = CLPFD(numconns);
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
establishconn(int bindfd, struct tls *bindtls)
{
	struct sockaddr_storage client_sa = { 0 };
	socklen_t client_sa_len = 0;
	size_t id;

	if (addconn(&id) < 0) return -1;

	CLPFD(id).fd = accept(bindfd,
		(struct sockaddr *)&client_sa,
		&client_sa_len);
	if (CLPFD(id).fd < 0) goto fail;

	if (tls_accept_socket(bindtls, &conns[id].tls, CLPFD(id).fd) < 0) {
		warn("tls_accept_socket(): %s", tls_error(bindtls));
		goto fail;
	}

	SVPFD(id).fd = backpath ? unixsocket(backpath, connect) :
		networksocket(backhost, backport, connect);
	if (SVPFD(id).fd < 0) goto fail;

	return 0;

fail:
	delconn(id);
	return -1;
}

static int
clin(struct conn *conn)
{
	ssize_t ret = tls_read(conn->tls,
		conn->cl2sv.data + conn->cl2sv.length,
		BUFSIZ - conn->cl2sv.length);
	switch (ret) {
	case -1:
		warn("tls_read(): %s", tls_error(conn->tls));
		return -1;
	case TLS_WANT_POLLIN:
		conn->clinevt = POLLIN;
		return 0;
	case TLS_WANT_POLLOUT:
		conn->clinevt = POLLOUT;
		return 0;
	default:
		conn->cl2sv.length += ret;
		conn->clinevt = POLLIN;
		return 0;
	}
}

static int
clout(struct conn *conn)
{
	ssize_t ret = tls_write(conn->tls, conn->sv2cl.data, conn->sv2cl.length);
	switch (ret) {
	case -1:
		warn("tls_write(): %s", tls_error(conn->tls));
		return -1;
	case TLS_WANT_POLLIN:
		conn->cloutevt = POLLIN;
		return 0;
	case TLS_WANT_POLLOUT:
		conn->cloutevt = POLLOUT;
		return 0;
	default:
		conn->sv2cl.length -= ret;
		memmove(conn->sv2cl.data, conn->sv2cl.data + ret,
			conn->sv2cl.length);
		conn->cloutevt = POLLOUT;
		return 0;
	}
}

static int
svin(struct conn *conn, int fd)
{
	for (;;) {
		ssize_t ret = read(fd,
			conn->sv2cl.data + conn->sv2cl.length,
			BUFSIZ - conn->sv2cl.length);
		if (ret > 0) {
			conn->sv2cl.length += ret;
			return 0;
		}
		if (!ret) {
			return 0;
		}
		if (errno != EINTR) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
			warn("read():");
			return -1;
		}
	}
}

static int
svout(struct conn *conn, int fd)
{
	for (;;) {
		ssize_t ret = write(fd,
			conn->cl2sv.data,
			conn->cl2sv.length);
		if (ret > 0) {
			conn->cl2sv.length -= ret;
			memmove(conn->cl2sv.data, conn->cl2sv.data + ret,
				conn->cl2sv.length);
			return 0;
		}
		if (errno != EINTR) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
			warn("write():");
			return -1;
		}
	}
}

static int
serve(size_t id)
{
	struct conn *conn = &conns[id];
	struct pollfd *clp = &CLPFD(id), *svp = &SVPFD(id);

	if ((clp->revents | svp->revents) & POLLNVAL)
		return -1;

	if (clp->revents & conn->clinevt) {
		if (clin(conn) < 0) return -1;
	}
	if (svp->revents & POLLIN) {
		if (svin(conn, svp->fd) < 0) return -1;
	}
	if (clp->revents & conn->cloutevt) {
		if (clout(conn) < 0) return -1;
	}
	if (svp->revents & POLLOUT) {
		if (svout(conn, svp->fd) < 0) return -1;
	}

	if ((clp->revents | svp->revents) & POLLHUP)
		if (!conn->sv2cl.length && !conn->cl2sv.length)
			return -1;
	if ((clp->revents | svp->revents) & POLLERR)
		return -1;

	svp->events = (conn->sv2cl.length < BUFSIZ/2 ? POLLIN : 0) |
		(conn->cl2sv.length < BUFSIZ/2 ? 0 : POLLOUT);
	clp->events = (conn->sv2cl.length < BUFSIZ/2 ? 0 : conn->cloutevt) |
		(conn->cl2sv.length < BUFSIZ/2 ? conn->clinevt : 0);

	return 0;
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-u backpath | -p backport [-h backhost]]"
	                " [-U frontpath | -P frontport [-H fronthost]]"
	                " ca-file cert-file key-file\n", argv0);
}

int 
main(int argc, char **argv)
{
	int bindfd = 0;
	struct tls_config *config;
	struct tls *bindtls;
	int status;

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

	if (!(bindtls = tls_server()))
		die("failed to create server context");

	if ((tls_configure(bindtls, config)) < 0)
		tdie(bindtls, "failed to configure server:");

	tls_config_free(config);

	bindfd = frontpath ? unixsocket(frontpath, bind) :
		networksocket(fronthost, frontport, bind);

	pfds = calloc(1, sizeof *pfds);
	pfds[0].fd = bindfd;
	pfds[0].events = POLLIN;

	if (listen(bindfd, BACKLOG) < 0)
		die("cannot listen on socket:");

	for (;;) {
		status = poll(pfds, numconns, -1);
		if (!status) continue;
		if (status < 0) {
			if (errno == EINTR) continue;
			warn("poll():");
			continue;
		}

		if (pfds[0].revents) {
			status--;
			establishconn(bindfd, bindtls);
		}

		size_t id;
		for (id = 0; status; id++) {
			int active = 0;
			if (SVPFD(id).events) status--, active = 1;
			if (CLPFD(id).events) status--, active = 1;
			if (active) {
				if (serve(id) < 0) {
					delconn(id);
					id--;
				}
			}
		}
	}
}

