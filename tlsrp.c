#include <stdio.h>
#include <string.h>
#include <bsd/string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>
#include <libressl/tls.h>

#include "util.h"

// capped at 104 for portability
#define SUN_PATH_LENGTH 104
#define BACKLOG 10
#define BUF_SIZE 1024
#define TIMEOUT 1000
#define SERVER 0
#define CLIENT 1

void 
usage()
{
    puts("usage: tlsrp [-h host] -p port -f PORT");
    puts("       tlsrp -U unixsocket -f PORT");
	exit(1);
}

// TODO add domain support?
static int
dobind(const char *host, const char *port)
{
    int sfd = -1;
    struct addrinfo *results = NULL, *rp = NULL;
    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                              .ai_socktype = SOCK_STREAM};

    int err;
    if ((err = getaddrinfo(host, port, &hints, &results)) != 0)
        die("dobind: getaddrinfo: %s", gai_strerror(err));

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(sfd);
    }
    
    if (rp == NULL)
        die("failed to bind:");

    free(results);
    return sfd;
}

static int
dounixconnect(const char *sockname)
{
    int sfd;
    struct sockaddr_un saddr = {0};

    if (strlen(sockname) > SUN_PATH_LENGTH-1)
        die("unix socket path too long");

    saddr.sun_family = AF_UNIX;

    strlcpy((char *) &saddr.sun_path, sockname, SUN_PATH_LENGTH);

    if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        die("failed to create unix socket:");

    if (connect(sfd, (struct sockaddr*)&saddr, sizeof(struct sockaddr_un)) == -1) {
        close(sfd);
        die("failed to connect to unix socket:");
    }

    return sfd;
}

static int
donetworkconnect(const char* host, const char* port)
{
    int sfd = -1;
    struct addrinfo *results = NULL, *rp = NULL;
    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                              .ai_socktype = SOCK_STREAM};

    if (getaddrinfo(host, port, &hints, &results) != 0)
        die("getaddrinfo failed:");

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(sfd);
    }
    
    if (rp == NULL)
        warn("failed to connect:");

    free(results);
    return sfd;
}

static void dowrite(int fd, char* buf, size_t towrite) {
    ssize_t written = 0;
    while (towrite > 0) {
        written = write(fd, buf, towrite);
        if (written == -1)
            die("failed to write:");
        towrite -= written;
        buf += written;
    }
}

static void dotlswrite(struct tls *tlss, char* buf, size_t towrite) {
    ssize_t written = 0;
    while (towrite > 0) {
        written = tls_write(tlss, buf, towrite);
        if (written == -1)
            die("failed to write:");
        towrite -= written;
        buf += written;
    }
}

static int
serve(int serverfd, int clientfd, struct tls *clientconn)
{
    struct pollfd pfd[] = {
        {serverfd, POLLIN | POLLOUT, 0},
        {clientfd, POLLIN | POLLOUT, 0}
    };

    char clibuf[BUF_SIZE] = {0};
    char serbuf[BUF_SIZE] = {0};

    size_t clicount = 0, sercount = 0;

    while (poll(pfd, 2, TIMEOUT) != 0) {
        if ((pfd[CLIENT].revents | pfd[SERVER].revents) & POLLNVAL)
            return -1;

        if ((pfd[CLIENT].revents & POLLIN)) {
            clicount = tls_read(clientconn, clibuf, BUF_SIZE);
            if (clicount == -1) {
                die("client read failed: %s\n", tls_error(clientconn));
                return -2;
            }
        }

        if ((pfd[SERVER].revents & POLLIN)) {
            sercount = read(serverfd, serbuf, BUF_SIZE);
            if (sercount == -1) {
                die("server read failed:");
                return -3;
            }
        }

        if ((pfd[SERVER].revents & POLLOUT) && clicount > 0) {
            dowrite(serverfd, clibuf, clicount);
            clicount = 0;
        }

        if ((pfd[CLIENT].revents & POLLOUT) && sercount > 0) {
            dotlswrite(clientconn, serbuf, sercount);
            sercount = 0;
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
    struct sockaddr_storage client_sa, server_sa = {0};
    struct tls_config *config;
    struct tls *tls_client, *conn;
    socklen_t client_sa_len = 0;
    char *usock = NULL,
         *host  = NULL,
         *backport = NULL,
         *frontport = NULL;

    if (argc < 3)
        usage();

    // TODO make parameter format enforcement stricter
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-U") == 0)
            usock = argv[++i];
        else if (strcmp(argv[i], "-h") == 0)
            host = argv[++i];
        else if (strcmp(argv[i], "-p") == 0)
            backport = argv[++i];
        else if (strcmp(argv[i], "-f") == 0)
            frontport = argv[++i];
        else
            usage();
    }

    if (usock && (host || backport))
        die("cannot use both unix and network socket");

    if ((config = tls_config_new()) == NULL) {
        die("failed to get tls config:");
    }

    if (tls_config_set_ca_file(config, "/home/nihal/projects/libtls/CA/root.pem") == -1) {
        tls_config_free(config);
        die("failed to load ca file:");
    }

    if (tls_config_set_cert_file(config, "/home/nihal/projects/libtls/CA/server.crt") == -1) {
        tls_config_free(config);
        die("failed to load cert file:");
    }

    if (tls_config_set_key_file(config, "/home/nihal/projects/libtls/CA/server.key") == -1) {
        tls_config_free(config);
        die("failed to load key file:");
    }

    if ((tls_client = tls_server()) == NULL) {
        tls_config_free(config);
        die("failed to create server context:");
    }

    if ((tls_configure(tls_client, config)) == -1) {
        tls_config_free(config);
        tls_free(tls_client);
        die("failed to configure server:");
    }
    
    tls_config_free(config);

    bindfd = dobind(NULL, frontport);

    if (listen(bindfd, BACKLOG) == -1) {
        close(bindfd);
        die("could not start listen:");
    }

    pid_t pid;

    while (1) {
        if ((clientfd = accept(bindfd, (struct sockaddr*) &client_sa, 
                        &client_sa_len)) == -1) {
            warn("could not accept connection:");
        }

        switch ((pid = fork())) {
            case -1:
                warn("fork:");
            case 0:
                if (usock)
                    serverfd = dounixconnect(usock);
                else
                    serverfd = donetworkconnect(host, backport);

                if (tls_accept_socket(tls_client, &conn, clientfd) == -1) {
                    warn("tls_accept_socket: %s", tls_error(tls_client));
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
            default:
                close(clientfd);
        }
    }
}

