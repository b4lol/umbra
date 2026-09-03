/*
 * SOCKS5 (RFC 1928) front-end — see socks5.h for the architecture
 * notes and the security invariants.
 */

#define _GNU_SOURCE

#include "socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Per-connection I/O deadline: a stalled client must not pin a worker. */
#define IO_TIMEOUT_SEC 10
/* Upstream dial deadline (non-blocking connect + poll). */
#define DIAL_TIMEOUT_MS 10000

#define SOCKS_VERSION 0x05u
#define METHOD_NO_AUTH 0x00u
#define METHOD_REJECT 0xffu
#define CMD_CONNECT 0x01u
#define ATYP_IPV4 0x01u
#define ATYP_DOMAIN 0x03u
#define ATYP_IPV6 0x04u

/* Reply codes (RFC 1928 §6). */
#define REP_SUCCEEDED 0x00u
#define REP_GENERAL_FAILURE 0x01u
#define REP_NOT_ALLOWED 0x02u
#define REP_NET_UNREACHABLE 0x03u
#define REP_HOST_UNREACHABLE 0x04u
#define REP_REFUSED 0x05u
#define REP_TTL_EXPIRED 0x06u
#define REP_CMD_UNSUPPORTED 0x07u
#define REP_ATYP_UNSUPPORTED 0x08u

/* Reads exactly len bytes or fails (EOF, error, timeout all collapse
 * into -1: every one of them aborts the connection). */
static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n == 0) {
            return -1; /* peer closed mid-frame */
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/* Method-selection reply (2 bytes). */
static int send_method_reply(int fd, uint8_t method)
{
    const uint8_t reply[2] = {SOCKS_VERSION, method};
    return write_full(fd, reply, sizeof(reply));
}

/* CONNECT reply: fixed 0.0.0.0:0 bind field — the bound address tells
 * the client nothing useful here and disclosing it would leak the
 * proxy's egress interface choice. */
static int send_connect_reply(int fd, uint8_t rep)
{
    const uint8_t reply[10] = {
        SOCKS_VERSION, rep, 0x00u, ATYP_IPV4, 0, 0, 0, 0, 0, 0,
    };
    return write_full(fd, reply, sizeof(reply));
}

/* Maps a failed connect()'s errno onto the RFC 1928 reply code. */
static uint8_t rep_from_errno(int err)
{
    switch (err) {
    case ECONNREFUSED:
        return REP_REFUSED;
    case ENETUNREACH:
        return REP_NET_UNREACHABLE;
    case EHOSTUNREACH:
        return REP_HOST_UNREACHABLE;
    case ETIMEDOUT:
        return REP_TTL_EXPIRED;
    case EACCES:
    case EPERM:
        return REP_NOT_ALLOWED;
    default:
        return REP_GENERAL_FAILURE;
    }
}

/* Bounded, deadline-guarded connect to host/port. Returns the
 * connected socket or -1 with *rep set for the client reply. */
static int dial_upstream(const char *host, uint16_t port, uint8_t *rep)
{
    struct addrinfo hints;
    struct addrinfo *list = NULL;
    char service[6];
    int fd = -1;
    int gai;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    if (snprintf(service, sizeof(service), "%u", (unsigned int)port) < 0) {
        *rep = REP_GENERAL_FAILURE;
        return -1;
    }
    /* NOTE: a DOMAIN target resolves through the system resolver. That
     * is intentional for THIS component: the proxy is the designated
     * place where name resolution may happen (Umbra itself never does
     * DNS; the Seccomp kill-switch blocks it there). */
    gai = getaddrinfo(host, service, &hints, &list);
    if (gai != 0) {
        fprintf(stderr, "umbra-pt-proxy: resolve %s: %s\n", host, gai_strerror(gai));
        *rep = REP_HOST_UNREACHABLE;
        return -1;
    }

    for (struct addrinfo *ai = list; ai != NULL; ai = ai->ai_next) {
        int flags;
        struct pollfd pfd;
        int so_error = 0;
        socklen_t optlen = (socklen_t)sizeof(so_error);

        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break; /* rare instant success */
        }
        if (errno != EINPROGRESS) {
            *rep = rep_from_errno(errno);
            close(fd);
            fd = -1;
            continue;
        }
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, DIAL_TIMEOUT_MS) <= 0) {
            *rep = REP_TTL_EXPIRED;
            close(fd);
            fd = -1;
            continue;
        }
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) != 0 || so_error != 0) {
            *rep = rep_from_errno(so_error != 0 ? so_error : errno);
            close(fd);
            fd = -1;
            continue;
        }
        break; /* connected */
    }
    freeaddrinfo(list);

    if (fd >= 0) {
        /* Back to blocking mode for the (future) relay loop. */
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
            close(fd);
            *rep = REP_GENERAL_FAILURE;
            return -1;
        }
    } else if (*rep == 0) {
        *rep = REP_GENERAL_FAILURE; /* address list exhausted */
    }
    return fd;
}

/* Parses the CONNECT request's address field. Returns the atyp on
 * success (host filled, port set) or 0 on a parse failure. */
static uint8_t parse_address(int fd, char *host, size_t host_len, uint16_t *port)
{
    uint8_t atyp;
    uint8_t len;
    uint8_t raw[16];
    uint8_t port_be[2];

    if (read_full(fd, &atyp, 1) != 0) {
        return 0;
    }
    switch (atyp) {
    case ATYP_IPV4:
        if (read_full(fd, raw, 4) != 0) {
            return 0;
        }
        if (inet_ntop(AF_INET, raw, host, (socklen_t)host_len) == NULL) {
            return 0;
        }
        break;
    case ATYP_IPV6:
        if (read_full(fd, raw, 16) != 0) {
            return 0;
        }
        if (inet_ntop(AF_INET6, raw, host, (socklen_t)host_len) == NULL) {
            return 0;
        }
        break;
    case ATYP_DOMAIN:
        if (read_full(fd, &len, 1) != 0 || len == 0
            || read_full(fd, raw, len) != 0 || (size_t)len >= host_len) {
            return 0;
        }
        memcpy(host, raw, len);
        host[len] = '\0';
        break;
    default:
        /* Unknown address type: answered with 0x08 by the caller. */
        return atyp;
    }
    if (read_full(fd, port_be, 2) != 0) {
        return 0;
    }
    *port = (uint16_t)(((uint16_t)port_be[0] << 8U) | (uint16_t)port_be[1]);
    return atyp;
}

void socks5_handle(int conn_fd)
{
    uint8_t header[2];
    uint8_t methods[255];
    uint8_t request[3];
    char host[256];
    uint16_t port = 0;
    uint8_t atyp;
    uint8_t rep;
    int upstream;
    int no_auth_seen = 0;
    const struct timeval timeout = {.tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0};

    /* I/O deadlines on both directions of the client socket. */
    if (setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, (socklen_t)sizeof(timeout)) != 0
        || setsockopt(conn_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, (socklen_t)sizeof(timeout))
               != 0) {
        perror("umbra-pt-proxy: setsockopt");
        return;
    }

    /* --- Greeting: VER NMETHODS METHODS... --- */
    if (read_full(conn_fd, header, 2) != 0 || header[0] != SOCKS_VERSION) {
        return; /* not SOCKS5: close silently (could be a port scanner) */
    }
    if (header[1] == 0 || read_full(conn_fd, methods, header[1]) != 0) {
        return;
    }
    for (uint8_t i = 0; i < header[1]; i++) {
        if (methods[i] == METHOD_NO_AUTH) {
            no_auth_seen = 1;
            break;
        }
    }
    /* No-auth ONLY: this proxy must stay unusable as an open relay even
     * before obfs4 lands; credential methods are out of scope. */
    if (!no_auth_seen) {
        (void)send_method_reply(conn_fd, METHOD_REJECT);
        return;
    }
    if (send_method_reply(conn_fd, METHOD_NO_AUTH) != 0) {
        return;
    }

    /* --- Request: VER CMD RSV --- */
    if (read_full(conn_fd, request, 3) != 0 || request[0] != SOCKS_VERSION) {
        return;
    }
    if (request[1] != CMD_CONNECT) {
        (void)send_connect_reply(conn_fd, REP_CMD_UNSUPPORTED);
        return;
    }
    /* request[2] (RSV) is ignored per RFC 1928. */

    memset(host, 0, sizeof(host));
    atyp = parse_address(conn_fd, host, sizeof(host), &port);
    if (atyp == 0) {
        return; /* truncated/oversized frame */
    }
    if (atyp != ATYP_IPV4 && atyp != ATYP_IPV6 && atyp != ATYP_DOMAIN) {
        (void)send_connect_reply(conn_fd, REP_ATYP_UNSUPPORTED);
        return;
    }
    if (port == 0) {
        (void)send_connect_reply(conn_fd, REP_NOT_ALLOWED);
        return;
    }

    rep = REP_SUCCEEDED;
    upstream = dial_upstream(host, port, &rep);
    if (upstream < 0) {
        (void)send_connect_reply(conn_fd, rep);
        return;
    }
    if (send_connect_reply(conn_fd, REP_SUCCEEDED) != 0) {
        close(upstream);
        return;
    }

    /* SCAFFOLD BOUNDARY: the bytes that would flow here next are the
     * obfs4 handshake. Relaying the client's plaintext Tor traffic to
     * the bridge would defeat the entire purpose of the transport, so
     * the tunnel is torn down immediately and loudly instead. */
    fprintf(stderr,
            "umbra-pt-proxy: CONNECT %s:%u dialed; relay disabled until obfs4 lands\n",
            host, (unsigned int)port);
    close(upstream);
}
