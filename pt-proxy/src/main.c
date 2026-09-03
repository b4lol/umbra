/*
 * umbra-pt-proxy — standalone pluggable-transport client proxy.
 *
 * STATUS: SKELETON — NOT FUNCTIONAL (see README.md roadmap). The
 * loopback-only SOCKS5 listener and process hygiene are in place; the
 * obfs4 protocol is NOT implemented, so every accepted connection is
 * closed immediately. Umbra talks to this proxy exclusively through a
 * loopback SOCKS5 endpoint (ADR-030 unmanaged model); this binary is
 * never spawned or linked by an Umbra process.
 *
 * Security invariants (must survive every future change):
 *  1. The listener binds LOOPBACK ONLY — enforced by parsing the bind
 *     address numerically and rejecting anything outside 127.0.0.0/8
 *     and ::1 BEFORE any socket syscall.
 *  2. No files are opened, ever (the proxy needs no state); a future
 *     Seccomp profile will enforce this.
 *  3. All secrets (once the obfs4 key schedule exists) are wiped with
 *     explicit_bzero() on every teardown path.
 */

/* Linux-only component (Umbra targets Linux/Android): _GNU_SOURCE for
 * accept4() and SOCK_CLOEXEC (close-on-exec by construction — no fd can
 * leak into a child if exec is ever added by mistake). */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socks5.h"

/* Default endpoint; override with --socks HOST:PORT. */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT "9444"
#define LISTEN_BACKLOG 16

/* Set by the signal handlers; checked in the accept loop. */
static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

/* Loopback gate: the ONLY addresses this proxy may bind. */
static int address_is_loopback(const char *host)
{
    struct in_addr v4;
    struct in6_addr v6;
    static const struct in6_addr V6_LOOPBACK = IN6ADDR_LOOPBACK_INIT;

    if (inet_pton(AF_INET, host, &v4) == 1) {
        /* The entire 127.0.0.0/8 block is loopback (RFC 1122). */
        return (ntohl(v4.s_addr) >> 24U) == 0x7fU;
    }
    if (inet_pton(AF_INET6, host, &v6) == 1) {
        return memcmp(&v6, &V6_LOOPBACK, sizeof(v6)) == 0;
    }
    /* Non-numeric (DNS) bind hosts are rejected outright: name
     * resolution here would be an uncontrolled network dependency. */
    return 0;
}

/* Port gate: 1–65535, decimal digits only. */
static int parse_port(const char *text, uint16_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || *text == '\0') {
        return -1;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0UL || value > 65535UL) {
        return -1;
    }
    *out = (uint16_t)value;
    return 0;
}

/* Splits "HOST:PORT" (IPv6 in [brackets]) and enforces the loopback
 * and port gates. Returns 0 on success. */
static int parse_endpoint(const char *spec, char *host, size_t host_len, uint16_t *port)
{
    const char *host_begin = spec;
    const char *host_end;
    const char *port_begin;
    size_t len;

    if (spec[0] == '[') {
        /* [v6]:port form. */
        const char *close = strchr(spec, ']');
        if (close == NULL || close[1] != ':') {
            return -1;
        }
        host_begin = spec + 1;
        host_end = close;
        port_begin = close + 2;
    } else {
        const char *colon = strrchr(spec, ':');
        if (colon == NULL) {
            return -1;
        }
        host_end = colon;
        port_begin = colon + 1;
    }

    len = (size_t)(host_end - host_begin);
    if (len == 0 || len >= host_len) {
        return -1;
    }
    memcpy(host, host_begin, len);
    host[len] = '\0';

    if (parse_port(port_begin, port) != 0) {
        return -1;
    }
    if (!address_is_loopback(host)) {
        fprintf(stderr, "umbra-pt-proxy: refusing non-loopback bind address '%s'\n", host);
        return -1;
    }
    return 0;
}

/* Binds and listens on the validated loopback endpoint. Returns the
 * listening socket or -1 (diagnostic already printed). */
static int open_listener(const char *host, uint16_t port)
{
    int fd = -1;
    int family = (strchr(host, ':') != NULL) ? AF_INET6 : AF_INET;
    int one = 1;

    fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("umbra-pt-proxy: socket");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one)) != 0) {
        perror("umbra-pt-proxy: setsockopt");
        close(fd);
        return -1;
    }

    if (family == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &addr.sin_addr) != 1
            || bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) != 0) {
            perror("umbra-pt-proxy: bind");
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, host, &addr6.sin6_addr) != 1
            || bind(fd, (struct sockaddr *)&addr6, (socklen_t)sizeof(addr6)) != 0) {
            perror("umbra-pt-proxy: bind");
            close(fd);
            return -1;
        }
    }

    if (listen(fd, LISTEN_BACKLOG) != 0) {
        perror("umbra-pt-proxy: listen");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    char host[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    const char *spec = DEFAULT_HOST ":" DEFAULT_PORT;
    int listener;
    struct sigaction sa;

    if (argc == 3 && strcmp(argv[1], "--socks") == 0) {
        spec = argv[2];
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--socks HOST:PORT]  (loopback only)\n", argv[0]);
        return 2;
    }
    if (parse_endpoint(spec, host, sizeof(host), &port) != 0) {
        fprintf(stderr, "umbra-pt-proxy: invalid endpoint '%s'\n", spec);
        return 2;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("umbra-pt-proxy: sigaction");
        return 1;
    }

    listener = open_listener(host, port);
    if (listener < 0) {
        return 1;
    }
    fprintf(stderr, "umbra-pt-proxy: listening on %s:%u (SCAFFOLD — relay disabled until obfs4)\n",
            host, (unsigned int)port);

    while (!g_stop) {
        int conn = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (conn < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("umbra-pt-proxy: accept");
            break;
        }
        /* Sequential handling is deliberate for the scaffold: the
         * listener is loopback-only and per-connection work is bounded
         * by the I/O deadlines in socks5_handle. Threading arrives with
         * the real relay (and its own review). */
        socks5_handle(conn);
        close(conn);
    }

    close(listener);
    return 0;
}
