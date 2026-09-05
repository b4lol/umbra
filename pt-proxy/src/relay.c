/*
 * umbra-pt-proxy — the obfs4 tunnel relay. See relay.h for the
 * architecture notes, the iat-mode shaping design and the security
 * invariants.
 */

/* _GNU_SOURCE must precede every libc include (CLOCK_MONOTONIC +
 * MSG_PEEK under strict -std=c11). */
#define _GNU_SOURCE

#include "relay.h"

#include "obfs4_frame.h"
#include "obfs4_packet.h"
#include "probdist.h"

#include <errno.h>
#include <poll.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Handshake read deadline on the upstream socket (bridges can be slow;
 * the SOCKS5-phase 10 s deadline stays what it is). */
#define RELAY_HANDSHAKE_TIMEOUT_SEC 30
/* Relay idle bound per direction (matches umbra-net's
 * READ_IDLE_TIMEOUT): a tunnel silent for 5 minutes is torn down. */
#define RELAY_IDLE_TIMEOUT_MS 300000

/* Client read burst: one burst = one padding sample (Go Write parity). */
#define RELAY_CLIENT_CHUNK (16u * OBFS4_MAX_PACKET_PAYLOAD)
/* Upstream accumulation buffer: many frames, bounded; a full buffer
 * with no decodable frame is a protocol error. */
#define RELAY_UPSTREAM_BUF (16u * OBFS4_MAX_SEGMENT_LEN)

/* Shaping bounds (lyrebird transports/obfs4/obfs4.go): the length
 * distribution spans [0, MaximumSegmentLength], the iat distribution
 * [0, maxIATDelay] in units of 100 µs. */
#define RELAY_LEN_DIST_MAX ((int32_t)OBFS4_MAX_SEGMENT_LEN)
#define RELAY_IAT_DIST_MAX 100

/* Pending-write queue (iat-mode 1/2): fixed slots, one burst each.
 * A burst is one client read (RELAY_CLIENT_CHUNK) plus padding; the
 * 4-segment slack covers the pad-up paths with wide margin (padding is
 * only ever appended at the burst tail, ≤ ~2 segments). */
#define RELAY_MAX_BURST \
    (RELAY_CLIENT_CHUNK + 4u * OBFS4_MAX_SEGMENT_LEN)
#define RELAY_PEND_SLOTS 4u

typedef struct {
    size_t off;     /* bytes already written */
    size_t len;     /* valid bytes in buf (grows when padded) */
    uint64_t due;   /* monotonic ms at which the next chunk may go out */
    uint8_t raw;    /* mode 2: buf holds raw payload until the head slot */
    uint8_t buf[RELAY_MAX_BURST];
} RelayPending;

typedef struct {
    RelayPending slots[RELAY_PEND_SLOTS];
    size_t head;   /* oldest burst */
    size_t count;  /* queued bursts */
    /* Mode 2 only: the ENCODED head burst. Payload frames and pad-ups
     * are both encoded at flush time, in wire order — encoding at
     * enqueue time would let a later burst advance the DRBG before an
     * earlier burst's pad frames, desyncing the stream. */
    size_t enc_off;
    size_t enc_len;
    uint8_t enc_buf[RELAY_MAX_BURST];
} RelayQueue;

/* Monotonic clock in milliseconds (poll-timeout domain). */
static uint64_t relay_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0; /* cannot happen on Linux; 0 disables the delays */
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Writes the whole buffer or fails (EINTR-retried). */
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

/* Runs the client handshake on the upstream socket. On success `keys`
 * holds the session keys and the bytes past the handshake are left in
 * `rest`/`rest_len` for the frame decoder. The SOCKS5 client socket is
 * watched alongside — but only for a genuine hangup: because the SOCKS5
 * success reply is sent before the handshake completes, the client MAY
 * already be piping payload at us, and that data must neither abort the
 * handshake nor be consumed (MSG_PEEK). Returns 0 on success. */
static int relay_handshake(int upstream_fd, int client_fd,
                           const Obfs4BridgeCert *cert,
                           Obfs4SessionKeys *keys, uint8_t *rest,
                           size_t *rest_len)
{
    static uint8_t request[OBFS4_CLIENT_MIN_HANDSHAKE_LEN +
                           OBFS4_CLIENT_MAX_PAD_LEN];
    static uint8_t resp[OBFS4_MAX_HANDSHAKE_LEN];
    Obfs4ClientHandshake hs;
    size_t request_len = 0;
    size_t resp_len = 0;
    size_t consumed = 0;
    int poll_client = 1;
    int rc = -1;

    *rest_len = 0;
    if (obfs4_client_init(&hs, cert) != OBFS4_OK) {
        return -1;
    }
    if (obfs4_client_request(&hs, request, sizeof(request), &request_len) !=
            OBFS4_OK ||
        write_full(upstream_fd, request, request_len) != 0) {
        goto out;
    }

    for (;;) {
        struct pollfd fds[2];
        ssize_t n = 0;
        Obfs4Status st;
        int ready;

        if (resp_len >= sizeof(resp)) {
            goto out; /* full buffer without a valid mark: fatal */
        }

        fds[0].fd = upstream_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = poll_client ? client_fd : -1;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        ready = poll(fds, 2, RELAY_HANDSHAKE_TIMEOUT_SEC * 1000);
        if (ready <= 0) {
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            goto out; /* handshake deadline or poll error */
        }
        if (fds[1].revents != 0) {
            uint8_t peek;
            ssize_t p = recv(client_fd, &peek, 1, MSG_PEEK);
            if (p <= 0) {
                goto out; /* EOF or error: the client is gone */
            }
            /* Early payload: legal, must not be consumed here; stop
             * polling the client (the data stays queued for the relay
             * loop) and keep waiting for the handshake. */
            poll_client = 0;
        }
        if (fds[0].revents == 0) {
            continue;
        }
        n = read(upstream_fd, resp + resp_len, sizeof(resp) - resp_len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            goto out; /* EOF or error */
        }
        resp_len += (size_t)n;

        st = obfs4_client_finish(&hs, resp, resp_len, keys, &consumed);
        if (st == OBFS4_AGAIN) {
            continue;
        }
        if (st != OBFS4_OK) {
            goto out;
        }
        break;
    }

    memcpy(rest, resp + consumed, resp_len - consumed);
    *rest_len = resp_len - consumed;
    rc = 0;

out:
    sodium_memzero(request, sizeof(request));
    sodium_memzero(resp, sizeof(resp));
    obfs4_client_wipe(&hs);
    return rc;
}

/* Drains any unconsumed client bytes before the socket is closed:
 * data left in the receive buffer turns close(2) into a RST, which
 * surfaces to the SOCKS5 client as ECONNRESET instead of a clean EOF.
 * Bounded — a peer that keeps flooding gets its RST anyway. */
static void relay_drain_client(int client_fd)
{
    uint8_t sink[4096];
    int i;

    for (i = 0; i < 16; i++) {
        if (recv(client_fd, sink, sizeof(sink), MSG_DONTWAIT) <= 0) {
            break;
        }
    }
    sodium_memzero(sink, sizeof(sink));
}

/* Builds one client burst (payload chunks +, for iat-mode 0/1, one
 * padding burst with a lenDist-sampled target — Go Write parity; the
 * paranoid mode pads per chunk instead). The burst is RETURNED, not
 * written: the caller decides between an immediate write (mode 0) and
 * the scheduled queue (modes 1/2). Returns 0 on success. */
static int relay_build_burst(Obfs4FrameEncoder *enc, Obfs4Dist *len_dist,
                             int iat_mode, const uint8_t *data,
                             size_t data_len, uint8_t *out,
                             size_t out_cap, size_t *out_len)
{
    size_t used = 0;
    size_t off = 0;
    size_t n = 0;

    while (off < data_len) {
        size_t chunk = data_len - off;
        if (chunk > OBFS4_MAX_PACKET_PAYLOAD) {
            chunk = OBFS4_MAX_PACKET_PAYLOAD;
        }
        if (obfs4_packet_encode(enc, OBFS4_PACKET_TYPE_PAYLOAD, data + off,
                                chunk, 0u, out + used, out_cap - used,
                                &n) != OBFS4_OK) {
            return -1;
        }
        used += n;
        off += chunk;
    }
    if (iat_mode != 2) {
        /* One padding burst per write burst, target sampled from the
         * length distribution (Go parity for iat-mode 0/1). */
        if (obfs4_packet_padburst(enc, used,
                                  (uint16_t)probdist_sample(len_dist),
                                  out + used, out_cap - used,
                                  &n) != OBFS4_OK) {
            return -1;
        }
        used += n;
    }

    *out_len = used;
    return 0;
}

/* Decodes every complete frame in the accumulate buffer and delivers
 * payloads to the client; a PRNG-seed packet resets the shaping
 * distributions (Go: the client converges on the server's
 * distribution). Returns 0 on success, -1 on a fatal protocol/crypto
 * error. */
static int relay_drain_upstream(Obfs4FrameDecoder *dec, uint8_t *buf,
                                size_t *buf_len, int client_fd,
                                Obfs4Dist *len_dist, Obfs4Dist *iat_dist,
                                int iat_mode)
{
    uint8_t decoded[OBFS4_MAX_FRAME_PAYLOAD];

    for (;;) {
        Obfs4PacketKind kind;
        const uint8_t *payload = NULL;
        size_t payload_len = 0;
        size_t decoded_len = 0;
        Obfs4Status st =
            obfs4_frame_decode(dec, buf, buf_len, decoded, &decoded_len);

        if (st == OBFS4_AGAIN) {
            sodium_memzero(decoded, sizeof(decoded));
            return 0;
        }
        if (st != OBFS4_OK) {
            sodium_memzero(decoded, sizeof(decoded));
            return -1;
        }
        if (obfs4_packet_parse(decoded, decoded_len, &kind, &payload,
                               &payload_len) != OBFS4_OK) {
            sodium_memzero(decoded, sizeof(decoded));
            return -1;
        }
        if (kind == OBFS4_PKT_PAYLOAD && payload_len > 0u &&
            write_full(client_fd, payload, payload_len) != 0) {
            sodium_memzero(decoded, sizeof(decoded));
            return -1;
        }
        if (kind == OBFS4_PKT_SEED) {
            probdist_reset(len_dist, RELAY_LEN_DIST_MAX, payload);
            if (iat_mode != 0) {
                /* iatSeed = SHA-256(lenSeed), truncated to the 24-byte
                 * seed format (Go parity). */
                uint8_t iat_hash[crypto_hash_sha256_BYTES];

                crypto_hash_sha256(iat_hash, payload,
                                   OBFS4_SEED_PAYLOAD_LEN);
                probdist_reset(iat_dist, RELAY_IAT_DIST_MAX, iat_hash);
                sodium_memzero(iat_hash, sizeof(iat_hash));
            }
        }
        sodium_memzero(decoded, sizeof(decoded));
    }
}

/* Sampled inter-chunk delay in milliseconds (iatDist unit = 100 µs,
 * quantized UP to poll granularity — we never write early). */
static uint64_t relay_iat_delay_ms(Obfs4Dist *iat_dist)
{
    uint32_t units = (uint32_t)probdist_sample(iat_dist);
    return ((uint64_t)units * 100u + 999u) / 1000u;
}

/* Writes every due chunk of the queued bursts. iat-mode 2 chops the
 * head burst at lenDist-sampled lengths (padding the tail up to the
 * target, Go padBurst parity, resample on wrap; a sampled 0 cannot make
 * progress and is redrawn — Go panics there). The mode-2 head is held
 * RAW in its slot and encoded into q->enc_buf only once it reaches the
 * head: the pad-ups are encoded at flush time, so the payload frames
 * must be encoded at flush time too or the DRBG would advance out of
 * wire order. Returns 0 on success. */
static int relay_flush_pending(int upstream_fd, RelayQueue *q,
                               Obfs4FrameEncoder *enc,
                               Obfs4Dist *len_dist, Obfs4Dist *iat_dist,
                               int iat_mode)
{
    while (q->count > 0u) {
        RelayPending *b = &q->slots[(q->head) % RELAY_PEND_SLOTS];
        uint64_t now = relay_now_ms();
        uint8_t *buf = b->buf;
        size_t *off = &b->off;
        size_t *len = &b->len;
        size_t cap = sizeof(b->buf);
        size_t rem;
        size_t chunk;

        if (now < b->due) {
            break; /* nothing due yet */
        }
        if (iat_mode == 2) {
            int32_t target;

            if (b->raw != 0u) {
                /* The burst became the head: encode its payload frames
                 * now (wire-order constraint above). */
                if (relay_build_burst(enc, len_dist, iat_mode, b->buf,
                                      b->len, q->enc_buf,
                                      sizeof(q->enc_buf),
                                      &q->enc_len) != 0) {
                    return -1;
                }
                sodium_memzero(b->buf, b->len);
                q->enc_off = 0;
                b->raw = 0;
            }
            buf = q->enc_buf;
            off = &q->enc_off;
            len = &q->enc_len;
            cap = sizeof(q->enc_buf);
            rem = *len - *off;

            do {
                target = probdist_sample(len_dist);
            } while (target == 0);
            if (rem < (size_t)target) {
                size_t n = 0;

                if (obfs4_packet_padburst(enc, rem, (uint16_t)target,
                                          buf + *len, cap - *len,
                                          &n) != OBFS4_OK) {
                    return -1;
                }
                *len += n;
                rem = *len - *off;
                if (rem != (size_t)target) {
                    continue; /* padding wrapped a segment: resample */
                }
            }
            chunk = (size_t)target;
        } else {
            rem = *len - *off;
            chunk = rem > OBFS4_MAX_SEGMENT_LEN ? OBFS4_MAX_SEGMENT_LEN
                                                : rem;
        }

        if (write_full(upstream_fd, buf + *off, chunk) != 0) {
            return -1;
        }
        *off += chunk;
        b->due = relay_now_ms() + relay_iat_delay_ms(iat_dist);

        if (*off >= *len) {
            sodium_memzero(buf, *len);
            if (iat_mode == 2) {
                q->enc_len = 0;
                q->enc_off = 0;
            }
            q->head++;
            q->count--;
            if (q->count > 0u) {
                /* A fresh burst starts immediately (Go: the next Write
                 * call carries no leftover delay). */
                q->slots[(q->head) % RELAY_PEND_SLOTS].due =
                    relay_now_ms();
            }
        }
    }
    return 0;
}

void relay_run(int client_fd, int upstream_fd, const Obfs4BridgeCert *cert,
               int iat_mode)
{
    Obfs4SessionKeys keys;
    Obfs4FrameEncoder enc;
    Obfs4FrameDecoder dec;
    Obfs4Dist len_dist;
    Obfs4Dist iat_dist;
    static RelayQueue queue;
    static uint8_t client_buf[RELAY_CLIENT_CHUNK];
    static uint8_t up_buf[RELAY_UPSTREAM_BUF];
    uint8_t len_seed[GORAND_SEED_LEN];
    size_t up_len = 0;

    if (relay_handshake(upstream_fd, client_fd, cert, &keys, up_buf,
                        &up_len) != 0) {
        fprintf(stderr, "umbra-pt-proxy: obfs4 handshake failed\n");
        sodium_memzero(&keys, sizeof(keys));
        relay_drain_client(client_fd);
        return;
    }
    obfs4_frame_encoder_init(&enc, &keys.send);
    obfs4_frame_decoder_init(&dec, &keys.recv);
    obfs4_session_keys_wipe(&keys);

    /* Shaping state: a fresh local seed now (Go newObfs4ClientConn
     * parity); the bridge's PRNG-seed packet resets the distributions
     * when it arrives. */
    randombytes_buf(len_seed, sizeof(len_seed));
    probdist_reset(&len_dist, RELAY_LEN_DIST_MAX, len_seed);
    if (iat_mode != 0) {
        uint8_t iat_hash[crypto_hash_sha256_BYTES];

        crypto_hash_sha256(iat_hash, len_seed, sizeof(len_seed));
        probdist_reset(&iat_dist, RELAY_IAT_DIST_MAX, iat_hash);
        sodium_memzero(iat_hash, sizeof(iat_hash));
    }
    sodium_memzero(len_seed, sizeof(len_seed));

    memset(&queue, 0, sizeof(queue));

    /* Bytes past the handshake mark may already hold frames (the seed
     * packet rides the server response burst). */
    if (relay_drain_upstream(&dec, up_buf, &up_len, client_fd, &len_dist,
                             &iat_dist, iat_mode) != 0) {
        goto out;
    }

    for (;;) {
        struct pollfd fds[2];
        int ready;
        int timeout = RELAY_IDLE_TIMEOUT_MS;

        if (relay_flush_pending(upstream_fd, &queue, &enc, &len_dist,
                                &iat_dist, iat_mode) != 0) {
            break;
        }

        if (queue.count > 0u) {
            uint64_t now = relay_now_ms();
            const RelayPending *b =
                &queue.slots[(queue.head) % RELAY_PEND_SLOTS];
            uint64_t wait = b->due > now ? b->due - now : 0u;
            if (wait < (uint64_t)timeout) {
                timeout = (int)wait;
            }
        }

        /* Backpressure: a full queue masks the client out of the poll
         * set until a burst drains. */
        fds[0].fd = queue.count < RELAY_PEND_SLOTS ? client_fd : -1;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = upstream_fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        ready = poll(fds, 2, timeout);
        if (ready <= 0) {
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            if (ready == 0 && queue.count > 0u) {
                continue; /* a chunk came due */
            }
            break; /* idle timeout or poll error */
        }

        /* Client -> bridge. */
        if (fds[0].revents != 0) {
            ssize_t n;
            if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                break;
            }
            n = read(client_fd, client_buf, sizeof(client_buf));
            if (n <= 0) {
                break; /* EOF/error: obfs4 has no close frame */
            }
            if (iat_mode == 0) {
                static uint8_t burst[RELAY_MAX_BURST];
                size_t burst_len = 0;

                if (relay_build_burst(&enc, &len_dist, iat_mode,
                                      client_buf, (size_t)n, burst,
                                      sizeof(burst), &burst_len) != 0 ||
                    write_full(upstream_fd, burst, burst_len) != 0) {
                    sodium_memzero(burst, sizeof(burst));
                    break;
                }
                sodium_memzero(burst, sizeof(burst));
            } else {
                RelayPending *b =
                    &queue.slots[(queue.head + queue.count) %
                                 RELAY_PEND_SLOTS];

                b->off = 0;
                b->due = relay_now_ms();
                if (iat_mode == 2) {
                    /* Raw payload: encoded only when the burst reaches
                     * the head (see relay_flush_pending). */
                    memcpy(b->buf, client_buf, (size_t)n);
                    b->len = (size_t)n;
                    b->raw = 1;
                } else {
                    b->raw = 0;
                    if (relay_build_burst(&enc, &len_dist, iat_mode,
                                          client_buf, (size_t)n, b->buf,
                                          sizeof(b->buf), &b->len) != 0) {
                        break;
                    }
                }
                queue.count++;
            }
        }

        /* Bridge -> client. */
        if (fds[1].revents != 0) {
            ssize_t n;
            if ((fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                break;
            }
            if (up_len >= sizeof(up_buf)) {
                break; /* full buffer, no decodable frame: fatal */
            }
            n = read(upstream_fd, up_buf + up_len, sizeof(up_buf) - up_len);
            if (n <= 0) {
                break;
            }
            up_len += (size_t)n;
            if (relay_drain_upstream(&dec, up_buf, &up_len, client_fd,
                                     &len_dist, &iat_dist,
                                     iat_mode) != 0) {
                break;
            }
        }
    }

out:
    relay_drain_client(client_fd);
    obfs4_frame_encoder_wipe(&enc);
    obfs4_frame_decoder_wipe(&dec);
    probdist_wipe(&len_dist);
    probdist_wipe(&iat_dist);
    sodium_memzero(&queue, sizeof(queue));
    sodium_memzero(client_buf, sizeof(client_buf));
    sodium_memzero(up_buf, sizeof(up_buf));
}
