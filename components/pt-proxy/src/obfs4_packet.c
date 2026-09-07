/*
 * umbra-pt-proxy — obfs4 packet layer. See obfs4_packet.h for the
 * format and the parsing rules.
 */

#include "obfs4_packet.h"

#include <string.h>

/* Frame overhead + packet overhead — the bytes a padding-only packet
 * adds to the burst beyond its padding (lyrebird headerLength). */
#define OBFS4_HEADER_LENGTH (OBFS4_FRAME_OVERHEAD + OBFS4_PACKET_OVERHEAD)

Obfs4Status obfs4_packet_encode(Obfs4FrameEncoder *enc, uint8_t type,
                                const uint8_t *data, size_t data_len,
                                size_t pad_len, uint8_t *out,
                                size_t out_cap, size_t *out_len)
{
    uint8_t pkt[OBFS4_MAX_FRAME_PAYLOAD];
    size_t pkt_len;

    if (enc == NULL || out == NULL || out_len == NULL ||
        (data == NULL && data_len > 0u)) {
        return OBFS4_ERR;
    }
    if (data_len > OBFS4_MAX_PACKET_PAYLOAD ||
        pad_len > OBFS4_MAX_PACKET_PAYLOAD - data_len) {
        return OBFS4_ERR;
    }

    pkt[0] = type;
    pkt[1] = (uint8_t)(data_len >> 8u);
    pkt[2] = (uint8_t)(data_len & 0xffu);
    if (data_len > 0u) {
        memcpy(pkt + OBFS4_PACKET_OVERHEAD, data, data_len);
    }
    memset(pkt + OBFS4_PACKET_OVERHEAD + data_len, 0, pad_len);
    pkt_len = OBFS4_PACKET_OVERHEAD + data_len + pad_len;

    return obfs4_frame_encode(enc, pkt, pkt_len, out, out_cap, out_len);
}

Obfs4Status obfs4_packet_padburst(Obfs4FrameEncoder *enc,
                                  size_t burst_len, uint16_t to_pad_to,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    size_t tail_len = burst_len % OBFS4_MAX_SEGMENT_LEN;
    size_t pad_len;
    size_t written = 0u;
    size_t n = 0u;

    if (enc == NULL || out == NULL || out_len == NULL) {
        return OBFS4_ERR;
    }

    /* Go padBurst(): bring the burst tail up to to_pad_to, wrapping
     * around a full segment when the sample is below the tail. */
    if ((size_t)to_pad_to >= tail_len) {
        pad_len = (size_t)to_pad_to - tail_len;
    } else {
        pad_len = (OBFS4_MAX_SEGMENT_LEN - tail_len) + (size_t)to_pad_to;
    }

    if (pad_len > OBFS4_HEADER_LENGTH) {
        if (obfs4_packet_encode(enc, OBFS4_PACKET_TYPE_PAYLOAD, NULL, 0u,
                                pad_len - OBFS4_HEADER_LENGTH, out,
                                out_cap, &n) != OBFS4_OK) {
            return OBFS4_ERR;
        }
        written += n;
    } else if (pad_len > 0u) {
        /* A short pad does not fit its own header: emit one full-size
         * padding packet first, then the remainder (Go parity). */
        if (obfs4_packet_encode(enc, OBFS4_PACKET_TYPE_PAYLOAD, NULL, 0u,
                                OBFS4_MAX_PACKET_PAYLOAD, out, out_cap,
                                &n) != OBFS4_OK) {
            return OBFS4_ERR;
        }
        written += n;
        if (out_cap < written ||
            obfs4_packet_encode(enc, OBFS4_PACKET_TYPE_PAYLOAD, NULL, 0u,
                                pad_len, out + written, out_cap - written,
                                &n) != OBFS4_OK) {
            return OBFS4_ERR;
        }
        written += n;
    }

    *out_len = written;
    return OBFS4_OK;
}

Obfs4Status obfs4_packet_parse(const uint8_t *frame_payload,
                               size_t frame_len, Obfs4PacketKind *kind,
                               const uint8_t **payload,
                               size_t *payload_len)
{
    size_t plen;

    if (frame_payload == NULL || kind == NULL || payload == NULL ||
        payload_len == NULL) {
        return OBFS4_ERR;
    }
    if (frame_len < OBFS4_PACKET_OVERHEAD) {
        return OBFS4_ERR;
    }
    plen = ((size_t)frame_payload[1] << 8u) | (size_t)frame_payload[2];
    if (plen > frame_len - OBFS4_PACKET_OVERHEAD) {
        return OBFS4_ERR;
    }

    switch (frame_payload[0]) {
    case OBFS4_PACKET_TYPE_PAYLOAD:
        *kind = OBFS4_PKT_PAYLOAD;
        *payload = frame_payload + OBFS4_PACKET_OVERHEAD;
        *payload_len = plen;
        return OBFS4_OK;
    case OBFS4_PACKET_TYPE_PRNG_SEED:
        /* A well-formed seed packet (24-byte payload) carries the
         * server's length-distribution seed; iat-mode uses it to reset
         * the shaping tables. Malformed sizes are ignored per the
         * reference. */
        if (plen == OBFS4_SEED_PAYLOAD_LEN) {
            *kind = OBFS4_PKT_SEED;
            *payload = frame_payload + OBFS4_PACKET_OVERHEAD;
            *payload_len = plen;
        } else {
            *kind = OBFS4_PKT_IGNORED;
            *payload = NULL;
            *payload_len = 0u;
        }
        return OBFS4_OK;
    default:
        *kind = OBFS4_PKT_IGNORED;
        *payload = NULL;
        *payload_len = 0u;
        return OBFS4_OK;
    }
}
