/*
 * umbra-pt-proxy — obfs4 packet layer (inside the AEAD frames).
 *
 * Packet format (lyrebird transports/obfs4/packet.go):
 *
 *     uint8      type   (0 = payload, 1 = PRNG seed)
 *     uint16 BE  length (payload length, padding excluded)
 *     uint8[]    payload
 *     uint8[]    zero padding
 *
 * The server sends ONE PRNG-seed packet (24-byte payload) right after
 * its handshake; iat-mode resets the shaping distributions from it
 * (relay.c). Unknown packet types are ignored; malformed packets are
 * fatal.
 */

#ifndef UMBRA_PT_OBFS4_PACKET_H
#define UMBRA_PT_OBFS4_PACKET_H

#include "obfs4.h"
#include "obfs4_frame.h"

#include <stddef.h>
#include <stdint.h>

#define OBFS4_PACKET_OVERHEAD 3u /* type + uint16 length */
#define OBFS4_MAX_PACKET_PAYLOAD \
    (OBFS4_MAX_FRAME_PAYLOAD - OBFS4_PACKET_OVERHEAD) /* 1427 */
#define OBFS4_PACKET_TYPE_PAYLOAD 0x00u
#define OBFS4_PACKET_TYPE_PRNG_SEED 0x01u
#define OBFS4_SEED_PAYLOAD_LEN 24u

typedef enum {
    OBFS4_PKT_PAYLOAD, /* payload data (may be empty: padding burst) */
    OBFS4_PKT_SEED,    /* 24-byte PRNG seed; accepted, ignored */
    OBFS4_PKT_IGNORED  /* unknown type: ignored per the reference */
} Obfs4PacketKind;

/* Encodes one packet (`type`, `data`, zero padding of `pad_len`) into
 * a frame. data_len + pad_len must be ≤ OBFS4_MAX_PACKET_PAYLOAD. */
Obfs4Status obfs4_packet_encode(Obfs4FrameEncoder *enc, uint8_t type,
                                const uint8_t *data, size_t data_len,
                                size_t pad_len, uint8_t *out,
                                size_t out_cap, size_t *out_len);

/* The Go padBurst() arithmetic: pads the current burst so its total
 * length becomes ≡ to_pad_to (mod OBFS4_MAX_SEGMENT_LEN), with one or
 * two padding-only packets. `burst_len` is the number of frame bytes
 * already produced for this burst. */
Obfs4Status obfs4_packet_padburst(Obfs4FrameEncoder *enc,
                                  size_t burst_len, uint16_t to_pad_to,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/* Parses one decoded frame payload. Bounds-checked; malformed packets
 * (short header, payload length overruns the frame) are OBFS4_ERR. */
Obfs4Status obfs4_packet_parse(const uint8_t *frame_payload,
                               size_t frame_len, Obfs4PacketKind *kind,
                               const uint8_t **payload,
                               size_t *payload_len);

#endif /* UMBRA_PT_OBFS4_PACKET_H */
