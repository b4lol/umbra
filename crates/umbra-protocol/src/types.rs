//! Wire-format constants and the packet-type opcode table (SPECIFICATION.md §1).

/// Fixed wire size of every packet, regardless of type (SPECIFICATION.md §1).
pub const PACKET_LEN: usize = 1024;

/// Protocol magic bytes: `"UM"` (0x55, 0x4D).
pub const MAGIC: [u8; 2] = [0x55, 0x4D];

/// Current protocol version byte.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Header size in bytes: magic (2) + version (1) + type (1) + payload length
/// (2) + ChaCha nonce (12).
pub const HEADER_LEN: usize = 18;

/// Length of the encrypted payload region (ciphertext without the
/// Poly1305 tag) in bytes.
///
/// SPECIFICATION.md's offset table implies an `ENCRYPTED_DATA` region of
/// 992 bytes starting at 0x012 plus a 16-byte tag at 0x3F2, which totals
/// 1026 bytes — 2 bytes beyond the mandated 1024-byte packet. This
/// implementation resolves the inconsistency arithmetically:
/// `HEADER_LEN (18) + BODY_LEN (990) + TAG_LEN (16) == PACKET_LEN (1024)`.
/// The table in SPECIFICATION.md should be corrected accordingly.
pub const BODY_LEN: usize = PACKET_LEN - HEADER_LEN - TAG_LEN;

/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Maximum plaintext payload per packet: the data + random-padding budget
/// that encrypts into `BODY_LEN` bytes of ciphertext plus `TAG_LEN` bytes
/// of tag.
pub const PAYLOAD_MAX: usize = BODY_LEN;

/// Wire opcodes (SPECIFICATION.md §1 "Packet Types").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
    /// PQXDH initiation packet from Alice to Bob.
    HandshakeInit,
    /// PQXDH response packet from Bob to Alice.
    HandshakeResp,
    /// End-to-end encrypted user text (default 24-hour TTL).
    DataMessage,
    /// Poisson artificial cover traffic; destroyed silently on receipt.
    DummyCover,
    /// View-Once photo keyed with a single-use EFK.
    ViewOncePhoto,
    /// 24-hour video/audio or file chunk keyed with EFK.
    MediaChunk,
    /// Acknowledgment that media was opened once and destroyed.
    MediaShredAck,
    /// P2P Tor circuit liveness check.
    HeartbeatPing,
    /// Session termination; mutually resets ephemeral keys.
    SessionTerminate,
}

impl PacketType {
    /// Maps the opcode to its wire byte (SPECIFICATION.md §1).
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::HandshakeInit => 0x01,
            Self::HandshakeResp => 0x02,
            Self::DataMessage => 0x03,
            Self::DummyCover => 0x04,
            Self::ViewOncePhoto => 0x05,
            Self::MediaChunk => 0x06,
            Self::MediaShredAck => 0x07,
            Self::HeartbeatPing => 0x08,
            Self::SessionTerminate => 0x09,
        }
    }
}

impl TryFrom<u8> for PacketType {
    type Error = crate::error::ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::HandshakeInit),
            0x02 => Ok(Self::HandshakeResp),
            0x03 => Ok(Self::DataMessage),
            0x04 => Ok(Self::DummyCover),
            0x05 => Ok(Self::ViewOncePhoto),
            0x06 => Ok(Self::MediaChunk),
            0x07 => Ok(Self::MediaShredAck),
            0x08 => Ok(Self::HeartbeatPing),
            0x09 => Ok(Self::SessionTerminate),
            other => Err(crate::error::ProtocolError::UnknownOpcode(other)),
        }
    }
}
