use std::fmt;

pub const HEADER_LEN_V2: usize = 16;

pub const HEADER_LEN_V1: usize = 8;

pub const VERSION_PACKET_LEN: usize = 20;

// What the device's resync scanner hunts for, so it goes in the version slot of every version packet.
pub const HOST_MAGIC: u32 = 0xFEED_FACE;

pub const DEVICE_MAGIC: u32 = 0xFACE_FACE;

pub const MAX_PACKET: usize = 0x8000;

pub const MAX_TRANSFER: usize = 0x7FFC;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MuxVersion {
    V1,
    V2,
}

impl MuxVersion {
    #[must_use]
    pub const fn header_len(self) -> usize {
        match self {
            Self::V1 => HEADER_LEN_V1,
            Self::V2 => HEADER_LEN_V2,
        }
    }

    #[must_use]
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    #[must_use]
    pub const fn negotiated_from(value: u32) -> Self {
        match value {
            1 => Self::V1,
            _ => Self::V2,
        }
    }

    #[must_use]
    pub const fn is_sequenced(self) -> bool {
        matches!(self, Self::V2)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Version,
    HostLogLevel,
    Tcp,
    Unknown(u32),
}

impl Protocol {
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::Version => 0,
            Self::HostLogLevel => 2,
            Self::Tcp => 6,
            Self::Unknown(value) => value,
        }
    }

    #[must_use]
    pub const fn from_wire(value: u32) -> Self {
        match value {
            0 => Self::Version,
            2 => Self::HostLogLevel,
            6 => Self::Tcp,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn is_dispatched(self) -> bool {
        matches!(self, Self::Version | Self::HostLogLevel | Self::Tcp)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => f.write_str("version"),
            Self::HostLogLevel => f.write_str("host log level"),
            Self::Tcp => f.write_str("tcp"),
            Self::Unknown(value) => write!(f, "unknown({value})"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxHeader {
    pub protocol: Protocol,
    // Must equal the bytes actually delivered, or the device drops the packet and re-frames.
    pub length: u32,
    pub magic: u32,
    pub tx_seq: u16,
    pub rx_ack: u16,
}

impl MuxHeader {
    #[must_use]
    pub const fn host(protocol: Protocol, length: u32, tx_seq: u16, rx_ack: u16) -> Self {
        Self {
            protocol,
            length,
            magic: HOST_MAGIC,
            tx_seq,
            rx_ack,
        }
    }

    pub fn encode(&self, version: MuxVersion, out: &mut [u8]) -> Result<usize, FrameError> {
        let len = version.header_len();
        if out.len() < len {
            return Err(FrameError::Short {
                needed: len,
                had: out.len(),
            });
        }
        out[0..4].copy_from_slice(&self.protocol.wire_value().to_be_bytes());
        out[4..8].copy_from_slice(&self.length.to_be_bytes());
        if version.is_sequenced() {
            out[8..12].copy_from_slice(&self.magic.to_be_bytes());
            out[12..14].copy_from_slice(&self.tx_seq.to_be_bytes());
            out[14..16].copy_from_slice(&self.rx_ack.to_be_bytes());
        }
        Ok(len)
    }

    pub fn decode(version: MuxVersion, bytes: &[u8]) -> Result<Self, FrameError> {
        let len = version.header_len();
        if bytes.len() < len {
            return Err(FrameError::Short {
                needed: len,
                had: bytes.len(),
            });
        }
        let protocol = Protocol::from_wire(be32(&bytes[0..4]));
        let length = be32(&bytes[4..8]);
        let (magic, tx_seq, rx_ack) = if version.is_sequenced() {
            (
                be32(&bytes[8..12]),
                be16(&bytes[12..14]),
                be16(&bytes[14..16]),
            )
        } else {
            (0, 0, 0)
        };
        Ok(Self {
            protocol,
            length,
            magic,
            tx_seq,
            rx_ack,
        })
    }

    pub fn payload<'a>(
        &self,
        version: MuxVersion,
        packet: &'a [u8],
    ) -> Result<&'a [u8], FrameError> {
        if self.length as usize != packet.len() {
            return Err(FrameError::LengthMismatch {
                declared: self.length,
                actual: packet.len(),
            });
        }
        let header = version.header_len();
        if packet.len() < header {
            return Err(FrameError::Short {
                needed: header,
                had: packet.len(),
            });
        }
        Ok(&packet[header..])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionPacket {
    pub version: u32,
    pub reserved: u32,
}

impl VersionPacket {
    #[must_use]
    pub fn encode(&self) -> [u8; VERSION_PACKET_LEN] {
        let mut out = [0u8; VERSION_PACKET_LEN];
        out[0..4].copy_from_slice(&Protocol::Version.wire_value().to_be_bytes());
        out[4..8].copy_from_slice(&(VERSION_PACKET_LEN as u32).to_be_bytes());
        out[8..12].copy_from_slice(&self.version.to_be_bytes());
        out[12..16].copy_from_slice(&self.reserved.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < VERSION_PACKET_LEN {
            return Err(FrameError::Short {
                needed: VERSION_PACKET_LEN,
                had: bytes.len(),
            });
        }
        let protocol = be32(&bytes[0..4]);
        if protocol != Protocol::Version.wire_value() {
            return Err(FrameError::NotVersion { protocol });
        }
        Ok(Self {
            version: be32(&bytes[8..12]),
            reserved: be32(&bytes[12..16]),
        })
    }

    #[must_use]
    pub const fn negotiated(&self) -> MuxVersion {
        MuxVersion::negotiated_from(self.version)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRequest(u32);

impl VersionRequest {
    #[must_use]
    pub const fn resync() -> Self {
        Self(HOST_MAGIC)
    }

    #[must_use]
    pub const fn exact(version: MuxVersion) -> Self {
        Self(version.wire_value())
    }

    #[must_use]
    pub const fn wire_value(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn expected(self) -> MuxVersion {
        MuxVersion::negotiated_from(self.0)
    }

    #[must_use]
    pub fn packet(self) -> VersionPacket {
        VersionPacket {
            version: self.0,
            reserved: 0,
        }
    }
}

impl Default for VersionRequest {
    fn default() -> Self {
        Self::resync()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    Short { needed: usize, had: usize },
    LengthMismatch { declared: u32, actual: usize },
    NotVersion { protocol: u32 },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { needed, had } => {
                write!(f, "need {needed} bytes of mux frame, have {had}")
            }
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "mux header declares {declared} bytes, {actual} were delivered"
            ),
            Self::NotVersion { protocol } => {
                write!(f, "expected a version packet, protocol word is {protocol}")
            }
        }
    }
}

impl std::error::Error for FrameError {}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_VERSION_PACKET: [u8; 20] = [
        0x00, 0x00, 0x00, 0x00, // protocol 0
        0x00, 0x00, 0x00, 0x14, // length 20
        0xFE, 0xED, 0xFA, 0xCE, // version slot carries the resync magic
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x00, // trailing four, untouched by the device
    ];

    const DEVICE_VERSION_REPLY_V2: [u8; 20] = [
        0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x14, //
        0x00, 0x00, 0x00, 0x02, // negotiated version 2
        0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, //
    ];

    const HOST_TCP_HEADER_V2: [u8; 16] = [
        0x00, 0x00, 0x00, 0x06, // protocol 6
        0x00, 0x00, 0x00, 0x24, // length 36
        0xFE, 0xED, 0xFA, 0xCE, // host magic
        0x00, 0x00, // tx sequence 0
        0xFF, 0xFF, // rx acknowledgement, nothing received yet
    ];

    const DEVICE_TCP_HEADER_V2: [u8; 16] = [
        0x00, 0x00, 0x00, 0x06, //
        0x00, 0x00, 0x00, 0x24, //
        0xFA, 0xCE, 0xFA, 0xCE, //
        0x00, 0x00, //
        0xFF, 0xFF, //
    ];

    #[test]
    fn the_header_words_are_big_endian_because_the_guest_byte_reverses_them() {
        let header = MuxHeader::host(Protocol::Tcp, 36, 0, 0xFFFF);
        let mut out = [0u8; HEADER_LEN_V2];
        assert_eq!(header.encode(MuxVersion::V2, &mut out).unwrap(), 16);
        assert_eq!(out, HOST_TCP_HEADER_V2);
        assert_eq!(&out[0..4], &[0x00, 0x00, 0x00, 0x06]);
        assert_eq!(&out[4..8], &[0x00, 0x00, 0x00, 0x24]);
    }

    #[test]
    fn a_device_header_decodes_with_the_device_magic() {
        let header = MuxHeader::decode(MuxVersion::V2, &DEVICE_TCP_HEADER_V2).unwrap();
        assert_eq!(header.protocol, Protocol::Tcp);
        assert_eq!(header.length, 36);
        assert_eq!(header.magic, DEVICE_MAGIC);
        assert_eq!(header.tx_seq, 0);
        assert_eq!(header.rx_ack, 0xFFFF);
    }

    #[test]
    fn version_one_headers_are_eight_bytes_and_carry_no_sequence() {
        let header = MuxHeader::host(Protocol::Tcp, 28, 7, 6);
        let mut out = [0u8; HEADER_LEN_V2];
        assert_eq!(header.encode(MuxVersion::V1, &mut out).unwrap(), 8);
        assert_eq!(
            &out[0..8],
            &[0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x1C]
        );
        assert_eq!(&out[8..16], &[0u8; 8]);

        let back = MuxHeader::decode(MuxVersion::V1, &out).unwrap();
        assert_eq!(back.protocol, Protocol::Tcp);
        assert_eq!(back.length, 28);
        assert_eq!(back.tx_seq, 0);
        assert_eq!(back.rx_ack, 0);
    }

    #[test]
    fn the_host_version_packet_is_the_bytes_the_resync_scanner_hunts_for() {
        assert_eq!(
            VersionRequest::resync().packet().encode(),
            HOST_VERSION_PACKET
        );
    }

    #[test]
    fn the_scanner_needs_a_zero_protocol_word_and_the_magic_at_offset_eight() {
        let packet = VersionRequest::resync().packet().encode();
        assert_eq!(u32::from_be_bytes(packet[0..4].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_be_bytes(packet[8..12].try_into().unwrap()),
            HOST_MAGIC
        );
        assert_eq!(&packet[8..12], &[0xFE, 0xED, 0xFA, 0xCE]);
    }

    #[test]
    fn the_guest_clamps_every_version_but_one_to_two() {
        assert_eq!(MuxVersion::negotiated_from(1), MuxVersion::V1);
        assert_eq!(MuxVersion::negotiated_from(2), MuxVersion::V2);
        assert_eq!(MuxVersion::negotiated_from(0), MuxVersion::V2);
        assert_eq!(MuxVersion::negotiated_from(3), MuxVersion::V2);
        assert_eq!(MuxVersion::negotiated_from(HOST_MAGIC), MuxVersion::V2);
        assert_eq!(VersionRequest::resync().expected(), MuxVersion::V2);
        assert_eq!(
            VersionRequest::exact(MuxVersion::V1).expected(),
            MuxVersion::V1
        );
    }

    #[test]
    fn the_device_reply_names_the_version_that_is_now_in_force() {
        let reply = VersionPacket::decode(&DEVICE_VERSION_REPLY_V2).unwrap();
        assert_eq!(reply.version, 2);
        assert_eq!(reply.negotiated(), MuxVersion::V2);
        assert_eq!(reply.negotiated().header_len(), 16);
        assert!(reply.negotiated().is_sequenced());
    }

    #[test]
    fn a_version_one_reply_selects_the_eight_byte_header() {
        let mut bytes = DEVICE_VERSION_REPLY_V2;
        bytes[11] = 0x01;
        let reply = VersionPacket::decode(&bytes).unwrap();
        assert_eq!(reply.negotiated(), MuxVersion::V1);
        assert_eq!(reply.negotiated().header_len(), 8);
        assert!(!reply.negotiated().is_sequenced());
    }

    #[test]
    fn a_version_packet_shorter_than_the_guest_accepts_is_refused_here_too() {
        let short = [0u8; 19];
        assert!(matches!(
            VersionPacket::decode(&short),
            Err(FrameError::Short {
                needed: 20,
                had: 19
            })
        ));
    }

    #[test]
    fn a_non_version_protocol_is_not_read_as_a_version_packet() {
        let mut bytes = DEVICE_VERSION_REPLY_V2;
        bytes[3] = 0x06;
        assert!(matches!(
            VersionPacket::decode(&bytes),
            Err(FrameError::NotVersion { protocol: 6 })
        ));
    }

    #[test]
    fn protocol_dispatch_matches_the_three_arms_the_guest_has() {
        assert_eq!(Protocol::from_wire(0), Protocol::Version);
        assert_eq!(Protocol::from_wire(2), Protocol::HostLogLevel);
        assert_eq!(Protocol::from_wire(6), Protocol::Tcp);
        assert_eq!(Protocol::from_wire(1), Protocol::Unknown(1));
        assert!(!Protocol::Unknown(1).is_dispatched());
        for protocol in [Protocol::Version, Protocol::HostLogLevel, Protocol::Tcp] {
            assert!(protocol.is_dispatched());
            assert_eq!(Protocol::from_wire(protocol.wire_value()), protocol);
        }
    }

    #[test]
    fn a_length_that_does_not_match_the_delivery_is_a_framing_failure() {
        let header = MuxHeader::decode(MuxVersion::V2, &DEVICE_TCP_HEADER_V2).unwrap();
        let packet = [0u8; 20];
        assert!(matches!(
            header.payload(MuxVersion::V2, &packet),
            Err(FrameError::LengthMismatch {
                declared: 36,
                actual: 20
            })
        ));
    }

    #[test]
    fn a_matching_length_yields_the_payload_after_the_header() {
        let mut packet = vec![0u8; 36];
        packet[0..16].copy_from_slice(&DEVICE_TCP_HEADER_V2);
        packet[16] = 0xAB;
        let header = MuxHeader::decode(MuxVersion::V2, &packet).unwrap();
        let payload = header.payload(MuxVersion::V2, &packet).unwrap();
        assert_eq!(payload.len(), 20);
        assert_eq!(payload[0], 0xAB);
    }

    #[test]
    fn encoding_into_a_buffer_that_cannot_hold_the_header_is_refused() {
        let header = MuxHeader::host(Protocol::Tcp, 36, 0, 0);
        let mut out = [0u8; 15];
        assert!(matches!(
            header.encode(MuxVersion::V2, &mut out),
            Err(FrameError::Short {
                needed: 16,
                had: 15
            })
        ));
    }

    #[test]
    fn the_transfer_bounds_are_the_ones_the_guest_allocates() {
        assert_eq!(MAX_PACKET, 32768);
        assert_eq!(MAX_TRANSFER, 32764);
        const { assert!(MAX_TRANSFER < MAX_PACKET) };
    }
}
