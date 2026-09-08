use std::fmt;

pub const TCP_HEADER_LEN: usize = 20;

pub const DATA_OFFSET_WORDS: u8 = 5;

// Wire window << 8 is the byte count; hardcoded both sides, no window-scale option.
pub const WINDOW_SCALE_SHIFT: u32 = 8;

pub const DEVICE_INITIAL_SEQUENCE: u32 = 0;

pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    // Established sessions: the device matches the flag byte for equality, not by bit test.
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    pub const SYN_ACK: u8 = SYN | ACK;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub window: u32,
}

impl TcpHeader {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, TcpError> {
        if out.len() < TCP_HEADER_LEN {
            return Err(TcpError::Short {
                needed: TCP_HEADER_LEN,
                had: out.len(),
            });
        }
        out[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        out[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        out[8..12].copy_from_slice(&self.acknowledgement.to_be_bytes());
        out[12] = DATA_OFFSET_WORDS << 4;
        out[13] = self.flags;
        out[14..16].copy_from_slice(&Self::window_to_wire(self.window).to_be_bytes());
        out[16..20].copy_from_slice(&[0, 0, 0, 0]);
        Ok(TCP_HEADER_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TcpError> {
        if bytes.len() < TCP_HEADER_LEN {
            return Err(TcpError::Short {
                needed: TCP_HEADER_LEN,
                had: bytes.len(),
            });
        }
        let offset_words = bytes[12] >> 4;
        if offset_words != DATA_OFFSET_WORDS {
            return Err(TcpError::Options { offset_words });
        }
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            acknowledgement: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: bytes[13],
            window: Self::window_from_wire(u16::from_be_bytes([bytes[14], bytes[15]])),
        })
    }

    #[must_use]
    pub fn declared_header_len(bytes: &[u8]) -> Option<usize> {
        bytes.get(12).map(|byte| usize::from((byte >> 2) & 0x3c))
    }

    #[must_use]
    pub const fn window_from_wire(value: u16) -> u32 {
        (value as u32) << WINDOW_SCALE_SHIFT
    }

    #[must_use]
    pub const fn window_to_wire(bytes: u32) -> u16 {
        let scaled = bytes >> WINDOW_SCALE_SHIFT;
        if scaled > u16::MAX as u32 {
            u16::MAX
        } else {
            scaled as u16
        }
    }

    #[must_use]
    pub const fn is_bare_ack(&self) -> bool {
        self.flags == flags::ACK
    }

    #[must_use]
    pub const fn is_bare_syn(&self) -> bool {
        self.flags == flags::SYN
    }

    #[must_use]
    pub const fn is_syn_ack(&self) -> bool {
        self.flags == flags::SYN_ACK
    }

    #[must_use]
    pub const fn is_reset(&self) -> bool {
        self.flags & flags::RST != 0
    }

    #[must_use]
    pub const fn window_edge(&self) -> u32 {
        self.acknowledgement.wrapping_add(self.window)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpError {
    Short { needed: usize, had: usize },
    Options { offset_words: u8 },
}

impl fmt::Display for TcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short { needed, had } => {
                write!(f, "need {needed} bytes of tcp header, have {had}")
            }
            Self::Options { offset_words } => write!(
                f,
                "tcp data offset is {offset_words} words, the mux only ever uses {DATA_OFFSET_WORDS}"
            ),
        }
    }
}

impl std::error::Error for TcpError {}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_SYN: [u8; 20] = [
        0xC0, 0x00, // source port 49152
        0xF2, 0x7E, // destination port 62078
        0x11, 0x22, 0x33, 0x44, // sequence
        0x00, 0x00, 0x00, 0x00, // acknowledgement, zero in a SYN
        0x50, // data offset 5, no options
        0x02, // SYN and nothing else
        0xFF, 0xFF, // window, 0xFFFF << 8 bytes
        0x00, 0x00, // checksum, never computed
        0x00, 0x00, // urgent pointer, never read
    ];

    const DEVICE_SYN_ACK: [u8; 20] = [
        0xF2, 0x7E, // source port 62078
        0xC0, 0x00, // destination port 49152
        0x00, 0x00, 0x00, 0x00, // the device's initial sequence is zero
        0x11, 0x22, 0x33, 0x45, // the host sequence plus one
        0x50, //
        0x12, // SYN and ACK
        0x01, 0x00, // window 0x0100, meaning 65536 bytes
        0x00, 0x00, //
        0x00, 0x00, //
    ];

    #[test]
    fn the_syn_encodes_to_the_bytes_the_guest_opens_a_session_for() {
        let header = TcpHeader {
            source_port: 49152,
            destination_port: 62078,
            sequence: 0x1122_3344,
            acknowledgement: 0,
            flags: flags::SYN,
            window: TcpHeader::window_from_wire(0xFFFF),
        };
        let mut out = [0u8; TCP_HEADER_LEN];
        assert_eq!(header.encode(&mut out).unwrap(), 20);
        assert_eq!(out, HOST_SYN);
    }

    #[test]
    fn the_data_offset_byte_is_what_the_guest_turns_into_twenty() {
        assert_eq!(TcpHeader::declared_header_len(&HOST_SYN), Some(20));
        assert_eq!(HOST_SYN[12], 0x50);
    }

    #[test]
    fn the_syn_ack_decodes_with_the_device_starting_at_sequence_zero() {
        let header = TcpHeader::decode(&DEVICE_SYN_ACK).unwrap();
        assert_eq!(header.source_port, 62078);
        assert_eq!(header.destination_port, 49152);
        assert_eq!(header.sequence, DEVICE_INITIAL_SEQUENCE);
        assert_eq!(header.acknowledgement, 0x1122_3345);
        assert!(header.is_syn_ack());
        assert!(!header.is_bare_ack());
    }

    #[test]
    fn the_window_is_shifted_by_eight_in_both_directions() {
        let header = TcpHeader::decode(&DEVICE_SYN_ACK).unwrap();
        assert_eq!(header.window, 65536);
        assert_eq!(TcpHeader::window_to_wire(65536), 0x0100);
        assert_eq!(TcpHeader::window_from_wire(0xFFFF), 0x00FF_FF00);
        assert_eq!(TcpHeader::window_from_wire(0xFFFF), 16_776_960);
        assert_eq!(TcpHeader::window_to_wire(16_776_960), 0xFFFF);
    }

    #[test]
    fn a_window_wider_than_the_field_saturates_rather_than_wrapping() {
        assert_eq!(TcpHeader::window_to_wire(u32::MAX), 0xFFFF);
        assert_eq!(TcpHeader::window_to_wire(511), 1);
        assert_eq!(TcpHeader::window_to_wire(255), 0);
    }

    #[test]
    fn the_window_edge_is_acknowledgement_plus_the_scaled_window() {
        let header = TcpHeader::decode(&DEVICE_SYN_ACK).unwrap();
        assert_eq!(header.window_edge(), 0x1122_3345u32.wrapping_add(65536));
    }

    #[test]
    fn round_tripping_preserves_every_field_the_guest_reads() {
        let header = TcpHeader {
            source_port: 1234,
            destination_port: 62078,
            sequence: 0xDEAD_BEEF,
            acknowledgement: 0x0BAD_F00D,
            flags: flags::ACK,
            window: TcpHeader::window_from_wire(0x0800),
        };
        let mut out = [0u8; TCP_HEADER_LEN];
        header.encode(&mut out).unwrap();
        assert_eq!(TcpHeader::decode(&out).unwrap(), header);
    }

    #[test]
    fn flags_are_matched_for_equality_because_the_guest_matches_them_that_way() {
        let mut header = TcpHeader::decode(&HOST_SYN).unwrap();
        assert!(header.is_bare_syn());
        header.flags = flags::SYN | flags::PSH;
        assert!(!header.is_bare_syn());
        header.flags = flags::ACK | flags::PSH;
        assert!(!header.is_bare_ack());
        header.flags = flags::ACK;
        assert!(header.is_bare_ack());
        header.flags = flags::RST | flags::ACK;
        assert!(header.is_reset());
    }

    #[test]
    fn a_header_carrying_options_is_refused_rather_than_mis_framed() {
        let mut bytes = HOST_SYN;
        bytes[12] = 0x60;
        assert!(matches!(
            TcpHeader::decode(&bytes),
            Err(TcpError::Options { offset_words: 6 })
        ));
        assert_eq!(TcpHeader::declared_header_len(&bytes), Some(24));
    }

    #[test]
    fn a_short_header_is_refused_at_the_same_bound_the_guest_uses() {
        let short = [0u8; 19];
        assert!(matches!(
            TcpHeader::decode(&short),
            Err(TcpError::Short {
                needed: 20,
                had: 19
            })
        ));
        let mut out = [0u8; 19];
        let header = TcpHeader::decode(&HOST_SYN).unwrap();
        assert!(matches!(
            header.encode(&mut out),
            Err(TcpError::Short {
                needed: 20,
                had: 19
            })
        ));
    }

    #[test]
    fn the_checksum_and_urgent_pointer_are_zeroed_and_never_consulted() {
        let header = TcpHeader::decode(&HOST_SYN).unwrap();
        let mut out = [0xAAu8; TCP_HEADER_LEN];
        header.encode(&mut out).unwrap();
        assert_eq!(&out[16..20], &[0, 0, 0, 0]);
        let mut noisy = HOST_SYN;
        noisy[16..20].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(TcpHeader::decode(&noisy).unwrap(), header);
    }
}
