pub fn embedded_panic_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn crc32c_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::{crc32c_update, embedded_panic_crc32};

    #[test]
    fn crc32c_matches_published_vector() {
        assert_eq!(!crc32c_update(u32::MAX, b"123456789"), 0xe306_9283);
    }

    #[test]
    fn crc32_matches_published_vectors() {
        assert_eq!(embedded_panic_crc32(b""), 0x0000_0000);
        assert_eq!(embedded_panic_crc32(b"123456789"), 0xcbf4_3926);
    }
}
