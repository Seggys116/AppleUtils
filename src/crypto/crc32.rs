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

#[cfg(test)]
mod tests {
    use super::embedded_panic_crc32;

    #[test]
    fn crc32_matches_published_vectors() {
        assert_eq!(embedded_panic_crc32(b""), 0x0000_0000);
        assert_eq!(embedded_panic_crc32(b"123456789"), 0xcbf4_3926);
    }
}
