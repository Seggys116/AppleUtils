use crate::crypto::Sha256;

const HIGH_TAG_NUMBER_FORM: u8 = 0x1f;

const MAX_LENGTH_BYTES: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum FdrTrustObjectError {
    Truncated { at: usize },
    BadLength { at: usize },
    Empty,
}

impl std::fmt::Display for FdrTrustObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "trust object file truncated at byte {at}"),
            Self::BadLength { at } => write!(f, "unusable DER length at byte {at}"),
            Self::Empty => write!(f, "trust object file is empty"),
        }
    }
}

impl std::error::Error for FdrTrustObjectError {}

fn read_top_level_element(bytes: &[u8], at: usize) -> Result<(usize, usize), FdrTrustObjectError> {
    let mut cursor = at;
    let identifier = *bytes
        .get(cursor)
        .ok_or(FdrTrustObjectError::Truncated { at })?;
    cursor += 1;
    if identifier & HIGH_TAG_NUMBER_FORM == HIGH_TAG_NUMBER_FORM {
        loop {
            let byte = *bytes
                .get(cursor)
                .ok_or(FdrTrustObjectError::Truncated { at: cursor })?;
            cursor += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let first_length = *bytes
        .get(cursor)
        .ok_or(FdrTrustObjectError::Truncated { at: cursor })?;
    cursor += 1;
    let length = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > MAX_LENGTH_BYTES {
            return Err(FdrTrustObjectError::BadLength { at: cursor - 1 });
        }
        let mut value = 0usize;
        for offset in 0..count {
            let byte = *bytes
                .get(cursor + offset)
                .ok_or(FdrTrustObjectError::Truncated {
                    at: cursor + offset,
                })?;
            value = (value << 8) | usize::from(byte);
        }
        cursor += count;
        value
    };
    let end = cursor
        .checked_add(length)
        .ok_or(FdrTrustObjectError::BadLength { at })?;
    if end > bytes.len() {
        return Err(FdrTrustObjectError::BadLength { at });
    }
    Ok((at, end))
}

pub fn top_level_elements(bytes: &[u8]) -> Result<Vec<(usize, usize)>, FdrTrustObjectError> {
    if bytes.is_empty() {
        return Err(FdrTrustObjectError::Empty);
    }
    let mut cursor = 0;
    let mut spans = Vec::new();
    while cursor < bytes.len() {
        let span = read_top_level_element(bytes, cursor)?;
        cursor = span.1;
        spans.push(span);
    }
    Ok(spans)
}

pub fn digest_top_level_elements(bytes: &[u8]) -> Result<Vec<[u8; 32]>, FdrTrustObjectError> {
    let spans = top_level_elements(bytes)?;
    Ok(spans
        .into_iter()
        .map(|(start, end)| {
            let mut hasher = Sha256::new();
            hasher.update(&bytes[start..end]);
            hasher.finish()
        })
        .collect())
}

// The guest tries element 0 first and stops at the first match.
pub fn primary_trust_object_digest(bytes: &[u8]) -> Result<([u8; 32], usize), FdrTrustObjectError> {
    let digests = digest_top_level_elements(bytes)?;
    let first = *digests.first().ok_or(FdrTrustObjectError::Empty)?;
    Ok((first, digests.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUND_TRUTH_ENV: &str = "APPLEUTILS_FDR_TRUST_GROUND_TRUTH";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn read_ground_truth() -> Option<Vec<u8>> {
        let Ok(path) = std::env::var(GROUND_TRUTH_ENV) else {
            eprintln!("skipping: {GROUND_TRUTH_ENV} is not set");
            return None;
        };
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                eprintln!("skipping: could not read {GROUND_TRUTH_ENV}={path}: {error}");
                None
            }
        }
    }

    #[test]
    fn ground_truth_file_splits_into_the_three_known_elements() {
        let Some(bytes) = read_ground_truth() else {
            return;
        };
        assert_eq!(bytes.len(), 9183);

        let spans = top_level_elements(&bytes).expect("three consecutive DER elements");
        assert_eq!(spans, vec![(0, 2884), (2884, 5992), (5992, 9183)]);

        let digests = digest_top_level_elements(&bytes).expect("every span hashes");
        assert_eq!(digests.len(), 3);
        assert_eq!(
            hex(&digests[0]),
            "5340b6a059bdb732e715e7bb1b292edcd45c2a8d1d07e6039d3f338d7c4428ab"
        );
        assert_eq!(
            hex(&digests[1]),
            "64b2585a38bf951a2f581e9922bbd7c6b98dd8655f94497ac3292ee28564cfca"
        );
        assert_eq!(
            hex(&digests[2]),
            "f2be39b98a0bf5c1886db2a762f8f144a6fb4b0e1ea2c40146518522e810e915"
        );

        let (primary, element_count) =
            primary_trust_object_digest(&bytes).expect("the primary digest is computable");
        assert_eq!(primary, digests[0]);
        assert_eq!(element_count, 3);
    }

    #[test]
    fn an_empty_file_is_refused() {
        assert_eq!(top_level_elements(&[]), Err(FdrTrustObjectError::Empty));
        assert_eq!(
            digest_top_level_elements(&[]),
            Err(FdrTrustObjectError::Empty)
        );
    }

    #[test]
    fn a_truncated_length_is_refused() {
        let bytes = [0x30, 0x84, 0x00];
        assert_eq!(
            top_level_elements(&bytes),
            Err(FdrTrustObjectError::Truncated { at: 3 })
        );
    }

    #[test]
    fn an_element_whose_length_runs_past_the_end_is_refused() {
        let bytes = [0x30, 0x0a, 0x01, 0x02];
        assert_eq!(
            top_level_elements(&bytes),
            Err(FdrTrustObjectError::BadLength { at: 0 })
        );
    }

    #[test]
    fn trailing_bytes_that_do_not_form_a_complete_element_are_refused() {
        let bytes = [0x30, 0x00, 0x30, 0x05];
        assert_eq!(
            top_level_elements(&bytes),
            Err(FdrTrustObjectError::BadLength { at: 2 })
        );
    }

    #[test]
    fn the_high_tag_number_form_is_handled() {
        let identifier = [0xff, 0x84, 0xea, 0x85, 0x9c, 0x42]; // private "MANB"
        let mut bytes = identifier.to_vec();
        bytes.push(0x00);
        let spans = top_level_elements(&bytes).expect("a valid high tag number element");
        assert_eq!(spans, vec![(0, bytes.len())]);
    }

    #[test]
    fn multiple_top_level_elements_are_each_hashed_independently() {
        let mut bytes = vec![0x04, 0x03, b'a', b'b', b'c']; // OCTET STRING "abc"
        bytes.extend_from_slice(&[0x04, 0x01, b'x']); // OCTET STRING "x"
        let digests = digest_top_level_elements(&bytes).unwrap();
        assert_eq!(digests.len(), 2);
        let mut hasher = Sha256::new();
        hasher.update(&bytes[0..5]);
        assert_eq!(digests[0], hasher.finish());
    }
}
