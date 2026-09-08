use std::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const PAD: u8 = b'=';

pub const PEM_LINE_WIDTH: usize = 64;

pub const LABEL_CERTIFICATE_REQUEST: &str = "CERTIFICATE REQUEST";

pub const LABEL_CERTIFICATE: &str = "CERTIFICATE";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PemError {
    NoBeginLine { label: String },
    NoEndLine { label: String },
    Alphabet { byte: u8, offset: usize },
    Length { characters: usize },
    Padding { offset: usize },
}

impl fmt::Display for PemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBeginLine { label } => {
                write!(formatter, "no -----BEGIN {label}----- line in the body")
            }
            Self::NoEndLine { label } => {
                write!(
                    formatter,
                    "no -----END {label}----- line after the begin line"
                )
            }
            Self::Alphabet { byte, offset } => write!(
                formatter,
                "byte 0x{byte:02x} at offset {offset} is not base64 and is not whitespace"
            ),
            Self::Length { characters } => write!(
                formatter,
                "{characters} base64 characters is not a whole number of four character groups"
            ),
            Self::Padding { offset } => write!(
                formatter,
                "padding at offset {offset} is not in the final group"
            ),
        }
    }
}

impl std::error::Error for PemError {}

#[must_use]
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let a = u32::from(group[0]);
        let b = group.get(1).copied().map_or(0, u32::from);
        let c = group.get(2).copied().map_or(0, u32::from);
        let word = (a << 16) | (b << 8) | c;
        out.push(ALPHABET[((word >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((word >> 12) & 0x3f) as usize] as char);
        if group.len() > 1 {
            out.push(ALPHABET[((word >> 6) & 0x3f) as usize] as char);
        } else {
            out.push(PAD as char);
        }
        if group.len() > 2 {
            out.push(ALPHABET[(word & 0x3f) as usize] as char);
        } else {
            out.push(PAD as char);
        }
    }
    out
}

fn alphabet_value(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn base64_decode(text: &[u8]) -> Result<Vec<u8>, PemError> {
    let mut accumulator: u32 = 0;
    let mut held = 0usize;
    let mut characters = 0usize;
    let mut padding = 0usize;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (offset, byte) in text.iter().copied().enumerate() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == PAD {
            padding += 1;
            characters += 1;
            continue;
        }
        if padding != 0 {
            return Err(PemError::Padding { offset });
        }
        let value = alphabet_value(byte).ok_or(PemError::Alphabet { byte, offset })?;
        accumulator = (accumulator << 6) | value;
        held += 1;
        characters += 1;
        if held == 4 {
            out.push((accumulator >> 16) as u8);
            out.push((accumulator >> 8) as u8);
            out.push(accumulator as u8);
            accumulator = 0;
            held = 0;
        }
    }
    if !characters.is_multiple_of(4) {
        return Err(PemError::Length { characters });
    }
    match held {
        0 => {}
        2 => out.push((accumulator >> 4) as u8),
        3 => {
            out.push((accumulator >> 10) as u8);
            out.push((accumulator >> 2) as u8);
        }
        _ => return Err(PemError::Length { characters }),
    }
    Ok(out)
}

#[must_use]
pub fn encode(label: &str, der: &[u8]) -> String {
    let body = base64_encode(der);
    let mut out =
        String::with_capacity(body.len() + body.len() / PEM_LINE_WIDTH + 2 * label.len() + 32);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let bytes = body.as_bytes();
    for line in bytes.chunks(PEM_LINE_WIDTH) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

pub fn decode(text: &[u8], label: &str) -> Result<Vec<u8>, PemError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = find(text, begin.as_bytes()).ok_or_else(|| PemError::NoBeginLine {
        label: label.to_string(),
    })? + begin.len();
    let stop = find(&text[start..], end.as_bytes()).ok_or_else(|| PemError::NoEndLine {
        label: label.to_string(),
    })?;
    base64_decode(&text[start..start + stop])
}

#[must_use]
pub fn looks_like_pem(text: &[u8]) -> bool {
    find(text, b"-----BEGIN ").is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded, "encoding {plain}");
            assert_eq!(
                base64_decode(encoded.as_bytes()).expect("decode"),
                plain.as_bytes(),
                "decoding {encoded}"
            );
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        let encoded = base64_encode(&all);
        assert_eq!(base64_decode(encoded.as_bytes()).expect("decode"), all);
    }

    #[test]
    fn armour_round_trips_through_the_line_wrapping() {
        let der: Vec<u8> = (0..200u32).map(|value| (value % 251) as u8).collect();
        let text = encode(LABEL_CERTIFICATE, &der);
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(
            decode(text.as_bytes(), LABEL_CERTIFICATE).expect("decode"),
            der
        );
    }

    #[test]
    fn the_label_has_to_match() {
        let text = encode(LABEL_CERTIFICATE, b"whatever");
        assert_eq!(
            decode(text.as_bytes(), LABEL_CERTIFICATE_REQUEST),
            Err(PemError::NoBeginLine {
                label: LABEL_CERTIFICATE_REQUEST.to_string()
            })
        );
    }

    #[test]
    fn a_foreign_byte_is_refused_with_its_offset() {
        assert_eq!(
            base64_decode(b"Zm9v*mFy"),
            Err(PemError::Alphabet {
                byte: b'*',
                offset: 4
            })
        );
    }

    #[test]
    fn padding_before_the_end_is_refused() {
        assert_eq!(
            base64_decode(b"Zg==Zg=="),
            Err(PemError::Padding { offset: 4 })
        );
    }
}
