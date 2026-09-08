use std::fmt;

pub const IDENTIFIER_BOOLEAN: u8 = 0x01;
pub const IDENTIFIER_INTEGER: u8 = 0x02;
pub const IDENTIFIER_BIT_STRING: u8 = 0x03;
pub const IDENTIFIER_OCTET_STRING: u8 = 0x04;
pub const IDENTIFIER_NULL: u8 = 0x05;
pub const IDENTIFIER_OID: u8 = 0x06;
pub const IDENTIFIER_UTF8_STRING: u8 = 0x0c;
pub const IDENTIFIER_PRINTABLE_STRING: u8 = 0x13;
pub const IDENTIFIER_IA5_STRING: u8 = 0x16;
pub const IDENTIFIER_UTC_TIME: u8 = 0x17;
pub const IDENTIFIER_GENERALIZED_TIME: u8 = 0x18;
pub const IDENTIFIER_SEQUENCE: u8 = 0x30;
pub const IDENTIFIER_SET: u8 = 0x31;

const CONSTRUCTED: u8 = 0x20;
const CLASS_CONTEXT: u8 = 0x80;
const CLASS_PRIVATE: u8 = 0xc0;
const HIGH_TAG_NUMBER_FORM: u8 = 0x1f;
const LOW_TAG_NUMBER_MAX: u8 = 30;

const FOURCC_BYTES: usize = 4;

const UTC_TIME_FIRST_YEAR: i64 = 1950;
const UTC_TIME_LAST_YEAR: i64 = 2049;
const GENERALIZED_TIME_LAST_YEAR: i64 = 9999;

const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerError {
    NotAFourCharacterCode { length: usize },
    OidTooShort { arcs: usize },
    OidFirstArc { value: u32 },
    OidSecondArc { first: u32, second: u32 },
    YearOutOfRange { year: i64 },
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAFourCharacterCode { length } => {
                write!(f, "a four character code cannot be {length} bytes")
            }
            Self::OidTooShort { arcs } => {
                write!(f, "an object identifier needs two arcs, got {arcs}")
            }
            Self::OidFirstArc { value } => {
                write!(f, "object identifier first arc {value} is not 0, 1 or 2")
            }
            Self::OidSecondArc { first, second } => write!(
                f,
                "object identifier second arc {second} does not fit under first arc {first}"
            ),
            Self::YearOutOfRange { year } => {
                write!(f, "year {year} cannot be spelled as a DER time")
            }
        }
    }
}

impl std::error::Error for DerError {}

pub fn tlv(identifier: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(identifier.len() + 5 + body.len());
    out.extend_from_slice(identifier);
    let length = body.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let digits = length.to_be_bytes();
        let first = digits
            .iter()
            .position(|digit| *digit != 0)
            .unwrap_or(digits.len() - 1);
        let significant = &digits[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(body);
    out
}

pub fn sequence(body: &[u8]) -> Vec<u8> {
    tlv(&[IDENTIFIER_SEQUENCE], body)
}

pub fn set(body: &[u8]) -> Vec<u8> {
    tlv(&[IDENTIFIER_SET], body)
}

pub fn ia5_string(text: &str) -> Vec<u8> {
    tlv(&[IDENTIFIER_IA5_STRING], text.as_bytes())
}

pub fn printable_string(text: &str) -> Vec<u8> {
    tlv(&[IDENTIFIER_PRINTABLE_STRING], text.as_bytes())
}

pub fn utf8_string(text: &str) -> Vec<u8> {
    tlv(&[IDENTIFIER_UTF8_STRING], text.as_bytes())
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(&[IDENTIFIER_OCTET_STRING], bytes)
}

pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0x00);
    body.extend_from_slice(bytes);
    tlv(&[IDENTIFIER_BIT_STRING], &body)
}

pub fn named_bit_string(bits: &[u8]) -> Vec<u8> {
    let last = bits.iter().rposition(|byte| *byte != 0);
    let Some(last) = last else {
        return tlv(&[IDENTIFIER_BIT_STRING], &[0x00]);
    };
    let unused = bits[last].trailing_zeros() as u8;
    let mut body = Vec::with_capacity(last + 2);
    body.push(unused);
    body.extend_from_slice(&bits[..=last]);
    tlv(&[IDENTIFIER_BIT_STRING], &body)
}

pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let start = magnitude.iter().position(|byte| *byte != 0);
    let Some(start) = start else {
        return tlv(&[IDENTIFIER_INTEGER], &[0x00]);
    };
    let trimmed = &magnitude[start..];
    if trimmed[0] & 0x80 != 0 {
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        body.push(0x00);
        body.extend_from_slice(trimmed);
        tlv(&[IDENTIFIER_INTEGER], &body)
    } else {
        tlv(&[IDENTIFIER_INTEGER], trimmed)
    }
}

pub fn integer_u64(value: u64) -> Vec<u8> {
    integer(&value.to_be_bytes())
}

pub fn boolean(value: bool) -> Vec<u8> {
    tlv(&[IDENTIFIER_BOOLEAN], &[if value { 0xff } else { 0x00 }])
}

pub fn null() -> Vec<u8> {
    tlv(&[IDENTIFIER_NULL], &[])
}

pub fn explicit(tag_number: u8, body: &[u8]) -> Vec<u8> {
    tlv(&context_identifier(tag_number, true), body)
}

pub fn context_primitive(tag_number: u8, body: &[u8]) -> Vec<u8> {
    tlv(&context_identifier(tag_number, false), body)
}

fn context_identifier(tag_number: u8, constructed: bool) -> Vec<u8> {
    let class = CLASS_CONTEXT | if constructed { CONSTRUCTED } else { 0 };
    if tag_number <= LOW_TAG_NUMBER_MAX {
        vec![class | tag_number]
    } else {
        let mut identifier = vec![class | HIGH_TAG_NUMBER_FORM];
        identifier.extend_from_slice(&base128(u64::from(tag_number)));
        identifier
    }
}

pub fn try_oid(arcs: &[u32]) -> Result<Vec<u8>, DerError> {
    if arcs.len() < 2 {
        return Err(DerError::OidTooShort { arcs: arcs.len() });
    }
    let first = arcs[0];
    let second = arcs[1];
    if first > 2 {
        return Err(DerError::OidFirstArc { value: first });
    }
    if first < 2 && second >= 40 {
        return Err(DerError::OidSecondArc { first, second });
    }
    let mut body = base128(u64::from(first) * 40 + u64::from(second));
    for arc in &arcs[2..] {
        body.extend_from_slice(&base128(u64::from(*arc)));
    }
    Ok(tlv(&[IDENTIFIER_OID], &body))
}

pub fn oid(arcs: &[u32]) -> Vec<u8> {
    match try_oid(arcs) {
        Ok(encoded) => encoded,
        Err(error) => panic!("constant object identifier {arcs:?} is malformed: {error}"),
    }
}

fn base128(mut value: u64) -> Vec<u8> {
    let mut groups = Vec::new();
    loop {
        groups.push((value & 0x7f) as u8);
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    groups.reverse();
    let last = groups.len() - 1;
    for (index, group) in groups.iter_mut().enumerate() {
        if index != last {
            *group |= 0x80;
        }
    }
    groups
}

pub fn fourcc_private(code: &str) -> Result<Vec<u8>, DerError> {
    let bytes = code.as_bytes();
    if bytes.len() != FOURCC_BYTES {
        return Err(DerError::NotAFourCharacterCode {
            length: bytes.len(),
        });
    }
    let tag = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut identifier = vec![CLASS_PRIVATE | CONSTRUCTED | HIGH_TAG_NUMBER_FORM];
    identifier.extend_from_slice(&base128(u64::from(tag)));
    Ok(identifier)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CivilTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

pub fn civil_from_unix(unix_secs: i64) -> CivilTime {
    let days = unix_secs.div_euclid(SECONDS_PER_DAY);
    let rem = unix_secs.rem_euclid(SECONDS_PER_DAY);

    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;

    CivilTime {
        year: year + i64::from(month <= 2),
        month,
        day,
        hour: (rem / 3_600) as u32,
        minute: ((rem / 60) % 60) as u32,
        second: (rem % 60) as u32,
    }
}

pub fn utc_time(unix_secs: i64) -> Result<Vec<u8>, DerError> {
    let time = civil_from_unix(unix_secs);
    if !(UTC_TIME_FIRST_YEAR..=UTC_TIME_LAST_YEAR).contains(&time.year) {
        return Err(DerError::YearOutOfRange { year: time.year });
    }
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        time.year % 100,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second
    );
    Ok(tlv(&[IDENTIFIER_UTC_TIME], text.as_bytes()))
}

pub fn generalized_time(unix_secs: i64) -> Result<Vec<u8>, DerError> {
    let time = civil_from_unix(unix_secs);
    if !(0..=GENERALIZED_TIME_LAST_YEAR).contains(&time.year) {
        return Err(DerError::YearOutOfRange { year: time.year });
    }
    let text = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    );
    Ok(tlv(&[IDENTIFIER_GENERALIZED_TIME], text.as_bytes()))
}

pub fn x509_time(unix_secs: i64) -> Result<Vec<u8>, DerError> {
    let year = civil_from_unix(unix_secs).year;
    if (UTC_TIME_FIRST_YEAR..=UTC_TIME_LAST_YEAR).contains(&year) {
        utc_time(unix_secs)
    } else {
        generalized_time(unix_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_take_the_minimal_definite_form_at_every_boundary() {
        let cases: [(usize, &[u8]); 8] = [
            (0, &[0x30, 0x00]),
            (1, &[0x30, 0x01]),
            (0x7f, &[0x30, 0x7f]),
            (0x80, &[0x30, 0x81, 0x80]),
            (0xff, &[0x30, 0x81, 0xff]),
            (0x100, &[0x30, 0x82, 0x01, 0x00]),
            (0xffff, &[0x30, 0x82, 0xff, 0xff]),
            (0x1_0000, &[0x30, 0x83, 0x01, 0x00, 0x00]),
        ];
        for (length, header) in cases {
            let body = vec![0x5au8; length];
            let encoded = sequence(&body);
            assert_eq!(&encoded[..header.len()], header, "length {length} header");
            assert_eq!(
                encoded.len(),
                header.len() + length,
                "length {length} total"
            );
            assert_eq!(&encoded[header.len()..], &body[..], "length {length} body");
        }
    }

    #[test]
    fn integers_are_minimal_and_never_read_back_negative() {
        assert_eq!(integer(&[]), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0x00, 0x00, 0x00]), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0x01]), vec![0x02, 0x01, 0x01]);
        assert_eq!(integer(&[0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(&[0xff]), vec![0x02, 0x02, 0x00, 0xff]);
        assert_eq!(
            integer(&[0x00, 0x00, 0x80, 0x01]),
            vec![0x02, 0x03, 0x00, 0x80, 0x01]
        );
        assert_eq!(integer(&[0x00, 0x7f, 0xff]), vec![0x02, 0x02, 0x7f, 0xff]);
        assert_eq!(integer_u64(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer_u64(255), vec![0x02, 0x02, 0x00, 0xff]);
        assert_eq!(
            integer_u64(u64::MAX),
            vec![
                0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
    }

    #[test]
    fn manb_encodes_as_the_known_private_identifier() {
        assert_eq!(
            fourcc_private("MANB").expect("MANB is four bytes"),
            vec![0xff, 0x84, 0xea, 0x85, 0x9c, 0x42]
        );
        assert_eq!(
            fourcc_private("MANP").expect("MANP is four bytes"),
            vec![0xff, 0x84, 0xea, 0x85, 0x9c, 0x50]
        );
    }

    #[test]
    fn a_code_that_is_not_four_bytes_is_refused() {
        assert_eq!(
            fourcc_private("MAN"),
            Err(DerError::NotAFourCharacterCode { length: 3 })
        );
        assert_eq!(
            fourcc_private(""),
            Err(DerError::NotAFourCharacterCode { length: 0 })
        );
        assert_eq!(
            fourcc_private("MANBX"),
            Err(DerError::NotAFourCharacterCode { length: 5 })
        );
    }

    #[test]
    fn object_identifiers_match_their_hand_computed_encodings() {
        assert_eq!(
            oid(&[1, 2, 840, 10045, 2, 1]),
            vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
        );
        assert_eq!(
            oid(&[1, 2, 840, 10045, 3, 1, 7]),
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        );
        assert_eq!(
            oid(&[1, 2, 840, 10045, 4, 3, 2]),
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
        );
        assert_eq!(
            oid(&[1, 2, 840, 113_635, 100, 6, 1, 15]),
            vec![
                0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f
            ]
        );
        assert_eq!(
            oid(&[1, 2, 840, 113_635, 100, 6, 17]),
            vec![
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x11
            ]
        );
        assert_eq!(oid(&[2, 5, 4, 3]), vec![0x06, 0x03, 0x55, 0x04, 0x03]);
        assert_eq!(oid(&[2, 5, 29, 19]), vec![0x06, 0x03, 0x55, 0x1d, 0x13]);
        assert_eq!(oid(&[0, 0]), vec![0x06, 0x01, 0x00]);
    }

    #[test]
    fn malformed_arc_lists_are_refused() {
        assert_eq!(try_oid(&[]), Err(DerError::OidTooShort { arcs: 0 }));
        assert_eq!(try_oid(&[1]), Err(DerError::OidTooShort { arcs: 1 }));
        assert_eq!(try_oid(&[3, 1]), Err(DerError::OidFirstArc { value: 3 }));
        assert_eq!(
            try_oid(&[1, 40]),
            Err(DerError::OidSecondArc {
                first: 1,
                second: 40
            })
        );
        assert!(try_oid(&[2, 100]).is_ok());
    }

    #[test]
    fn x509_times_change_type_at_2050_and_get_leap_days_right() {
        assert_eq!(
            x509_time(2_524_607_999).expect("1949 to 2049 is UTCTime"),
            tlv(&[IDENTIFIER_UTC_TIME], b"491231235959Z")
        );
        assert_eq!(
            x509_time(2_524_608_000).expect("2050 onwards is GeneralizedTime"),
            tlv(&[IDENTIFIER_GENERALIZED_TIME], b"20500101000000Z")
        );
        assert_eq!(
            x509_time(0).expect("the epoch is UTCTime"),
            tlv(&[IDENTIFIER_UTC_TIME], b"700101000000Z")
        );
        assert_eq!(
            x509_time(1_709_210_096).expect("a leap day is UTCTime"),
            tlv(&[IDENTIFIER_UTC_TIME], b"240229123456Z")
        );
    }

    #[test]
    fn the_century_leap_rule_holds_in_both_directions() {
        assert_eq!(
            civil_from_unix(951_782_400),
            CivilTime {
                year: 2000,
                month: 2,
                day: 29,
                hour: 0,
                minute: 0,
                second: 0
            }
        );
        assert_eq!(
            civil_from_unix(4_107_542_400),
            CivilTime {
                year: 2100,
                month: 3,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0
            }
        );
        assert_eq!(
            civil_from_unix(-2_203_891_200),
            CivilTime {
                year: 1900,
                month: 3,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0
            }
        );
    }

    #[test]
    fn years_outside_the_encodable_range_are_refused() {
        assert_eq!(
            utc_time(2_524_608_000),
            Err(DerError::YearOutOfRange { year: 2050 })
        );
        assert_eq!(
            utc_time(-631_152_001),
            Err(DerError::YearOutOfRange { year: 1949 })
        );
        assert_eq!(
            utc_time(-631_152_000).expect("1950 is the first UTCTime year"),
            tlv(&[IDENTIFIER_UTC_TIME], b"500101000000Z")
        );
        assert!(matches!(
            generalized_time(300_000_000_000),
            Err(DerError::YearOutOfRange { .. })
        ));
    }

    #[test]
    fn primitive_helpers_emit_their_documented_shapes() {
        assert_eq!(boolean(true), vec![0x01, 0x01, 0xff]);
        assert_eq!(boolean(false), vec![0x01, 0x01, 0x00]);
        assert_eq!(null(), vec![0x05, 0x00]);
        assert_eq!(
            bit_string(&[0xab, 0xcd]),
            vec![0x03, 0x03, 0x00, 0xab, 0xcd]
        );
        assert_eq!(octet_string(&[0x01]), vec![0x04, 0x01, 0x01]);
        assert_eq!(utf8_string("AU"), vec![0x0c, 0x02, b'A', b'U']);
        assert_eq!(ia5_string("MANB"), vec![0x16, 0x04, b'M', b'A', b'N', b'B']);
        assert_eq!(
            printable_string("AU"),
            vec![IDENTIFIER_PRINTABLE_STRING, 0x02, b'A', b'U']
        );
        assert_eq!(
            explicit(0, &[0x02, 0x01, 0x02]),
            vec![0xa0, 0x03, 0x02, 0x01, 0x02]
        );
        assert_eq!(explicit(3, &[]), vec![0xa3, 0x00]);
        assert_eq!(context_primitive(0, &[0xaa]), vec![0x80, 0x01, 0xaa]);
        assert_eq!(named_bit_string(&[0x86]), vec![0x03, 0x02, 0x01, 0x86]);
        assert_eq!(named_bit_string(&[0x04]), vec![0x03, 0x02, 0x02, 0x04]);
        assert_eq!(named_bit_string(&[0x00]), vec![0x03, 0x01, 0x00]);
    }
}
