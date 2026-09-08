use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LzvnError {
    Truncated {
        at: usize,
    },
    ReservedOpcode {
        at: usize,
        opcode: u8,
    },
    DistanceTooFar {
        at: usize,
        distance: usize,
        decoded: usize,
    },
    NoPreviousDistance {
        at: usize,
    },
    OutputTooLarge {
        limit: usize,
    },
    Unterminated {
        decoded: usize,
    },
}

impl fmt::Display for LzvnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { at } => {
                write!(f, "the stream ends inside the opcode at offset {at}")
            }
            Self::ReservedOpcode { at, opcode } => write!(
                f,
                "{opcode:#04x} at offset {at} is an opcode the format reserves"
            ),
            Self::DistanceTooFar {
                at,
                distance,
                decoded,
            } => write!(
                f,
                "the match at offset {at} reaches {distance} bytes back through {decoded} decoded \
                 bytes"
            ),
            Self::NoPreviousDistance { at } => write!(
                f,
                "the opcode at offset {at} reuses a distance no earlier opcode set"
            ),
            Self::OutputTooLarge { limit } => {
                write!(f, "the stream decodes to more than {limit} bytes")
            }
            Self::Unterminated { decoded } => write!(
                f,
                "the stream ends after {decoded} bytes without an end of stream opcode"
            ),
        }
    }
}

impl std::error::Error for LzvnError {}

const END_OF_STREAM_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opcode {
    SmallDistance,
    MediumDistance,
    LargeDistance,
    PreviousDistance,
    SmallLiteral,
    LargeLiteral,
    SmallMatch,
    LargeMatch,
    Nop,
    EndOfStream,
    Reserved,
}

fn classify(opcode: u8) -> Opcode {
    match opcode {
        0xe0 => Opcode::LargeLiteral,
        0xe1..=0xef => Opcode::SmallLiteral,
        0xf0 => Opcode::LargeMatch,
        0xf1..=0xff => Opcode::SmallMatch,
        0xa0..=0xbf => Opcode::MediumDistance,
        0x06 => Opcode::EndOfStream,
        0x0e | 0x16 => Opcode::Nop,
        0x1e | 0x26 | 0x2e | 0x36 | 0x3e => Opcode::Reserved,
        0x70..=0x7f | 0xd0..=0xdf => Opcode::Reserved,
        _ => match opcode & 0x07 {
            7 => Opcode::LargeDistance,
            6 => Opcode::PreviousDistance,
            _ => Opcode::SmallDistance,
        },
    }
}

pub fn decode(stream: &[u8], limit: usize) -> Result<Vec<u8>, LzvnError> {
    let mut out = Vec::with_capacity(limit);
    decode_onto(stream, limit, &mut out)?;
    Ok(out)
}

pub fn decode_onto(stream: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<(), LzvnError> {
    let base = out.len();
    let ceiling = base
        .checked_add(limit)
        .ok_or(LzvnError::OutputTooLarge { limit })?;
    let mut at = 0usize;
    let mut distance = 0usize;

    loop {
        let Some(&opcode) = stream.get(at) else {
            return Err(LzvnError::Unterminated {
                decoded: out.len() - base,
            });
        };
        let start = at;
        let literals;
        let length;

        match classify(opcode) {
            Opcode::EndOfStream => {
                if stream.len() - at < END_OF_STREAM_BYTES {
                    return Err(LzvnError::Truncated { at });
                }
                return Ok(());
            }
            Opcode::Nop => {
                at += 1;
                continue;
            }
            Opcode::Reserved => return Err(LzvnError::ReservedOpcode { at, opcode }),
            Opcode::SmallDistance => {
                let low = byte_at(stream, at + 1, start)?;
                literals = usize::from(opcode >> 6);
                length = usize::from((opcode >> 3) & 0x07) + 3;
                distance = usize::from(opcode & 0x07) << 8 | usize::from(low);
                at += 2;
            }
            Opcode::MediumDistance => {
                let packed = half_word_at(stream, at + 1, start)?;
                literals = usize::from((opcode >> 3) & 0x03);
                length = (usize::from(opcode & 0x07) << 2 | usize::from(packed & 0x03)) + 3;
                distance = usize::from(packed >> 2);
                at += 3;
            }
            Opcode::LargeDistance => {
                literals = usize::from(opcode >> 6);
                length = usize::from((opcode >> 3) & 0x07) + 3;
                distance = usize::from(half_word_at(stream, at + 1, start)?);
                at += 3;
            }
            Opcode::PreviousDistance => {
                literals = usize::from(opcode >> 6);
                length = usize::from((opcode >> 3) & 0x07) + 3;
                at += 1;
            }
            Opcode::SmallLiteral => {
                literals = usize::from(opcode & 0x0f);
                length = 0;
                at += 1;
            }
            Opcode::LargeLiteral => {
                literals = usize::from(byte_at(stream, at + 1, start)?) + 16;
                length = 0;
                at += 2;
            }
            Opcode::SmallMatch => {
                literals = 0;
                length = usize::from(opcode & 0x0f);
                at += 1;
            }
            Opcode::LargeMatch => {
                literals = 0;
                length = usize::from(byte_at(stream, at + 1, start)?) + 16;
                at += 2;
            }
        }

        if literals != 0 {
            let end = at
                .checked_add(literals)
                .filter(|end| *end <= stream.len())
                .ok_or(LzvnError::Truncated { at: start })?;
            if out.len() + literals > ceiling {
                return Err(LzvnError::OutputTooLarge { limit });
            }
            out.extend_from_slice(&stream[at..end]);
            at = end;
        }

        if length != 0 {
            if distance == 0 {
                return Err(LzvnError::NoPreviousDistance { at: start });
            }
            let decoded = out.len() - base;
            if distance > decoded {
                return Err(LzvnError::DistanceTooFar {
                    at: start,
                    distance,
                    decoded,
                });
            }
            if out.len() + length > ceiling {
                return Err(LzvnError::OutputTooLarge { limit });
            }
            for from in (out.len() - distance..).take(length) {
                let byte = out[from];
                out.push(byte);
            }
        }
    }
}

fn byte_at(stream: &[u8], at: usize, start: usize) -> Result<u8, LzvnError> {
    stream
        .get(at)
        .copied()
        .ok_or(LzvnError::Truncated { at: start })
}

fn half_word_at(stream: &[u8], at: usize, start: usize) -> Result<u16, LzvnError> {
    let low = byte_at(stream, at, start)?;
    let high = byte_at(stream, at + 1, start)?;
    Ok(u16::from_le_bytes([low, high]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finished(head: &[u8]) -> Vec<u8> {
        let mut stream = head.to_vec();
        stream.push(0x06);
        stream.extend_from_slice(&[0u8; END_OF_STREAM_BYTES - 1]);
        stream
    }

    #[test]
    fn an_empty_stream_is_its_end_of_stream_opcode() {
        assert_eq!(decode(&finished(&[]), 0), Ok(Vec::new()));
    }

    #[test]
    fn bytes_after_the_end_of_stream_opcode_are_ignored() {
        let mut stream = finished(&[0xe3, b'a', b'b', b'c']);
        stream.extend_from_slice(b"encoder scratch nobody reads");
        assert_eq!(decode(&stream, 3), Ok(b"abc".to_vec()));
    }

    #[test]
    fn a_stream_without_an_end_of_stream_opcode_is_refused() {
        assert_eq!(
            decode(&[0xe4, b'a', b'b', b'c', b'd'], 16),
            Err(LzvnError::Unterminated { decoded: 4 })
        );
    }

    #[test]
    fn an_end_of_stream_opcode_without_its_payload_is_truncated() {
        assert_eq!(
            decode(&[0xe1, b'a', 0x06, 0x00, 0x00], 16),
            Err(LzvnError::Truncated { at: 2 })
        );
    }

    #[test]
    fn a_small_literal_run_decodes() {
        assert_eq!(
            decode(&finished(&[0xe3, b'a', b'b', b'c']), 3),
            Ok(b"abc".to_vec())
        );
        let mut fifteen = vec![0xef];
        fifteen.extend_from_slice(b"abcdefghijklmno");
        assert_eq!(
            decode(&finished(&fifteen), 15),
            Ok(b"abcdefghijklmno".to_vec())
        );
    }

    #[test]
    fn a_large_literal_run_decodes_at_both_ends_of_its_range() {
        let mut shortest = vec![0xe0, 0];
        shortest.extend_from_slice(b"abcdefghijklmnop");
        assert_eq!(
            decode(&finished(&shortest), 16),
            Ok(b"abcdefghijklmnop".to_vec())
        );

        let body: Vec<u8> = (0..271).map(|n| b'0' + (n % 10) as u8).collect();
        let mut longest = vec![0xe0, 255];
        longest.extend_from_slice(&body);
        assert_eq!(decode(&finished(&longest), 271), Ok(body));
    }

    #[test]
    fn a_small_distance_instruction_decodes() {
        assert_eq!(
            decode(&finished(&[0xe4, b'a', b'b', b'c', b'd', 0x20, 0x04]), 11),
            Ok(b"abcdabcdabc".to_vec())
        );
        assert_eq!(
            decode(
                &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x60, 0x04, b'Q']),
                12
            ),
            Ok(b"abcdQbcdQbcd".to_vec())
        );
        assert_eq!(
            decode(&finished(&[0xe4, b'a', b'b', b'c', b'd', 0x38, 0x04]), 14),
            Ok(b"abcdabcdabcdab".to_vec())
        );
    }

    #[test]
    fn a_small_distance_reaches_past_one_byte() {
        let body: Vec<u8> = (0..271).map(|n| b'0' + (n % 10) as u8).collect();
        let mut stream = vec![0xe0, 255];
        stream.extend_from_slice(&body);
        stream.extend_from_slice(&[0x21, 0x00]);

        let mut expected = body.clone();
        for step in 0..7 {
            expected.push(expected[271 - 256 + step]);
        }
        assert_eq!(decode(&finished(&stream), 278), Ok(expected));
    }

    #[test]
    fn an_overlapping_match_repeats_the_run_it_is_producing() {
        assert_eq!(
            decode(&finished(&[0xe1, b'z', 0x30, 0x01]), 10),
            Ok(b"zzzzzzzzzz".to_vec())
        );
    }

    #[test]
    fn a_medium_distance_instruction_unpacks_its_split_length() {
        let mut stream = vec![0xe0, 0];
        stream.extend_from_slice(b"abcdefghijklmnop");
        stream.extend_from_slice(&[0xa9, 0x46, 0x00, b'Z']);
        assert_eq!(
            decode(&finished(&stream), 26),
            Ok(b"abcdefghijklmnopZabcdefghi".to_vec())
        );
    }

    #[test]
    fn a_large_distance_instruction_decodes() {
        let body: Vec<u8> = (0..271).map(|n| b'0' + (n % 10) as u8).collect();
        let mut stream = vec![0xe0, 255];
        stream.extend_from_slice(&body);
        stream.extend_from_slice(&[0x07, 0x00, 0x01]);

        let mut expected = body.clone();
        for step in 0..3 {
            expected.push(expected[271 - 256 + step]);
        }
        assert_eq!(decode(&finished(&stream), 274), Ok(expected));
    }

    #[test]
    fn a_previous_distance_instruction_reuses_the_last_distance() {
        assert_eq!(
            decode(
                &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, 0x46, b'Q']),
                11
            ),
            Ok(b"abcdabcQabc".to_vec())
        );
        assert_eq!(
            decode(
                &finished(&[
                    0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, 0xce, b'X', b'Y', b'Z'
                ]),
                14
            ),
            Ok(b"abcdabcXYZcXYZ".to_vec())
        );
    }

    #[test]
    fn a_small_match_reuses_the_previous_distance() {
        assert_eq!(
            decode(
                &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, 0xf1]),
                8
            ),
            Ok(b"abcdabcd".to_vec())
        );
        assert_eq!(
            decode(
                &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, 0xff]),
                22
            ),
            Ok(b"abcdabcdabcdabcdabcdab".to_vec())
        );
    }

    #[test]
    fn a_large_match_decodes_at_both_ends_of_its_range() {
        assert_eq!(
            decode(
                &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, 0xf0, 0]),
                23
            ),
            Ok(b"abcdabcdabcdabcdabcdabc".to_vec())
        );
        assert_eq!(
            decode(
                &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, 0xf0, 30]),
                53
            ),
            Ok(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcda".to_vec())
        );
    }

    #[test]
    fn the_no_operation_opcodes_are_stepped_over() {
        for nop in [0x0e, 0x16] {
            assert_eq!(
                decode(
                    &finished(&[0xe4, b'a', b'b', b'c', b'd', 0x00, 0x04, nop, 0xe1, b'Q']),
                    8
                ),
                Ok(b"abcdabcQ".to_vec())
            );
        }
    }

    #[test]
    fn the_reserved_opcodes_are_refused() {
        let reserved: Vec<u8> = (0u8..=0xff)
            .filter(|byte| classify(*byte) == Opcode::Reserved)
            .collect();
        let expected: Vec<u8> = [0x1e, 0x26, 0x2e, 0x36, 0x3e]
            .into_iter()
            .chain(0x70..=0x7f)
            .chain(0xd0..=0xdf)
            .collect();
        assert_eq!(reserved, expected);

        for opcode in reserved {
            assert_eq!(
                decode(&finished(&[0xe4, b'a', b'b', b'c', b'd', opcode, 0x04]), 64),
                Err(LzvnError::ReservedOpcode { at: 5, opcode })
            );
        }
    }

    #[test]
    fn a_match_with_no_previous_distance_is_refused() {
        assert_eq!(
            decode(&finished(&[0xf5]), 16),
            Err(LzvnError::NoPreviousDistance { at: 0 })
        );
    }

    #[test]
    fn a_match_reaching_past_the_start_is_refused() {
        assert_eq!(
            decode(&finished(&[0xe1, b'z', 0x00, 0x09]), 16),
            Err(LzvnError::DistanceTooFar {
                at: 2,
                distance: 9,
                decoded: 1,
            })
        );
    }

    #[test]
    fn an_appended_stream_cannot_match_into_the_one_before_it() {
        let mut out = b"earlier chunk".to_vec();
        assert_eq!(
            decode_onto(&finished(&[0xe1, b'z', 0x00, 0x05]), 16, &mut out),
            Err(LzvnError::DistanceTooFar {
                at: 2,
                distance: 5,
                decoded: 1,
            })
        );
    }

    #[test]
    fn output_past_the_limit_is_refused() {
        let mut literals = vec![0xe0, 255];
        literals.extend(std::iter::repeat_n(b'x', 271));
        assert_eq!(
            decode(&finished(&literals), 64),
            Err(LzvnError::OutputTooLarge { limit: 64 })
        );
        assert_eq!(
            decode(&finished(&[0xe4, b'a', b'b', b'c', b'd', 0x38, 0x04]), 8),
            Err(LzvnError::OutputTooLarge { limit: 8 })
        );
    }

    #[test]
    fn a_field_past_the_end_of_the_stream_is_refused() {
        assert_eq!(
            decode(&[0xef, b'a', b'b'], 64),
            Err(LzvnError::Truncated { at: 0 })
        );
        for head in [
            vec![0xe0],       // large literal, no count
            vec![0xf0],       // large match, no count
            vec![0x00],       // small distance, no low byte
            vec![0x07, 0x01], // large distance, half a half word
            vec![0xa0, 0x01], // medium distance, half a half word
        ] {
            assert_eq!(
                decode(&head, 64),
                Err(LzvnError::Truncated { at: 0 }),
                "{head:02x?}"
            );
        }
    }

    #[test]
    fn no_malformed_stream_escapes_its_bounds() {
        for opcode in 0u8..=0xff {
            for length in 0..12usize {
                let mut stream = vec![opcode];
                stream.extend((0..length).map(|n| (n as u8).wrapping_mul(37)));
                for limit in [0usize, 1, 7, 64] {
                    let mut out = b"bytes an earlier chunk left".to_vec();
                    let before = out.clone();
                    let outcome = decode_onto(&stream, limit, &mut out);
                    assert!(
                        out.len() <= before.len() + limit,
                        "{opcode:#04x} {length} {limit}"
                    );
                    assert_eq!(&out[..before.len()], &before[..], "{opcode:#04x}");
                    if outcome.is_ok() {
                        assert_eq!(classify(opcode), Opcode::EndOfStream);
                    }
                }
            }
        }
    }

    const MODULE_MAP_STREAM: [u8; 178] = [
        0xe0, 0x29, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x6d, 0x6f, 0x64,
        0x75, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x72, 0x65, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x20, 0x5b,
        0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5d, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x75, 0x6d, 0x62,
        0x72, 0x65, 0x6c, 0x6c, 0x61, 0x20, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x20, 0x22, 0x30,
        0x28, 0xc0, 0x20, 0x2e, 0x68, 0x22, 0xea, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x2a,
        0x0a, 0x20, 0x28, 0x49, 0xc8, 0x16, 0x2a, 0x20, 0x7b, 0xf5, 0x80, 0x18, 0x20, 0x7d, 0x18,
        0x26, 0xe5, 0x6c, 0x69, 0x63, 0x69, 0x74, 0x30, 0x6d, 0xe9, 0x49, 0x46, 0x69, 0x6c, 0x74,
        0x65, 0x72, 0x42, 0x75, 0x00, 0x07, 0xc8, 0x6b, 0x69, 0x6e, 0x73, 0xf1, 0x08, 0x01, 0x30,
        0x66, 0x38, 0x21, 0xf5, 0x18, 0x6d, 0x08, 0x01, 0x38, 0x71, 0xf1, 0xe4, 0x7d, 0x0a, 0x7d,
        0x0a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0xe0, 0x09, 0x6e, 0x63, 0x6c,
        0x75, 0x64, 0x65, 0x20, 0x3c, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x64,
        0x69, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x00, 0xad, 0x68, 0x21, 0x3e, 0xf4,
    ];

    const MODULE_MAP_PLAIN: &[u8] = b"framework module CoreImage [system] {\n  \
umbrella header \"CoreImage.h\"\n  export *\n  module * { export * }\n  \n  \
explicit module CIFilterBuiltins {\n      header \"CIFilterBuiltins.h\"\n      \
export *\n  }\n}\n";

    #[test]
    fn a_stream_apples_encoder_produced_decodes_to_the_file_it_came_from() {
        assert_eq!(MODULE_MAP_PLAIN.len(), 200);
        assert_eq!(
            decode(&MODULE_MAP_STREAM, MODULE_MAP_PLAIN.len()),
            Ok(MODULE_MAP_PLAIN.to_vec())
        );
    }

    #[test]
    fn the_stored_chunk_marker_cannot_begin_a_producing_stream() {
        for tail in 0u8..=0xff {
            let stream = [0x06, tail, tail, tail, tail, tail, tail, tail];
            assert_eq!(decode(&stream, 64), Ok(Vec::new()));
        }
    }
}
