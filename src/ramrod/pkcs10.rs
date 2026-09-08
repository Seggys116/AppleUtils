use std::fmt;

use crate::crypto::{
    P256_SIGNATURE_BYTES, P256_UNCOMPRESSED_BYTES, sha256, sha384, verify_uncompressed,
};

pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

pub const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

pub const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

pub const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

// Read, never required: real clients send other values here.
pub const CERTIFICATION_REQUEST_VERSION: u64 = 0;

const MAX_VERSION_BYTES: usize = 8;

const ATTRIBUTES_TAG: u8 = 0xa0;

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureDigest {
    Sha256,
    Sha384,
}

impl SignatureDigest {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "ecdsa-with-SHA256",
            Self::Sha384 => "ecdsa-with-SHA384",
        }
    }

    #[must_use]
    pub fn reduce(self, message: &[u8]) -> [u8; 32] {
        match self {
            Self::Sha256 => sha256(message),
            Self::Sha384 => {
                let wide = sha384(message);
                let mut narrow = [0u8; 32];
                narrow.copy_from_slice(&wide[..32]);
                narrow
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pkcs10Error {
    Der {
        field: &'static str,
    },
    Tag {
        field: &'static str,
        expected: u8,
        found: u8,
    },
    Trailing {
        field: &'static str,
        bytes: usize,
    },
    Version {
        found: Vec<u8>,
    },
    UnsupportedKeyAlgorithm {
        oid: Vec<u8>,
    },
    UnsupportedCurve {
        oid: Vec<u8>,
    },
    UnsupportedSignatureAlgorithm {
        oid: Vec<u8>,
    },
    PublicKeyShape {
        unused_bits: u8,
        bytes: usize,
    },
    SignatureShape {
        unused_bits: u8,
    },
    SignatureEncoding,
    ProofOfPossession {
        algorithm: &'static str,
    },
    EmptySubject,
}

impl fmt::Display for Pkcs10Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Der { field } => write!(formatter, "malformed DER reading {field}"),
            Self::Tag {
                field,
                expected,
                found,
            } => write!(
                formatter,
                "{field} carried tag 0x{found:02x} where 0x{expected:02x} was required"
            ),
            Self::Trailing { field, bytes } => {
                write!(formatter, "{bytes} bytes remained after {field}")
            }
            Self::Version { found } => write!(
                formatter,
                "certificationRequestInfo version 0x{} is not a readable non negative integer of at most {MAX_VERSION_BYTES} bytes",
                found
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            Self::UnsupportedKeyAlgorithm { oid } => write!(
                formatter,
                "subject public key algorithm OID {} is not id-ecPublicKey, and the local authority issues only P-256 certificates",
                describe_oid(oid)
            ),
            Self::UnsupportedCurve { oid } => write!(
                formatter,
                "named curve OID {} is not prime256v1",
                describe_oid(oid)
            ),
            Self::UnsupportedSignatureAlgorithm { oid } => write!(
                formatter,
                "signature algorithm OID {} is neither ecdsa-with-SHA256 nor ecdsa-with-SHA384, so the proof of possession cannot be checked",
                describe_oid(oid)
            ),
            Self::PublicKeyShape { unused_bits, bytes } => write!(
                formatter,
                "subjectPublicKey is {bytes} bytes with {unused_bits} unused bits, not a {P256_UNCOMPRESSED_BYTES} byte uncompressed P-256 point"
            ),
            Self::SignatureShape { unused_bits } => write!(
                formatter,
                "the signature BIT STRING carries {unused_bits} unused bits"
            ),
            Self::SignatureEncoding => write!(
                formatter,
                "the signature is not a readable SEQUENCE of two P-256 sized INTEGERs"
            ),
            Self::ProofOfPossession { algorithm } => write!(
                formatter,
                "the {algorithm} signature over certificationRequestInfo does not verify against the subject public key, so the sender has not proved it holds that key"
            ),
            Self::EmptySubject => write!(formatter, "the subject Name is empty"),
        }
    }
}

impl std::error::Error for Pkcs10Error {}

fn describe_oid(encoded: &[u8]) -> String {
    let Some((first, rest)) = encoded.split_first() else {
        return String::from("<empty>");
    };
    let mut arcs = vec![u32::from(*first) / 40, u32::from(*first) % 40];
    let mut value: u64 = 0;
    for byte in rest {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            arcs.push(value as u32);
            value = 0;
        }
    }
    arcs.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
}

fn tlv<'a>(input: &'a [u8], field: &'static str) -> Result<(Tlv<'a>, &'a [u8]), Pkcs10Error> {
    let (&tag, rest) = input.split_first().ok_or(Pkcs10Error::Der { field })?;
    let (&first, rest) = rest.split_first().ok_or(Pkcs10Error::Der { field })?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < count {
            return Err(Pkcs10Error::Der { field });
        }
        let mut length = 0usize;
        for byte in &rest[..count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, &rest[count..])
    };
    if rest.len() < length {
        return Err(Pkcs10Error::Der { field });
    }
    let header = input.len() - rest.len();
    Ok((
        Tlv {
            tag,
            full: &input[..header + length],
            value: &rest[..length],
        },
        &rest[length..],
    ))
}

fn expect<'a>(
    input: &'a [u8],
    tag: u8,
    field: &'static str,
) -> Result<(Tlv<'a>, &'a [u8]), Pkcs10Error> {
    let (item, rest) = tlv(input, field)?;
    if item.tag != tag {
        return Err(Pkcs10Error::Tag {
            field,
            expected: tag,
            found: item.tag,
        });
    }
    Ok((item, rest))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificationRequest<'a> {
    pub der: &'a [u8],
    pub info: &'a [u8],
    pub version: u64,
    pub subject: &'a [u8],
    pub subject_public_key_info: &'a [u8],
    pub subject_public_key: [u8; P256_UNCOMPRESSED_BYTES],
    pub attributes: &'a [u8],
    pub digest: SignatureDigest,
    pub signature: &'a [u8],
}

impl<'a> CertificationRequest<'a> {
    pub fn verify_proof_of_possession(&self) -> Result<(), Pkcs10Error> {
        let signature = decode_ecdsa_signature(self.signature)?;
        let digest = self.digest.reduce(self.info);
        if verify_uncompressed(&self.subject_public_key, &digest, &signature) {
            Ok(())
        } else {
            Err(Pkcs10Error::ProofOfPossession {
                algorithm: self.digest.name(),
            })
        }
    }
}

fn decode_ecdsa_signature(der: &[u8]) -> Result<[u8; P256_SIGNATURE_BYTES], Pkcs10Error> {
    let (sequence, rest) =
        expect(der, TAG_SEQUENCE, "signature").map_err(|_| Pkcs10Error::SignatureEncoding)?;
    if !rest.is_empty() {
        return Err(Pkcs10Error::SignatureEncoding);
    }
    let (r, rest) = expect(sequence.value, TAG_INTEGER, "signature r")
        .map_err(|_| Pkcs10Error::SignatureEncoding)?;
    let (s, rest) =
        expect(rest, TAG_INTEGER, "signature s").map_err(|_| Pkcs10Error::SignatureEncoding)?;
    if !rest.is_empty() {
        return Err(Pkcs10Error::SignatureEncoding);
    }
    let mut out = [0u8; P256_SIGNATURE_BYTES];
    let half = P256_SIGNATURE_BYTES / 2;
    for (index, magnitude) in [r.value, s.value].into_iter().enumerate() {
        let trimmed = magnitude
            .iter()
            .position(|byte| *byte != 0)
            .map_or(&magnitude[magnitude.len().saturating_sub(1)..], |start| {
                &magnitude[start..]
            });
        if trimmed.len() > half || magnitude.is_empty() {
            return Err(Pkcs10Error::SignatureEncoding);
        }
        let base = index * half + (half - trimmed.len());
        out[base..base + trimmed.len()].copy_from_slice(trimmed);
    }
    Ok(out)
}

fn read_version(magnitude: &[u8]) -> Result<u64, Pkcs10Error> {
    let refused = || Pkcs10Error::Version {
        found: magnitude.to_vec(),
    };
    let (&first, rest) = magnitude.split_first().ok_or_else(refused)?;
    if first & 0x80 != 0 {
        return Err(refused());
    }
    let trimmed = if first == 0 && !rest.is_empty() {
        rest
    } else {
        magnitude
    };
    if trimmed.len() > MAX_VERSION_BYTES {
        return Err(refused());
    }
    let mut value: u64 = 0;
    for byte in trimmed {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

pub fn parse(der: &[u8]) -> Result<CertificationRequest<'_>, Pkcs10Error> {
    let (request, rest) = expect(der, TAG_SEQUENCE, "CertificationRequest")?;
    if !rest.is_empty() {
        return Err(Pkcs10Error::Trailing {
            field: "CertificationRequest",
            bytes: rest.len(),
        });
    }

    let (info, rest) = expect(request.value, TAG_SEQUENCE, "certificationRequestInfo")?;
    let (algorithm, rest) = expect(rest, TAG_SEQUENCE, "signatureAlgorithm")?;
    let (signature, rest) = expect(rest, TAG_BIT_STRING, "signature")?;
    if !rest.is_empty() {
        return Err(Pkcs10Error::Trailing {
            field: "signature",
            bytes: rest.len(),
        });
    }

    let (algorithm_oid, _) = expect(algorithm.value, TAG_OID, "signatureAlgorithm algorithm")?;
    let digest = if algorithm_oid.value == OID_ECDSA_WITH_SHA256 {
        SignatureDigest::Sha256
    } else if algorithm_oid.value == OID_ECDSA_WITH_SHA384 {
        SignatureDigest::Sha384
    } else {
        return Err(Pkcs10Error::UnsupportedSignatureAlgorithm {
            oid: algorithm_oid.value.to_vec(),
        });
    };

    let (&unused_bits, signature_body) = signature
        .value
        .split_first()
        .ok_or(Pkcs10Error::Der { field: "signature" })?;
    if unused_bits != 0 {
        return Err(Pkcs10Error::SignatureShape { unused_bits });
    }

    let (version, rest) = expect(info.value, TAG_INTEGER, "version")?;
    let version = read_version(version.value)?;
    let (subject, rest) = expect(rest, TAG_SEQUENCE, "subject")?;
    if subject.value.is_empty() {
        return Err(Pkcs10Error::EmptySubject);
    }
    let (spki, rest) = expect(rest, TAG_SEQUENCE, "subjectPKInfo")?;
    let attributes = match tlv(rest, "attributes") {
        Ok((item, _)) if item.tag == ATTRIBUTES_TAG => item.full,
        _ => &[][..],
    };

    let (spki_algorithm, spki_rest) = expect(spki.value, TAG_SEQUENCE, "subjectPKInfo algorithm")?;
    let (key_oid, curve_rest) =
        expect(spki_algorithm.value, TAG_OID, "subjectPKInfo algorithm oid")?;
    if key_oid.value != OID_EC_PUBLIC_KEY {
        return Err(Pkcs10Error::UnsupportedKeyAlgorithm {
            oid: key_oid.value.to_vec(),
        });
    }
    let (curve_oid, _) = expect(curve_rest, TAG_OID, "subjectPKInfo named curve")?;
    if curve_oid.value != OID_PRIME256V1 {
        return Err(Pkcs10Error::UnsupportedCurve {
            oid: curve_oid.value.to_vec(),
        });
    }

    let (key_bits, _) = expect(spki_rest, TAG_BIT_STRING, "subjectPublicKey")?;
    let (&key_unused, point) = key_bits.value.split_first().ok_or(Pkcs10Error::Der {
        field: "subjectPublicKey",
    })?;
    if key_unused != 0 || point.len() != P256_UNCOMPRESSED_BYTES || point[0] != 0x04 {
        return Err(Pkcs10Error::PublicKeyShape {
            unused_bits: key_unused,
            bytes: point.len(),
        });
    }
    let mut subject_public_key = [0u8; P256_UNCOMPRESSED_BYTES];
    subject_public_key.copy_from_slice(point);

    Ok(CertificationRequest {
        der: request.full,
        info: info.full,
        version,
        subject: subject.full,
        subject_public_key_info: spki.full,
        subject_public_key,
        attributes,
        digest,
        signature: signature_body,
    })
}

pub fn parse_and_verify(der: &[u8]) -> Result<CertificationRequest<'_>, Pkcs10Error> {
    let request = parse(der)?;
    request.verify_proof_of_possession()?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{P256PrivateKey, signature_to_der};
    use crate::ramrod::der;

    const TEST_COMMON_NAME: &str = "AppleUtils FDR Device";

    fn request_for(key: &P256PrivateKey, digest: SignatureDigest, common_name: &str) -> Vec<u8> {
        request_versioned(key, digest, common_name, CERTIFICATION_REQUEST_VERSION)
    }

    fn request_versioned(
        key: &P256PrivateKey,
        digest: SignatureDigest,
        common_name: &str,
        version: u64,
    ) -> Vec<u8> {
        let mut spki_algorithm = der::oid(&[1, 2, 840, 10045, 2, 1]);
        spki_algorithm.extend_from_slice(&der::oid(&[1, 2, 840, 10045, 3, 1, 7]));
        let mut spki = der::sequence(&spki_algorithm);
        spki.extend_from_slice(&der::bit_string(&key.public_uncompressed()));
        let spki = der::sequence(&spki);

        let mut attribute = der::oid(&[2, 5, 4, 3]);
        attribute.extend_from_slice(&der::utf8_string(common_name));
        let name = der::sequence(&der::set(&der::sequence(&attribute)));

        let mut info = der::integer_u64(version);
        info.extend_from_slice(&name);
        info.extend_from_slice(&spki);
        info.extend_from_slice(&der::explicit(0, &[]));
        let info = der::sequence(&info);

        let arcs: &[u32] = match digest {
            SignatureDigest::Sha256 => &[1, 2, 840, 10045, 4, 3, 2],
            SignatureDigest::Sha384 => &[1, 2, 840, 10045, 4, 3, 3],
        };
        let algorithm = der::sequence(&der::oid(arcs));
        let signature = key.sign_digest(&digest.reduce(&info));

        let mut body = info;
        body.extend_from_slice(&algorithm);
        body.extend_from_slice(&der::bit_string(&signature_to_der(&signature)));
        der::sequence(&body)
    }

    fn key() -> P256PrivateKey {
        P256PrivateKey::derive(&[0x5a; 32], b"pkcs10 test")
    }

    #[test]
    fn a_p256_request_parses_and_proves_possession() {
        let key = key();
        for digest in [SignatureDigest::Sha256, SignatureDigest::Sha384] {
            let der = request_for(&key, digest, TEST_COMMON_NAME);
            let request = parse_and_verify(&der).expect("parse and verify");
            assert_eq!(request.subject_public_key, key.public_uncompressed());
            assert_eq!(request.digest, digest);
            assert_eq!(request.der, der.as_slice());
            assert_eq!(request.version, CERTIFICATION_REQUEST_VERSION);
            assert!(!request.subject.is_empty());
        }
    }

    #[test]
    fn a_version_other_than_zero_is_read_rather_than_refused() {
        let key = key();
        for version in [0u64, 1, 2, 3, 0x100] {
            let der = request_versioned(&key, SignatureDigest::Sha256, TEST_COMMON_NAME, version);
            let request = parse_and_verify(&der).expect("parse and verify");
            assert_eq!(request.version, version, "version {version}");
            assert_eq!(request.subject_public_key, key.public_uncompressed());
        }
    }

    #[test]
    fn an_unreadable_version_is_still_refused() {
        assert!(read_version(&[]).is_err());
        assert!(read_version(&[0x80]).is_err());
        assert!(read_version(&[0xff, 0x01]).is_err());
        assert_eq!(
            read_version(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            Ok(0x0102_0304_0506_0708)
        );
        assert!(
            read_version(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]).is_err()
        );
        assert_eq!(read_version(&[0x00]), Ok(0));
        assert_eq!(read_version(&[0x02]), Ok(2));
        assert_eq!(read_version(&[0x00, 0x80]), Ok(0x80));
    }

    #[test]
    fn relaxing_the_version_did_not_relax_the_rest() {
        let key = key();
        let mut der = request_versioned(&key, SignatureDigest::Sha256, TEST_COMMON_NAME, 2);
        let at = der
            .windows(TEST_COMMON_NAME.len())
            .position(|window| window == TEST_COMMON_NAME.as_bytes())
            .expect("subject present");
        der[at] = b'N';
        assert!(matches!(
            parse_and_verify(&der),
            Err(Pkcs10Error::ProofOfPossession { .. })
        ));
    }

    #[test]
    fn the_signature_covers_the_complete_info_element() {
        let key = key();
        let der = request_for(&key, SignatureDigest::Sha256, TEST_COMMON_NAME);
        let request = parse(&der).expect("parse");
        assert_eq!(request.info.first(), Some(&TAG_SEQUENCE));
        let digest = SignatureDigest::Sha256.reduce(request.info);
        let signature = decode_ecdsa_signature(request.signature).expect("signature");
        assert!(verify_uncompressed(
            &request.subject_public_key,
            &digest,
            &signature
        ));
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let signer = key();
        let mut der = request_for(&signer, SignatureDigest::Sha256, TEST_COMMON_NAME);
        let impostor = P256PrivateKey::derive(&[0xa5; 32], b"pkcs10 test");
        let point = impostor.public_uncompressed();
        let at = der
            .windows(P256_UNCOMPRESSED_BYTES)
            .position(|window| window == signer.public_uncompressed())
            .expect("subject key present");
        der[at..at + P256_UNCOMPRESSED_BYTES].copy_from_slice(&point);
        assert_eq!(
            parse_and_verify(&der),
            Err(Pkcs10Error::ProofOfPossession {
                algorithm: "ecdsa-with-SHA256"
            })
        );
    }

    #[test]
    fn a_tampered_subject_is_refused() {
        let key = key();
        let mut der = request_for(&key, SignatureDigest::Sha256, TEST_COMMON_NAME);
        let at = der
            .windows(TEST_COMMON_NAME.len())
            .position(|window| window == TEST_COMMON_NAME.as_bytes())
            .expect("subject present");
        der[at] = b'N';
        assert!(matches!(
            parse_and_verify(&der),
            Err(Pkcs10Error::ProofOfPossession { .. })
        ));
    }

    #[test]
    fn a_non_ec_subject_key_is_named_and_refused() {
        let key = key();
        let der = request_for(&key, SignatureDigest::Sha256, TEST_COMMON_NAME);
        let rsa: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let at = der
            .windows(OID_EC_PUBLIC_KEY.len())
            .position(|window| window == OID_EC_PUBLIC_KEY)
            .expect("key oid present");
        let mut broken = der;
        broken[at..at + OID_EC_PUBLIC_KEY.len()].copy_from_slice(&rsa[..OID_EC_PUBLIC_KEY.len()]);
        assert!(matches!(
            parse(&broken),
            Err(Pkcs10Error::UnsupportedKeyAlgorithm { .. })
        ));
    }

    #[test]
    fn every_truncation_is_an_error_rather_than_a_panic() {
        let key = key();
        let der = request_for(&key, SignatureDigest::Sha256, TEST_COMMON_NAME);
        for length in 0..der.len() {
            assert!(
                parse(&der[..length]).is_err(),
                "a {length} byte prefix parsed"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let key = key();
        let mut der = request_for(&key, SignatureDigest::Sha256, TEST_COMMON_NAME);
        der.push(0x00);
        assert_eq!(
            parse(&der),
            Err(Pkcs10Error::Trailing {
                field: "CertificationRequest",
                bytes: 1
            })
        );
    }
}
