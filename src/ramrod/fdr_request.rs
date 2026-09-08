use std::fmt;

use super::fdr_manifest::{
    CLASS_PROPERTY_TAG, DIGEST_PROPERTY_TAG, INSTANCE_PROPERTY_TAG, OBJECT_DIGEST_BYTES,
};
use super::ticket::read_manifest;

pub const ACTION_CODE_SEALING: u64 = 0x0b;

pub const MANIFEST_ENTRY_TAG: &str = "IM4M";

pub const SEAL_URL_CLASS: &str = "seal";

pub const CLASS_INSTANCE_SEPARATOR: char = ':';

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_1_CONSTRUCTED: u8 = 0xa1;

const CONTAINER_IMG4: &str = "IMG4";

const CONTAINER_IM4P: &str = "IM4P";

const MAX_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealingRequestError {
    Der {
        field: &'static str,
    },
    Tag {
        field: &'static str,
        expected: u8,
        found: u8,
    },
    NoAction,
    KeyNotText,
    KeyHasNoSeparator {
        key: String,
    },
    EmptyClass {
        key: String,
    },
    UnknownShape {
        identifier: Option<u8>,
    },
    NoManifests {
        keys: Vec<String>,
    },
    Manifest {
        entry: usize,
        error: String,
    },
    ObjectHasNoDigest {
        entry: usize,
        class: String,
    },
    DigestLength {
        class: String,
        length: usize,
    },
    ConflictingDigest {
        class: String,
    },
}

impl fmt::Display for SealingRequestError {
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
            Self::NoAction => write!(formatter, "the request envelope carried no action group"),
            Self::KeyNotText => write!(formatter, "a record key was not valid UTF-8"),
            Self::KeyHasNoSeparator { key } => write!(
                formatter,
                "record key {key:?} carries no '{CLASS_INSTANCE_SEPARATOR}', so its class and instance cannot be told apart"
            ),
            Self::EmptyClass { key } => write!(
                formatter,
                "record key {key:?} names an empty class before its '{CLASS_INSTANCE_SEPARATOR}'"
            ),
            Self::UnknownShape { identifier } => match identifier {
                Some(byte) => write!(
                    formatter,
                    "the body opens with 0x{byte:02x} and is neither the multi request envelope nor the per instance sealing request"
                ),
                None => write!(formatter, "the body is empty"),
            },
            Self::NoManifests { keys } => write!(
                formatter,
                "no {MANIFEST_ENTRY_TAG} entry anywhere in the request, so the guest sent no digests to sign; the records carried were [{}]",
                keys.join(", ")
            ),
            Self::Manifest { entry, error } => write!(
                formatter,
                "{MANIFEST_ENTRY_TAG} entry {entry} could not be read: {error}"
            ),
            Self::ObjectHasNoDigest { entry, class } => write!(
                formatter,
                "object {class:?} in {MANIFEST_ENTRY_TAG} entry {entry} carries no {DIGEST_PROPERTY_TAG}"
            ),
            Self::DigestLength { class, length } => write!(
                formatter,
                "the digest for {class:?} is {length} bytes where {OBJECT_DIGEST_BYTES} were required"
            ),
            Self::ConflictingDigest { class } => write!(
                formatter,
                "two manifests name class {class:?} with different digests, and the host cannot choose between them"
            ),
        }
    }
}

impl std::error::Error for SealingRequestError {}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn tlv<'a>(
    input: &'a [u8],
    field: &'static str,
) -> Result<(Tlv<'a>, &'a [u8]), SealingRequestError> {
    let (&tag, rest) = input
        .split_first()
        .ok_or(SealingRequestError::Der { field })?;
    let (&first, rest) = rest
        .split_first()
        .ok_or(SealingRequestError::Der { field })?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < count {
            return Err(SealingRequestError::Der { field });
        }
        let mut length = 0usize;
        for byte in &rest[..count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, &rest[count..])
    };
    if rest.len() < length {
        return Err(SealingRequestError::Der { field });
    }
    Ok((
        Tlv {
            tag,
            value: &rest[..length],
        },
        &rest[length..],
    ))
}

fn expect<'a>(
    input: &'a [u8],
    tag: u8,
    field: &'static str,
) -> Result<(Tlv<'a>, &'a [u8]), SealingRequestError> {
    let (item, rest) = tlv(input, field)?;
    if item.tag != tag {
        return Err(SealingRequestError::Tag {
            field,
            expected: tag,
            found: item.tag,
        });
    }
    Ok((item, rest))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealingRecord {
    pub class: String,
    pub instance: String,
    pub value: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassDigest {
    pub class: String,
    pub instance: Option<String>,
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealingRequestShape {
    MultiRequest {
        action: u64,
        records: Vec<SealingRecord>,
    },
    PerInstance {
        instance: String,
        body: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealingRequest {
    pub shape: SealingRequestShape,
}

impl SealingRequest {
    #[must_use]
    pub fn shape_name(&self) -> &'static str {
        match self.shape {
            SealingRequestShape::MultiRequest { .. } => "multi-request",
            SealingRequestShape::PerInstance { .. } => "per-instance",
        }
    }

    #[must_use]
    pub fn action(&self) -> Option<u64> {
        match &self.shape {
            SealingRequestShape::MultiRequest { action, .. } => Some(*action),
            SealingRequestShape::PerInstance { .. } => None,
        }
    }

    #[must_use]
    pub fn record_keys(&self) -> Vec<String> {
        match &self.shape {
            SealingRequestShape::MultiRequest { records, .. } => records
                .iter()
                .map(|record| {
                    format!(
                        "{}{CLASS_INSTANCE_SEPARATOR}{}",
                        record.class, record.instance
                    )
                })
                .collect(),
            SealingRequestShape::PerInstance { instance, .. } => vec![instance.clone()],
        }
    }

    pub fn class_digests(&self) -> Result<Vec<ClassDigest>, SealingRequestError> {
        let mut entries = Vec::new();
        match &self.shape {
            SealingRequestShape::MultiRequest { records, .. } => {
                for record in records {
                    let payload = unwrap_containers(&record.value)?;
                    collect_manifest_entries(&payload, 0, &mut entries)?;
                }
            }
            SealingRequestShape::PerInstance { body, .. } => {
                let payload = unwrap_containers(body)?;
                collect_manifest_entries(&payload, 0, &mut entries)?;
            }
        }
        if entries.is_empty() {
            return Err(SealingRequestError::NoManifests {
                keys: self.record_keys(),
            });
        }

        let mut out: Vec<ClassDigest> = Vec::new();
        for (index, manifest) in entries.iter().enumerate() {
            let parsed =
                read_manifest(manifest).map_err(|error| SealingRequestError::Manifest {
                    entry: index,
                    error: error.to_string(),
                })?;
            for object in &parsed.objects {
                let class = object
                    .property(CLASS_PROPERTY_TAG)
                    .and_then(|property| property.value.as_bytes())
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .unwrap_or_else(|| object.tag.clone());
                let digest =
                    object
                        .digest()
                        .ok_or_else(|| SealingRequestError::ObjectHasNoDigest {
                            entry: index,
                            class: class.clone(),
                        })?;
                if digest.len() != OBJECT_DIGEST_BYTES {
                    return Err(SealingRequestError::DigestLength {
                        class,
                        length: digest.len(),
                    });
                }
                let instance = object
                    .property(INSTANCE_PROPERTY_TAG)
                    .and_then(|property| property.value.as_bytes())
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned());

                match out.iter().find(|existing| existing.class == class) {
                    Some(existing) if existing.digest == digest => {}
                    Some(_) => return Err(SealingRequestError::ConflictingDigest { class }),
                    None => out.push(ClassDigest {
                        class,
                        instance,
                        digest: digest.to_vec(),
                    }),
                }
            }
        }
        Ok(out)
    }
}

fn unwrap_containers(value: &[u8]) -> Result<Vec<u8>, SealingRequestError> {
    let mut current = value.to_vec();
    for _ in 0..MAX_DEPTH {
        let Ok((sequence, _)) = tlv(&current, "container") else {
            return Ok(current);
        };
        if sequence.tag != TAG_SEQUENCE {
            return Ok(current);
        }
        let Ok((name, rest)) = tlv(sequence.value, "container name") else {
            return Ok(current);
        };
        if name.tag != TAG_IA5_STRING {
            return Ok(current);
        }
        match std::str::from_utf8(name.value) {
            Ok(CONTAINER_IMG4) => {
                let (payload, _) = expect(rest, TAG_SEQUENCE, "IMG4 payload")?;
                let mut next = Vec::with_capacity(payload.value.len() + 8);
                next.extend_from_slice(&super::der::sequence(payload.value));
                current = next;
            }
            Ok(CONTAINER_IM4P) => {
                let (_type, rest) = expect(rest, TAG_IA5_STRING, "IM4P type")?;
                let (_version, rest) = expect(rest, TAG_IA5_STRING, "IM4P version")?;
                let (payload, _) = expect(rest, TAG_OCTET_STRING, "IM4P payload")?;
                current = payload.value.to_vec();
            }
            _ => return Ok(current),
        }
    }
    Ok(current)
}

fn collect_manifest_entries(
    buffer: &[u8],
    depth: usize,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), SealingRequestError> {
    if depth >= MAX_DEPTH {
        return Ok(());
    }
    let mut rest = buffer;
    while !rest.is_empty() {
        let (item, next) = match tlv(rest, "payload element") {
            Ok(read) => read,
            Err(_) => return Ok(()),
        };
        if item.tag == TAG_SEQUENCE {
            if let Some(manifest) = manifest_entry(item.value) {
                out.push(manifest.to_vec());
            } else {
                collect_manifest_entries(item.value, depth + 1, out)?;
            }
        } else if item.tag & 0x20 != 0 {
            collect_manifest_entries(item.value, depth + 1, out)?;
        }
        rest = next;
    }
    Ok(())
}

fn manifest_entry(body: &[u8]) -> Option<&[u8]> {
    let (name, rest) = tlv(body, "entry name").ok()?;
    if name.tag != TAG_IA5_STRING || name.value != MANIFEST_ENTRY_TAG.as_bytes() {
        return None;
    }
    let (manifest, rest) = tlv(rest, "entry manifest").ok()?;
    if manifest.tag != TAG_OCTET_STRING || !rest.is_empty() {
        return None;
    }
    Some(manifest.value)
}

pub fn parse_sealing_request(der: &[u8]) -> Result<SealingRequest, SealingRequestError> {
    let (envelope, _) = tlv(der, "request envelope")?;
    if envelope.tag != TAG_SEQUENCE {
        return Err(SealingRequestError::UnknownShape {
            identifier: der.first().copied(),
        });
    }
    let (first, _) = tlv(envelope.value, "request envelope contents")?;
    match first.tag {
        TAG_SEQUENCE => parse_multi_request(envelope.value),
        TAG_IA5_STRING => Ok(SealingRequest {
            shape: SealingRequestShape::PerInstance {
                instance: String::from_utf8_lossy(first.value).into_owned(),
                body: der.to_vec(),
            },
        }),
        identifier => Err(SealingRequestError::UnknownShape {
            identifier: Some(identifier),
        }),
    }
}

fn parse_multi_request(contents: &[u8]) -> Result<SealingRequest, SealingRequestError> {
    let (group, _) = expect(contents, TAG_SEQUENCE, "action group")?;
    if group.value.is_empty() {
        return Err(SealingRequestError::NoAction);
    }
    let (action, rest) = expect(group.value, TAG_INTEGER, "action code")?;
    let mut code: u64 = 0;
    for byte in action.value {
        code = (code << 8) | u64::from(*byte);
    }
    let (set, _) = expect(rest, TAG_SET, "record set")?;

    let mut records = Vec::new();
    let mut rest = set.value;
    while !rest.is_empty() {
        let (record, next) = expect(rest, TAG_SEQUENCE, "record")?;
        records.push(read_record(record.value)?);
        rest = next;
    }

    Ok(SealingRequest {
        shape: SealingRequestShape::MultiRequest {
            action: code,
            records,
        },
    })
}

fn read_record(body: &[u8]) -> Result<SealingRecord, SealingRequestError> {
    let (key, rest) = expect(body, TAG_IA5_STRING, "record key")?;
    let key = std::str::from_utf8(key.value).map_err(|_| SealingRequestError::KeyNotText)?;
    let (class, instance) = key.split_once(CLASS_INSTANCE_SEPARATOR).ok_or_else(|| {
        SealingRequestError::KeyHasNoSeparator {
            key: key.to_string(),
        }
    })?;
    // The class half is not four characters: minimal-manifest is a real class name.
    if class.is_empty() {
        return Err(SealingRequestError::EmptyClass {
            key: key.to_string(),
        });
    }

    let (wrapper, rest) = expect(rest, TAG_CONTEXT_1_CONSTRUCTED, "record value wrapper")?;
    let (value, _) = expect(wrapper.value, TAG_OCTET_STRING, "record value")?;

    let metadata = match tlv(rest, "record metadata") {
        Ok((item, _)) if item.tag & 0x20 != 0 => Some(item.value.to_vec()),
        _ => None,
    };

    Ok(SealingRecord {
        class: class.to_string(),
        instance: instance.to_string(),
        value: value.value.to_vec(),
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ramrod::der;
    use crate::ramrod::fdr_manifest::{
        ManifestProperties, SERVER_NONCE_BYTES, SealObject, build_seal_manifest,
    };
    use crate::ramrod::fdr_pki::{
        CertificateIdentity, DistinguishedName, FDR_LEAF_KEY_DOMAIN, FDR_ROOT_CA_KEY_DOMAIN,
        FdrKeyPair, issue_fdr_leaf, issue_root_ca,
    };

    const INSTANCE: &str = "00008103-1122334455667788";
    const NOT_BEFORE: i64 = 1_767_225_600;
    const NOT_AFTER: i64 = 2_082_758_400;

    fn class_manifest(class: &str, digest: &[u8]) -> Vec<u8> {
        let root_key = FdrKeyPair::from_seed([0x11; 32], FDR_ROOT_CA_KEY_DOMAIN);
        let leaf_key = FdrKeyPair::from_seed([0x22; 32], FDR_LEAF_KEY_DOMAIN);
        let root_name = DistinguishedName::new().common_name("Test Device Root");
        let root = issue_root_ca(
            &CertificateIdentity {
                subject: root_name.clone(),
                serial: vec![0x01],
                not_before: NOT_BEFORE,
                not_after: NOT_AFTER,
            },
            root_key.private(),
        )
        .expect("root");
        assert!(!root.is_empty());
        let leaf = issue_fdr_leaf(
            &CertificateIdentity {
                subject: DistinguishedName::new().common_name("Test Device"),
                serial: vec![0x02],
                not_before: NOT_BEFORE,
                not_after: NOT_AFTER,
            },
            &leaf_key.public_uncompressed(),
            &root_name,
            root_key.private(),
            None,
        )
        .expect("leaf");
        let properties = ManifestProperties::new([0x33; SERVER_NONCE_BYTES], false);
        let objects = [SealObject::new(class, digest)];
        build_seal_manifest(INSTANCE, &properties, &objects, &[leaf], leaf_key.private())
            .expect("manifest")
            .manifest()
            .to_vec()
    }

    fn sealing_payload(manifests: &[Vec<u8>]) -> Vec<u8> {
        let mut body = der::ia5_string(INSTANCE);
        for manifest in manifests {
            let mut entry = der::ia5_string(MANIFEST_ENTRY_TAG);
            entry.extend_from_slice(&der::octet_string(manifest));
            body.extend_from_slice(&der::sequence(&der::sequence(&entry)));
        }
        der::sequence(&body)
    }

    fn envelope(payload: &[u8], extra: &[(&str, &str)]) -> Vec<u8> {
        let mut records = Vec::new();
        let mut key = der::ia5_string(&format!("sreq{CLASS_INSTANCE_SEPARATOR}{INSTANCE}"));
        key.extend_from_slice(&der::tlv(
            &[TAG_CONTEXT_1_CONSTRUCTED],
            &der::octet_string(payload),
        ));
        records.extend_from_slice(&der::sequence(&key));
        for (class, instance) in extra {
            let mut other =
                der::ia5_string(&format!("{class}{CLASS_INSTANCE_SEPARATOR}{instance}"));
            other.extend_from_slice(&der::tlv(
                &[TAG_CONTEXT_1_CONSTRUCTED],
                &der::octet_string(b"other"),
            ));
            records.extend_from_slice(&der::sequence(&other));
        }
        let mut group = der::integer_u64(ACTION_CODE_SEALING);
        group.extend_from_slice(&der::set(&records));
        der::sequence(&der::sequence(&group))
    }

    #[test]
    fn the_digests_come_out_of_the_guests_own_manifests() {
        let digest = vec![0xab; OBJECT_DIGEST_BYTES];
        let payload = sealing_payload(&[class_manifest("scrt", &digest)]);
        let request = parse_sealing_request(&envelope(&payload, &[])).expect("parse");
        assert_eq!(request.action(), Some(ACTION_CODE_SEALING));
        assert_eq!(request.shape_name(), "multi-request");
        assert_eq!(
            request.record_keys(),
            vec![format!("sreq{CLASS_INSTANCE_SEPARATOR}{INSTANCE}")]
        );

        let digests = request.class_digests().expect("digests");
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].class, "scrt");
        assert_eq!(digests[0].digest, digest);
        assert_eq!(digests[0].instance.as_deref(), Some(INSTANCE));
    }

    #[test]
    fn every_class_the_guest_sent_is_read() {
        let first = vec![0x01; OBJECT_DIGEST_BYTES];
        let second = vec![0x02; OBJECT_DIGEST_BYTES];
        let payload = sealing_payload(&[
            class_manifest("scrt", &first),
            class_manifest("eCfg", &second),
        ]);
        let request = parse_sealing_request(&envelope(&payload, &[])).expect("parse");
        let digests = request.class_digests().expect("digests");
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0].class, "scrt");
        assert_eq!(digests[0].digest, first);
        assert_eq!(digests[1].class, "eCfg");
        assert_eq!(digests[1].digest, second);
    }

    #[test]
    fn the_same_class_twice_with_one_digest_is_read_once() {
        let digest = vec![0x7f; OBJECT_DIGEST_BYTES];
        let payload = sealing_payload(&[
            class_manifest("scrt", &digest),
            class_manifest("scrt", &digest),
        ]);
        let request = parse_sealing_request(&envelope(&payload, &[])).expect("parse");
        let digests = request.class_digests().expect("digests");
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].digest, digest);
    }

    #[test]
    fn two_digests_for_one_class_are_refused() {
        let payload = sealing_payload(&[
            class_manifest("scrt", &[0x01; OBJECT_DIGEST_BYTES]),
            class_manifest("scrt", &[0x02; OBJECT_DIGEST_BYTES]),
        ]);
        let request = parse_sealing_request(&envelope(&payload, &[])).expect("parse");
        assert_eq!(
            request.class_digests(),
            Err(SealingRequestError::ConflictingDigest {
                class: "scrt".to_string()
            })
        );
    }

    #[test]
    fn a_key_without_a_colon_is_refused() {
        let payload = sealing_payload(&[class_manifest("scrt", &[0x01; OBJECT_DIGEST_BYTES])]);
        let mut der = envelope(&payload, &[]);
        let at = der
            .windows(1)
            .position(|window| window == b":")
            .expect("colon present");
        der[at] = b'/';
        assert!(matches!(
            parse_sealing_request(&der),
            Err(SealingRequestError::KeyHasNoSeparator { .. })
        ));
    }

    #[test]
    fn a_request_with_no_manifest_names_what_it_carried() {
        let mut records = der::ia5_string(&format!("appv{CLASS_INSTANCE_SEPARATOR}{INSTANCE}"));
        records.extend_from_slice(&der::tlv(
            &[TAG_CONTEXT_1_CONSTRUCTED],
            &der::octet_string(b"payload"),
        ));
        let mut group = der::integer_u64(ACTION_CODE_SEALING);
        group.extend_from_slice(&der::set(&der::sequence(&records)));
        let der = der::sequence(&der::sequence(&group));
        let request = parse_sealing_request(&der).expect("parse");
        assert_eq!(
            request.class_digests(),
            Err(SealingRequestError::NoManifests {
                keys: vec![format!("appv{CLASS_INSTANCE_SEPARATOR}{INSTANCE}")]
            })
        );
    }

    #[test]
    fn a_class_longer_than_four_characters_is_read() {
        let digest = vec![0x6d; OBJECT_DIGEST_BYTES];
        let payload = sealing_payload(&[class_manifest("scrt", &digest)]);
        let mut key = der::ia5_string(&format!(
            "minimal-manifest{CLASS_INSTANCE_SEPARATOR}{INSTANCE}"
        ));
        key.extend_from_slice(&der::tlv(
            &[TAG_CONTEXT_1_CONSTRUCTED],
            &der::octet_string(&payload),
        ));
        let mut group = der::integer_u64(ACTION_CODE_SEALING);
        group.extend_from_slice(&der::set(&der::sequence(&key)));
        let der = der::sequence(&der::sequence(&group));
        let request = parse_sealing_request(&der).expect("parse");
        assert_eq!(request.class_digests().expect("digests")[0].digest, digest);
    }

    #[test]
    fn the_bare_per_instance_request_is_read() {
        let digest = vec![0x4e; OBJECT_DIGEST_BYTES];
        let payload = sealing_payload(&[class_manifest("eCfg", &digest)]);
        let request = parse_sealing_request(&payload).expect("parse");
        assert_eq!(request.shape_name(), "per-instance");
        assert_eq!(request.action(), None);
        assert_eq!(request.record_keys(), vec![INSTANCE.to_string()]);
        let digests = request.class_digests().expect("digests");
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].class, "eCfg");
        assert_eq!(digests[0].digest, digest);
    }

    #[test]
    fn a_body_that_is_neither_shape_is_named() {
        assert_eq!(
            parse_sealing_request(&der::set(&der::integer_u64(1))),
            Err(SealingRequestError::UnknownShape {
                identifier: Some(0x31)
            })
        );
    }

    #[test]
    fn the_containers_are_stripped() {
        let digest = vec![0x5c; OBJECT_DIGEST_BYTES];
        let payload = sealing_payload(&[class_manifest("scrt", &digest)]);
        let mut im4p = der::ia5_string("IM4P");
        im4p.extend_from_slice(&der::ia5_string("sreq"));
        im4p.extend_from_slice(&der::ia5_string("1.0"));
        im4p.extend_from_slice(&der::octet_string(&payload));
        let im4p = der::sequence(&im4p);
        let mut img4 = der::ia5_string("IMG4");
        img4.extend_from_slice(&im4p);
        img4.extend_from_slice(&der::explicit(0, b"\x30\x00"));
        let img4 = der::sequence(&img4);

        let request = parse_sealing_request(&envelope(&img4, &[])).expect("parse");
        let digests = request.class_digests().expect("digests");
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].digest, digest);
    }

    #[test]
    fn every_truncation_is_an_error_rather_than_a_panic() {
        let payload = sealing_payload(&[class_manifest("scrt", &[0x11; OBJECT_DIGEST_BYTES])]);
        let der = envelope(&payload, &[]);
        for length in 0..der.len() {
            let _ =
                parse_sealing_request(&der[..length]).and_then(|request| request.class_digests());
        }
    }
}
