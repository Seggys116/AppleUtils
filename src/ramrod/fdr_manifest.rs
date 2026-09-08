use std::fmt;
use std::fs::File;
use std::io::Read;

use crate::crypto::{P256_SIGNATURE_BYTES, P256PrivateKey, sha384, signature_to_der};

use super::der::{self, DerError};
use super::fdr_pki::FDR_KEY_ENTROPY_SOURCE;

pub const MANIFEST_TAG: &str = "IM4M";

pub const MANIFEST_BODY_TAG: &str = "MANB";

pub const MANIFEST_PROPERTIES_TAG: &str = "MANP";

pub const MANIFEST_BODY_DER_TAG: u64 = 0xe000_0000_4d41_4e42;

// Version 2 makes MANB's inner container a SEQUENCE; 0 keeps it a SET.
pub const MANIFEST_VERSION: u64 = 0;

pub const OBJECT_DIGEST_BYTES: usize = 48;

pub const CLASS_CODE_BYTES: usize = 4;

pub const SERVER_NONCE_BYTES: usize = 32;

pub const MANIFEST_DIGEST_BYTES: usize = 48;

pub const SIGNING_DIGEST_BYTES: usize = 32;

pub const DIGEST_PROPERTY_TAG: &str = "DGST";

pub const CLASS_PROPERTY_TAG: &str = "clas";

pub const INSTANCE_PROPERTY_TAG: &str = "inst";

pub const PRID_PROPERTY_TAG: &str = "prid";

// Spelled asid, not said; the transposed form is ignored rather than refused.
pub const ASID_PROPERTY_TAG: &str = "asid";

pub const SCDG_PROPERTY_TAG: &str = "SCDG";

pub const SERVER_NONCE_PROPERTY_TAG: &str = "srvn";

pub const FAIC_PROPERTY_TAG: &str = "faic";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestValue {
    Bytes(Vec<u8>),
    Boolean(bool),
    Integer(u64),
}

impl ManifestValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => der::octet_string(bytes),
            Self::Boolean(value) => der::boolean(*value),
            Self::Integer(value) => der::integer_u64(*value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestProperty {
    pub tag: String,
    pub value: ManifestValue,
}

impl ManifestProperty {
    #[must_use]
    pub fn new(tag: &str, value: ManifestValue) -> Self {
        Self {
            tag: tag.to_string(),
            value,
        }
    }

    #[must_use]
    pub fn bytes(tag: &str, value: &[u8]) -> Self {
        Self::new(tag, ManifestValue::Bytes(value.to_vec()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestProperties {
    pub server_nonce: [u8; SERVER_NONCE_BYTES],
    pub faic: bool,
    pub instance: Option<String>,
    pub prid: Option<Vec<u8>>,
    pub extra: Vec<ManifestProperty>,
}

impl ManifestProperties {
    #[must_use]
    pub fn new(server_nonce: [u8; SERVER_NONCE_BYTES], faic: bool) -> Self {
        Self {
            server_nonce,
            faic,
            instance: None,
            prid: None,
            extra: Vec::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, property: ManifestProperty) -> Self {
        self.extra.push(property);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealObject {
    pub class: String,
    pub digest: Vec<u8>,
    pub instance: Option<String>,
    pub prid: Option<Vec<u8>>,
    pub asid: Option<Vec<u8>>,
    pub scdg: Option<Vec<u8>>,
}

impl SealObject {
    #[must_use]
    pub fn new(class: &str, digest: &[u8]) -> Self {
        Self {
            class: class.to_string(),
            digest: digest.to_vec(),
            instance: None,
            prid: None,
            asid: None,
            scdg: None,
        }
    }
}

#[derive(Debug)]
pub enum SealManifestError {
    DigestLength {
        class: String,
        length: usize,
    },
    ClassCodeLength {
        class: String,
        length: usize,
    },
    PropertyTagLength {
        tag: String,
        length: usize,
    },
    DuplicateClass {
        class: String,
    },
    NoObjects,
    EmptyInstance {
        class: Option<String>,
    },
    EmptyChain,
    MalformedCertificate {
        position: usize,
        identifier: Option<u8>,
    },
    Encoding(DerError),
    Entropy(std::io::Error),
}

impl fmt::Display for SealManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestLength { class, length } => write!(
                f,
                "the {class} digest is {length} bytes, not {OBJECT_DIGEST_BYTES}"
            ),
            Self::ClassCodeLength { class, length } => write!(
                f,
                "the class code {class:?} is {length} bytes, not {CLASS_CODE_BYTES}"
            ),
            Self::PropertyTagLength { tag, length } => write!(
                f,
                "the property tag {tag:?} is {length} bytes, not {CLASS_CODE_BYTES}"
            ),
            Self::DuplicateClass { class } => {
                write!(f, "the class {class} is listed more than once")
            }
            Self::NoObjects => {
                f.write_str("a sealing manifest that lists no objects seals nothing")
            }
            Self::EmptyInstance { class } => match class {
                Some(class) => write!(f, "the {class} object was given an empty instance"),
                None => f.write_str("the manifest was given an empty instance"),
            },
            Self::EmptyChain => {
                f.write_str("the certificate chain is empty, so nothing can verify the signature")
            }
            Self::MalformedCertificate {
                position,
                identifier,
            } => match identifier {
                Some(identifier) => write!(
                    f,
                    "chain certificate {position} starts with identifier {identifier:#04x}, \
                     not a SEQUENCE"
                ),
                None => write!(f, "chain certificate {position} is empty"),
            },
            Self::Encoding(error) => write!(f, "a manifest field cannot be encoded: {error}"),
            Self::Entropy(error) => write!(
                f,
                "a server nonce cannot be drawn from {FDR_KEY_ENTROPY_SOURCE}: {error}"
            ),
        }
    }
}

impl std::error::Error for SealManifestError {}

impl From<DerError> for SealManifestError {
    fn from(error: DerError) -> Self {
        Self::Encoding(error)
    }
}

pub struct SealManifest {
    manifest: Vec<u8>,
    signed_body: Vec<u8>,
    manifest_digest: [u8; MANIFEST_DIGEST_BYTES],
    signature: [u8; P256_SIGNATURE_BYTES],
}

impl SealManifest {
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    #[must_use]
    pub fn signed_body(&self) -> &[u8] {
        &self.signed_body
    }

    #[must_use]
    pub fn manifest_digest(&self) -> [u8; MANIFEST_DIGEST_BYTES] {
        self.manifest_digest
    }

    #[must_use]
    pub fn signing_digest(&self) -> [u8; SIGNING_DIGEST_BYTES] {
        signing_digest(&self.manifest_digest)
    }

    #[must_use]
    pub fn signature(&self) -> &[u8; P256_SIGNATURE_BYTES] {
        &self.signature
    }
}

#[must_use]
pub fn signing_digest(digest: &[u8; MANIFEST_DIGEST_BYTES]) -> [u8; SIGNING_DIGEST_BYTES] {
    let mut prefix = [0u8; SIGNING_DIGEST_BYTES];
    prefix.copy_from_slice(&digest[..SIGNING_DIGEST_BYTES]);
    prefix
}

pub fn random_server_nonce() -> Result<[u8; SERVER_NONCE_BYTES], SealManifestError> {
    let mut nonce = [0u8; SERVER_NONCE_BYTES];
    File::open(FDR_KEY_ENTROPY_SOURCE)
        .and_then(|mut source| source.read_exact(&mut nonce))
        .map_err(SealManifestError::Entropy)?;
    Ok(nonce)
}

fn named_element(tag: &str, body: &[u8]) -> Result<Vec<u8>, DerError> {
    let identifier = der::fourcc_private(tag)?;
    let mut inner = der::ia5_string(tag);
    inner.extend_from_slice(body);
    Ok(der::tlv(&identifier, &der::sequence(&inner)))
}

fn sorted_set(mut members: Vec<Vec<u8>>) -> Vec<u8> {
    members.sort();
    der::set(&members.concat())
}

fn property_element(tag: &str, value: &ManifestValue) -> Result<Vec<u8>, SealManifestError> {
    named_element(tag, &value.encode()).map_err(|error| match error {
        DerError::NotAFourCharacterCode { length } => SealManifestError::PropertyTagLength {
            tag: tag.to_string(),
            length,
        },
        other => SealManifestError::Encoding(other),
    })
}

fn encode_manifest_properties(
    properties: &ManifestProperties,
) -> Result<Vec<u8>, SealManifestError> {
    let mut members = vec![
        property_element(
            SERVER_NONCE_PROPERTY_TAG,
            &ManifestValue::Bytes(properties.server_nonce.to_vec()),
        )?,
        property_element(FAIC_PROPERTY_TAG, &ManifestValue::Boolean(properties.faic))?,
    ];
    if let Some(instance) = &properties.instance {
        if instance.is_empty() {
            return Err(SealManifestError::EmptyInstance { class: None });
        }
        members.push(property_element(
            INSTANCE_PROPERTY_TAG,
            &ManifestValue::Bytes(instance.as_bytes().to_vec()),
        )?);
    }
    if let Some(prid) = &properties.prid {
        members.push(property_element(
            PRID_PROPERTY_TAG,
            &ManifestValue::Bytes(prid.clone()),
        )?);
    }
    for property in &properties.extra {
        members.push(property_element(&property.tag, &property.value)?);
    }
    named_element(MANIFEST_PROPERTIES_TAG, &sorted_set(members)).map_err(SealManifestError::from)
}

fn encode_object(
    object: &SealObject,
    default_instance: &str,
) -> Result<Vec<u8>, SealManifestError> {
    if object.class.len() != CLASS_CODE_BYTES {
        return Err(SealManifestError::ClassCodeLength {
            class: object.class.clone(),
            length: object.class.len(),
        });
    }
    if object.digest.len() != OBJECT_DIGEST_BYTES {
        return Err(SealManifestError::DigestLength {
            class: object.class.clone(),
            length: object.digest.len(),
        });
    }
    let instance = object.instance.as_deref().unwrap_or(default_instance);
    if instance.is_empty() {
        return Err(SealManifestError::EmptyInstance {
            class: Some(object.class.clone()),
        });
    }

    let mut members = vec![
        property_element(
            DIGEST_PROPERTY_TAG,
            &ManifestValue::Bytes(object.digest.clone()),
        )?,
        property_element(
            CLASS_PROPERTY_TAG,
            &ManifestValue::Bytes(object.class.as_bytes().to_vec()),
        )?,
        property_element(
            INSTANCE_PROPERTY_TAG,
            &ManifestValue::Bytes(instance.as_bytes().to_vec()),
        )?,
    ];
    for (tag, value) in [
        (PRID_PROPERTY_TAG, &object.prid),
        (ASID_PROPERTY_TAG, &object.asid),
        (SCDG_PROPERTY_TAG, &object.scdg),
    ] {
        if let Some(bytes) = value {
            members.push(property_element(tag, &ManifestValue::Bytes(bytes.clone()))?);
        }
    }

    named_element(&object.class, &sorted_set(members)).map_err(SealManifestError::from)
}

pub fn encode_signed_body(
    instance: &str,
    properties: &ManifestProperties,
    objects: &[SealObject],
) -> Result<Vec<u8>, SealManifestError> {
    if objects.is_empty() {
        return Err(SealManifestError::NoObjects);
    }
    if instance.is_empty() && objects.iter().any(|object| object.instance.is_none()) {
        return Err(SealManifestError::EmptyInstance { class: None });
    }

    let mut seen: Vec<&str> = Vec::with_capacity(objects.len());
    let mut entries = vec![encode_manifest_properties(properties)?];
    for object in objects {
        if seen.contains(&object.class.as_str()) {
            return Err(SealManifestError::DuplicateClass {
                class: object.class.clone(),
            });
        }
        seen.push(&object.class);
        entries.push(encode_object(object, instance)?);
    }

    let body = named_element(MANIFEST_BODY_TAG, &sorted_set(entries))?;
    Ok(der::set(&body))
}

fn check_chain<C: AsRef<[u8]>>(chain: &[C]) -> Result<(), SealManifestError> {
    if chain.is_empty() {
        return Err(SealManifestError::EmptyChain);
    }
    for (position, certificate) in chain.iter().enumerate() {
        match certificate.as_ref().first() {
            None => {
                return Err(SealManifestError::MalformedCertificate {
                    position,
                    identifier: None,
                });
            }
            Some(identifier) if *identifier != der::IDENTIFIER_SEQUENCE => {
                return Err(SealManifestError::MalformedCertificate {
                    position,
                    identifier: Some(*identifier),
                });
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn seal_envelope_with_signature<C: AsRef<[u8]>>(
    signed_body: Vec<u8>,
    chain: &[C],
    signature: [u8; P256_SIGNATURE_BYTES],
) -> SealManifest {
    let manifest_digest = sha384(&signed_body);

    let mut certificates = Vec::new();
    for certificate in chain {
        certificates.extend_from_slice(certificate.as_ref());
    }

    let mut body = der::ia5_string(MANIFEST_TAG);
    body.extend_from_slice(&der::integer_u64(MANIFEST_VERSION));
    body.extend_from_slice(&signed_body);
    body.extend_from_slice(&der::octet_string(&signature_to_der(&signature)));
    body.extend_from_slice(&der::sequence(&certificates));

    SealManifest {
        manifest: der::sequence(&body),
        signed_body,
        manifest_digest,
        signature,
    }
}

fn seal_envelope<C: AsRef<[u8]>>(
    signed_body: Vec<u8>,
    chain: &[C],
    signing_key: &P256PrivateKey,
) -> SealManifest {
    let manifest_digest = sha384(&signed_body);
    let signature = signing_key.sign_digest(&signing_digest(&manifest_digest));
    seal_envelope_with_signature(signed_body, chain, signature)
}

pub fn build_manifest_from_signed_body<C: AsRef<[u8]>>(
    signed_body: Vec<u8>,
    chain: &[C],
    signature: [u8; P256_SIGNATURE_BYTES],
) -> Result<SealManifest, SealManifestError> {
    check_chain(chain)?;
    Ok(seal_envelope_with_signature(signed_body, chain, signature))
}

// chain is leaf first and must omit the self signed root, which the guest pins.
pub fn build_seal_manifest<C: AsRef<[u8]>>(
    instance: &str,
    properties: &ManifestProperties,
    objects: &[SealObject],
    chain: &[C],
    signing_key: &P256PrivateKey,
) -> Result<SealManifest, SealManifestError> {
    check_chain(chain)?;
    let signed_body = encode_signed_body(instance, properties, objects)?;
    Ok(seal_envelope(signed_body, chain, signing_key))
}

pub fn encode_properties_only_body(
    properties: &ManifestProperties,
) -> Result<Vec<u8>, SealManifestError> {
    if properties.instance.is_none() {
        return Err(SealManifestError::EmptyInstance { class: None });
    }
    let body = named_element(
        MANIFEST_BODY_TAG,
        &sorted_set(vec![encode_manifest_properties(properties)?]),
    )?;
    Ok(der::set(&body))
}

pub fn build_properties_only_manifest<C: AsRef<[u8]>>(
    properties: &ManifestProperties,
    chain: &[C],
    signing_key: &P256PrivateKey,
) -> Result<SealManifest, SealManifestError> {
    check_chain(chain)?;
    let signed_body = encode_properties_only_body(properties)?;
    Ok(seal_envelope(signed_body, chain, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify_uncompressed;
    use crate::ramrod::fdr_pki::{
        CertificateIdentity, DEFAULT_LEAF_COMMON_NAME, DEFAULT_ORGANIZATION,
        DEFAULT_ROOT_CA_COMMON_NAME, DistinguishedName, FDR_KEY_SEED_BYTES, FDR_LEAF_KEY_DOMAIN,
        FDR_ROOT_CA_KEY_DOMAIN, FdrKeyPair, issue_fdr_leaf, issue_root_ca,
    };
    use crate::ramrod::fdr_store::{SEAL_CLASS, instance_identifier, seal_key};

    const GROUND_TRUTH_ENV: &str = "APPLEUTILS_FDR_MANIFEST_GROUND_TRUTH";

    const GROUND_TRUTH_SIGNED_RANGE: (usize, usize) = (13, 3273);

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

    const NOT_BEFORE: i64 = 1_767_225_600;
    const NOT_AFTER: i64 = 2_082_758_400;

    const CHIP_ID: u32 = 0x8103;
    const UNIQUE_CHIP_ID: u64 = 0x1122_3344_5566_7788;

    struct Element {
        identifier: Vec<u8>,
        start: usize,
        body: usize,
        end: usize,
    }

    impl Element {
        fn element<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
            &bytes[self.start..self.end]
        }

        fn value<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
            &bytes[self.body..self.end]
        }

        fn fourcc(&self) -> String {
            let mut value = 0u64;
            for byte in &self.identifier[1..] {
                value = (value << 7) | u64::from(byte & 0x7f);
            }
            String::from_utf8_lossy(&(value as u32).to_be_bytes()).into_owned()
        }
    }

    fn read(bytes: &[u8], at: usize) -> Element {
        let mut cursor = at;
        let first = bytes[cursor];
        cursor += 1;
        if first & 0x1f == 0x1f {
            while bytes[cursor] & 0x80 != 0 {
                cursor += 1;
            }
            cursor += 1;
        }
        let identifier = bytes[at..cursor].to_vec();
        let length_byte = bytes[cursor];
        cursor += 1;
        let length = if length_byte & 0x80 == 0 {
            usize::from(length_byte)
        } else {
            let count = usize::from(length_byte & 0x7f);
            let mut value = 0usize;
            for byte in &bytes[cursor..cursor + count] {
                value = (value << 8) | usize::from(*byte);
            }
            cursor += count;
            value
        };
        Element {
            identifier,
            start: at,
            body: cursor,
            end: cursor + length,
        }
    }

    fn children(bytes: &[u8], parent: &Element) -> Vec<Element> {
        let mut out = Vec::new();
        let mut at = parent.body;
        while at < parent.end {
            let element = read(bytes, at);
            at = element.end;
            out.push(element);
        }
        out
    }

    fn top_level(bytes: &[u8]) -> Vec<Element> {
        children(bytes, &read(bytes, 0))
    }

    fn manb_entries(bytes: &[u8], signed_body: &Element) -> Vec<Element> {
        let members = children(bytes, signed_body);
        assert_eq!(members.len(), 1, "the signed SET holds one member");
        assert_eq!(members[0].fourcc(), MANIFEST_BODY_TAG);
        let sequences = children(bytes, &members[0]);
        assert_eq!(sequences.len(), 1);
        assert_eq!(sequences[0].identifier, vec![der::IDENTIFIER_SEQUENCE]);
        let inner = children(bytes, &sequences[0]);
        assert_eq!(inner.len(), 2);
        assert_eq!(inner[0].identifier, vec![der::IDENTIFIER_IA5_STRING]);
        assert_eq!(inner[0].value(bytes), MANIFEST_BODY_TAG.as_bytes());
        assert_eq!(inner[1].identifier, vec![der::IDENTIFIER_SET]);
        children(bytes, &inner[1])
    }

    fn entry_properties(bytes: &[u8], entry: &Element) -> Vec<Element> {
        let sequences = children(bytes, entry);
        assert_eq!(sequences.len(), 1);
        let parts = children(bytes, &sequences[0]);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].value(bytes), entry.fourcc().as_bytes());
        assert_eq!(parts[1].identifier, vec![der::IDENTIFIER_SET]);
        children(bytes, &parts[1])
    }

    fn assert_sorted(bytes: &[u8], members: &[Element], what: &str) {
        let encoded: Vec<&[u8]> = members.iter().map(|member| member.element(bytes)).collect();
        let mut sorted = encoded.clone();
        sorted.sort_unstable();
        assert_eq!(
            encoded, sorted,
            "{what} must be in ascending encoding order"
        );
    }

    fn instance() -> String {
        instance_identifier(CHIP_ID, UNIQUE_CHIP_ID)
    }

    fn digest_of(seed: u8) -> Vec<u8> {
        vec![seed; OBJECT_DIGEST_BYTES]
    }

    fn properties() -> ManifestProperties {
        ManifestProperties::new([0x5a; SERVER_NONCE_BYTES], true)
            .with(ManifestProperty::bytes(
                "BMac",
                &[0x02, 0x00, 0x00, 0x11, 0x22, 0x33],
            ))
            .with(ManifestProperty::bytes("nuid", instance().as_bytes()))
    }

    fn objects() -> Vec<SealObject> {
        vec![
            SealObject::new("scrt", &digest_of(0x11)),
            SealObject::new("appv", &digest_of(0x22)),
            SealObject::new("fCfg", &digest_of(0x33)),
            SealObject::new("eCfg", &digest_of(0x44)),
        ]
    }

    fn chain() -> (Vec<Vec<u8>>, FdrKeyPair) {
        let root_key = FdrKeyPair::from_seed([0x31; FDR_KEY_SEED_BYTES], FDR_ROOT_CA_KEY_DOMAIN);
        let leaf_key = FdrKeyPair::from_seed([0x31; FDR_KEY_SEED_BYTES], FDR_LEAF_KEY_DOMAIN);
        let root_subject = DistinguishedName::new()
            .common_name(DEFAULT_ROOT_CA_COMMON_NAME)
            .organization(DEFAULT_ORGANIZATION);
        let root_identity = CertificateIdentity {
            subject: root_subject.clone(),
            serial: vec![0x4d, 0x58, 0x11],
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        };
        issue_root_ca(&root_identity, root_key.private()).expect("the root must issue");
        let leaf_identity = CertificateIdentity {
            subject: DistinguishedName::new()
                .common_name(DEFAULT_LEAF_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            serial: vec![0x4d, 0x58, 0x12],
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        };
        let leaf = issue_fdr_leaf(
            &leaf_identity,
            &leaf_key.public_uncompressed(),
            &root_subject,
            root_key.private(),
            None,
        )
        .expect("the leaf must issue");
        (vec![leaf], leaf_key)
    }

    fn manifest() -> (SealManifest, FdrKeyPair) {
        let (chain, leaf_key) = chain();
        let manifest = build_seal_manifest(
            &instance(),
            &properties(),
            &objects(),
            &chain,
            leaf_key.private(),
        )
        .expect("the manifest must build");
        (manifest, leaf_key)
    }

    #[test]
    fn the_signature_covers_exactly_the_set_element() {
        let (manifest, leaf_key) = manifest();
        let bytes = manifest.manifest();

        let expected =
            encode_signed_body(&instance(), &properties(), &objects()).expect("the body encodes");
        assert_eq!(manifest.signed_body(), &expected[..]);
        assert_eq!(manifest.signed_body()[0], der::IDENTIFIER_SET);

        let fields = top_level(bytes);
        assert_eq!(fields[2].element(bytes), manifest.signed_body());

        assert_eq!(manifest.manifest_digest(), sha384(manifest.signed_body()));
        assert_eq!(
            manifest.signing_digest(),
            manifest.manifest_digest()[..SIGNING_DIGEST_BYTES]
        );
        assert!(verify_uncompressed(
            &leaf_key.public_uncompressed(),
            &manifest.signing_digest(),
            manifest.signature()
        ));

        for at in [0, 1, manifest.signed_body().len() - 1] {
            let mut tampered = manifest.signed_body().to_vec();
            tampered[at] ^= 0x01;
            assert!(
                !verify_uncompressed(
                    &leaf_key.public_uncompressed(),
                    &signing_digest(&sha384(&tampered)),
                    manifest.signature()
                ),
                "flipping byte {at} of the signed body must break the signature"
            );
        }

        let payload = &manifest.signed_body()[fields[2].body - fields[2].start..];
        assert_ne!(signing_digest(&sha384(payload)), manifest.signing_digest());
    }

    #[test]
    fn the_octet_string_carries_the_der_form_of_the_signature() {
        let (manifest, _) = manifest();
        let bytes = manifest.manifest();
        let fields = top_level(bytes);
        assert_eq!(fields[3].identifier, vec![der::IDENTIFIER_OCTET_STRING]);
        assert_eq!(
            fields[3].value(bytes),
            &signature_to_der(manifest.signature())[..]
        );
    }

    #[test]
    fn the_five_top_level_fields_are_in_the_artifact_order() {
        let (manifest, _) = manifest();
        let bytes = manifest.manifest();
        assert_eq!(bytes[0], der::IDENTIFIER_SEQUENCE);
        assert_eq!(read(bytes, 0).end, bytes.len());

        let fields = top_level(bytes);
        let identifiers: Vec<u8> = fields
            .iter()
            .map(|field| field.identifier[0])
            .collect::<Vec<u8>>();
        assert_eq!(
            identifiers,
            vec![
                der::IDENTIFIER_IA5_STRING,
                der::IDENTIFIER_INTEGER,
                der::IDENTIFIER_SET,
                der::IDENTIFIER_OCTET_STRING,
                der::IDENTIFIER_SEQUENCE,
            ]
        );
        assert_eq!(fields[0].value(bytes), MANIFEST_TAG.as_bytes());
        assert_eq!(fields[1].value(bytes), &[0x00]);

        let (chain, _) = chain();
        assert_eq!(fields[4].value(bytes), &chain.concat()[..]);
    }

    #[test]
    fn the_body_nests_by_class_four_character_code_with_no_objp() {
        let (manifest, _) = manifest();
        let bytes = manifest.manifest();
        let fields = top_level(bytes);
        let entries = manb_entries(bytes, &fields[2]);

        let tags: Vec<String> = entries.iter().map(Element::fourcc).collect();
        assert_eq!(tags.len(), objects().len() + 1);
        assert!(tags.contains(&MANIFEST_PROPERTIES_TAG.to_string()));
        for object in objects() {
            assert!(
                tags.contains(&object.class),
                "{} must be listed",
                object.class
            );
        }

        for entry in &entries {
            assert!(!entry_properties(bytes, entry).is_empty());
        }

        assert!(
            !manifest
                .signed_body()
                .windows(4)
                .any(|window| window == b"OBJP"),
            "no object in the manifest body is named OBJP"
        );
    }

    #[test]
    fn every_entry_carries_its_unconditional_properties() {
        let (manifest, _) = manifest();
        let bytes = manifest.manifest();
        let fields = top_level(bytes);

        for entry in manb_entries(bytes, &fields[2]) {
            let class = entry.fourcc();
            let mut found = Vec::new();
            for property in entry_properties(bytes, &entry) {
                let tag = property.fourcc();
                let parts = children(bytes, &children(bytes, &property)[0]);
                assert_eq!(parts[0].value(bytes), tag.as_bytes());
                let value = parts[1].value(bytes);
                match tag.as_str() {
                    DIGEST_PROPERTY_TAG => {
                        assert_eq!(parts[1].identifier, vec![der::IDENTIFIER_OCTET_STRING]);
                        assert_eq!(value.len(), OBJECT_DIGEST_BYTES);
                    }
                    CLASS_PROPERTY_TAG => {
                        assert_eq!(value, class.as_bytes());
                        assert_eq!(value.len(), CLASS_CODE_BYTES);
                    }
                    INSTANCE_PROPERTY_TAG => assert_eq!(value, instance().as_bytes()),
                    SERVER_NONCE_PROPERTY_TAG => {
                        assert_eq!(parts[1].identifier, vec![der::IDENTIFIER_OCTET_STRING]);
                        assert_eq!(value.len(), SERVER_NONCE_BYTES);
                    }
                    FAIC_PROPERTY_TAG => {
                        assert_eq!(parts[1].identifier, vec![der::IDENTIFIER_BOOLEAN]);
                        assert_eq!(value, &[0xff]);
                    }
                    _ => {}
                }
                found.push(tag);
            }
            if class == MANIFEST_PROPERTIES_TAG {
                for tag in [SERVER_NONCE_PROPERTY_TAG, FAIC_PROPERTY_TAG] {
                    assert!(found.contains(&tag.to_string()), "MANP needs {tag}");
                }
                assert!(!found.contains(&DIGEST_PROPERTY_TAG.to_string()));
            } else {
                for tag in [
                    DIGEST_PROPERTY_TAG,
                    CLASS_PROPERTY_TAG,
                    INSTANCE_PROPERTY_TAG,
                ] {
                    assert!(found.contains(&tag.to_string()), "{class} needs {tag}");
                }
                for tag in [PRID_PROPERTY_TAG, ASID_PROPERTY_TAG, SCDG_PROPERTY_TAG] {
                    assert!(
                        !found.contains(&tag.to_string()),
                        "{tag} is optional and was not supplied"
                    );
                }
            }
        }
    }

    #[test]
    fn set_members_are_sorted_whatever_order_they_arrive_in() {
        let mut reversed = objects();
        reversed.reverse();
        let forward =
            encode_signed_body(&instance(), &properties(), &objects()).expect("forward encodes");
        let backward =
            encode_signed_body(&instance(), &properties(), &reversed).expect("backward encodes");
        assert_eq!(forward, backward);

        let mut shuffled_properties = properties();
        shuffled_properties.extra.reverse();
        let shuffled = encode_signed_body(&instance(), &shuffled_properties, &objects())
            .expect("shuffled encodes");
        assert_eq!(forward, shuffled);

        let body = read(&forward, 0);
        let entries = manb_entries(&forward, &body);
        assert_sorted(&forward, &entries, "MANB entries");
        assert_eq!(
            entries[0].fourcc(),
            MANIFEST_PROPERTIES_TAG,
            "MANP sorts below every lower case four character code"
        );
        for entry in &entries {
            let properties = entry_properties(&forward, entry);
            assert_sorted(&forward, &properties, "properties");
        }
    }

    #[test]
    fn a_digest_that_is_not_forty_eight_bytes_is_refused() {
        for length in [OBJECT_DIGEST_BYTES - 1, OBJECT_DIGEST_BYTES + 1, 0, 32] {
            let objects = vec![SealObject::new("scrt", &vec![0x11; length])];
            assert!(
                matches!(
                    encode_signed_body(&instance(), &properties(), &objects),
                    Err(SealManifestError::DigestLength { length: got, .. }) if got == length
                ),
                "a {length} byte digest must be refused"
            );
        }
        assert!(
            encode_signed_body(
                &instance(),
                &properties(),
                &[SealObject::new("scrt", &digest_of(0x11))]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_class_code_that_is_not_four_bytes_is_refused() {
        for class in ["scr", "scrtx", "", "seal1"] {
            let objects = vec![SealObject::new(class, &digest_of(0x11))];
            assert!(
                matches!(
                    encode_signed_body(&instance(), &properties(), &objects),
                    Err(SealManifestError::ClassCodeLength { length, .. })
                        if length == class.len()
                ),
                "the class code {class:?} must be refused"
            );
        }
        assert_eq!(SEAL_CLASS.len(), CLASS_CODE_BYTES);
        assert_eq!(seal_key(&instance()), format!("seal-{}", instance()));
    }

    #[test]
    fn the_server_nonce_is_exactly_thirty_two_bytes() {
        let drawn = random_server_nonce().expect("the host entropy source must be readable");
        assert_eq!(drawn.len(), SERVER_NONCE_BYTES);
        assert_ne!(drawn, [0u8; SERVER_NONCE_BYTES]);

        let properties = ManifestProperties::new(drawn, false);
        let body = encode_signed_body(&instance(), &properties, &objects()).expect("encodes");
        let needle = der::octet_string(&drawn);
        assert_eq!(
            body.windows(needle.len())
                .filter(|window| *window == needle)
                .count(),
            1,
            "srvn must appear once as a 32 byte OCTET STRING"
        );
    }

    #[test]
    fn empty_and_contradictory_inputs_are_refused() {
        let (chain, leaf_key) = chain();

        assert!(matches!(
            encode_signed_body(&instance(), &properties(), &[]),
            Err(SealManifestError::NoObjects)
        ));
        assert!(matches!(
            build_seal_manifest(
                &instance(),
                &properties(),
                &objects(),
                &[] as &[Vec<u8>],
                leaf_key.private()
            ),
            Err(SealManifestError::EmptyChain)
        ));
        assert!(matches!(
            build_seal_manifest(
                &instance(),
                &properties(),
                &objects(),
                &[vec![0x31, 0x00]],
                leaf_key.private()
            ),
            Err(SealManifestError::MalformedCertificate {
                position: 0,
                identifier: Some(0x31)
            })
        ));
        assert!(matches!(
            build_seal_manifest(
                &instance(),
                &properties(),
                &objects(),
                &[chain[0].clone(), Vec::new()],
                leaf_key.private()
            ),
            Err(SealManifestError::MalformedCertificate {
                position: 1,
                identifier: None
            })
        ));
        assert!(matches!(
            encode_signed_body("", &properties(), &objects()),
            Err(SealManifestError::EmptyInstance { class: None })
        ));

        let mut duplicated = objects();
        duplicated.push(SealObject::new("scrt", &digest_of(0x55)));
        assert!(matches!(
            encode_signed_body(&instance(), &properties(), &duplicated),
            Err(SealManifestError::DuplicateClass { .. })
        ));

        let mut bad_tag = properties();
        bad_tag
            .extra
            .push(ManifestProperty::bytes("nuidx", &[0x00]));
        assert!(matches!(
            encode_signed_body(&instance(), &bad_tag, &objects()),
            Err(SealManifestError::PropertyTagLength { length: 5, .. })
        ));
    }

    #[test]
    fn a_per_class_instance_overrides_the_manifest_one() {
        let mut objects = objects();
        objects[0].instance = Some("PCRT-INSTANCE".to_string());
        let body = encode_signed_body(&instance(), &properties(), &objects).expect("encodes");
        assert!(body.windows(13).any(|window| window == b"PCRT-INSTANCE"));
        assert!(
            body.windows(instance().len())
                .any(|window| window == instance().as_bytes())
        );

        objects[0].instance = Some(String::new());
        assert!(matches!(
            encode_signed_body(&instance(), &properties(), &objects),
            Err(SealManifestError::EmptyInstance { class: Some(class) }) if class == "scrt"
        ));
    }

    #[test]
    fn the_optional_object_properties_appear_only_when_supplied() {
        let mut objects = objects();
        objects[0].prid = Some(vec![0x01, 0x02]);
        objects[0].asid = Some(vec![0x03, 0x04]);
        objects[0].scdg = Some(vec![0x05, 0x06]);
        let body = encode_signed_body(&instance(), &properties(), &objects).expect("encodes");
        let element = read(&body, 0);
        let entries = manb_entries(&body, &element);
        for entry in &entries {
            let tags: Vec<String> = entry_properties(&body, entry)
                .iter()
                .map(Element::fourcc)
                .collect();
            let expected_optional = entry.fourcc() == objects[0].class;
            for tag in [PRID_PROPERTY_TAG, ASID_PROPERTY_TAG, SCDG_PROPERTY_TAG] {
                assert_eq!(
                    tags.contains(&tag.to_string()),
                    expected_optional,
                    "{tag} on {}",
                    entry.fourcc()
                );
            }
        }
        assert!(!body.windows(4).any(|window| window == b"said"));
    }

    #[test]
    fn the_signature_encoder_emits_minimal_der_integers() {
        let mut signature = [0u8; P256_SIGNATURE_BYTES];
        signature[0] = 0xff;
        signature[31] = 0x01;
        signature[32] = 0x00;
        signature[33] = 0x7f;
        signature[63] = 0x02;
        let encoded = signature_to_der(&signature);
        assert_eq!(encoded[0], der::IDENTIFIER_SEQUENCE);
        assert_eq!(usize::from(encoded[1]), encoded.len() - 2);
        assert_eq!(encoded[2], der::IDENTIFIER_INTEGER);
        assert_eq!(usize::from(encoded[3]), 33);
        assert_eq!(encoded[4], 0x00, "a set top bit takes a leading zero");
        assert_eq!(encoded[5], 0xff);
        let s_at = 4 + 33;
        assert_eq!(encoded[s_at], der::IDENTIFIER_INTEGER);
        assert_eq!(usize::from(encoded[s_at + 1]), 31);
        assert_eq!(encoded[s_at + 2], 0x7f, "a leading zero byte is dropped");

        assert_eq!(
            signature_to_der(&[0u8; P256_SIGNATURE_BYTES]),
            vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );

        let (manifest, _) = manifest();
        let der = signature_to_der(manifest.signature());
        let mut at = 2;
        for _ in 0..2 {
            assert_eq!(der[at], der::IDENTIFIER_INTEGER);
            let length = usize::from(der[at + 1]);
            let value = &der[at + 2..at + 2 + length];
            assert!(!value.is_empty());
            if value.len() > 1 {
                assert!(
                    value[0] != 0x00 || value[1] & 0x80 != 0,
                    "a leading zero is only allowed to clear a set top bit"
                );
            }
            assert!(
                value[0] & 0x80 == 0,
                "the value must not read back negative"
            );
            at += 2 + length;
        }
        assert_eq!(at, der.len());
    }

    #[test]
    fn the_manifest_is_reproducible_from_the_same_inputs() {
        let (first, _) = manifest();
        let (second, _) = manifest();
        assert_eq!(first.manifest(), second.manifest());
        assert_eq!(first.signature(), second.signature());
    }

    #[test]
    fn the_shape_matches_the_real_apple_manifest() {
        let Some(artifact) = read_ground_truth() else {
            return;
        };
        let (manifest, _) = manifest();
        let mine = manifest.manifest();

        let theirs = top_level(&artifact);
        let ours = top_level(mine);
        assert_eq!(
            theirs
                .iter()
                .map(|field| field.identifier[0])
                .collect::<Vec<u8>>(),
            ours.iter()
                .map(|field| field.identifier[0])
                .collect::<Vec<u8>>(),
            "the five top level tags must match the artifact"
        );
        assert_eq!(theirs[0].value(&artifact), MANIFEST_TAG.as_bytes());
        assert_eq!(theirs[1].value(&artifact), &[0x00]);
        assert_eq!(
            theirs[1].value(&artifact),
            ours[1].value(mine),
            "the version INTEGER must be the artifact's"
        );

        assert_eq!(
            (theirs[2].start, theirs[2].end),
            GROUND_TRUTH_SIGNED_RANGE,
            "the signed SET element is bytes [13, 3273) of the artifact"
        );
        assert_eq!(
            theirs[2].element(&artifact).len(),
            theirs[2].end - theirs[2].start
        );

        let theirs_entries = manb_entries(&artifact, &theirs[2]);
        let ours_entries = manb_entries(mine, &ours[2]);
        assert_eq!(theirs_entries[0].fourcc(), MANIFEST_PROPERTIES_TAG);
        assert_eq!(ours_entries[0].fourcc(), MANIFEST_PROPERTIES_TAG);
        assert_sorted(&artifact, &theirs_entries, "the artifact's MANB entries");
        assert_sorted(mine, &ours_entries, "locally authored MANB entries");
        for entry in &theirs_entries {
            let properties = entry_properties(&artifact, entry);
            assert_sorted(&artifact, &properties, "the artifact's properties");
        }

        let body = &artifact[theirs[2].start..theirs[2].end];
        assert!(!body.windows(4).any(|window| window == b"OBJP"));
        assert!(
            artifact.windows(4).any(|window| window == b"OBJP"),
            "the artifact does carry OBJP, inside the certificate bag"
        );
        assert!(
            theirs_entries
                .iter()
                .skip(1)
                .all(|entry| entry.fourcc() != MANIFEST_PROPERTIES_TAG)
        );
        assert!(theirs_entries.iter().any(|entry| {
            entry_properties(&artifact, entry)
                .iter()
                .any(|property| property.fourcc() == DIGEST_PROPERTY_TAG)
        }));
    }

    fn der_tag(identifier: &[u8]) -> u64 {
        let mut number = 0u64;
        for byte in &identifier[1..] {
            number = (number << 7) | u64::from(byte & 0x7f);
        }
        (u64::from(identifier[0] & 0xe0) << 56) | number
    }

    fn properties_only() -> ManifestProperties {
        let mut properties = ManifestProperties::new([0x5a; SERVER_NONCE_BYTES], false);
        properties.instance = Some(instance());
        properties
    }

    fn properties_only_manifest() -> SealManifest {
        let (chain, leaf_key) = chain();
        build_properties_only_manifest(&properties_only(), &chain, leaf_key.private())
            .expect("the properties only manifest must build")
    }

    #[test]
    fn the_properties_only_manifest_carries_the_whole_im4m_tag_set() {
        let manifest = properties_only_manifest();
        let bytes = manifest.manifest();
        assert_eq!(bytes[0], der::IDENTIFIER_SEQUENCE);

        let fields = top_level(bytes);
        assert_eq!(fields.len(), 5, "IM4M has five top level fields");
        assert_eq!(fields[0].identifier, vec![der::IDENTIFIER_IA5_STRING]);
        assert_eq!(fields[0].value(bytes), MANIFEST_TAG.as_bytes());
        assert_eq!(fields[1].identifier, vec![der::IDENTIFIER_INTEGER]);
        assert_eq!(fields[2].identifier, vec![der::IDENTIFIER_SET]);
        assert_eq!(fields[3].identifier, vec![der::IDENTIFIER_OCTET_STRING]);
        assert_eq!(fields[4].identifier, vec![der::IDENTIFIER_SEQUENCE]);

        assert_eq!(manifest.signed_body(), fields[2].element(bytes));
    }

    #[test]
    fn the_properties_only_manifest_carries_the_version_integer() {
        let manifest = properties_only_manifest();
        let bytes = manifest.manifest();
        let version = &top_level(bytes)[1];
        assert_eq!(version.identifier, vec![der::IDENTIFIER_INTEGER]);
        assert_eq!(
            version.value(bytes),
            &der::integer_u64(MANIFEST_VERSION)[2..]
        );
        assert_eq!(MANIFEST_VERSION, 0);
    }

    #[test]
    fn the_manb_element_spells_the_tag_the_decoder_looks_up() {
        let manifest = properties_only_manifest();
        let bytes = manifest.manifest();
        let members = children(bytes, &top_level(bytes)[2]);
        assert_eq!(members.len(), 1, "the signed SET holds MANB alone");
        assert_eq!(members[0].fourcc(), MANIFEST_BODY_TAG);
        assert_eq!(der_tag(&members[0].identifier), MANIFEST_BODY_DER_TAG);
        assert_eq!(MANIFEST_BODY_DER_TAG, 0xe000_0000_4d41_4e42);
        assert_eq!(
            MANIFEST_BODY_DER_TAG & 0xffff_ffff,
            u64::from(u32::from_be_bytes(*b"MANB"))
        );
    }

    #[test]
    fn the_properties_only_manifest_names_no_data_class_object() {
        let manifest = properties_only_manifest();
        let bytes = manifest.manifest();
        let entries = manb_entries(bytes, &top_level(bytes)[2]);
        assert_eq!(entries.len(), 1, "MANP is the only MANB entry");
        assert_eq!(entries[0].fourcc(), MANIFEST_PROPERTIES_TAG);

        let properties = entry_properties(bytes, &entries[0]);
        let named: Vec<String> = properties.iter().map(Element::fourcc).collect();
        assert!(named.contains(&SERVER_NONCE_PROPERTY_TAG.to_string()));
        assert!(named.contains(&FAIC_PROPERTY_TAG.to_string()));
        assert!(named.contains(&INSTANCE_PROPERTY_TAG.to_string()));
        assert!(
            !named.contains(&DIGEST_PROPERTY_TAG.to_string()),
            "a properties only manifest asserts no digest, found {named:?}"
        );
        assert_sorted(bytes, &properties, "MANP properties");
    }

    #[test]
    fn the_properties_only_manifest_emits_no_meta_property() {
        let manifest = properties_only_manifest();
        let bytes = manifest.manifest();
        let entries = manb_entries(bytes, &top_level(bytes)[2]);
        for entry in &entries {
            for property in entry_properties(bytes, entry) {
                assert_ne!(property.fourcc(), "meta", "meta must not be emitted");
            }
        }
        let signed = manifest.signed_body();
        assert!(!signed.windows(4).any(|window| window == b"meta"));
    }

    #[test]
    fn a_properties_only_manifest_without_an_instance_is_refused() {
        let unnamed = ManifestProperties::new([0x5a; SERVER_NONCE_BYTES], false);
        assert!(matches!(
            encode_properties_only_body(&unnamed),
            Err(SealManifestError::EmptyInstance { class: None })
        ));
        let mut empty = unnamed;
        empty.instance = Some(String::new());
        assert!(matches!(
            encode_properties_only_body(&empty),
            Err(SealManifestError::EmptyInstance { class: None })
        ));
    }

    #[test]
    fn the_properties_only_manifest_is_signed_the_same_way() {
        let (chain, leaf_key) = chain();
        let manifest =
            build_properties_only_manifest(&properties_only(), &chain, leaf_key.private())
                .expect("the manifest must build");
        let digest = sha384(manifest.signed_body());
        assert_eq!(manifest.manifest_digest(), digest);
        assert!(verify_uncompressed(
            &leaf_key.public_uncompressed(),
            &signing_digest(&digest),
            manifest.signature()
        ));
    }
}
