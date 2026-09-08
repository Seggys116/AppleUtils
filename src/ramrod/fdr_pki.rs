use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{P256_UNCOMPRESSED_BYTES, P256PrivateKey, sha1, sha256, signature_to_der};

use super::der::{self, DerError};

pub const FDR_KEY_SEED_BYTES: usize = 32;

pub const FDR_KEY_ENTROPY_SOURCE: &str = "/dev/urandom";

pub const FDR_ROOT_CA_KEY_DOMAIN: &[u8] = b"AppleUtils FDR sealing root CA";

pub const FDR_TLS_ROOT_KEY_DOMAIN: &[u8] = b"AppleUtils FDR sealing TLS root";

pub const FDR_LEAF_KEY_DOMAIN: &[u8] = b"AppleUtils FDR sealing leaf";

pub const MAXIMUM_SERIAL_BYTES: usize = 20;

pub const RANDOM_SERIAL_BYTES: usize = 16;

pub const FDR_LEAF_CONSTRAINT_EXTENSION_OID: &[u32] = &[1, 2, 840, 113_635, 100, 6, 1, 15];

pub const FDR_PROVISIONING_EXTENSION_OID: &[u32] = &[1, 2, 840, 113_635, 100, 6, 17];

// A tag, not a length: the consumer matches the inner TLV's tag against UTF8String.
pub const FDR_PROVISIONING_VALUE_TAG: u8 = 0x0c;

pub const DEFAULT_ROOT_CA_COMMON_NAME: &str = "AppleUtils FDR Sealing Root CA";

pub const DEFAULT_TLS_ROOT_COMMON_NAME: &str = "AppleUtils FDR Sealing TLS Root CA";

pub const DEFAULT_LEAF_COMMON_NAME: &str = "AppleUtils FDR Sealing Signer";

pub const DEFAULT_ORGANIZATION: &str = "AppleUtils";

const REFUSED_IDENTITY: &str = "apple";

const LOCAL_IDENTITY: &str = "appleutils";

const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_SUBJECT_KEY_IDENTIFIER: &[u32] = &[2, 5, 29, 14];
const OID_KEY_USAGE: &[u32] = &[2, 5, 29, 15];
const OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
const OID_AUTHORITY_KEY_IDENTIFIER: &[u32] = &[2, 5, 29, 35];

const X509_VERSION_3: u64 = 2;

const TBS_VERSION_TAG: u8 = 0;
const TBS_EXTENSIONS_TAG: u8 = 3;
const AUTHORITY_KEY_IDENTIFIER_TAG: u8 = 0;

#[derive(Debug)]
pub enum PkiError {
    Encoding(DerError),
    Entropy(std::io::Error),
    SeedFile {
        path: PathBuf,
        error: std::io::Error,
    },
    SeedLength {
        path: PathBuf,
        length: usize,
    },
    SerialNotPositive,
    SerialTooLong {
        length: usize,
    },
    EmptyName {
        which: &'static str,
    },
    RefusedIdentity {
        which: &'static str,
        value: String,
    },
    ValidityInverted {
        not_before: i64,
        not_after: i64,
    },
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(error) => write!(f, "certificate field cannot be encoded: {error}"),
            Self::Entropy(error) => {
                write!(f, "cannot read {FDR_KEY_ENTROPY_SOURCE}: {error}")
            }
            Self::SeedFile { path, error } => {
                write!(f, "seed file '{}': {error}", path.display())
            }
            Self::SeedLength { path, length } => write!(
                f,
                "seed file '{}' holds {length} bytes, not {FDR_KEY_SEED_BYTES}",
                path.display()
            ),
            Self::SerialNotPositive => {
                write!(f, "a certificate serial number must be a positive integer")
            }
            Self::SerialTooLong { length } => write!(
                f,
                "a serial number of {length} bytes exceeds the {MAXIMUM_SERIAL_BYTES} byte maximum"
            ),
            Self::EmptyName { which } => write!(f, "the {which} name carries no attributes"),
            Self::RefusedIdentity { which, value } => write!(
                f,
                "the {which} name '{value}' claims an identity the host may not issue under"
            ),
            Self::ValidityInverted {
                not_before,
                not_after,
            } => write!(
                f,
                "validity ends at {not_after}, which is before it begins at {not_before}"
            ),
        }
    }
}

impl std::error::Error for PkiError {}

impl From<DerError> for PkiError {
    fn from(error: DerError) -> Self {
        Self::Encoding(error)
    }
}

pub struct FdrKeyPair {
    seed: [u8; FDR_KEY_SEED_BYTES],
    key: P256PrivateKey,
}

impl FdrKeyPair {
    pub fn from_seed(seed: [u8; FDR_KEY_SEED_BYTES], domain: &[u8]) -> Self {
        Self {
            key: P256PrivateKey::derive(&seed, domain),
            seed,
        }
    }

    pub fn generate(domain: &[u8]) -> Result<Self, PkiError> {
        let mut seed = [0u8; FDR_KEY_SEED_BYTES];
        File::open(FDR_KEY_ENTROPY_SOURCE)
            .and_then(|mut source| source.read_exact(&mut seed))
            .map_err(PkiError::Entropy)?;
        Ok(Self::from_seed(seed, domain))
    }

    pub fn load(path: &Path, domain: &[u8]) -> Result<Self, PkiError> {
        let bytes = fs::read(path).map_err(|error| PkiError::SeedFile {
            path: path.to_path_buf(),
            error,
        })?;
        if bytes.len() != FDR_KEY_SEED_BYTES {
            return Err(PkiError::SeedLength {
                path: path.to_path_buf(),
                length: bytes.len(),
            });
        }
        let mut seed = [0u8; FDR_KEY_SEED_BYTES];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(seed, domain))
    }

    pub fn load_or_generate(path: &Path, domain: &[u8]) -> Result<Self, PkiError> {
        match Self::load(path, domain) {
            Ok(pair) => Ok(pair),
            Err(PkiError::SeedFile { error, .. })
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                let pair = Self::generate(domain)?;
                pair.save(path)?;
                Ok(pair)
            }
            Err(error) => Err(error),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), PkiError> {
        let fail = |error| PkiError::SeedFile {
            path: path.to_path_buf(),
            error,
        };
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(fail)?;
        }
        let mut file = create_private(path).map_err(fail)?;
        file.write_all(&self.seed).map_err(fail)?;
        file.sync_all().map_err(fail)
    }

    pub fn seed(&self) -> &[u8; FDR_KEY_SEED_BYTES] {
        &self.seed
    }

    pub fn private(&self) -> &P256PrivateKey {
        &self.key
    }

    pub fn public_uncompressed(&self) -> [u8; P256_UNCOMPRESSED_BYTES] {
        self.key.public_uncompressed()
    }

    pub fn key_identifier(&self) -> [u8; 20] {
        key_identifier(&self.public_uncompressed())
    }
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<File> {
    File::create(path)
}

pub fn key_identifier(public_key: &[u8; P256_UNCOMPRESSED_BYTES]) -> [u8; 20] {
    sha1(public_key)
}

pub fn random_serial() -> Result<Vec<u8>, PkiError> {
    let mut serial = [0u8; RANDOM_SERIAL_BYTES];
    File::open(FDR_KEY_ENTROPY_SOURCE)
        .and_then(|mut source| source.read_exact(&mut serial))
        .map_err(PkiError::Entropy)?;
    serial[0] &= 0x7f;
    serial[RANDOM_SERIAL_BYTES - 1] |= 0x01;
    Ok(serial.to_vec())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameAttribute {
    CommonName,
    OrganizationName,
    StateOrProvinceName,
}

impl NameAttribute {
    pub fn arcs(self) -> &'static [u32] {
        match self {
            Self::CommonName => &[2, 5, 4, 3],
            Self::OrganizationName => &[2, 5, 4, 10],
            Self::StateOrProvinceName => &[2, 5, 4, 8],
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistinguishedName {
    attributes: Vec<(NameAttribute, String)>,
}

impl DistinguishedName {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, attribute: NameAttribute, value: &str) -> Self {
        self.attributes.push((attribute, value.to_string()));
        self
    }

    pub fn common_name(self, value: &str) -> Self {
        self.with(NameAttribute::CommonName, value)
    }

    pub fn organization(self, value: &str) -> Self {
        self.with(NameAttribute::OrganizationName, value)
    }

    pub fn state_or_province(self, value: &str) -> Self {
        self.with(NameAttribute::StateOrProvinceName, value)
    }

    pub fn attributes(&self) -> &[(NameAttribute, String)] {
        &self.attributes
    }

    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    pub fn encode(&self) -> Result<Vec<u8>, DerError> {
        let mut body = Vec::new();
        for (attribute, value) in &self.attributes {
            let mut pair = der::try_oid(attribute.arcs())?;
            pair.extend_from_slice(&der::utf8_string(value));
            body.extend_from_slice(&der::set(&der::sequence(&pair)));
        }
        Ok(der::sequence(&body))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyUsage(u16);

impl KeyUsage {
    pub const NONE: Self = Self(0);
    pub const DIGITAL_SIGNATURE: Self = Self(1 << 0);
    pub const NON_REPUDIATION: Self = Self(1 << 1);
    pub const KEY_ENCIPHERMENT: Self = Self(1 << 2);
    pub const DATA_ENCIPHERMENT: Self = Self(1 << 3);
    pub const KEY_AGREEMENT: Self = Self(1 << 4);
    pub const KEY_CERT_SIGN: Self = Self(1 << 5);
    pub const CRL_SIGN: Self = Self(1 << 6);
    pub const ENCIPHER_ONLY: Self = Self(1 << 7);
    pub const DECIPHER_ONLY: Self = Self(1 << 8);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn to_named_bits(self) -> [u8; 2] {
        let mut bytes = [0u8; 2];
        for index in 0..9usize {
            if self.0 & (1 << index) != 0 {
                bytes[index / 8] |= 0x80 >> (index % 8);
            }
        }
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct CertificateParams {
    pub serial: Vec<u8>,
    pub issuer: DistinguishedName,
    pub subject: DistinguishedName,
    pub subject_der: Option<Vec<u8>>,
    pub not_before: i64,
    pub not_after: i64,
    pub subject_public_key: [u8; P256_UNCOMPRESSED_BYTES],
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub key_usage: KeyUsage,
    pub extra_extensions: Vec<(Vec<u32>, bool, Vec<u8>)>,
}

impl CertificateParams {
    pub fn new(
        subject: DistinguishedName,
        serial: Vec<u8>,
        not_before: i64,
        not_after: i64,
        subject_public_key: [u8; P256_UNCOMPRESSED_BYTES],
    ) -> Self {
        Self {
            serial,
            issuer: subject.clone(),
            subject,
            subject_der: None,
            not_before,
            not_after,
            subject_public_key,
            is_ca: false,
            path_len: None,
            key_usage: KeyUsage::NONE,
            extra_extensions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CertificateIdentity {
    pub subject: DistinguishedName,
    pub serial: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

fn ecdsa_with_sha256_algorithm() -> Vec<u8> {
    der::sequence(&der::oid(OID_ECDSA_WITH_SHA256))
}

fn subject_public_key_info(public_key: &[u8; P256_UNCOMPRESSED_BYTES]) -> Vec<u8> {
    let mut algorithm = der::oid(OID_EC_PUBLIC_KEY);
    algorithm.extend_from_slice(&der::oid(OID_PRIME256V1));
    let mut body = der::sequence(&algorithm);
    body.extend_from_slice(&der::bit_string(public_key));
    der::sequence(&body)
}

fn extension(arcs: &[u32], critical: bool, value: &[u8]) -> Result<Vec<u8>, DerError> {
    let mut body = der::try_oid(arcs)?;
    if critical {
        body.extend_from_slice(&der::boolean(true));
    }
    body.extend_from_slice(&der::octet_string(value));
    Ok(der::sequence(&body))
}

fn standard_extensions(
    params: &CertificateParams,
    issuer_public_key: &[u8; P256_UNCOMPRESSED_BYTES],
) -> Result<Vec<u8>, PkiError> {
    let mut out = Vec::new();

    let mut constraints = der::boolean(params.is_ca);
    if params.is_ca
        && let Some(path_len) = params.path_len
    {
        constraints.extend_from_slice(&der::integer_u64(u64::from(path_len)));
    }
    out.extend_from_slice(&extension(
        OID_BASIC_CONSTRAINTS,
        params.is_ca,
        &der::sequence(&constraints),
    )?);

    if !params.key_usage.is_empty() {
        out.extend_from_slice(&extension(
            OID_KEY_USAGE,
            true,
            &der::named_bit_string(&params.key_usage.to_named_bits()),
        )?);
    }

    out.extend_from_slice(&extension(
        OID_SUBJECT_KEY_IDENTIFIER,
        false,
        &der::octet_string(&key_identifier(&params.subject_public_key)),
    )?);

    let authority = der::sequence(&der::context_primitive(
        AUTHORITY_KEY_IDENTIFIER_TAG,
        &key_identifier(issuer_public_key),
    ));
    out.extend_from_slice(&extension(OID_AUTHORITY_KEY_IDENTIFIER, false, &authority)?);

    for (arcs, critical, value) in &params.extra_extensions {
        out.extend_from_slice(&extension(arcs, *critical, value)?);
    }

    Ok(out)
}

fn claims_refused_identity(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let bytes = value.as_bytes();
    let mut offset = 0;

    while let Some(relative) = value[offset..].find(REFUSED_IDENTITY) {
        let start = offset + relative;
        let local_end = start + LOCAL_IDENTITY.len();
        let local_identity = value[start..].starts_with(LOCAL_IDENTITY)
            && (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
            && (local_end == bytes.len() || !bytes[local_end].is_ascii_alphanumeric());
        if !local_identity {
            return true;
        }
        offset = local_end;
    }

    false
}

fn check_identity(which: &'static str, name: &DistinguishedName) -> Result<(), PkiError> {
    if name.is_empty() {
        return Err(PkiError::EmptyName { which });
    }
    for (_, value) in name.attributes() {
        if claims_refused_identity(value) {
            return Err(PkiError::RefusedIdentity {
                which,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn check(params: &CertificateParams) -> Result<(), PkiError> {
    check_identity("issuer", &params.issuer)?;
    match &params.subject_der {
        Some(der) if der.len() > 2 => {}
        Some(_) => return Err(PkiError::EmptyName { which: "subject" }),
        None => check_identity("subject", &params.subject)?,
    }
    if params.serial.len() > MAXIMUM_SERIAL_BYTES {
        return Err(PkiError::SerialTooLong {
            length: params.serial.len(),
        });
    }
    if params.serial.iter().all(|byte| *byte == 0) {
        return Err(PkiError::SerialNotPositive);
    }
    if params.not_after < params.not_before {
        return Err(PkiError::ValidityInverted {
            not_before: params.not_before,
            not_after: params.not_after,
        });
    }
    Ok(())
}

pub fn encode_tbs_certificate(
    params: &CertificateParams,
    issuer_public_key: &[u8; P256_UNCOMPRESSED_BYTES],
) -> Result<Vec<u8>, PkiError> {
    check(params)?;
    let mut body = der::explicit(TBS_VERSION_TAG, &der::integer_u64(X509_VERSION_3));
    body.extend_from_slice(&der::integer(&params.serial));
    body.extend_from_slice(&ecdsa_with_sha256_algorithm());
    body.extend_from_slice(&params.issuer.encode()?);

    let mut validity = der::x509_time(params.not_before)?;
    validity.extend_from_slice(&der::x509_time(params.not_after)?);
    body.extend_from_slice(&der::sequence(&validity));

    match &params.subject_der {
        Some(der) => body.extend_from_slice(der),
        None => body.extend_from_slice(&params.subject.encode()?),
    }
    body.extend_from_slice(&subject_public_key_info(&params.subject_public_key));

    let extensions = standard_extensions(params, issuer_public_key)?;
    body.extend_from_slice(&der::explicit(
        TBS_EXTENSIONS_TAG,
        &der::sequence(&extensions),
    ));

    Ok(der::sequence(&body))
}

pub fn issue_certificate(
    params: &CertificateParams,
    issuer_key: &P256PrivateKey,
) -> Result<Vec<u8>, PkiError> {
    let issuer_public_key = issuer_key.public_uncompressed();
    let tbs = encode_tbs_certificate(params, &issuer_public_key)?;
    let signature = issuer_key.sign_digest(&sha256(&tbs));
    let mut body = tbs;
    body.extend_from_slice(&ecdsa_with_sha256_algorithm());
    body.extend_from_slice(&der::bit_string(&signature_to_der(&signature)));
    Ok(der::sequence(&body))
}

pub fn issue_self_signed(
    params: &CertificateParams,
    key: &P256PrivateKey,
) -> Result<Vec<u8>, PkiError> {
    let mut params = params.clone();
    params.issuer = params.subject.clone();
    params.subject_public_key = key.public_uncompressed();
    issue_certificate(&params, key)
}

pub fn issue_root_ca(
    identity: &CertificateIdentity,
    key: &P256PrivateKey,
) -> Result<Vec<u8>, PkiError> {
    let mut params = CertificateParams::new(
        identity.subject.clone(),
        identity.serial.clone(),
        identity.not_before,
        identity.not_after,
        key.public_uncompressed(),
    );
    params.is_ca = true;
    params.key_usage = KeyUsage::DIGITAL_SIGNATURE
        .union(KeyUsage::KEY_CERT_SIGN)
        .union(KeyUsage::CRL_SIGN);
    issue_self_signed(&params, key)
}

pub fn issue_tls_root(
    identity: &CertificateIdentity,
    key: &P256PrivateKey,
) -> Result<Vec<u8>, PkiError> {
    let mut params = CertificateParams::new(
        identity.subject.clone(),
        identity.serial.clone(),
        identity.not_before,
        identity.not_after,
        key.public_uncompressed(),
    );
    params.is_ca = true;
    params.key_usage = KeyUsage::DIGITAL_SIGNATURE
        .union(KeyUsage::KEY_CERT_SIGN)
        .union(KeyUsage::CRL_SIGN);
    issue_self_signed(&params, key)
}

pub fn issue_fdr_leaf(
    identity: &CertificateIdentity,
    subject_public_key: &[u8; P256_UNCOMPRESSED_BYTES],
    issuer: &DistinguishedName,
    issuer_key: &P256PrivateKey,
    provisioning: Option<&str>,
) -> Result<Vec<u8>, PkiError> {
    let mut params = CertificateParams::new(
        identity.subject.clone(),
        identity.serial.clone(),
        identity.not_before,
        identity.not_after,
        *subject_public_key,
    );
    params.issuer = issuer.clone();
    params.key_usage = KeyUsage::DIGITAL_SIGNATURE;
    params.extra_extensions.push((
        FDR_LEAF_CONSTRAINT_EXTENSION_OID.to_vec(),
        false,
        empty_constraint_set(),
    ));
    if let Some(value) = provisioning {
        params.extra_extensions.push((
            FDR_PROVISIONING_EXTENSION_OID.to_vec(),
            false,
            der::utf8_string(value),
        ));
    }
    issue_certificate(&params, issuer_key)
}

pub fn issue_fdr_device_certificate(
    subject_der: &[u8],
    subject_public_key: &[u8; P256_UNCOMPRESSED_BYTES],
    issuer: &DistinguishedName,
    issuer_key: &P256PrivateKey,
    serial: Vec<u8>,
    not_before: i64,
    not_after: i64,
) -> Result<Vec<u8>, PkiError> {
    let mut params = CertificateParams::new(
        issuer.clone(),
        serial,
        not_before,
        not_after,
        *subject_public_key,
    );
    params.issuer = issuer.clone();
    params.subject_der = Some(subject_der.to_vec());
    params.key_usage = KeyUsage::DIGITAL_SIGNATURE;
    params.extra_extensions.push((
        FDR_LEAF_CONSTRAINT_EXTENSION_OID.to_vec(),
        false,
        empty_constraint_set(),
    ));
    issue_certificate(&params, issuer_key)
}

// A SET, not a SEQUENCE: the consumer requires identifier octet 0x31 and refuses 30 00.
pub fn empty_constraint_set() -> Vec<u8> {
    der::set(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify_uncompressed;

    const NOT_BEFORE: i64 = 1_767_225_600;
    const NOT_AFTER: i64 = 2_082_758_400;

    fn identity(common_name: &str) -> CertificateIdentity {
        CertificateIdentity {
            subject: DistinguishedName::new()
                .common_name(common_name)
                .organization(DEFAULT_ORGANIZATION),
            serial: vec![0x01, 0x02, 0x03, 0x04],
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        }
    }

    fn root_key() -> FdrKeyPair {
        FdrKeyPair::from_seed([0x11; FDR_KEY_SEED_BYTES], FDR_ROOT_CA_KEY_DOMAIN)
    }

    fn leaf_key() -> FdrKeyPair {
        FdrKeyPair::from_seed([0x11; FDR_KEY_SEED_BYTES], FDR_LEAF_KEY_DOMAIN)
    }

    fn take(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
        let identifier = bytes[0];
        let first = bytes[1];
        let (length, header) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let count = (first & 0x7f) as usize;
            let mut value = 0usize;
            for byte in &bytes[2..2 + count] {
                value = (value << 8) | *byte as usize;
            }
            (value, 2 + count)
        };
        (
            identifier,
            &bytes[header..header + length],
            &bytes[header + length..],
        )
    }

    #[test]
    fn a_root_certificate_has_the_three_top_level_fields_in_order() {
        let key = root_key();
        let certificate = issue_root_ca(&identity(DEFAULT_ROOT_CA_COMMON_NAME), key.private())
            .expect("the root must issue");
        let (identifier, body, rest) = take(&certificate);
        assert_eq!(identifier, 0x30);
        assert!(rest.is_empty(), "nothing may follow the certificate");

        let (tbs_identifier, _, after_tbs) = take(body);
        assert_eq!(tbs_identifier, 0x30);
        let tbs_len = body.len() - after_tbs.len();
        let tbs = &body[..tbs_len];

        let (algorithm_identifier, algorithm, after_algorithm) = take(after_tbs);
        assert_eq!(algorithm_identifier, 0x30);
        assert_eq!(
            algorithm,
            &der::oid(OID_ECDSA_WITH_SHA256)[..],
            "the algorithm identifier must carry the OID and no parameters"
        );

        let (signature_identifier, signature, tail) = take(after_algorithm);
        assert_eq!(signature_identifier, 0x03);
        assert!(tail.is_empty());
        assert_eq!(signature[0], 0x00, "no unused bits in the signature");

        let raw = key.private().sign_digest(&sha256(tbs));
        assert_eq!(&signature[1..], &signature_to_der(&raw)[..]);
        assert!(verify_uncompressed(
            &key.public_uncompressed(),
            &sha256(tbs),
            &raw
        ));
    }

    #[test]
    fn a_changed_body_no_longer_verifies() {
        let key = root_key();
        let identity = identity(DEFAULT_ROOT_CA_COMMON_NAME);
        let tbs = {
            let mut params = CertificateParams::new(
                identity.subject.clone(),
                identity.serial.clone(),
                identity.not_before,
                identity.not_after,
                key.public_uncompressed(),
            );
            params.is_ca = true;
            params.key_usage = KeyUsage::KEY_CERT_SIGN;
            encode_tbs_certificate(&params, &key.public_uncompressed()).expect("tbs must encode")
        };
        let signature = key.private().sign_digest(&sha256(&tbs));
        let mut tampered = tbs.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(verify_uncompressed(
            &key.public_uncompressed(),
            &sha256(&tbs),
            &signature
        ));
        assert!(!verify_uncompressed(
            &key.public_uncompressed(),
            &sha256(&tampered),
            &signature
        ));
    }

    #[test]
    fn a_leaf_names_and_points_at_its_issuer() {
        let root = root_key();
        let leaf = leaf_key();
        let root_identity = identity(DEFAULT_ROOT_CA_COMMON_NAME);
        let leaf_identity = identity(DEFAULT_LEAF_COMMON_NAME);
        let certificate = issue_fdr_leaf(
            &leaf_identity,
            &leaf.public_uncompressed(),
            &root_identity.subject,
            root.private(),
            None,
        )
        .expect("the leaf must issue");

        let issuer = root_identity
            .subject
            .encode()
            .expect("the name must encode");
        assert!(
            certificate
                .windows(issuer.len())
                .any(|window| window == issuer),
            "the leaf must carry the root's name as its issuer"
        );
        let authority = der::sequence(&der::context_primitive(
            AUTHORITY_KEY_IDENTIFIER_TAG,
            &root.key_identifier(),
        ));
        assert!(
            certificate
                .windows(authority.len())
                .any(|window| window == authority),
            "the leaf's authority key identifier must be the root's"
        );
        let constraint = extension(FDR_LEAF_CONSTRAINT_EXTENSION_OID, false, &der::set(&[]))
            .expect("the constraint extension must encode");
        assert!(
            certificate
                .windows(constraint.len())
                .any(|window| window == constraint),
            "the leaf must carry the empty constraint set"
        );
    }

    #[test]
    fn the_empty_constraint_set_is_a_set_not_a_sequence() {
        assert_eq!(empty_constraint_set(), vec![0x31, 0x00]);

        let encoded = extension(
            FDR_LEAF_CONSTRAINT_EXTENSION_OID,
            false,
            &empty_constraint_set(),
        )
        .expect("the constraint extension must encode");
        assert_eq!(
            encoded,
            vec![
                0x30, 0x10, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0f,
                0x04, 0x02, 0x31, 0x00,
            ]
        );
    }

    #[test]
    fn the_provisioning_extension_carries_a_utf8_string_of_any_length() {
        let root = root_key();
        let leaf = leaf_key();
        let root_identity = identity(DEFAULT_ROOT_CA_COMMON_NAME);
        let leaf_identity = identity(DEFAULT_LEAF_COMMON_NAME);

        for value in ["", "id", "an identifier longer than twelve octets"] {
            let certificate = issue_fdr_leaf(
                &leaf_identity,
                &leaf.public_uncompressed(),
                &root_identity.subject,
                root.private(),
                Some(value),
            )
            .expect("any length of ClientID must issue");
            let encoded = der::utf8_string(value);
            assert_eq!(encoded[0], FDR_PROVISIONING_VALUE_TAG);
            let present = extension(FDR_PROVISIONING_EXTENSION_OID, false, &encoded)
                .expect("the ClientID extension must encode");
            assert!(
                certificate
                    .windows(present.len())
                    .any(|window| window == present),
                "the leaf must carry the ClientID extension for {value:?}"
            );
        }

        assert_eq!(der::utf8_string(""), vec![0x0c, 0x00]);

        let bare = issue_fdr_leaf(
            &leaf_identity,
            &leaf.public_uncompressed(),
            &root_identity.subject,
            root.private(),
            None,
        )
        .expect("a leaf without a ClientID must issue");
        let oid = der::oid(FDR_PROVISIONING_EXTENSION_OID);
        assert!(
            !bare.windows(oid.len()).any(|window| window == oid),
            "no ClientID extension when none was asked for"
        );
    }

    #[test]
    fn a_name_claiming_apple_is_refused() {
        assert!(!claims_refused_identity(DEFAULT_ROOT_CA_COMMON_NAME));
        assert!(claims_refused_identity("NotAppleUtils Root CA"));
        assert!(claims_refused_identity("AppleUtils Apple Root CA"));

        let key = root_key();
        let mut params = CertificateParams::new(
            DistinguishedName::new().common_name("Apple Root CA"),
            vec![0x01],
            NOT_BEFORE,
            NOT_AFTER,
            key.public_uncompressed(),
        );
        assert!(matches!(
            issue_certificate(&params, key.private()),
            Err(PkiError::RefusedIdentity { .. })
        ));
        params.subject = DistinguishedName::new().common_name(DEFAULT_ROOT_CA_COMMON_NAME);
        params.issuer = DistinguishedName::new().common_name("apple inc.");
        assert!(matches!(
            issue_certificate(&params, key.private()),
            Err(PkiError::RefusedIdentity {
                which: "issuer",
                ..
            })
        ));
    }

    #[test]
    fn impossible_parameters_are_refused() {
        let key = root_key();
        let base = CertificateParams::new(
            DistinguishedName::new().common_name(DEFAULT_ROOT_CA_COMMON_NAME),
            vec![0x01],
            NOT_BEFORE,
            NOT_AFTER,
            key.public_uncompressed(),
        );

        let mut zero_serial = base.clone();
        zero_serial.serial = vec![0x00, 0x00];
        assert!(matches!(
            issue_certificate(&zero_serial, key.private()),
            Err(PkiError::SerialNotPositive)
        ));

        let mut long_serial = base.clone();
        long_serial.serial = vec![0x01; MAXIMUM_SERIAL_BYTES + 1];
        assert!(matches!(
            issue_certificate(&long_serial, key.private()),
            Err(PkiError::SerialTooLong { length: 21 })
        ));

        let mut empty_subject = base.clone();
        empty_subject.subject = DistinguishedName::new();
        assert!(matches!(
            issue_certificate(&empty_subject, key.private()),
            Err(PkiError::EmptyName { which: "subject" })
        ));

        let mut inverted = base.clone();
        inverted.not_after = NOT_BEFORE - 1;
        assert!(matches!(
            issue_certificate(&inverted, key.private()),
            Err(PkiError::ValidityInverted { .. })
        ));
    }

    #[test]
    fn key_usage_bits_land_where_rfc_5280_numbers_them() {
        assert_eq!(KeyUsage::DIGITAL_SIGNATURE.to_named_bits(), [0x80, 0x00]);
        assert_eq!(KeyUsage::KEY_CERT_SIGN.to_named_bits(), [0x04, 0x00]);
        assert_eq!(KeyUsage::CRL_SIGN.to_named_bits(), [0x02, 0x00]);
        assert_eq!(KeyUsage::DECIPHER_ONLY.to_named_bits(), [0x00, 0x80]);
        let ca = KeyUsage::DIGITAL_SIGNATURE
            .union(KeyUsage::KEY_CERT_SIGN)
            .union(KeyUsage::CRL_SIGN);
        assert_eq!(ca.to_named_bits(), [0x86, 0x00]);
        assert!(ca.contains(KeyUsage::CRL_SIGN));
        assert!(!ca.contains(KeyUsage::KEY_AGREEMENT));
        assert_eq!(
            der::named_bit_string(&ca.to_named_bits()),
            vec![0x03, 0x02, 0x01, 0x86]
        );
    }

    #[test]
    fn a_persisted_seed_rebuilds_the_same_key() {
        let directory = std::env::temp_dir().join(format!(
            "appleutils-fdr-pki-seed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = directory.join("root.seed");
        let generated = FdrKeyPair::from_seed([0x3c; FDR_KEY_SEED_BYTES], FDR_ROOT_CA_KEY_DOMAIN);
        generated.save(&path).expect("the seed must persist");
        let reloaded = FdrKeyPair::load(&path, FDR_ROOT_CA_KEY_DOMAIN).expect("the seed must load");
        assert_eq!(generated.seed(), reloaded.seed());
        assert_eq!(
            generated.public_uncompressed(),
            reloaded.public_uncompressed()
        );
        assert_ne!(
            generated.public_uncompressed(),
            FdrKeyPair::from_seed([0x3c; FDR_KEY_SEED_BYTES], FDR_LEAF_KEY_DOMAIN)
                .public_uncompressed(),
            "a different domain must give a different key from the same seed"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path)
                .expect("the seed file must exist")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the seed must be owner only");
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&directory);
    }

    #[test]
    fn a_seed_file_of_the_wrong_length_is_refused() {
        let directory = std::env::temp_dir().join(format!(
            "appleutils-fdr-pki-short-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).expect("the directory must be creatable");
        let path = directory.join("short.seed");
        fs::write(&path, [0x00; 8]).expect("the short seed must write");
        assert!(matches!(
            FdrKeyPair::load(&path, FDR_ROOT_CA_KEY_DOMAIN),
            Err(PkiError::SeedLength { length: 8, .. })
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&directory);
    }
}
