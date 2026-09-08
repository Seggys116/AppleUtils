use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{P256PrivateKey, Sha256};

use super::der;
use super::fdr_pki::{
    CertificateIdentity, DEFAULT_LEAF_COMMON_NAME, DEFAULT_ORGANIZATION,
    DEFAULT_ROOT_CA_COMMON_NAME, DEFAULT_TLS_ROOT_COMMON_NAME, DistinguishedName,
    FDR_LEAF_KEY_DOMAIN, FDR_ROOT_CA_KEY_DOMAIN, FDR_TLS_ROOT_KEY_DOMAIN, FdrKeyPair,
    MAXIMUM_SERIAL_BYTES, PkiError, issue_fdr_leaf, issue_root_ca, issue_tls_root, random_serial,
};
use super::fdr_trust::{FdrTrustObjectError, top_level_elements};

pub const TRUST_OBJECT_TAG: &str = "secb";

pub const ROOT_CA_ELEMENT_TAG: &str = "trst";

pub const TLS_ROOT_ELEMENT_TAG: &str = "rssl";

pub const REVOCATION_ELEMENT_TAG: &str = "rvok";

pub const TRUST_OBJECT_DIGEST_BYTES: usize = 32;

pub const ROOT_CA_SEED_FILE_NAME: &str = "root-ca.seed";

pub const TLS_ROOT_SEED_FILE_NAME: &str = "tls-root.seed";

pub const ROOT_CA_SERIAL_FILE_NAME: &str = "root-ca.serial";

pub const TLS_ROOT_SERIAL_FILE_NAME: &str = "tls-root.serial";

pub const SEALING_LEAF_SEED_FILE_NAME: &str = "sealing-leaf.seed";

pub const SEALING_LEAF_SERIAL_FILE_NAME: &str = "sealing-leaf.serial";

#[derive(Debug)]
pub enum FdrObjectError {
    EmptyCertificate {
        which: &'static str,
    },
    MalformedCertificate {
        which: &'static str,
        error: FdrTrustObjectError,
    },
    TrailingCertificateBytes {
        which: &'static str,
        elements: usize,
    },
    CertificateNotASequence {
        which: &'static str,
        identifier: u8,
    },
    Pki(PkiError),
    MaterialFile {
        path: PathBuf,
        error: std::io::Error,
    },
    SerialLength {
        path: PathBuf,
        length: usize,
    },
}

impl std::fmt::Display for FdrObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCertificate { which } => {
                write!(f, "the {which} element was given no certificate")
            }
            Self::MalformedCertificate { which, error } => {
                write!(f, "the {which} certificate is not one DER element: {error}")
            }
            Self::TrailingCertificateBytes { which, elements } => write!(
                f,
                "the {which} certificate holds {elements} top level elements, not 1"
            ),
            Self::CertificateNotASequence { which, identifier } => write!(
                f,
                "the {which} certificate starts with identifier {identifier:#04x}, not a SEQUENCE"
            ),
            Self::Pki(error) => write!(f, "trust material cannot be issued: {error}"),
            Self::MaterialFile { path, error } => {
                write!(f, "trust material file '{}': {error}", path.display())
            }
            Self::SerialLength { path, length } => write!(
                f,
                "serial file '{}' holds {length} bytes, which is not between 1 and \
                 {MAXIMUM_SERIAL_BYTES}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for FdrObjectError {}

impl From<PkiError> for FdrObjectError {
    fn from(error: PkiError) -> Self {
        Self::Pki(error)
    }
}

fn tagged_element(tag: &str, body: &[u8]) -> Vec<u8> {
    let mut inner = der::ia5_string(tag);
    inner.extend_from_slice(body);
    der::sequence(&inner)
}

fn check_certificate(which: &'static str, certificate: &[u8]) -> Result<(), FdrObjectError> {
    if certificate.is_empty() {
        return Err(FdrObjectError::EmptyCertificate { which });
    }
    if certificate[0] != der::IDENTIFIER_SEQUENCE {
        return Err(FdrObjectError::CertificateNotASequence {
            which,
            identifier: certificate[0],
        });
    }
    let spans = top_level_elements(certificate)
        .map_err(|error| FdrObjectError::MalformedCertificate { which, error })?;
    if spans.len() != 1 {
        return Err(FdrObjectError::TrailingCertificateBytes {
            which,
            elements: spans.len(),
        });
    }
    Ok(())
}

pub fn build_trust_object(
    root_ca_der: &[u8],
    tls_root_der: &[u8],
) -> Result<Vec<u8>, FdrObjectError> {
    check_certificate(ROOT_CA_ELEMENT_TAG, root_ca_der)?;
    check_certificate(TLS_ROOT_ELEMENT_TAG, tls_root_der)?;

    let mut body = der::ia5_string(TRUST_OBJECT_TAG);
    body.extend_from_slice(&tagged_element(
        ROOT_CA_ELEMENT_TAG,
        &der::octet_string(root_ca_der),
    ));
    body.extend_from_slice(&tagged_element(
        TLS_ROOT_ELEMENT_TAG,
        &der::octet_string(tls_root_der),
    ));
    body.extend_from_slice(&tagged_element(REVOCATION_ELEMENT_TAG, &[]));
    Ok(der::sequence(&body))
}

pub fn trust_object_digest(object: &[u8]) -> [u8; TRUST_OBJECT_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(object);
    hasher.finish()
}

pub struct FdrTrustMaterial {
    root_ca_key: FdrKeyPair,
    tls_root_key: FdrKeyPair,
    root_ca_subject: DistinguishedName,
    root_ca_certificate: Vec<u8>,
    tls_root_certificate: Vec<u8>,
    trust_object: Vec<u8>,
}

pub struct SealingLeaf {
    key: P256PrivateKey,
    certificate: Vec<u8>,
}

impl SealingLeaf {
    pub fn key(&self) -> &P256PrivateKey {
        &self.key
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

impl FdrTrustMaterial {
    pub fn issue(
        root_ca_key: FdrKeyPair,
        tls_root_key: FdrKeyPair,
        root_ca_identity: &CertificateIdentity,
        tls_root_identity: &CertificateIdentity,
    ) -> Result<Self, FdrObjectError> {
        let root_ca_certificate = issue_root_ca(root_ca_identity, root_ca_key.private())?;
        let tls_root_certificate = issue_tls_root(tls_root_identity, tls_root_key.private())?;
        let trust_object = build_trust_object(&root_ca_certificate, &tls_root_certificate)?;
        Ok(Self {
            root_ca_key,
            tls_root_key,
            root_ca_subject: root_ca_identity.subject.clone(),
            root_ca_certificate,
            tls_root_certificate,
            trust_object,
        })
    }

    // Seeds, serials and the validity window all persist: the guest hashes the whole object, so any change moves its digest.
    pub fn load_or_generate(
        directory: &Path,
        not_before: i64,
        not_after: i64,
    ) -> Result<Self, FdrObjectError> {
        Self::load_or_generate_named(
            directory,
            DistinguishedName::new()
                .common_name(DEFAULT_ROOT_CA_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            DistinguishedName::new()
                .common_name(DEFAULT_TLS_ROOT_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            not_before,
            not_after,
        )
    }

    pub fn load_or_generate_named(
        directory: &Path,
        root_ca_subject: DistinguishedName,
        tls_root_subject: DistinguishedName,
        not_before: i64,
        not_after: i64,
    ) -> Result<Self, FdrObjectError> {
        fs::create_dir_all(directory).map_err(|error| FdrObjectError::MaterialFile {
            path: directory.to_path_buf(),
            error,
        })?;

        let root_ca_key = FdrKeyPair::load_or_generate(
            &directory.join(ROOT_CA_SEED_FILE_NAME),
            FDR_ROOT_CA_KEY_DOMAIN,
        )?;
        let tls_root_key = FdrKeyPair::load_or_generate(
            &directory.join(TLS_ROOT_SEED_FILE_NAME),
            FDR_TLS_ROOT_KEY_DOMAIN,
        )?;

        let root_ca_identity = CertificateIdentity {
            subject: root_ca_subject,
            serial: load_or_generate_serial(&directory.join(ROOT_CA_SERIAL_FILE_NAME))?,
            not_before,
            not_after,
        };
        let tls_root_identity = CertificateIdentity {
            subject: tls_root_subject,
            serial: load_or_generate_serial(&directory.join(TLS_ROOT_SERIAL_FILE_NAME))?,
            not_before,
            not_after,
        };

        Self::issue(
            root_ca_key,
            tls_root_key,
            &root_ca_identity,
            &tls_root_identity,
        )
    }

    pub fn root_ca_key(&self) -> &FdrKeyPair {
        &self.root_ca_key
    }

    pub fn tls_root_key(&self) -> &FdrKeyPair {
        &self.tls_root_key
    }

    pub fn root_ca_subject(&self) -> &DistinguishedName {
        &self.root_ca_subject
    }

    pub fn root_ca_certificate(&self) -> &[u8] {
        &self.root_ca_certificate
    }

    pub fn tls_root_certificate(&self) -> &[u8] {
        &self.tls_root_certificate
    }

    pub fn trust_object(&self) -> &[u8] {
        &self.trust_object
    }

    pub fn digest(&self) -> [u8; TRUST_OBJECT_DIGEST_BYTES] {
        trust_object_digest(&self.trust_object)
    }

    pub fn load_or_generate_sealing_leaf(
        &self,
        directory: &Path,
        not_before: i64,
        not_after: i64,
    ) -> Result<SealingLeaf, FdrObjectError> {
        fs::create_dir_all(directory).map_err(|error| FdrObjectError::MaterialFile {
            path: directory.to_path_buf(),
            error,
        })?;
        let key = FdrKeyPair::load_or_generate(
            &directory.join(SEALING_LEAF_SEED_FILE_NAME),
            FDR_LEAF_KEY_DOMAIN,
        )?;
        self.issue_sealing_leaf(directory, *key.private(), not_before, not_after)
    }

    // Signing version 2: the guest verifies with the raw SIK public key, so the leaf must certify that same key.
    pub fn issue_sealing_leaf(
        &self,
        directory: &Path,
        key: P256PrivateKey,
        not_before: i64,
        not_after: i64,
    ) -> Result<SealingLeaf, FdrObjectError> {
        fs::create_dir_all(directory).map_err(|error| FdrObjectError::MaterialFile {
            path: directory.to_path_buf(),
            error,
        })?;
        let identity = CertificateIdentity {
            subject: DistinguishedName::new()
                .common_name(DEFAULT_LEAF_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            serial: load_or_generate_serial(&directory.join(SEALING_LEAF_SERIAL_FILE_NAME))?,
            not_before,
            not_after,
        };
        let certificate = issue_fdr_leaf(
            &identity,
            &key.public_uncompressed(),
            &self.root_ca_subject,
            self.root_ca_key.private(),
            None,
        )?;
        Ok(SealingLeaf { key, certificate })
    }
}

pub fn load_or_generate_serial(path: &Path) -> Result<Vec<u8>, FdrObjectError> {
    match fs::read(path) {
        Ok(serial) => {
            if serial.is_empty() || serial.len() > MAXIMUM_SERIAL_BYTES {
                return Err(FdrObjectError::SerialLength {
                    path: path.to_path_buf(),
                    length: serial.len(),
                });
            }
            Ok(serial)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let serial = random_serial()?;
            fs::write(path, &serial).map_err(|error| FdrObjectError::MaterialFile {
                path: path.to_path_buf(),
                error,
            })?;
            Ok(serial)
        }
        Err(error) => Err(FdrObjectError::MaterialFile {
            path: path.to_path_buf(),
            error,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ramrod::fdr_pki::{FDR_KEY_SEED_BYTES, FDR_LEAF_KEY_DOMAIN};
    use crate::ramrod::fdr_trust::primary_trust_object_digest;

    const GROUND_TRUTH_ENV: &str = "APPLEUTILS_FDR_OBJECT_GROUND_TRUTH";

    const GROUND_TRUTH_ELEMENT_0: (usize, usize) = (0, 2884);

    const NOT_BEFORE: i64 = 1_767_225_600;
    const NOT_AFTER: i64 = 2_082_758_400;

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

    fn material() -> FdrTrustMaterial {
        let root_ca_key = FdrKeyPair::from_seed([0x21; FDR_KEY_SEED_BYTES], FDR_ROOT_CA_KEY_DOMAIN);
        let tls_root_key =
            FdrKeyPair::from_seed([0x21; FDR_KEY_SEED_BYTES], FDR_TLS_ROOT_KEY_DOMAIN);
        let root_ca_identity = CertificateIdentity {
            subject: DistinguishedName::new()
                .common_name(DEFAULT_ROOT_CA_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            serial: vec![0x4d, 0x58, 0x01],
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        };
        let tls_root_identity = CertificateIdentity {
            subject: DistinguishedName::new()
                .common_name(DEFAULT_TLS_ROOT_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            serial: vec![0x4d, 0x58, 0x02],
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
        };
        FdrTrustMaterial::issue(
            root_ca_key,
            tls_root_key,
            &root_ca_identity,
            &tls_root_identity,
        )
        .expect("the trust material must issue")
    }

    fn take(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
        let identifier = bytes[0];
        let first = bytes[1];
        let (length, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7f);
            let mut value = 0usize;
            for byte in &bytes[2..2 + count] {
                value = (value << 8) | usize::from(*byte);
            }
            (value, 2 + count)
        };
        (
            identifier,
            &bytes[header..header + length],
            &bytes[header + length..],
        )
    }

    fn shape(bytes: &[u8], depth: usize, out: &mut Vec<(usize, u8)>) {
        let mut rest = bytes;
        while !rest.is_empty() {
            let (identifier, body, tail) = take(rest);
            out.push((depth, identifier));
            if identifier & 0x20 != 0 {
                shape(body, depth + 1, out);
            }
            rest = tail;
        }
    }

    const EXPECTED_SHAPE: &[(usize, u8)] = &[
        (0, 0x30), // the object
        (1, 0x16), // secb
        (1, 0x30), // trst element
        (2, 0x16),
        (2, 0x04),
        (1, 0x30), // rssl element
        (2, 0x16),
        (2, 0x04),
        (1, 0x30), // rvok element
        (2, 0x16),
    ];

    #[test]
    fn the_object_is_one_top_level_element_covering_the_whole_buffer() {
        let material = material();
        let object = material.trust_object();
        let spans = top_level_elements(object).expect("the object must be one DER element");
        assert_eq!(spans, vec![(0, object.len())]);
    }

    #[test]
    fn the_revocation_element_carries_no_payload() {
        let material = material();
        let object = material.trust_object();
        const REVOCATION: [u8; 8] = [0x30, 0x06, 0x16, 0x04, 0x72, 0x76, 0x6f, 0x6b];
        assert_eq!(
            &object[object.len() - REVOCATION.len()..],
            &REVOCATION,
            "rvok must be the last element and carry nothing"
        );
        assert_eq!(
            object
                .windows(REVOCATION.len())
                .filter(|window| *window == REVOCATION)
                .count(),
            1,
            "rvok must appear once"
        );
    }

    #[test]
    fn no_trpk_element_is_emitted() {
        let material = material();
        assert!(
            !material
                .trust_object()
                .windows(4)
                .any(|window| window == b"trpk"),
            "trpk must not appear anywhere in the object"
        );
    }

    #[test]
    fn the_four_tags_appear_in_the_fixed_order() {
        let material = material();
        let object = material.trust_object();
        let mut found = Vec::new();
        for tag in [
            TRUST_OBJECT_TAG,
            ROOT_CA_ELEMENT_TAG,
            TLS_ROOT_ELEMENT_TAG,
            REVOCATION_ELEMENT_TAG,
        ] {
            let encoded = der::ia5_string(tag);
            let at = object
                .windows(encoded.len())
                .position(|window| window == encoded)
                .unwrap_or_else(|| panic!("{tag} must be present as an IA5String"));
            found.push((at, tag));
        }
        let mut sorted = found.clone();
        sorted.sort_by_key(|(at, _)| *at);
        assert_eq!(
            sorted, found,
            "the tags must appear in secb, trst, rssl, rvok order"
        );
    }

    #[test]
    fn the_octet_strings_hold_the_certificates_unchanged() {
        let material = material();
        let object = material.trust_object();
        let (identifier, body, rest) = take(object);
        assert_eq!(identifier, der::IDENTIFIER_SEQUENCE);
        assert!(rest.is_empty());

        let (_, _, after_secb) = take(body);
        let (trst_identifier, trst, after_trst) = take(after_secb);
        assert_eq!(trst_identifier, der::IDENTIFIER_SEQUENCE);
        let (_, _, trst_payload) = take(trst);
        let (octet_identifier, certificate, trst_tail) = take(trst_payload);
        assert_eq!(octet_identifier, der::IDENTIFIER_OCTET_STRING);
        assert!(trst_tail.is_empty());
        assert_eq!(certificate, material.root_ca_certificate());

        let (rssl_identifier, rssl, _) = take(after_trst);
        assert_eq!(rssl_identifier, der::IDENTIFIER_SEQUENCE);
        let (_, _, rssl_payload) = take(rssl);
        let (octet_identifier, certificate, rssl_tail) = take(rssl_payload);
        assert_eq!(octet_identifier, der::IDENTIFIER_OCTET_STRING);
        assert!(rssl_tail.is_empty());
        assert_eq!(certificate, material.tls_root_certificate());
    }

    #[test]
    fn the_digest_matches_the_element_walking_path() {
        let material = material();
        let (primary, element_count) =
            primary_trust_object_digest(material.trust_object()).expect("the digest is computable");
        assert_eq!(element_count, 1);
        assert_eq!(material.digest(), primary);
        assert_eq!(
            material.digest(),
            trust_object_digest(material.trust_object())
        );
    }

    #[test]
    fn the_object_is_reproducible_from_the_same_material() {
        assert_eq!(material().trust_object(), material().trust_object());
        assert_eq!(material().digest(), material().digest());
    }

    #[test]
    fn payloads_that_are_not_one_certificate_are_refused() {
        let material = material();
        let certificate = material.root_ca_certificate();

        assert!(matches!(
            build_trust_object(&[], certificate),
            Err(FdrObjectError::EmptyCertificate { which: "trst" })
        ));
        assert!(matches!(
            build_trust_object(certificate, &[]),
            Err(FdrObjectError::EmptyCertificate { which: "rssl" })
        ));
        assert!(matches!(
            build_trust_object(&[0x04, 0x01, 0x00], certificate),
            Err(FdrObjectError::CertificateNotASequence {
                which: "trst",
                identifier: 0x04
            })
        ));
        assert!(matches!(
            build_trust_object(&certificate[..certificate.len() - 1], certificate),
            Err(FdrObjectError::MalformedCertificate { which: "trst", .. })
        ));

        let mut doubled = certificate.to_vec();
        doubled.extend_from_slice(certificate);
        assert!(matches!(
            build_trust_object(&doubled, certificate),
            Err(FdrObjectError::TrailingCertificateBytes {
                which: "trst",
                elements: 2
            })
        ));
    }

    #[test]
    fn persisted_material_rebuilds_the_same_object() {
        let directory = std::env::temp_dir().join(format!(
            "appleutils-fdr-object-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&directory);

        let first = FdrTrustMaterial::load_or_generate(&directory, NOT_BEFORE, NOT_AFTER)
            .expect("the material must generate");
        let second = FdrTrustMaterial::load_or_generate(&directory, NOT_BEFORE, NOT_AFTER)
            .expect("the material must reload");
        assert_eq!(first.trust_object(), second.trust_object());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(
            first.root_ca_key().public_uncompressed(),
            second.root_ca_key().public_uncompressed()
        );
        assert_ne!(
            first.root_ca_key().public_uncompressed(),
            first.tls_root_key().public_uncompressed(),
            "the two roots must not share a key"
        );
        assert_ne!(
            first.root_ca_key().public_uncompressed(),
            FdrKeyPair::from_seed(*first.root_ca_key().seed(), FDR_LEAF_KEY_DOMAIN)
                .public_uncompressed(),
            "the leaf domain must give a different key from the same seed"
        );

        let serial = directory.join(ROOT_CA_SERIAL_FILE_NAME);
        fs::write(&serial, [0u8; MAXIMUM_SERIAL_BYTES + 1]).expect("the serial must overwrite");
        assert!(matches!(
            FdrTrustMaterial::load_or_generate(&directory, NOT_BEFORE, NOT_AFTER),
            Err(FdrObjectError::SerialLength { length: 21, .. })
        ));

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_shape_matches_the_real_element_zero() {
        let material = material();
        let mut mine = Vec::new();
        shape(material.trust_object(), 0, &mut mine);
        assert_eq!(mine, EXPECTED_SHAPE);

        let Some(bytes) = read_ground_truth() else {
            return;
        };
        let spans = top_level_elements(&bytes).expect("the artifact must split");
        assert_eq!(spans[0], GROUND_TRUTH_ELEMENT_0);
        let element = &bytes[GROUND_TRUTH_ELEMENT_0.0..GROUND_TRUTH_ELEMENT_0.1];

        let mut theirs = Vec::new();
        shape(element, 0, &mut theirs);
        assert_eq!(
            mine, theirs,
            "the local object must have the artifact's tag sequence and nesting depth"
        );

        for tag in [
            TRUST_OBJECT_TAG,
            ROOT_CA_ELEMENT_TAG,
            TLS_ROOT_ELEMENT_TAG,
            REVOCATION_ELEMENT_TAG,
        ] {
            let encoded = der::ia5_string(tag);
            assert!(element.windows(encoded.len()).any(|w| w == encoded));
            assert!(
                material
                    .trust_object()
                    .windows(encoded.len())
                    .any(|w| w == encoded)
            );
        }
        assert_eq!(
            &element[element.len() - 8..],
            &[0x30, 0x06, 0x16, 0x04, 0x72, 0x76, 0x6f, 0x6b]
        );
    }
}
