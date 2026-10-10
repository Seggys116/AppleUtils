use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{P256PrivateKey, Sha256};

use super::der;
use super::fdr_material_format::{
    FDR_MATERIAL_CREATION_FILE_NAME, FDR_MATERIAL_FILE_NAME, FdrAuthorityDescriptor,
    FdrMaterialCreationInputs, FdrMaterialCreationRecord, FdrMaterialDescriptor,
    FdrMaterialFormatError,
};
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
    MaterialFormat(FdrMaterialFormatError),
    UnrecordedMaterial {
        path: PathBuf,
    },
    PortableRefusal {
        name: &'static str,
        detail: String,
    },
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
            Self::MaterialFormat(error) => write!(f, "{error}"),
            Self::UnrecordedMaterial { path } => write!(
                f,
                "fdr-material-unrecorded-existing: {} requires explicit owner-profile adoption",
                path.display()
            ),
            Self::PortableRefusal { name, detail } => write!(f, "fdr-material-{name}: {detail}"),
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

impl From<FdrMaterialFormatError> for FdrObjectError {
    fn from(error: FdrMaterialFormatError) -> Self {
        Self::MaterialFormat(error)
    }
}

fn portable_refusal(name: &'static str, detail: impl std::fmt::Display) -> FdrObjectError {
    FdrObjectError::PortableRefusal {
        name,
        detail: detail.to_string(),
    }
}

pub(crate) fn sdk_material_descriptor(not_before: i64, not_after: i64) -> FdrMaterialDescriptor {
    FdrMaterialDescriptor::new(
        FdrAuthorityDescriptor::new(
            FDR_ROOT_CA_KEY_DOMAIN,
            &DistinguishedName::new()
                .common_name(DEFAULT_ROOT_CA_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            not_before,
            not_after,
        ),
        FdrAuthorityDescriptor::new(
            FDR_TLS_ROOT_KEY_DOMAIN,
            &DistinguishedName::new()
                .common_name(DEFAULT_TLS_ROOT_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            not_before,
            not_after,
        ),
    )
}

fn read_portable_serial(directory: &Path, filename: &str) -> Result<Vec<u8>, FdrObjectError> {
    let path = directory.join(filename);
    let serial = fs::read(&path).map_err(|error| {
        portable_refusal("serial-unreadable", format!("{}: {error}", path.display()))
    })?;
    if serial.is_empty() || serial.len() > MAXIMUM_SERIAL_BYTES {
        return Err(portable_refusal(
            "serial-invalid",
            format!("{} holds {} bytes", path.display(), serial.len()),
        ));
    }
    Ok(serial)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreationPublication {
    Record,
    RootCaSeed,
    TlsRootSeed,
    RootCaSerial,
    TlsRootSerial,
    Descriptor,
}

impl CreationPublication {
    fn file_name(self) -> &'static str {
        match self {
            Self::Record => FDR_MATERIAL_CREATION_FILE_NAME,
            Self::RootCaSeed => ROOT_CA_SEED_FILE_NAME,
            Self::TlsRootSeed => TLS_ROOT_SEED_FILE_NAME,
            Self::RootCaSerial => ROOT_CA_SERIAL_FILE_NAME,
            Self::TlsRootSerial => TLS_ROOT_SERIAL_FILE_NAME,
            Self::Descriptor => FDR_MATERIAL_FILE_NAME,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationBoundary {
    Before,
    After,
}

struct ValidatedCreation {
    inputs: FdrMaterialCreationInputs,
    material: FdrTrustMaterial,
}

fn validate_creation(
    record: &FdrMaterialCreationRecord,
) -> Result<ValidatedCreation, FdrObjectError> {
    let inputs = record.inputs()?;
    let root_domain = inputs.descriptor.root_ca.key_derivation_domain("rootCa")?;
    let tls_domain = inputs
        .descriptor
        .tls_root
        .key_derivation_domain("tlsRoot")?;
    let root_identity = CertificateIdentity {
        subject: inputs.descriptor.root_ca.subject_name("rootCa")?,
        serial: inputs.root_ca_serial.clone(),
        not_before: inputs.descriptor.root_ca.not_before,
        not_after: inputs.descriptor.root_ca.not_after,
    };
    let tls_identity = CertificateIdentity {
        subject: inputs.descriptor.tls_root.subject_name("tlsRoot")?,
        serial: inputs.tls_root_serial.clone(),
        not_before: inputs.descriptor.tls_root.not_before,
        not_after: inputs.descriptor.tls_root.not_after,
    };
    let material = FdrTrustMaterial::issue(
        FdrKeyPair::from_seed(inputs.root_ca_seed, &root_domain),
        FdrKeyPair::from_seed(inputs.tls_root_seed, &tls_domain),
        &root_identity,
        &tls_identity,
    )
    .map_err(|_| {
        portable_refusal(
            "creation-invalid",
            "recorded authority identity cannot be issued",
        )
    })?;
    Ok(ValidatedCreation { inputs, material })
}

fn creation_file_matches(path: &Path, expected: &[u8]) -> Result<bool, FdrObjectError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(portable_refusal(
                "creation-unreadable",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    if !metadata.file_type().is_file() {
        return Err(portable_refusal(
            "creation-conflict",
            format!("{} must be a regular authority member", path.display()),
        ));
    }
    let actual = fs::read(path).map_err(|error| {
        portable_refusal(
            "creation-unreadable",
            format!("{}: {error}", path.display()),
        )
    })?;
    if actual != expected {
        return Err(portable_refusal(
            "creation-conflict",
            format!(
                "{} differs from the selected creation record",
                path.display()
            ),
        ));
    }
    Ok(true)
}

fn publish_creation_file(
    directory: &Path,
    stage: CreationPublication,
    bytes: &[u8],
    publisher: &mut impl FnMut(PublicationBoundary, CreationPublication) -> Result<(), FdrObjectError>,
) -> Result<(), FdrObjectError> {
    use std::io::Write as _;
    publisher(PublicationBoundary::Before, stage)?;
    let path = directory.join(stage.file_name());
    if !creation_file_matches(&path, bytes)? {
        let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
            portable_refusal(
                "creation-unreadable",
                format!("{}: {error}", path.display()),
            )
        })?;
        temporary
            .write_all(bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|error| {
                portable_refusal(
                    "creation-unreadable",
                    format!("{}: {error}", path.display()),
                )
            })?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(portable_refusal(
                    "creation-unreadable",
                    format!("{}: {}", path.display(), error.error),
                ));
            }
        }
        if !creation_file_matches(&path, bytes)? {
            return Err(portable_refusal(
                "creation-unreadable",
                format!("{} could not be read after publication", path.display()),
            ));
        }
    }
    publisher(PublicationBoundary::After, stage)
}

fn refuse_pending_creation(directory: &Path) -> Result<(), FdrObjectError> {
    let path = directory.join(FDR_MATERIAL_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(FdrMaterialFormatError::Read { path, error }.into()),
    }
    if FdrMaterialCreationRecord::load(directory)?.is_some() {
        return Err(portable_refusal(
            "creation-conflict",
            "explicit legacy adoption cannot replace a pending creation transaction",
        ));
    }
    Ok(())
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
    pub fn load_from_directory(directory: &Path) -> Result<Self, FdrObjectError> {
        let descriptor = FdrMaterialDescriptor::load(directory)?;
        Self::load_with_descriptor(directory, &descriptor)
    }

    pub(crate) fn load_with_descriptor(
        directory: &Path,
        descriptor: &FdrMaterialDescriptor,
    ) -> Result<Self, FdrObjectError> {
        descriptor.validate()?;
        let root_domain = descriptor.root_ca.key_derivation_domain("rootCa")?;
        let tls_domain = descriptor.tls_root.key_derivation_domain("tlsRoot")?;
        let root_key = FdrKeyPair::load(&directory.join(ROOT_CA_SEED_FILE_NAME), &root_domain)
            .map_err(|error| portable_refusal("root-key-unreadable", error))?;
        let tls_key = FdrKeyPair::load(&directory.join(TLS_ROOT_SEED_FILE_NAME), &tls_domain)
            .map_err(|error| portable_refusal("tls-key-unreadable", error))?;
        let root_identity = CertificateIdentity {
            subject: descriptor.root_ca.subject_name("rootCa")?,
            serial: read_portable_serial(directory, ROOT_CA_SERIAL_FILE_NAME)?,
            not_before: descriptor.root_ca.not_before,
            not_after: descriptor.root_ca.not_after,
        };
        let tls_identity = CertificateIdentity {
            subject: descriptor.tls_root.subject_name("tlsRoot")?,
            serial: read_portable_serial(directory, TLS_ROOT_SERIAL_FILE_NAME)?,
            not_before: descriptor.tls_root.not_before,
            not_after: descriptor.tls_root.not_after,
        };
        Self::issue(root_key, tls_key, &root_identity, &tls_identity)
            .map_err(|error| portable_refusal("identity-invalid", error))
    }

    pub fn adopt_legacy_material(
        directory: &Path,
        descriptor: &FdrMaterialDescriptor,
        expected_trust_object: &[u8],
    ) -> Result<Self, FdrObjectError> {
        refuse_pending_creation(directory)?;
        let material = Self::load_with_descriptor(directory, descriptor)?;
        if material.trust_object() != expected_trust_object {
            return Err(portable_refusal(
                "legacy-object-mismatch",
                "the explicit owner profile does not reproduce the expected trust object",
            ));
        }
        refuse_pending_creation(directory)?;
        descriptor.write_new(directory)?;
        Ok(material)
    }

    pub fn load_or_generate_portable(
        directory: &Path,
        not_before: i64,
        not_after: i64,
    ) -> Result<Self, FdrObjectError> {
        Self::load_or_generate_portable_with_publisher(
            directory,
            not_before,
            not_after,
            &mut |_, _| Ok(()),
        )
    }

    fn load_committed_portable(
        directory: &Path,
        not_before: i64,
        not_after: i64,
    ) -> Result<Option<Self>, FdrObjectError> {
        let path = directory.join(FDR_MATERIAL_FILE_NAME);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let descriptor = FdrMaterialDescriptor::load(directory)?;
                descriptor.require_window(not_before, not_after)?;
                Self::load_with_descriptor(directory, &descriptor).map(Some)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(FdrMaterialFormatError::Read { path, error }.into()),
        }
    }

    fn resume_creation(
        directory: &Path,
        record: &FdrMaterialCreationRecord,
        not_before: i64,
        not_after: i64,
        publisher: &mut impl FnMut(
            PublicationBoundary,
            CreationPublication,
        ) -> Result<(), FdrObjectError>,
    ) -> Result<Self, FdrObjectError> {
        let selected = validate_creation(record)?;
        selected
            .inputs
            .descriptor
            .require_window(not_before, not_after)?;
        let files: [(CreationPublication, &[u8]); 5] = [
            (
                CreationPublication::RootCaSeed,
                &selected.inputs.root_ca_seed,
            ),
            (
                CreationPublication::TlsRootSeed,
                &selected.inputs.tls_root_seed,
            ),
            (
                CreationPublication::RootCaSerial,
                &selected.inputs.root_ca_serial,
            ),
            (
                CreationPublication::TlsRootSerial,
                &selected.inputs.tls_root_serial,
            ),
            (
                CreationPublication::Descriptor,
                record.descriptor_json.as_bytes(),
            ),
        ];
        for (stage, bytes) in &files {
            creation_file_matches(&directory.join(stage.file_name()), bytes)?;
        }
        for (stage, bytes) in files {
            publish_creation_file(directory, stage, bytes, publisher)?;
        }
        let loaded = Self::load_from_directory(directory)?;
        if loaded.trust_object() != selected.material.trust_object() {
            return Err(portable_refusal(
                "creation-conflict",
                "published authority does not reproduce the selected trust object",
            ));
        }
        Ok(loaded)
    }

    fn load_or_generate_portable_with_publisher(
        directory: &Path,
        not_before: i64,
        not_after: i64,
        publisher: &mut impl FnMut(
            PublicationBoundary,
            CreationPublication,
        ) -> Result<(), FdrObjectError>,
    ) -> Result<Self, FdrObjectError> {
        if let Some(committed) = Self::load_committed_portable(directory, not_before, not_after)? {
            return Ok(committed);
        }
        if let Some(record) = FdrMaterialCreationRecord::load(directory)? {
            return Self::resume_creation(directory, &record, not_before, not_after, publisher);
        }
        for filename in [
            ROOT_CA_SEED_FILE_NAME,
            TLS_ROOT_SEED_FILE_NAME,
            ROOT_CA_SERIAL_FILE_NAME,
            TLS_ROOT_SERIAL_FILE_NAME,
        ] {
            let path = directory.join(filename);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    if let Some(committed) =
                        Self::load_committed_portable(directory, not_before, not_after)?
                    {
                        return Ok(committed);
                    }
                    if let Some(record) = FdrMaterialCreationRecord::load(directory)? {
                        return Self::resume_creation(
                            directory, &record, not_before, not_after, publisher,
                        );
                    }
                    return Err(FdrObjectError::UnrecordedMaterial { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(portable_refusal(
                        "creation-unreadable",
                        format!("{}: {error}", path.display()),
                    ));
                }
            }
        }
        let descriptor = sdk_material_descriptor(not_before, not_after);
        descriptor.validate()?;
        let root_key = FdrKeyPair::generate(FDR_ROOT_CA_KEY_DOMAIN)?;
        let tls_key = FdrKeyPair::generate(FDR_TLS_ROOT_KEY_DOMAIN)?;
        let candidate = FdrMaterialCreationRecord::new(
            &descriptor,
            root_key.seed(),
            tls_key.seed(),
            &random_serial()?,
            &random_serial()?,
        )?;
        validate_creation(&candidate)?;
        fs::create_dir_all(directory).map_err(|error| {
            portable_refusal(
                "creation-unreadable",
                format!("{}: {error}", directory.display()),
            )
        })?;
        if let Some(committed) = Self::load_committed_portable(directory, not_before, not_after)? {
            return Ok(committed);
        }
        publisher(PublicationBoundary::Before, CreationPublication::Record)?;
        let record = if candidate.publish_new(directory)? {
            candidate
        } else {
            FdrMaterialCreationRecord::load(directory)?.ok_or_else(|| {
                portable_refusal(
                    "creation-unreadable",
                    "the competing creator's record could not be read",
                )
            })?
        };
        validate_creation(&record)?;
        publisher(PublicationBoundary::After, CreationPublication::Record)?;
        Self::resume_creation(directory, &record, not_before, not_after, publisher)
    }

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

    fn portable_snapshot(directory: &Path) -> Vec<Vec<u8>> {
        [
            ROOT_CA_SEED_FILE_NAME,
            TLS_ROOT_SEED_FILE_NAME,
            ROOT_CA_SERIAL_FILE_NAME,
            TLS_ROOT_SERIAL_FILE_NAME,
            FDR_MATERIAL_FILE_NAME,
        ]
        .iter()
        .map(|name| fs::read(directory.join(name)).unwrap())
        .collect()
    }

    fn legacy_snapshot(directory: &Path) -> Vec<Vec<u8>> {
        [
            ROOT_CA_SEED_FILE_NAME,
            TLS_ROOT_SEED_FILE_NAME,
            ROOT_CA_SERIAL_FILE_NAME,
            TLS_ROOT_SERIAL_FILE_NAME,
        ]
        .iter()
        .map(|name| fs::read(directory.join(name)).unwrap())
        .collect()
    }

    #[test]
    fn portable_sdk_material_retains_identity_and_readonly_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let expected =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .unwrap();
        let before = portable_snapshot(directory.path());
        let loaded = FdrTrustMaterial::load_from_directory(directory.path()).unwrap();
        assert_eq!(
            loaded.root_ca_key().public_uncompressed(),
            expected.root_ca_key().public_uncompressed()
        );
        assert_eq!(loaded.root_ca_certificate(), expected.root_ca_certificate());
        assert_eq!(
            loaded.tls_root_certificate(),
            expected.tls_root_certificate()
        );
        assert_eq!(loaded.trust_object(), expected.trust_object());
        assert_eq!(loaded.digest(), expected.digest());
        assert_eq!(portable_snapshot(directory.path()), before);
        let sdk =
            FdrTrustMaterial::load_or_generate(directory.path(), NOT_BEFORE, NOT_AFTER).unwrap();
        assert_eq!(loaded.trust_object(), sdk.trust_object());
        assert_eq!(
            FdrMaterialDescriptor::load(directory.path()).unwrap(),
            sdk_material_descriptor(NOT_BEFORE, NOT_AFTER)
        );
    }

    #[test]
    fn readonly_material_preserves_the_recorded_authority_profile() {
        use super::super::fdr_pki::NameAttribute;
        let directory = tempfile::tempdir().unwrap();
        let root_domain = b"fixture owner root derivation\0";
        let tls_domain = b"fixture owner TLS derivation\xff";
        let root_subject = DistinguishedName::new()
            .organization("fixture owner")
            .common_name("fixture sealing root")
            .with(NameAttribute::StateOrProvinceName, "fixture state");
        let tls_subject = DistinguishedName::new()
            .common_name("fixture TLS root")
            .organization("fixture owner");
        let descriptor = FdrMaterialDescriptor::new(
            FdrAuthorityDescriptor::new(root_domain, &root_subject, NOT_BEFORE, NOT_AFTER),
            FdrAuthorityDescriptor::new(tls_domain, &tls_subject, NOT_BEFORE + 1, NOT_AFTER + 2),
        );
        let root_seed = [0x26; FDR_KEY_SEED_BYTES];
        let tls_seed = [0x72; FDR_KEY_SEED_BYTES];
        let root_serial = vec![0x13, 0x27];
        let tls_serial = vec![0x21, 0x42];
        fs::write(directory.path().join(ROOT_CA_SEED_FILE_NAME), root_seed).unwrap();
        fs::write(directory.path().join(TLS_ROOT_SEED_FILE_NAME), tls_seed).unwrap();
        fs::write(
            directory.path().join(ROOT_CA_SERIAL_FILE_NAME),
            &root_serial,
        )
        .unwrap();
        fs::write(
            directory.path().join(TLS_ROOT_SERIAL_FILE_NAME),
            &tls_serial,
        )
        .unwrap();
        descriptor.write_new(directory.path()).unwrap();
        let expected = FdrTrustMaterial::issue(
            FdrKeyPair::from_seed(root_seed, root_domain),
            FdrKeyPair::from_seed(tls_seed, tls_domain),
            &CertificateIdentity {
                subject: root_subject.clone(),
                serial: root_serial,
                not_before: NOT_BEFORE,
                not_after: NOT_AFTER,
            },
            &CertificateIdentity {
                subject: tls_subject,
                serial: tls_serial,
                not_before: NOT_BEFORE + 1,
                not_after: NOT_AFTER + 2,
            },
        )
        .unwrap();
        let before = portable_snapshot(directory.path());
        let loaded = FdrTrustMaterial::load_from_directory(directory.path()).unwrap();
        assert_eq!(
            loaded.root_ca_subject().attributes(),
            root_subject.attributes()
        );
        assert_eq!(
            loaded.root_ca_key().public_uncompressed(),
            expected.root_ca_key().public_uncompressed()
        );
        assert_eq!(
            loaded.tls_root_key().public_uncompressed(),
            expected.tls_root_key().public_uncompressed()
        );
        assert_eq!(loaded.root_ca_certificate(), expected.root_ca_certificate());
        assert_eq!(
            loaded.tls_root_certificate(),
            expected.tls_root_certificate()
        );
        assert_eq!(loaded.trust_object(), expected.trust_object());
        assert_eq!(loaded.digest(), expected.digest());
        assert_eq!(portable_snapshot(directory.path()), before);
    }

    #[test]
    fn portable_reload_preserves_recorded_profile_and_refuses_window_contradictions() {
        let directory = tempfile::tempdir().unwrap();
        let expected =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .unwrap();
        let before = portable_snapshot(directory.path());
        let loaded =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .unwrap();
        assert_eq!(loaded.trust_object(), expected.trust_object());
        let error = FdrTrustMaterial::load_or_generate_portable(
            directory.path(),
            NOT_BEFORE + 1,
            NOT_AFTER,
        )
        .err()
        .expect("an explicit window contradicting the descriptor must be refused");
        assert!(
            error.to_string().contains("fdr-material-window-mismatch"),
            "{error}"
        );
        assert_eq!(portable_snapshot(directory.path()), before);
    }

    #[test]
    fn explicit_legacy_adoption_preserves_existing_material_files_and_object() {
        let directory = tempfile::tempdir().unwrap();
        let expected =
            FdrTrustMaterial::load_or_generate(directory.path(), NOT_BEFORE, NOT_AFTER).unwrap();
        let before = legacy_snapshot(directory.path());
        let descriptor = sdk_material_descriptor(NOT_BEFORE, NOT_AFTER);
        let adopted = FdrTrustMaterial::adopt_legacy_material(
            directory.path(),
            &descriptor,
            expected.trust_object(),
        )
        .unwrap();
        assert_eq!(adopted.trust_object(), expected.trust_object());
        assert_eq!(legacy_snapshot(directory.path()), before);
        assert_eq!(
            FdrMaterialDescriptor::load(directory.path()).unwrap(),
            descriptor
        );
        let loaded = FdrTrustMaterial::load_from_directory(directory.path()).unwrap();
        assert_eq!(loaded.trust_object(), expected.trust_object());
        assert_eq!(loaded.digest(), expected.digest());
    }

    #[test]
    fn legacy_adoption_requires_the_expected_exact_object() {
        let directory = tempfile::tempdir().unwrap();
        let expected =
            FdrTrustMaterial::load_or_generate(directory.path(), NOT_BEFORE, NOT_AFTER).unwrap();
        let before = legacy_snapshot(directory.path());
        let mut mismatched = expected.trust_object().to_vec();
        mismatched[0] ^= 1;
        let error = FdrTrustMaterial::adopt_legacy_material(
            directory.path(),
            &sdk_material_descriptor(NOT_BEFORE, NOT_AFTER),
            &mismatched,
        )
        .err()
        .expect("adoption must prove the caller's exact trust object");
        assert!(
            error
                .to_string()
                .contains("fdr-material-legacy-object-mismatch"),
            "{error}"
        );
        assert_eq!(legacy_snapshot(directory.path()), before);
    }

    #[test]
    fn incomplete_or_unrecorded_portable_material_is_refused_by_name() {
        let directory = tempfile::tempdir().unwrap();
        let error = FdrTrustMaterial::load_from_directory(directory.path())
            .err()
            .expect("consumption requires a declared authority profile");
        assert!(
            error
                .to_string()
                .contains("fdr-material-metadata-unreadable"),
            "{error}"
        );
        let seed = [0x31; FDR_KEY_SEED_BYTES];
        fs::write(directory.path().join(ROOT_CA_SEED_FILE_NAME), seed).unwrap();
        let error =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .err()
                .expect("existing material requires an explicit owner profile");
        assert!(
            error
                .to_string()
                .contains("fdr-material-unrecorded-existing"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.path().join(ROOT_CA_SEED_FILE_NAME)).unwrap(),
            seed
        );
        let descriptor = sdk_material_descriptor(NOT_BEFORE, NOT_AFTER);
        descriptor.write_new(directory.path()).unwrap();
        let error = FdrTrustMaterial::load_from_directory(directory.path())
            .err()
            .expect("read-only consumption requires both existing keys");
        assert!(
            error
                .to_string()
                .contains("fdr-material-tls-key-unreadable"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.path().join(ROOT_CA_SEED_FILE_NAME)).unwrap(),
            seed
        );
    }

    fn selected_creation_record() -> FdrMaterialCreationRecord {
        let root_subject = DistinguishedName::new()
            .organization("fixture owner")
            .common_name("fixture authority root");
        let tls_subject = DistinguishedName::new()
            .common_name("fixture authority TLS root")
            .organization("fixture owner");
        let descriptor = FdrMaterialDescriptor::new(
            FdrAuthorityDescriptor::new(
                b"fixture root domain\0",
                &root_subject,
                NOT_BEFORE,
                NOT_AFTER,
            ),
            FdrAuthorityDescriptor::new(
                b"fixture TLS domain\xff",
                &tls_subject,
                NOT_BEFORE,
                NOT_AFTER,
            ),
        );
        let mut record = FdrMaterialCreationRecord::new(
            &descriptor,
            &[0x46; FDR_KEY_SEED_BYTES],
            &[0x54; FDR_KEY_SEED_BYTES],
            &[0x01, 0x23],
            &[0x04, 0x56],
        )
        .unwrap();
        record.descriptor_json = format!("\n{}\n", record.descriptor_json);
        validate_creation(&record).unwrap();
        record
    }

    fn assert_selected_authority(actual: &FdrTrustMaterial, expected: &FdrTrustMaterial) {
        assert_eq!(
            actual.root_ca_key().public_uncompressed(),
            expected.root_ca_key().public_uncompressed()
        );
        assert_eq!(
            actual.tls_root_key().public_uncompressed(),
            expected.tls_root_key().public_uncompressed()
        );
        assert_eq!(actual.root_ca_certificate(), expected.root_ca_certificate());
        assert_eq!(
            actual.tls_root_certificate(),
            expected.tls_root_certificate()
        );
        assert_eq!(actual.trust_object(), expected.trust_object());
        assert_eq!(actual.digest(), expected.digest());
    }

    #[test]
    fn portable_creation_retries_each_reached_publication_boundary_with_exact_authority() {
        for stage in [
            CreationPublication::Record,
            CreationPublication::RootCaSeed,
            CreationPublication::TlsRootSeed,
            CreationPublication::RootCaSerial,
            CreationPublication::TlsRootSerial,
            CreationPublication::Descriptor,
        ] {
            for boundary in [PublicationBoundary::Before, PublicationBoundary::After] {
                let directory = tempfile::tempdir().unwrap();
                let mut reached = Vec::new();
                let error = FdrTrustMaterial::load_or_generate_portable_with_publisher(
                    directory.path(),
                    NOT_BEFORE,
                    NOT_AFTER,
                    &mut |current_boundary, current_stage| {
                        reached.push((current_boundary, current_stage));
                        if (current_boundary, current_stage) == (boundary, stage) {
                            return Err(portable_refusal(
                                "creation-unreadable",
                                "injected process interruption at a reached publication boundary",
                            ));
                        }
                        Ok(())
                    },
                )
                .err()
                .expect("the reached publication boundary must inject its failure");
                assert!(
                    reached.contains(&(boundary, stage)),
                    "the requested boundary must have executed"
                );
                assert!(
                    error
                        .to_string()
                        .contains("fdr-material-creation-unreadable"),
                    "{error}"
                );
                let selected_before_retry = FdrMaterialCreationRecord::load(directory.path())
                    .unwrap()
                    .map(|record| validate_creation(&record).unwrap().material);
                let recovered = FdrTrustMaterial::load_or_generate_portable(
                    directory.path(),
                    NOT_BEFORE,
                    NOT_AFTER,
                )
                .unwrap();
                if let Some(expected) = selected_before_retry {
                    assert_selected_authority(&recovered, &expected);
                }
                let record = FdrMaterialCreationRecord::load(directory.path())
                    .unwrap()
                    .expect("successful creation retains its authority record");
                let expected = validate_creation(&record).unwrap().material;
                assert_selected_authority(&recovered, &expected);
                let record_bytes =
                    fs::read(directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME)).unwrap();
                let stable = FdrTrustMaterial::load_from_directory(directory.path()).unwrap();
                assert_selected_authority(&stable, &expected);
                assert!(
                    fs::read(directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME)).unwrap()
                        == record_bytes,
                    "read-only consumption must retain the exact selected record"
                );
                assert_eq!(
                    fs::read(directory.path().join(FDR_MATERIAL_FILE_NAME)).unwrap(),
                    record.descriptor_json.as_bytes()
                );
            }
        }
    }

    #[test]
    fn concurrent_portable_creators_elect_one_exact_authority() {
        let directory = tempfile::tempdir().unwrap();
        let election = std::sync::Barrier::new(2);
        let (first, second) = std::thread::scope(|scope| {
            let create = || {
                let mut record_reached = false;
                let material = FdrTrustMaterial::load_or_generate_portable_with_publisher(
                    directory.path(),
                    NOT_BEFORE,
                    NOT_AFTER,
                    &mut |boundary, stage| {
                        if (boundary, stage)
                            == (PublicationBoundary::Before, CreationPublication::Record)
                        {
                            record_reached = true;
                            election.wait();
                        }
                        Ok(())
                    },
                )
                .unwrap();
                assert!(
                    record_reached,
                    "each competing creator must reach authority election"
                );
                material
            };
            let first = scope.spawn(create);
            let second = scope.spawn(create);
            (first.join().unwrap(), second.join().unwrap())
        });
        assert_selected_authority(&first, &second);
        let record = FdrMaterialCreationRecord::load(directory.path())
            .unwrap()
            .expect("a creator must publish the election record");
        let expected = validate_creation(&record).unwrap().material;
        assert_selected_authority(&first, &expected);
        assert_selected_authority(
            &FdrTrustMaterial::load_from_directory(directory.path()).unwrap(),
            &expected,
        );
    }

    #[test]
    fn concurrent_window_requests_preserve_the_elected_authority_and_name_the_contradiction() {
        let directory = tempfile::tempdir().unwrap();
        let election = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let create = |not_before| {
                let mut record_reached = false;
                let result = FdrTrustMaterial::load_or_generate_portable_with_publisher(
                    directory.path(),
                    not_before,
                    NOT_AFTER,
                    &mut |boundary, stage| {
                        if (boundary, stage)
                            == (PublicationBoundary::Before, CreationPublication::Record)
                        {
                            record_reached = true;
                            election.wait();
                        }
                        Ok(())
                    },
                );
                assert!(record_reached, "both window requests must reach election");
                result
            };
            let first = scope.spawn(move || create(NOT_BEFORE));
            let second = scope.spawn(move || create(NOT_BEFORE + 1));
            [first.join().unwrap(), second.join().unwrap()]
        });
        let mut accepted = Vec::new();
        let mut refusals = Vec::new();
        for result in results {
            match result {
                Ok(material) => accepted.push(material),
                Err(error) => refusals.push(error),
            }
        }
        assert_eq!(accepted.len(), 1);
        assert_eq!(refusals.len(), 1);
        assert!(
            refusals[0]
                .to_string()
                .contains("fdr-material-window-mismatch")
        );
        let record = FdrMaterialCreationRecord::load(directory.path())
            .unwrap()
            .expect("the elected authority is retained");
        assert_selected_authority(&accepted[0], &validate_creation(&record).unwrap().material);
    }

    #[test]
    fn pending_foreign_profile_recovery_preserves_exact_descriptor_text_and_authority() {
        let directory = tempfile::tempdir().unwrap();
        let record = selected_creation_record();
        let expected = validate_creation(&record).unwrap().material;
        assert!(record.publish_new(directory.path()).unwrap());
        let recovered =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .unwrap();
        assert_selected_authority(&recovered, &expected);
        assert_eq!(
            fs::read(directory.path().join(FDR_MATERIAL_FILE_NAME)).unwrap(),
            record.descriptor_json.as_bytes()
        );
        assert_selected_authority(
            &FdrTrustMaterial::load_from_directory(directory.path()).unwrap(),
            &expected,
        );
    }

    #[test]
    fn creation_replay_conflicts_and_unreadable_records_are_named() {
        for directory_conflict in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let record = selected_creation_record();
            assert!(record.publish_new(directory.path()).unwrap());
            let member = directory.path().join(ROOT_CA_SEED_FILE_NAME);
            if directory_conflict {
                fs::create_dir(&member).unwrap();
            } else {
                fs::write(&member, [0x71; FDR_KEY_SEED_BYTES]).unwrap();
            }
            let error = FdrTrustMaterial::load_or_generate_portable(
                directory.path(),
                NOT_BEFORE,
                NOT_AFTER,
            )
            .err()
            .expect("a conflicting authority member must be named");
            assert!(
                error.to_string().contains("fdr-material-creation-conflict"),
                "{error}"
            );
            assert!(
                error.to_string().contains(ROOT_CA_SEED_FILE_NAME),
                "{error}"
            );
        }
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME)).unwrap();
        let error =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .err()
                .expect("a nonregular creation record must be refused");
        assert!(
            error
                .to_string()
                .contains("fdr-material-creation-unreadable"),
            "{error}"
        );
    }

    #[test]
    fn concurrent_descriptor_publication_requires_the_selected_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let record = selected_creation_record();
        assert!(record.publish_new(directory.path()).unwrap());
        let mut other = sdk_material_descriptor(NOT_BEFORE, NOT_AFTER);
        other.root_ca.subject[0].value = "another declared owner".to_string();
        let other_bytes = serde_json::to_vec_pretty(&other).unwrap();
        let mut publication_reached = false;
        let error = FdrTrustMaterial::load_or_generate_portable_with_publisher(
            directory.path(),
            NOT_BEFORE,
            NOT_AFTER,
            &mut |boundary, stage| {
                if (boundary, stage)
                    == (PublicationBoundary::Before, CreationPublication::Descriptor)
                {
                    publication_reached = true;
                    fs::write(directory.path().join(FDR_MATERIAL_FILE_NAME), &other_bytes).unwrap();
                }
                Ok(())
            },
        )
        .err()
        .expect("concurrent descriptor bytes must agree with the selected authority");
        assert!(
            publication_reached,
            "descriptor publication must be reached"
        );
        assert!(
            error.to_string().contains("fdr-material-creation-conflict"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.path().join(FDR_MATERIAL_FILE_NAME)).unwrap(),
            other_bytes
        );
    }

    #[test]
    fn damaged_committed_authority_returns_its_named_read_refusal() {
        let directory = tempfile::tempdir().unwrap();
        FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
            .unwrap();
        let record_bytes =
            fs::read(directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME)).unwrap();
        let members = legacy_snapshot(directory.path());
        fs::write(directory.path().join(FDR_MATERIAL_FILE_NAME), b"{").unwrap();
        let error =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .err()
                .expect("the committed descriptor remains the authority");
        assert!(
            error.to_string().contains("fdr-material-metadata-invalid"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.path().join(FDR_MATERIAL_FILE_NAME)).unwrap(),
            b"{"
        );
        assert!(
            legacy_snapshot(directory.path()) == members,
            "existing authority members retain their exact bytes"
        );
        assert!(
            fs::read(directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME)).unwrap()
                == record_bytes,
            "the selected private record retains its exact bytes"
        );
    }

    #[test]
    fn pending_creation_refuses_explicit_legacy_adoption() {
        let directory = tempfile::tempdir().unwrap();
        let legacy =
            FdrTrustMaterial::load_or_generate(directory.path(), NOT_BEFORE, NOT_AFTER).unwrap();
        let before = legacy_snapshot(directory.path());
        let record = selected_creation_record();
        assert!(record.publish_new(directory.path()).unwrap());
        let error = FdrTrustMaterial::adopt_legacy_material(
            directory.path(),
            &sdk_material_descriptor(NOT_BEFORE, NOT_AFTER),
            legacy.trust_object(),
        )
        .err()
        .expect("pending authority election must be handled by its producer");
        assert!(
            error.to_string().contains("fdr-material-creation-conflict"),
            "{error}"
        );
        assert!(
            legacy_snapshot(directory.path()) == before,
            "legacy authority bytes are preserved"
        );
        let retained = FdrMaterialCreationRecord::load(directory.path())
            .unwrap()
            .expect("the selected record is retained");
        assert_eq!(retained.descriptor_json, record.descriptor_json);
    }

    #[test]
    fn malformed_and_unissuable_creation_records_are_refused_by_name() {
        let record = selected_creation_record();
        let original = serde_json::to_value(&record).unwrap();
        for (field, value) in [
            ("creationVersion", serde_json::json!(2)),
            ("rootCaSeedHex", serde_json::json!("41".repeat(31))),
            ("tlsRootSeedHex", serde_json::json!("+f".repeat(32))),
            (
                "rootCaSerialHex",
                serde_json::json!("01".repeat(MAXIMUM_SERIAL_BYTES + 1)),
            ),
            ("tlsRootSerialHex", serde_json::json!("00")),
            ("descriptorJson", serde_json::json!("{}")),
            ("undeclared", serde_json::json!(true)),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut malformed = original.clone();
            malformed[field] = value;
            fs::write(
                directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME),
                serde_json::to_vec(&malformed).unwrap(),
            )
            .unwrap();
            let error = FdrTrustMaterial::load_or_generate_portable(
                directory.path(),
                NOT_BEFORE,
                NOT_AFTER,
            )
            .err()
            .expect("creation metadata must be validated before replay");
            assert!(
                error.to_string().contains("fdr-material-creation-invalid"),
                "{error}"
            );
        }
        let directory = tempfile::tempdir().unwrap();
        let mut malformed = original;
        let mut descriptor = sdk_material_descriptor(NOT_BEFORE, NOT_AFTER);
        descriptor.root_ca.subject[0].value = "Apple".to_string();
        malformed["descriptorJson"] =
            serde_json::json!(serde_json::to_string(&descriptor).unwrap());
        fs::write(
            directory.path().join(FDR_MATERIAL_CREATION_FILE_NAME),
            serde_json::to_vec(&malformed).unwrap(),
        )
        .unwrap();
        let error =
            FdrTrustMaterial::load_or_generate_portable(directory.path(), NOT_BEFORE, NOT_AFTER)
                .err()
                .expect("recorded certificate identities must be issuable before replay");
        assert!(
            error.to_string().contains("fdr-material-creation-invalid"),
            "{error}"
        );
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
