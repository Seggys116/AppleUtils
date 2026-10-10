use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::fdr_pki::{DistinguishedName, NameAttribute};

pub const FDR_MATERIAL_FILE_NAME: &str = "fdr-material.json";
pub const FDR_MATERIAL_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FdrMaterialDescriptor {
    pub format_version: u32,
    pub root_ca: FdrAuthorityDescriptor,
    pub tls_root: FdrAuthorityDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FdrAuthorityDescriptor {
    pub key_derivation_domain_hex: String,
    pub subject: Vec<FdrSubjectAttribute>,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FdrSubjectAttribute {
    pub attribute: FdrSubjectNameAttribute,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FdrSubjectNameAttribute {
    CommonName,
    OrganizationName,
    StateOrProvinceName,
}

#[derive(Debug)]
pub enum FdrMaterialFormatError {
    Read {
        path: PathBuf,
        error: std::io::Error,
    },
    Write {
        path: PathBuf,
        error: std::io::Error,
    },
    Refused {
        name: &'static str,
        detail: String,
    },
}

impl std::fmt::Display for FdrMaterialFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, error } => write!(
                f,
                "fdr-material-metadata-unreadable: {}: {error}",
                path.display()
            ),
            Self::Write { path, error } => write!(
                f,
                "fdr-material-metadata-write-refused: {}: {error}",
                path.display()
            ),
            Self::Refused { name, detail } => write!(f, "fdr-material-{name}: {detail}"),
        }
    }
}

impl std::error::Error for FdrMaterialFormatError {}

fn refused(name: &'static str, detail: impl Into<String>) -> FdrMaterialFormatError {
    FdrMaterialFormatError::Refused {
        name,
        detail: detail.into(),
    }
}

impl FdrAuthorityDescriptor {
    #[must_use]
    pub fn new(
        domain: &[u8],
        subject: &DistinguishedName,
        not_before: i64,
        not_after: i64,
    ) -> Self {
        let mut encoded = String::with_capacity(domain.len() * 2);
        for byte in domain {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        Self {
            key_derivation_domain_hex: encoded,
            subject: subject
                .attributes()
                .iter()
                .map(|(attribute, value)| FdrSubjectAttribute {
                    attribute: match attribute {
                        NameAttribute::CommonName => FdrSubjectNameAttribute::CommonName,
                        NameAttribute::OrganizationName => {
                            FdrSubjectNameAttribute::OrganizationName
                        }
                        NameAttribute::StateOrProvinceName => {
                            FdrSubjectNameAttribute::StateOrProvinceName
                        }
                    },
                    value: value.clone(),
                })
                .collect(),
            not_before,
            not_after,
        }
    }

    pub fn key_derivation_domain(
        &self,
        authority: &str,
    ) -> Result<Vec<u8>, FdrMaterialFormatError> {
        let text = &self.key_derivation_domain_hex;
        if text.is_empty()
            || !text.len().is_multiple_of(2)
            || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(refused(
                "domain-invalid",
                format!("{authority}.keyDerivationDomainHex must be nonempty exact-byte hex"),
            ));
        }
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        pairs
            .iter()
            .enumerate()
            .map(|(index, pair)| {
                let pair = std::str::from_utf8(pair).map_err(|_| {
                    refused("domain-invalid", format!("{authority} domain byte {index}"))
                })?;
                u8::from_str_radix(pair, 16).map_err(|_| {
                    refused("domain-invalid", format!("{authority} domain byte {index}"))
                })
            })
            .collect()
    }

    pub fn subject_name(
        &self,
        authority: &str,
    ) -> Result<DistinguishedName, FdrMaterialFormatError> {
        if self.subject.is_empty() {
            return Err(refused(
                "name-invalid",
                format!("{authority}.subject must carry ordered name attributes"),
            ));
        }
        let mut subject = DistinguishedName::new();
        for attribute in &self.subject {
            let kind = match attribute.attribute {
                FdrSubjectNameAttribute::CommonName => NameAttribute::CommonName,
                FdrSubjectNameAttribute::OrganizationName => NameAttribute::OrganizationName,
                FdrSubjectNameAttribute::StateOrProvinceName => NameAttribute::StateOrProvinceName,
            };
            subject = subject.with(kind, &attribute.value);
        }
        Ok(subject)
    }

    fn validate(&self, authority: &str) -> Result<(), FdrMaterialFormatError> {
        self.key_derivation_domain(authority)?;
        self.subject_name(authority)?;
        if self.not_after < self.not_before {
            return Err(refused(
                "window-invalid",
                format!(
                    "{authority}: notAfter={} precedes notBefore={}",
                    self.not_after, self.not_before
                ),
            ));
        }
        Ok(())
    }
}

impl FdrMaterialDescriptor {
    #[must_use]
    pub fn new(root_ca: FdrAuthorityDescriptor, tls_root: FdrAuthorityDescriptor) -> Self {
        Self {
            format_version: FDR_MATERIAL_FORMAT_VERSION,
            root_ca,
            tls_root,
        }
    }

    pub fn validate(&self) -> Result<(), FdrMaterialFormatError> {
        if self.format_version != FDR_MATERIAL_FORMAT_VERSION {
            return Err(refused(
                "metadata-version",
                format!(
                    "formatVersion={} is unsupported; expected {}",
                    self.format_version, FDR_MATERIAL_FORMAT_VERSION
                ),
            ));
        }
        self.root_ca.validate("rootCa")?;
        self.tls_root.validate("tlsRoot")
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FdrMaterialFormatError> {
        let descriptor: Self = serde_json::from_slice(bytes)
            .map_err(|error| refused("metadata-invalid", error.to_string()))?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn load(directory: &Path) -> Result<Self, FdrMaterialFormatError> {
        let path = directory.join(FDR_MATERIAL_FILE_NAME);
        let bytes =
            fs::read(&path).map_err(|error| FdrMaterialFormatError::Read { path, error })?;
        Self::parse(&bytes)
    }

    pub fn require_window(
        &self,
        not_before: i64,
        not_after: i64,
    ) -> Result<(), FdrMaterialFormatError> {
        for (name, authority) in [("rootCa", &self.root_ca), ("tlsRoot", &self.tls_root)] {
            if authority.not_before != not_before || authority.not_after != not_after {
                return Err(refused(
                    "window-mismatch",
                    format!(
                        "{name}: recorded=[{},{}] requested=[{not_before},{not_after}]",
                        authority.not_before, authority.not_after
                    ),
                ));
            }
        }
        Ok(())
    }

    // The descriptor records encoding inputs; callers authenticate the reconstructed trust object.
    pub fn write_new(&self, directory: &Path) -> Result<(), FdrMaterialFormatError> {
        self.validate()?;
        let path = directory.join(FDR_MATERIAL_FILE_NAME);
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| refused("metadata-encoding", error.to_string()))?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
            FdrMaterialFormatError::Write {
                path: path.clone(),
                error,
            }
        })?;
        temporary
            .write_all(&bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|error| FdrMaterialFormatError::Write {
                path: path.clone(),
                error,
            })?;
        temporary
            .persist_noclobber(&path)
            .map_err(|error| FdrMaterialFormatError::Write {
                path,
                error: error.error,
            })?;
        Ok(())
    }
}

pub(crate) const FDR_MATERIAL_CREATION_FILE_NAME: &str = "fdr-material.creation.json";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FdrMaterialCreationRecord {
    creation_version: u32,
    pub(crate) descriptor_json: String,
    root_ca_seed_hex: String,
    tls_root_seed_hex: String,
    root_ca_serial_hex: String,
    tls_root_serial_hex: String,
}

pub(crate) struct FdrMaterialCreationInputs {
    pub(crate) descriptor: FdrMaterialDescriptor,
    pub(crate) root_ca_seed: [u8; super::fdr_pki::FDR_KEY_SEED_BYTES],
    pub(crate) tls_root_seed: [u8; super::fdr_pki::FDR_KEY_SEED_BYTES],
    pub(crate) root_ca_serial: Vec<u8>,
    pub(crate) tls_root_serial: Vec<u8>,
}

fn creation_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn creation_bytes(text: &str, field: &str) -> Result<Vec<u8>, FdrMaterialFormatError> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(refused(
            "creation-invalid",
            format!("{field} must contain nonempty exact-byte hex"),
        ));
    }
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| {
                refused("creation-invalid", format!("{field} contains invalid hex"))
            })?;
            u8::from_str_radix(pair, 16)
                .map_err(|_| refused("creation-invalid", format!("{field} contains invalid hex")))
        })
        .collect()
}

impl FdrMaterialCreationRecord {
    pub(crate) fn new(
        descriptor: &FdrMaterialDescriptor,
        root_ca_seed: &[u8; super::fdr_pki::FDR_KEY_SEED_BYTES],
        tls_root_seed: &[u8; super::fdr_pki::FDR_KEY_SEED_BYTES],
        root_ca_serial: &[u8],
        tls_root_serial: &[u8],
    ) -> Result<Self, FdrMaterialFormatError> {
        let record = Self {
            creation_version: 1,
            descriptor_json: serde_json::to_string_pretty(descriptor)
                .map_err(|_| refused("creation-invalid", "descriptor could not be encoded"))?,
            root_ca_seed_hex: creation_hex(root_ca_seed),
            tls_root_seed_hex: creation_hex(tls_root_seed),
            root_ca_serial_hex: creation_hex(root_ca_serial),
            tls_root_serial_hex: creation_hex(tls_root_serial),
        };
        record.inputs()?;
        Ok(record)
    }

    pub(crate) fn inputs(&self) -> Result<FdrMaterialCreationInputs, FdrMaterialFormatError> {
        use super::fdr_pki::{FDR_KEY_SEED_BYTES, MAXIMUM_SERIAL_BYTES};
        if self.creation_version != 1 {
            return Err(refused("creation-invalid", "creationVersion must be 1"));
        }
        let descriptor =
            FdrMaterialDescriptor::parse(self.descriptor_json.as_bytes()).map_err(|_| {
                refused(
                    "creation-invalid",
                    "descriptorJson must contain a valid complete v1 authority descriptor",
                )
            })?;
        let seed =
            |text: &str, field: &str| -> Result<[u8; FDR_KEY_SEED_BYTES], FdrMaterialFormatError> {
                creation_bytes(text, field)?.try_into().map_err(|_| {
                    refused(
                        "creation-invalid",
                        format!("{field} must encode {FDR_KEY_SEED_BYTES} bytes"),
                    )
                })
            };
        let serial = |text: &str, field: &str| -> Result<Vec<u8>, FdrMaterialFormatError> {
            let bytes = creation_bytes(text, field)?;
            if bytes.len() > MAXIMUM_SERIAL_BYTES || bytes.iter().all(|byte| *byte == 0) {
                return Err(refused(
                    "creation-invalid",
                    format!(
                        "{field} must encode a positive serial of at most {MAXIMUM_SERIAL_BYTES} bytes"
                    ),
                ));
            }
            Ok(bytes)
        };
        Ok(FdrMaterialCreationInputs {
            descriptor,
            root_ca_seed: seed(&self.root_ca_seed_hex, "rootCaSeedHex")?,
            tls_root_seed: seed(&self.tls_root_seed_hex, "tlsRootSeedHex")?,
            root_ca_serial: serial(&self.root_ca_serial_hex, "rootCaSerialHex")?,
            tls_root_serial: serial(&self.tls_root_serial_hex, "tlsRootSerialHex")?,
        })
    }

    pub(crate) fn load(directory: &Path) -> Result<Option<Self>, FdrMaterialFormatError> {
        let path = directory.join(FDR_MATERIAL_CREATION_FILE_NAME);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(refused(
                    "creation-unreadable",
                    format!("{}: {error}", path.display()),
                ));
            }
        };
        if !metadata.file_type().is_file() {
            return Err(refused(
                "creation-unreadable",
                format!("{} must be a regular creation record", path.display()),
            ));
        }
        let bytes = fs::read(&path).map_err(|error| {
            refused(
                "creation-unreadable",
                format!("{}: {error}", path.display()),
            )
        })?;
        let record: Self = serde_json::from_slice(&bytes).map_err(|error| {
            refused(
                "creation-invalid",
                format!(
                    "record JSON is invalid at line {} column {}",
                    error.line(),
                    error.column()
                ),
            )
        })?;
        record.inputs()?;
        Ok(Some(record))
    }

    pub(crate) fn publish_new(&self, directory: &Path) -> Result<bool, FdrMaterialFormatError> {
        self.inputs()?;
        let path = directory.join(FDR_MATERIAL_CREATION_FILE_NAME);
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| refused("creation-invalid", "creation record could not be encoded"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
            refused(
                "creation-unreadable",
                format!("{}: {error}", path.display()),
            )
        })?;
        temporary
            .write_all(&bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|error| {
                refused(
                    "creation-unreadable",
                    format!("{}: {error}", path.display()),
                )
            })?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => Ok(true),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(refused(
                "creation-unreadable",
                format!("{}: {}", path.display(), error.error),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> FdrMaterialDescriptor {
        let root = DistinguishedName::new()
            .organization("test owner")
            .common_name("test root")
            .with(NameAttribute::StateOrProvinceName, "test state");
        let tls = DistinguishedName::new()
            .common_name("test TLS root")
            .organization("test owner");
        FdrMaterialDescriptor::new(
            FdrAuthorityDescriptor::new(
                &[0, 0x80, 0xff, 0x41],
                &root,
                1_577_836_800,
                2_524_608_000,
            ),
            FdrAuthorityDescriptor::new(b"test TLS derivation", &tls, 1_577_836_800, 2_524_608_000),
        )
    }

    #[test]
    fn descriptor_round_trip_preserves_exact_domains_and_ordered_subjects() {
        let expected = descriptor();
        let bytes = serde_json::to_vec(&expected).unwrap();
        let parsed = FdrMaterialDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(
            parsed.root_ca.key_derivation_domain("rootCa").unwrap(),
            vec![0, 0x80, 0xff, 0x41]
        );
        let subject = parsed.root_ca.subject_name("rootCa").unwrap();
        assert_eq!(
            subject.attributes(),
            &[
                (NameAttribute::OrganizationName, "test owner".to_string()),
                (NameAttribute::CommonName, "test root".to_string()),
                (NameAttribute::StateOrProvinceName, "test state".to_string()),
            ]
        );
    }

    #[test]
    fn descriptor_metadata_refusals_are_named() {
        let value = serde_json::to_value(descriptor()).unwrap();
        for (key, replacement, expected) in [
            (
                "formatVersion",
                serde_json::json!(2),
                "fdr-material-metadata-version",
            ),
            (
                "undeclaredField",
                serde_json::json!(true),
                "fdr-material-metadata-invalid",
            ),
        ] {
            let mut malformed = value.clone();
            malformed[key] = replacement;
            let error =
                FdrMaterialDescriptor::parse(&serde_json::to_vec(&malformed).unwrap()).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
        for text in ["", "0", "+f", "é"] {
            let mut malformed = descriptor();
            malformed.root_ca.key_derivation_domain_hex = text.to_string();
            let error = malformed.validate().unwrap_err();
            assert!(
                error.to_string().contains("fdr-material-domain-invalid"),
                "{error}"
            );
        }
        let mut malformed = descriptor();
        malformed.root_ca.subject.clear();
        assert!(
            malformed
                .validate()
                .unwrap_err()
                .to_string()
                .contains("fdr-material-name-invalid")
        );
        let mut malformed = descriptor();
        malformed.tls_root.not_after = malformed.tls_root.not_before - 1;
        assert!(
            malformed
                .validate()
                .unwrap_err()
                .to_string()
                .contains("fdr-material-window-invalid")
        );
    }

    #[test]
    fn descriptor_write_refuses_to_replace_an_existing_profile() {
        let directory = tempfile::tempdir().unwrap();
        let expected = descriptor();
        expected.write_new(directory.path()).unwrap();
        let before = fs::read(directory.path().join(FDR_MATERIAL_FILE_NAME)).unwrap();
        let mut replacement = expected.clone();
        replacement.root_ca.key_derivation_domain_hex = "01".to_string();
        let error = replacement.write_new(directory.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fdr-material-metadata-write-refused"),
            "{error}"
        );
        assert_eq!(
            fs::read(directory.path().join(FDR_MATERIAL_FILE_NAME)).unwrap(),
            before
        );
        assert_eq!(
            FdrMaterialDescriptor::load(directory.path()).unwrap(),
            expected
        );
    }
}
