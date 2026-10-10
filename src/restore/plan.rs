use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::crypto::sha384;

use crate::ramrod::fdr_trust::{primary_trust_object_digest, top_level_elements};
use crate::ramrod::ticket::BOOT_NONCE_HASH_BYTES;
use crate::ramrod::{FdrTrustMaterial, RestoreBehavior, machine_instance_identifier};

use super::report::{MUX_PREFIX, SharedReporter, report};

pub const FDR_TRUST_OBJECT_PATH: &str = "/System/Library/FDR/fdrtrustobject";

pub const FDR_TRUST_MATERIAL_DIR_NAME: &str = "fdr-trust";

// Fixed, never clock derived: these bytes feed the digest already signed into `/chosen/boot-manifest-hash`, so a moving window retires it.
pub const FDR_TRUST_NOT_BEFORE: i64 = 1_577_836_800;

pub const FDR_TRUST_NOT_AFTER: i64 = 2_524_608_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorePlan {
    pub image: PathBuf,
    /// `None` falls back to the BuildManifest `OS` component under [`Self::image_root`], never to [`Self::image`], which would write the wrong contents and report success.
    pub system_image: Option<PathBuf>,
    pub recovery_image: Option<PathBuf>,
    pub image_root: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub behavior: Option<RestoreBehavior>,
    pub port: u16,
    pub timeout: Duration,
    pub window: Duration,
    pub retry: Duration,
    pub read_poll: Duration,
    pub asr_read_timeout: Option<Duration>,
    pub metadata: bool,
    pub global_manifests: Option<PathBuf>,
    pub firmware_root: Option<PathBuf>,
    pub bootability_bundle: Option<PathBuf>,
    pub corrupt_manifest: bool,
    pub staged_boot_manifest_sha384: Option<[u8; 48]>,
    pub staged_boot_manifest: Option<Vec<u8>>,
    pub fdr_trust_digest: Option<FdrTrustDigest>,
    pub restore_ramdisk: Option<PathBuf>,
    pub fdr_material_dir: Option<PathBuf>,
    pub sign_recovery_os_local_policy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FdrTrustDigest {
    pub digest: [u8; 32],
    pub element_index: usize,
    pub element_count: usize,
    pub trust_object: Vec<u8>,
    pub instance: Option<String>,
}

impl FdrTrustDigest {
    #[must_use]
    pub fn hex(&self) -> String {
        hex_digest(&self.digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdrTrustObjectsApplied {
    NoDigest,
    Unparsed(String),
    AlreadyPresent,
    Added { before: usize, after: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootNonceStaged {
    NoNonce,
    Unwritable(String),
    AlreadyPresent,
    Written { before: usize, after: usize },
}

pub fn apply_local_ticket_objects(
    manifest: Vec<u8>,
    trust_digest: Option<&FdrTrustDigest>,
    ap_nonce: Option<&[u8; BOOT_NONCE_HASH_BYTES]>,
) -> (Vec<u8>, FdrTrustObjectsApplied, BootNonceStaged) {
    let (manifest, trust_outcome) = apply_fdr_trust_objects(manifest, trust_digest);
    let Some(ap_nonce) = ap_nonce else {
        return (manifest, trust_outcome, BootNonceStaged::NoNonce);
    };
    match crate::ramrod::ticket::set_boot_nonce_hash(&manifest, ap_nonce) {
        Ok(updated) => {
            if updated == manifest {
                (manifest, trust_outcome, BootNonceStaged::AlreadyPresent)
            } else {
                let staged = BootNonceStaged::Written {
                    before: manifest.len(),
                    after: updated.len(),
                };
                (updated, trust_outcome, staged)
            }
        }
        Err(error) => {
            let staged = BootNonceStaged::Unwritable(error.to_string());
            (manifest, trust_outcome, staged)
        }
    }
}

pub fn apply_fdr_trust_objects(
    manifest: Vec<u8>,
    trust_digest: Option<&FdrTrustDigest>,
) -> (Vec<u8>, FdrTrustObjectsApplied) {
    let Some(trust_digest) = trust_digest else {
        return (manifest, FdrTrustObjectsApplied::NoDigest);
    };
    match crate::ramrod::ticket::add_fdr_trust_objects(&manifest, &trust_digest.digest) {
        Ok(updated) => {
            if updated.len() == manifest.len() {
                (updated, FdrTrustObjectsApplied::AlreadyPresent)
            } else {
                let outcome = FdrTrustObjectsApplied::Added {
                    before: manifest.len(),
                    after: updated.len(),
                };
                (updated, outcome)
            }
        }
        Err(error) => {
            let outcome = FdrTrustObjectsApplied::Unparsed(error.to_string());
            (manifest, outcome)
        }
    }
}

pub fn staged_boot_manifest_sha384(
    boot_manifest_path: Option<&str>,
    bundle_dir: &Path,
    trust_digest: Option<&FdrTrustDigest>,
    ap_nonce: Option<&[u8; BOOT_NONCE_HASH_BYTES]>,
    reporter: &SharedReporter,
) -> Option<[u8; 48]> {
    // The bundle-relative resolution the boot path uses; an absolute path here would name a manifest the boot path refuses.
    let resolved = match resolve_bundle_relative_path(boot_manifest_path, bundle_dir) {
        Ok(resolved) => resolved?,
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=staged-boot-manifest-outside-bundle meaning=\"the machine names an Image4 manifest the bundle does not hold, so the boot path refuses it and no digest is published; every root ticket will be refused\" detail=\"{error}\""
            );
            report(reporter, "staged-boot-manifest-outside-bundle", &line);
            return None;
        }
    };
    match std::fs::read(&resolved) {
        Ok(bytes) if !bytes.is_empty() => {
            let raw = bytes.len();
            let (staged, outcome, nonce_staged) =
                apply_local_ticket_objects(bytes, trust_digest, ap_nonce);
            let digest = sha384(&staged);
            let line = format!(
                "{MUX_PREFIX} result=staged-boot-manifest-resolved raw={raw} staged={} fdr_objects={} boot_nonce={} sha384={} meaning=\"this is the SHA-384 the machine published in /chosen/boot-manifest-hash, taken over the manifest after the local restore service signed its FDR trust objects and this boot's AP nonce into it, which is what the boot path stages; every served ticket is compared against this value at the moment it goes out\" detail=\"path={}\"",
                staged.len(),
                match &outcome {
                    FdrTrustObjectsApplied::NoDigest => "none-resolved".to_string(),
                    FdrTrustObjectsApplied::Unparsed(error) => format!("unparsed({error})"),
                    FdrTrustObjectsApplied::AlreadyPresent => "already-present".to_string(),
                    FdrTrustObjectsApplied::Added { .. } => "added".to_string(),
                },
                match &nonce_staged {
                    BootNonceStaged::NoNonce => "none-resolved".to_string(),
                    BootNonceStaged::Unwritable(error) => format!("unwritable({error})"),
                    BootNonceStaged::AlreadyPresent => "already-present".to_string(),
                    BootNonceStaged::Written { .. } => "written".to_string(),
                },
                hex_digest(&digest),
                resolved.display()
            );
            report(reporter, "staged-boot-manifest-resolved", &line);
            Some(digest)
        }
        Ok(_) => {
            let line = format!(
                "{MUX_PREFIX} result=staged-boot-manifest-empty meaning=\"the machine names an Image4 manifest that is empty, so it published no digest and every root ticket will be refused\" detail=\"path={}\"",
                resolved.display()
            );
            report(reporter, "staged-boot-manifest-empty", &line);
            None
        }
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=staged-boot-manifest-unreadable meaning=\"the machine names an Image4 manifest the host cannot read, so the digest it publishes cannot be checked against the ticket it serves\" detail=\"path={}: {error}\"",
                resolved.display()
            );
            report(reporter, "staged-boot-manifest-unreadable", &line);
            None
        }
    }
}

pub fn fdr_trust_digest_from_ramdisk_payload(payload: &[u8]) -> Result<FdrTrustDigest, String> {
    let file = crate::apfs_read::read_file_from_container(payload, FDR_TRUST_OBJECT_PATH)
        .map_err(|error| error.to_string())?;
    let (digest, element_count) =
        primary_trust_object_digest(&file).map_err(|error| error.to_string())?;
    // The guest must be handed exactly the hashed element, not the whole file.
    let (start, end) = *top_level_elements(&file)
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "the trust object file holds no top level element".to_string())?;
    Ok(FdrTrustDigest {
        digest,
        element_index: 0,
        element_count,
        trust_object: file[start..end].to_vec(),
        instance: None,
    })
}

pub fn stock_fdr_trust_from_ramdisk_and_ticket(
    ramdisk: &[u8],
    ticket: &[u8],
) -> Result<FdrTrustDigest, String> {
    let manifest = crate::ramrod::read_manifest(ticket)
        .map_err(|error| format!("stock-fdr-ticket-unreadable: {error}"))?;
    let digest = manifest
        .object(crate::ramrod::ticket::RESTORE_FDR_TRUST_OBJECT_TAG)
        .and_then(|object| object.digest())
        .ok_or("stock-fdr-ticket-rfta-missing: signed AP ticket has no rfta digest")?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| "stock-fdr-ticket-rfta-unreadable: digest is not SHA-256".to_string())?;
    let decoded = crate::asahi_kernel::decode_im4p(ramdisk, usize::MAX)
        .map_err(|error| format!("stock-fdr-ramdisk-unreadable: {error}"))?;
    if decoded.payload_type != *b"rdsk" {
        return Err(format!(
            "stock-fdr-ramdisk-type-mismatch: expected rdsk, got {:?}",
            decoded.payload_type
        ));
    }
    let file = crate::apfs_read::read_file_from_container(&decoded.bytes, FDR_TRUST_OBJECT_PATH)
        .map_err(|error| format!("stock-fdr-trust-file-unreadable: {error}"))?;
    stock_fdr_trust_from_file_and_digest(&file, digest)
}

fn stock_fdr_trust_from_file_and_digest(
    file: &[u8],
    digest: [u8; 32],
) -> Result<FdrTrustDigest, String> {
    let spans = top_level_elements(file).map_err(|error| error.to_string())?;
    let matches = crate::ramrod::fdr_trust::digest_top_level_elements(file)
        .map_err(|error| error.to_string())?;
    let Some(index) = matches.iter().position(|candidate| *candidate == digest) else {
        return Err(format!(
            "stock-fdr-trust-digest-mismatch: ticket rfta {} matches none of {} ramdisk elements",
            hex_digest(&digest),
            spans.len()
        ));
    };
    let (start, end) = spans[index];
    Ok(FdrTrustDigest {
        digest,
        element_index: index,
        element_count: spans.len(),
        trust_object: file[start..end].to_vec(),
        instance: None,
    })
}

pub fn host_fdr_trust_digest(
    chip_id: Option<&str>,
    unique_chip_id: Option<u64>,
    bundle_dir: &Path,
) -> Result<FdrTrustDigest, String> {
    validate_bundle_directory(bundle_dir)?;
    let directory = bundle_dir.join(FDR_TRUST_MATERIAL_DIR_NAME);
    let material = FdrTrustMaterial::load_or_generate_portable(
        &directory,
        FDR_TRUST_NOT_BEFORE,
        FDR_TRUST_NOT_AFTER,
    )
    .or_else(|error| match error {
        crate::ramrod::FdrObjectError::UnrecordedMaterial { .. } => {
            let descriptor = crate::ramrod::fdr_object::sdk_material_descriptor(
                FDR_TRUST_NOT_BEFORE,
                FDR_TRUST_NOT_AFTER,
            );
            let expected = FdrTrustMaterial::load_with_descriptor(&directory, &descriptor)?;
            FdrTrustMaterial::adopt_legacy_material(
                &directory,
                &descriptor,
                expected.trust_object(),
            )
        }
        error => Err(error),
    })
    .map_err(|error| format!("{error} (material directory {})", directory.display()))?;
    Ok(FdrTrustDigest {
        digest: material.digest(),
        element_index: 0,
        element_count: 1,
        trust_object: material.trust_object().to_vec(),
        instance: chip_id
            .zip(unique_chip_id)
            .and_then(|(chip_id, unique_chip_id)| {
                machine_instance_identifier(chip_id, unique_chip_id).ok()
            }),
    })
}

pub fn fdr_trust_digest(
    restore_ramdisk_path: Option<&str>,
    chip_id: Option<&str>,
    unique_chip_id: Option<u64>,
    bundle_dir: &Path,
    reporter: &SharedReporter,
) -> Option<FdrTrustDigest> {
    restore_ramdisk_path
        .map(str::trim)
        .filter(|path| !path.is_empty())?;
    match host_fdr_trust_digest(chip_id, unique_chip_id, bundle_dir) {
        Ok(resolved) => {
            let line = format!(
                "{MUX_PREFIX} result=fdr-trust-digest-resolved bytes={} sha256={} instance={} meaning=\"this is the host's FDR trust object, issued under keys the local restore service holds and kept stable across runs by the seeds and serial numbers under the machine's bundle; the same bytes are served to the device's memory store and the same SHA-256 is signed into every OS ticket's rfta/ftap and into the manifest this machine stages, so what the device hashes back and what it reads out of the ticket are the same fact\" detail=\"material={}\"",
                resolved.trust_object.len(),
                resolved.hex(),
                resolved.instance.as_deref().unwrap_or("none"),
                bundle_dir.join(FDR_TRUST_MATERIAL_DIR_NAME).display()
            );
            report(reporter, "fdr-trust-digest-resolved", &line);
            Some(resolved)
        }
        Err(error) => {
            let line = format!(
                "{MUX_PREFIX} result=fdr-trust-digest-unresolved meaning=\"the host's FDR trust object could not be built, so no rfta/ftap digest can be injected, nothing can be served for the memory store, and fdr_create will find them absent; no substitute digest is invented, because one that does not match the bytes the device hashes reproduces the same failure under a different cause\" detail=\"{error}\""
            );
            report(reporter, "fdr-trust-digest-unresolved", &line);
            None
        }
    }
}

pub fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn resolve_bundle_relative_path(
    path: Option<&str>,
    bundle_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = path.trim();
    if path.is_empty() {
        return Ok(None);
    }
    validate_bundle_directory(bundle_dir)?;
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Err(format!(
            "absolute boot manifest path '{}' is outside the bundle",
            candidate.display()
        ));
    }

    let mut resolved = PathBuf::from(bundle_dir);
    for component in candidate.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => resolved.push(part),
            std::path::Component::ParentDir => {
                return Err(format!(
                    "boot manifest path '{}' escapes the bundle",
                    candidate.display()
                ));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(format!(
                    "boot manifest path '{}' is outside the bundle",
                    candidate.display()
                ));
            }
        }
    }

    Ok(Some(resolved))
}

fn validate_bundle_directory(bundle_dir: &Path) -> Result<(), String> {
    if bundle_dir
        .components()
        .any(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Ok(());
    }
    Err(format!(
        "bundle directory '{}' must contain a normal path component",
        bundle_dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        host_fdr_trust_digest, resolve_bundle_relative_path, stock_fdr_trust_from_file_and_digest,
    };

    #[test]
    fn stock_trust_selects_the_element_signed_by_the_ticket_digest() {
        let file = [0x04, 0x01, 0x11, 0x04, 0x02, 0x22, 0x33];
        let digest = crate::crypto::sha256(&file[3..]);
        let selected = stock_fdr_trust_from_file_and_digest(&file, digest)
            .expect("signed element in the ramdisk trust file");
        assert_eq!(selected.element_index, 1);
        assert_eq!(selected.element_count, 2);
        assert_eq!(selected.trust_object, file[3..]);
        assert_eq!(selected.digest, digest);
    }

    #[test]
    fn sdk_trust_producer_hands_exact_material_to_the_readonly_consumer() {
        let bundle = tempfile::tempdir().unwrap();
        let produced = host_fdr_trust_digest(None, None, bundle.path()).unwrap();
        let directory = bundle.path().join(super::FDR_TRUST_MATERIAL_DIR_NAME);
        let consumed = crate::ramrod::FdrTrustMaterial::load_from_directory(&directory).unwrap();
        assert_eq!(consumed.trust_object(), produced.trust_object.as_slice());
        assert_eq!(consumed.digest(), produced.digest);
    }

    #[test]
    fn sdk_trust_producer_adopts_its_complete_existing_authority() {
        let bundle = tempfile::tempdir().unwrap();
        let directory = bundle.path().join(super::FDR_TRUST_MATERIAL_DIR_NAME);
        let expected = crate::ramrod::FdrTrustMaterial::load_or_generate(
            &directory,
            super::FDR_TRUST_NOT_BEFORE,
            super::FDR_TRUST_NOT_AFTER,
        )
        .unwrap();
        let produced = host_fdr_trust_digest(None, None, bundle.path()).unwrap();
        let consumed = crate::ramrod::FdrTrustMaterial::load_from_directory(&directory).unwrap();
        assert_eq!(produced.trust_object, expected.trust_object());
        assert_eq!(consumed.trust_object(), expected.trust_object());
        assert_eq!(consumed.digest(), produced.digest);
    }

    #[test]
    fn sdk_trust_producer_recovers_the_foreign_profile_selected_by_a_pending_record() {
        use crate::ramrod::fdr_material_format::{
            FDR_MATERIAL_CREATION_FILE_NAME, FdrAuthorityDescriptor, FdrMaterialDescriptor,
        };
        use crate::ramrod::fdr_pki::{CertificateIdentity, DistinguishedName, FdrKeyPair};
        let bundle = tempfile::tempdir().unwrap();
        let directory = bundle.path().join(super::FDR_TRUST_MATERIAL_DIR_NAME);
        std::fs::create_dir(&directory).unwrap();
        let root_domain = b"fixture owner root domain";
        let tls_domain = b"fixture owner TLS domain";
        let root_subject = DistinguishedName::new()
            .organization("fixture owner")
            .common_name("fixture sealing root");
        let tls_subject = DistinguishedName::new()
            .common_name("fixture TLS root")
            .organization("fixture owner");
        let descriptor = FdrMaterialDescriptor::new(
            FdrAuthorityDescriptor::new(
                root_domain,
                &root_subject,
                super::FDR_TRUST_NOT_BEFORE,
                super::FDR_TRUST_NOT_AFTER,
            ),
            FdrAuthorityDescriptor::new(
                tls_domain,
                &tls_subject,
                super::FDR_TRUST_NOT_BEFORE,
                super::FDR_TRUST_NOT_AFTER,
            ),
        );
        let descriptor_json = format!("\n{}\n", serde_json::to_string_pretty(&descriptor).unwrap());
        let record = serde_json::json!({
            "creationVersion": 1, "descriptorJson": descriptor_json,
            "rootCaSeedHex": "41".repeat(32), "tlsRootSeedHex": "52".repeat(32),
            "rootCaSerialHex": "010203", "tlsRootSerialHex": "040506",
        });
        std::fs::write(
            directory.join(FDR_MATERIAL_CREATION_FILE_NAME),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let expected = crate::ramrod::FdrTrustMaterial::issue(
            FdrKeyPair::from_seed([0x41; 32], root_domain),
            FdrKeyPair::from_seed([0x52; 32], tls_domain),
            &CertificateIdentity {
                subject: root_subject,
                serial: vec![1, 2, 3],
                not_before: super::FDR_TRUST_NOT_BEFORE,
                not_after: super::FDR_TRUST_NOT_AFTER,
            },
            &CertificateIdentity {
                subject: tls_subject,
                serial: vec![4, 5, 6],
                not_before: super::FDR_TRUST_NOT_BEFORE,
                not_after: super::FDR_TRUST_NOT_AFTER,
            },
        )
        .unwrap();
        let produced = host_fdr_trust_digest(None, None, bundle.path()).unwrap();
        assert_eq!(produced.trust_object, expected.trust_object());
        assert_eq!(produced.digest, expected.digest());
        let loaded = crate::ramrod::FdrTrustMaterial::load_from_directory(&directory).unwrap();
        assert_eq!(
            loaded.root_ca_key().public_uncompressed(),
            expected.root_ca_key().public_uncompressed()
        );
        assert_eq!(
            loaded.tls_root_certificate(),
            expected.tls_root_certificate()
        );
        assert_eq!(
            std::fs::read(directory.join(crate::ramrod::FDR_MATERIAL_FILE_NAME)).unwrap(),
            record["descriptorJson"].as_str().unwrap().as_bytes()
        );
    }

    #[test]
    fn sdk_trust_producer_names_a_malformed_pending_record() {
        let bundle = tempfile::tempdir().unwrap();
        let directory = bundle.path().join(super::FDR_TRUST_MATERIAL_DIR_NAME);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join(crate::ramrod::fdr_material_format::FDR_MATERIAL_CREATION_FILE_NAME),
            b"{",
        )
        .unwrap();
        let error = host_fdr_trust_digest(None, None, bundle.path()).unwrap_err();
        assert!(error.contains("fdr-material-creation-invalid"), "{error}");
    }

    #[test]
    fn current_directory_is_not_accepted_as_a_bundle_directory() {
        for bundle_dir in [".", "./"] {
            let error =
                resolve_bundle_relative_path(Some("firmware/apticket.im4m"), Path::new(bundle_dir))
                    .expect_err("a bundle directory needs a normal path component");
            assert!(error.contains("normal path component"), "{error}");
        }
    }

    #[test]
    fn host_trust_material_is_not_created_under_the_current_directory() {
        for bundle_dir in [".", "./"] {
            let error = host_fdr_trust_digest(None, None, Path::new(bundle_dir))
                .expect_err("a bundle directory needs a normal path component");
            assert!(error.contains("normal path component"), "{error}");
        }
    }
}
