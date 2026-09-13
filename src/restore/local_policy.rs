use std::collections::BTreeMap;
use std::fmt;

use crate::crypto::sha384;
use crate::ramrod::{
    CHIP_IDENTITY_PROPERTY_TAG, Im4mManifest, PropertyValue, TicketError, read_manifest,
    wrap_image4,
};

pub const RECOVERY_OS_LOCAL_POLICY_DATA_TYPE: &str = "RecoveryOSLocalPolicy";
pub const KEY_AP_NEXT_STAGE_IM4M_HASH: &str = "Ap,NextStageIM4MHash";
pub const KEY_AP_RECOVERY_OS_POLICY_NONCE_HASH: &str = "Ap,RecoveryOSPolicyNonceHash";
pub const KEY_AP_VOLUME_UUID: &str = "Ap,VolumeUUID";
pub const KEY_AP_LOCAL_POLICY: &str = "Ap,LocalPolicy";
pub const KEY_AP_LOCAL_BOOT: &str = "Ap,LocalBoot";
pub const KEY_AP_IMG4_TICKET_REQUESTED: &str = "@ApImg4Ticket";

pub const KEY_AP_CHIP_ID: &str = "ApChipID";
pub const KEY_AP_BOARD_ID: &str = "ApBoardID";
pub const KEY_AP_ECID: &str = "ApECID";
pub const KEY_AP_PRODUCTION_MODE: &str = "ApProductionMode";
pub const KEY_AP_SECURITY_DOMAIN: &str = "ApSecurityDomain";
pub const KEY_AP_SECURITY_MODE: &str = "ApSecurityMode";

pub const KEY_DIGEST: &str = "Digest";
pub const KEY_TRUSTED: &str = "Trusted";

// Response ticket key is the request's @ApImg4Ticket without the leading @.
pub const KEY_RESPONSE_AP_IMG4_TICKET: &str = "ApImg4Ticket";

// Image4 4CCs for Ap,RecoveryOSPolicyNonceHash / Ap,NextStageIM4MHash / Ap,VolumeUUID.
pub const RECOVERY_OS_POLICY_NONCE_TAG: &str = "ronh";
pub const NEXT_STAGE_IM4M_HASH_TAG: &str = "nsih";
pub const VOLUME_UUID_TAG: &str = "vuid";

pub const POLICY_HASH_BYTES: usize = 0x30;

pub const VOLUME_UUID_BYTES: usize = 16;

pub const RECOVERY_OS_LOCAL_POLICY_IM4P: [u8; 22] = [
    0x30, 0x14, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b'l', b'p', b'o', b'l', 0x16, 0x03,
    b'1', b'.', b'0', 0x04, 0x01, 0x00,
];

pub const RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384: [u8; 48] = [
    0xd1, 0x01, 0x54, 0x38, 0xc4, 0xa8, 0x91, 0x72, 0xa3, 0x04, 0x8d, 0x5e, 0xae, 0xbc, 0xb2, 0xde,
    0x65, 0x77, 0x75, 0xc6, 0x6a, 0xf8, 0x68, 0x91, 0x6a, 0xa7, 0x96, 0x19, 0x02, 0x3d, 0x82, 0x86,
    0xa1, 0x46, 0x10, 0xc7, 0x25, 0xe4, 0x91, 0xce, 0x67, 0xf4, 0x0c, 0xbd, 0x58, 0xb7, 0x78, 0x72,
];

const TAG_CHIP: &str = "CHIP";
const TAG_BOARD: &str = "BORD";
const TAG_SECURITY_DOMAIN: &str = "SDOM";
const TAG_PRODUCTION_MODE: &str = "CPRO";
const TAG_SECURITY_MODE: &str = "CSEC";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalPolicyIdentity {
    pub ecid: u64,
    pub chip_id: u32,
    pub board_id: u32,
    pub security_domain: u32,
    pub production_mode: bool,
    pub security_mode: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityRefusal {
    TicketUnreadable {
        detail: String,
    },
    NotPersonalisable {
        chip: Option<u64>,
        board: Option<u64>,
        board_tag: Option<String>,
    },
    PropertyMissing {
        tag: &'static str,
    },
    PropertyUnreadable {
        tag: &'static str,
        rendered: String,
    },
}

impl IdentityRefusal {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::TicketUnreadable { .. } => "recovery-os-local-policy-identity-ticket-unreadable",
            Self::NotPersonalisable { .. } => {
                "recovery-os-local-policy-identity-not-personalisable"
            }
            Self::PropertyMissing { .. } => "recovery-os-local-policy-identity-property-missing",
            Self::PropertyUnreadable { .. } => {
                "recovery-os-local-policy-identity-property-unreadable"
            }
        }
    }
}

impl fmt::Display for IdentityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TicketUnreadable { detail } => write!(
                f,
                "the AP root ticket this host served did not read back as an IM4M manifest: {detail}"
            ),
            Self::NotPersonalisable {
                chip,
                board,
                board_tag,
            } => {
                let render = |value: &Option<u64>| {
                    value.map_or_else(|| "absent".to_string(), |value| format!("0x{value:x}"))
                };
                write!(
                    f,
                    "the AP root ticket this host served carries no {CHIP_IDENTITY_PROPERTY_TAG} property in its MANP, so it is a global manifest that names a board and not a part: CHIP={} BORD={} tagt={}",
                    render(chip),
                    render(board),
                    board_tag.as_deref().unwrap_or("absent")
                )
            }
            Self::PropertyMissing { tag } => write!(
                f,
                "the AP root ticket names a part but its MANP carries no {tag} property, and the server request has no term to put in its place"
            ),
            Self::PropertyUnreadable { tag, rendered } => write!(
                f,
                "the MANP property {tag} is present as {rendered}, which is not the shape the server request term needs"
            ),
        }
    }
}

fn integer_property(
    manifest: &Im4mManifest,
    tag: &'static str,
) -> Result<u64, Box<IdentityRefusal>> {
    let property = manifest
        .property(tag)
        .ok_or(IdentityRefusal::PropertyMissing { tag })?;
    property
        .value
        .as_integer()
        .ok_or_else(|| IdentityRefusal::PropertyUnreadable {
            tag,
            rendered: property.value.render(),
        })
        .map_err(Box::new)
}

fn boolean_property(
    manifest: &Im4mManifest,
    tag: &'static str,
) -> Result<bool, Box<IdentityRefusal>> {
    let property = manifest
        .property(tag)
        .ok_or(IdentityRefusal::PropertyMissing { tag })?;
    match property.value {
        PropertyValue::Boolean(value) => Ok(value),
        _ => Err(Box::new(IdentityRefusal::PropertyUnreadable {
            tag,
            rendered: property.value.render(),
        })),
    }
}

fn narrow(tag: &'static str, value: u64) -> Result<u32, Box<IdentityRefusal>> {
    u32::try_from(value).map_err(|_| {
        Box::new(IdentityRefusal::PropertyUnreadable {
            tag,
            rendered: format!("0x{value:x}, wider than the 32 bit request term"),
        })
    })
}

impl LocalPolicyIdentity {
    pub fn from_root_ticket(ticket: &[u8]) -> Result<Self, Box<IdentityRefusal>> {
        let manifest = read_manifest(ticket).map_err(|error: TicketError| {
            Box::new(IdentityRefusal::TicketUnreadable {
                detail: error.to_string(),
            })
        })?;
        Self::from_manifest(&manifest)
    }

    pub fn from_manifest(manifest: &Im4mManifest) -> Result<Self, Box<IdentityRefusal>> {
        if !manifest.is_personalised() {
            return Err(Box::new(IdentityRefusal::NotPersonalisable {
                chip: manifest.chip(),
                board: manifest.board(),
                board_tag: manifest.board_tag().map(str::to_string),
            }));
        }
        let ecid = integer_property(manifest, CHIP_IDENTITY_PROPERTY_TAG)?;
        let chip_id = narrow(TAG_CHIP, integer_property(manifest, TAG_CHIP)?)?;
        let board_id = narrow(TAG_BOARD, integer_property(manifest, TAG_BOARD)?)?;
        let security_domain = narrow(
            TAG_SECURITY_DOMAIN,
            integer_property(manifest, TAG_SECURITY_DOMAIN)?,
        )?;
        let production_mode = boolean_property(manifest, TAG_PRODUCTION_MODE)?;
        let security_mode = boolean_property(manifest, TAG_SECURITY_MODE)?;
        Ok(Self {
            ecid,
            chip_id,
            board_id,
            security_domain,
            production_mode,
            security_mode,
        })
    }

    #[must_use]
    pub fn trace_fields(&self) -> String {
        format!(
            "ecid=0x{:x} chip=0x{:x} board=0x{:x} security_domain={} production_mode={} security_mode={}",
            self.ecid,
            self.chip_id,
            self.board_id,
            self.security_domain,
            self.production_mode,
            self.security_mode
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputRefusal {
    Missing {
        key: &'static str,
    },
    NotData {
        key: &'static str,
        rendered: String,
    },
    WrongLength {
        key: &'static str,
        wanted: usize,
        found: usize,
    },
    NotText {
        key: &'static str,
        rendered: String,
    },
    UuidUnparsable {
        text: String,
    },
}

impl InputRefusal {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "recovery-os-local-policy-argument-missing",
            Self::NotData { .. } | Self::NotText { .. } => {
                "recovery-os-local-policy-argument-wrong-type"
            }
            Self::WrongLength { .. } => "recovery-os-local-policy-argument-wrong-length",
            Self::UuidUnparsable { .. } => "recovery-os-local-policy-volume-uuid-unparsable",
        }
    }
}

impl fmt::Display for InputRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { key } => write!(
                f,
                "the guest's request carries no {key}, and the server request term it fills cannot be invented"
            ),
            Self::NotData { key, rendered } => write!(
                f,
                "the guest sent {key} as {rendered} where the send at 0x10002b4d8 makes it a CFData"
            ),
            Self::WrongLength { key, wanted, found } => write!(
                f,
                "the guest sent {key} as {found} bytes where both halves of this exchange fix it at {wanted}"
            ),
            Self::NotText { key, rendered } => write!(
                f,
                "the guest sent {key} as {rendered} where the constant at 0x10025d860 makes it a CFString"
            ),
            Self::UuidUnparsable { text } => write!(
                f,
                "the guest sent the volume UUID as {text:?}, which does not parse the way uuid_parse at 0x10002b590 parses it, so CFUUIDGetUUIDBytes has no 16 bytes to give the request"
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryOsLocalPolicyInputs {
    pub next_stage_im4m_hash: Vec<u8>,
    pub policy_nonce_hash: Vec<u8>,
    pub volume_uuid_text: String,
    pub volume_uuid_bytes: [u8; VOLUME_UUID_BYTES],
}

fn read_hash(
    arguments: &plist::Dictionary,
    key: &'static str,
) -> Result<Vec<u8>, Box<InputRefusal>> {
    let value = arguments
        .get(key)
        .ok_or(InputRefusal::Missing { key })
        .map_err(Box::new)?;
    let bytes = value
        .as_data()
        .ok_or_else(|| InputRefusal::NotData {
            key,
            rendered: describe_value(value),
        })
        .map_err(Box::new)?;
    if bytes.len() != POLICY_HASH_BYTES {
        return Err(Box::new(InputRefusal::WrongLength {
            key,
            wanted: POLICY_HASH_BYTES,
            found: bytes.len(),
        }));
    }
    Ok(bytes.to_vec())
}

fn describe_value(value: &plist::Value) -> String {
    match value {
        plist::Value::String(text) => format!("the string {text:?}"),
        plist::Value::Integer(integer) => format!("the integer {integer}"),
        plist::Value::Boolean(flag) => format!("the boolean {flag}"),
        plist::Value::Data(bytes) => format!("{} bytes of data", bytes.len()),
        plist::Value::Array(items) => format!("an array of {} items", items.len()),
        plist::Value::Dictionary(nested) => format!("a dictionary of {} keys", nested.len()),
        other => format!("{other:?}"),
    }
}

pub fn volume_uuid_bytes(text: &str) -> Option<[u8; VOLUME_UUID_BYTES]> {
    let groups: Vec<&str> = text.split('-').collect();
    if groups.len() != 5 {
        return None;
    }
    const WIDTHS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut digits = String::with_capacity(32);
    for (group, width) in groups.iter().zip(WIDTHS) {
        if group.len() != width || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        digits.push_str(group);
    }
    let bytes = digits.as_bytes();
    let mut out = [0u8; VOLUME_UUID_BYTES];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&bytes[index * 2..index * 2 + 2]).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

impl RecoveryOsLocalPolicyInputs {
    pub fn read(arguments: &plist::Dictionary) -> Result<Self, Box<InputRefusal>> {
        let next_stage_im4m_hash = read_hash(arguments, KEY_AP_NEXT_STAGE_IM4M_HASH)?;
        let policy_nonce_hash = read_hash(arguments, KEY_AP_RECOVERY_OS_POLICY_NONCE_HASH)?;
        let value = arguments
            .get(KEY_AP_VOLUME_UUID)
            .ok_or(InputRefusal::Missing {
                key: KEY_AP_VOLUME_UUID,
            })
            .map_err(Box::new)?;
        let text = value
            .as_string()
            .ok_or_else(|| InputRefusal::NotText {
                key: KEY_AP_VOLUME_UUID,
                rendered: describe_value(value),
            })
            .map_err(Box::new)?;
        let volume_uuid_bytes = volume_uuid_bytes(text).ok_or_else(|| {
            Box::new(InputRefusal::UuidUnparsable {
                text: text.to_string(),
            })
        })?;
        Ok(Self {
            next_stage_im4m_hash,
            policy_nonce_hash,
            volume_uuid_text: text.to_string(),
            volume_uuid_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryOsLocalPolicyRequest {
    pub identity: LocalPolicyIdentity,
    pub inputs: RecoveryOsLocalPolicyInputs,
}

impl RecoveryOsLocalPolicyRequest {
    #[must_use]
    pub fn new(identity: LocalPolicyIdentity, inputs: RecoveryOsLocalPolicyInputs) -> Self {
        Self { identity, inputs }
    }

    #[must_use]
    pub fn body(&self) -> plist::Dictionary {
        let mut policy = plist::Dictionary::new();
        policy.insert(
            KEY_DIGEST.to_string(),
            plist::Value::Data(RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384.to_vec()),
        );
        policy.insert(KEY_TRUSTED.to_string(), plist::Value::Boolean(true));

        let mut body = plist::Dictionary::new();
        body.insert(
            KEY_AP_IMG4_TICKET_REQUESTED.to_string(),
            plist::Value::Boolean(true),
        );
        body.insert(
            KEY_AP_CHIP_ID.to_string(),
            plist::Value::Integer(i64::from(self.identity.chip_id).into()),
        );
        body.insert(
            KEY_AP_BOARD_ID.to_string(),
            plist::Value::Integer(i64::from(self.identity.board_id).into()),
        );
        body.insert(
            KEY_AP_ECID.to_string(),
            plist::Value::Integer(self.identity.ecid.into()),
        );
        body.insert(
            KEY_AP_PRODUCTION_MODE.to_string(),
            plist::Value::Boolean(self.identity.production_mode),
        );
        body.insert(
            KEY_AP_SECURITY_DOMAIN.to_string(),
            plist::Value::Integer(i64::from(self.identity.security_domain).into()),
        );
        body.insert(
            KEY_AP_SECURITY_MODE.to_string(),
            plist::Value::Boolean(self.identity.security_mode),
        );
        body.insert(
            KEY_AP_LOCAL_POLICY.to_string(),
            plist::Value::Dictionary(policy),
        );
        body.insert(
            KEY_AP_NEXT_STAGE_IM4M_HASH.to_string(),
            plist::Value::Data(self.inputs.next_stage_im4m_hash.clone()),
        );
        body.insert(
            KEY_AP_RECOVERY_OS_POLICY_NONCE_HASH.to_string(),
            plist::Value::Data(self.inputs.policy_nonce_hash.clone()),
        );
        body.insert(
            KEY_AP_VOLUME_UUID.to_string(),
            plist::Value::Data(self.inputs.volume_uuid_bytes.to_vec()),
        );
        body.insert(KEY_AP_LOCAL_BOOT.to_string(), plist::Value::Boolean(true));
        body
    }

    #[must_use]
    pub fn trace_fields(&self) -> String {
        format!(
            "{} next_stage_im4m_sha384={} policy_nonce_sha384={} volume_uuid={} payload_digest={}",
            self.identity.trace_fields(),
            hex(&self.inputs.next_stage_im4m_hash),
            hex(&self.inputs.policy_nonce_hash),
            self.inputs.volume_uuid_text,
            hex(&RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384),
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub trait RecoveryOsLocalPolicySigner: Send + Sync {
    fn source(&self) -> &'static str;

    fn personalize(&self, request: &plist::Dictionary) -> Result<plist::Dictionary, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningRefusal {
    ServiceAbsent,
    ServiceFailed {
        source: &'static str,
        detail: String,
    },
    ResponseMissingTicket {
        source: &'static str,
    },
    ResponseTicketNotData {
        source: &'static str,
        rendered: String,
    },
    TicketUnreadable {
        source: &'static str,
        detail: String,
    },
    TicketNotBound {
        source: &'static str,
        mismatches: Vec<String>,
    },
    StitchFailed {
        source: &'static str,
        detail: String,
    },
}

impl SigningRefusal {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ServiceAbsent => "recovery-os-local-policy-signing-service-absent",
            Self::ServiceFailed { .. } => "recovery-os-local-policy-signing-service-failed",
            Self::ResponseMissingTicket { .. } => "recovery-os-local-policy-response-no-manifest",
            Self::ResponseTicketNotData { .. } => {
                "recovery-os-local-policy-response-manifest-not-data"
            }
            Self::TicketUnreadable { .. } => {
                "recovery-os-local-policy-response-manifest-unreadable"
            }
            Self::TicketNotBound { .. } => "recovery-os-local-policy-response-manifest-unbound",
            Self::StitchFailed { .. } => "recovery-os-local-policy-stitch-failed",
        }
    }
}

impl fmt::Display for SigningRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceAbsent => write!(
                f,
                "the request is complete and this host has no service to issue it to; the only thing missing from the object the guest wants is Apple's signature over these exact terms. This build can issue it and does not unless the operator says so: pass {SIGNING_OPT_IN_FLAG} on the command line, or press {SIGNING_OPT_IN_KEY} on the recovery screen before the restore starts. Arming it posts the request above, which names this part's ECID, chip and board, to {SIGNING_SERVER_DEFAULT_BASE_URL}"
            ),
            Self::ServiceFailed { source, detail } => {
                write!(f, "the {source} signing service did not answer: {detail}")
            }
            Self::ResponseMissingTicket { source } => write!(
                f,
                "the {source} signing service answered without {KEY_RESPONSE_AP_IMG4_TICKET}, which is the one key the stitch at 0x2845d8 reads"
            ),
            Self::ResponseTicketNotData { source, rendered } => write!(
                f,
                "the {source} signing service returned {KEY_RESPONSE_AP_IMG4_TICKET} as {rendered} where the stitch needs data"
            ),
            Self::TicketUnreadable { source, detail } => write!(
                f,
                "the manifest the {source} signing service returned did not read back as an IM4M: {detail}"
            ),
            Self::TicketNotBound { source, mismatches } => write!(
                f,
                "the manifest the {source} signing service returned is signed for something other than what was asked for, so it is not served: {}",
                mismatches.join("; ")
            ),
            Self::StitchFailed { source, detail } => write!(
                f,
                "the manifest the {source} signing service returned could not be stitched into an IMG4 over the constant lpol payload: {detail}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingReport {
    pub ecid: Option<bool>,
    pub chip: Option<bool>,
    pub board: Option<bool>,
    pub policy_nonce: Option<bool>,
    pub next_stage: Option<bool>,
    pub volume_uuid: Option<bool>,
}

impl BindingReport {
    #[must_use]
    pub fn mismatches(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut note = |field: &str, agreed: Option<bool>| {
            if agreed == Some(false) {
                out.push(format!(
                    "{field} in the returned manifest is not the one asked for"
                ));
            }
        };
        note("ECID", self.ecid);
        note("CHIP", self.chip);
        note("BORD", self.board);
        note(RECOVERY_OS_POLICY_NONCE_TAG, self.policy_nonce);
        note(NEXT_STAGE_IM4M_HASH_TAG, self.next_stage);
        note(VOLUME_UUID_TAG, self.volume_uuid);
        out
    }

    #[must_use]
    pub fn trace_fields(&self) -> String {
        let render = |value: Option<bool>| match value {
            Some(true) => "match",
            Some(false) => "differs",
            None => "not-carried",
        };
        format!(
            "bound_ecid={} bound_chip={} bound_board={} bound_{RECOVERY_OS_POLICY_NONCE_TAG}={} bound_{NEXT_STAGE_IM4M_HASH_TAG}={} bound_{VOLUME_UUID_TAG}={}",
            render(self.ecid),
            render(self.chip),
            render(self.board),
            render(self.policy_nonce),
            render(self.next_stage),
            render(self.volume_uuid)
        )
    }
}

#[must_use]
pub fn binding_report(
    manifest: &Im4mManifest,
    request: &RecoveryOsLocalPolicyRequest,
) -> BindingReport {
    let compare_integer = |tag: &str, wanted: u64| {
        manifest
            .property(tag)
            .and_then(|property| property.value.as_integer())
            .map(|found| found == wanted)
    };
    let compare_bytes = |tag: &str, wanted: &[u8]| {
        manifest
            .property(tag)
            .and_then(|property| property.value.as_bytes())
            .map(|found| found == wanted)
    };
    BindingReport {
        ecid: compare_integer(CHIP_IDENTITY_PROPERTY_TAG, request.identity.ecid),
        chip: compare_integer(TAG_CHIP, u64::from(request.identity.chip_id)),
        board: compare_integer(TAG_BOARD, u64::from(request.identity.board_id)),
        policy_nonce: compare_bytes(
            RECOVERY_OS_POLICY_NONCE_TAG,
            &request.inputs.policy_nonce_hash,
        ),
        next_stage: compare_bytes(
            NEXT_STAGE_IM4M_HASH_TAG,
            &request.inputs.next_stage_im4m_hash,
        ),
        volume_uuid: compare_bytes(VOLUME_UUID_TAG, &request.inputs.volume_uuid_bytes),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonalizedLocalPolicy {
    pub image: Vec<u8>,
    pub manifest: Vec<u8>,
    pub binding: BindingReport,
    pub source: &'static str,
}

pub fn personalize(
    signer: &dyn RecoveryOsLocalPolicySigner,
    request: &RecoveryOsLocalPolicyRequest,
) -> Result<PersonalizedLocalPolicy, Box<SigningRefusal>> {
    let source = signer.source();
    let response = signer
        .personalize(&request.body())
        .map_err(|detail| Box::new(SigningRefusal::ServiceFailed { source, detail }))?;
    let value = response
        .get(KEY_RESPONSE_AP_IMG4_TICKET)
        .ok_or(SigningRefusal::ResponseMissingTicket { source })
        .map_err(Box::new)?;
    let manifest_bytes = value
        .as_data()
        .ok_or_else(|| SigningRefusal::ResponseTicketNotData {
            source,
            rendered: describe_value(value),
        })
        .map_err(Box::new)?
        .to_vec();
    let manifest = read_manifest(&manifest_bytes).map_err(|error| {
        Box::new(SigningRefusal::TicketUnreadable {
            source,
            detail: error.to_string(),
        })
    })?;
    let binding = binding_report(&manifest, request);
    let mismatches = binding.mismatches();
    if !mismatches.is_empty() {
        return Err(Box::new(SigningRefusal::TicketNotBound {
            source,
            mismatches,
        }));
    }
    let image = wrap_image4(&RECOVERY_OS_LOCAL_POLICY_IM4P, &manifest_bytes)
        .map_err(|detail| Box::new(SigningRefusal::StitchFailed { source, detail }))?;
    Ok(PersonalizedLocalPolicy {
        image,
        manifest: manifest_bytes,
        binding,
        source,
    })
}

#[must_use]
pub fn next_stage_im4m_hash(root_ticket: &[u8]) -> [u8; POLICY_HASH_BYTES] {
    sha384(root_ticket)
}

pub const SIGNING_SERVER_DEFAULT_BASE_URL: &str = "https://gs.apple.com:443/";
pub const SIGNING_OPT_IN_FLAG: &str = "--sign-recovery-os-local-policy";
pub const SIGNING_OPT_IN_KEY: &str = "p";
// Path from _tss_submit_job_with_retry; action=2 is the personalize submit.
pub const SIGNING_SERVER_REQUEST_PATH: &str = "TSS/controller?action=2";

pub const SIGNING_SERVER_CONTENT_TYPE: &str = "text/xml; charset=\"utf-8\"";

pub const KEY_HOST_PLATFORM_INFO: &str = "@HostPlatformInfo";
pub const KEY_VERSION_INFO: &str = "@VersionInfo";
pub const KEY_BB_TICKET: &str = "@BBTicket";
pub const KEY_UUID: &str = "@UUID";

const RESPONSE_TOKEN_STATUS: &str = "STATUS";
const RESPONSE_TOKEN_MESSAGE: &str = "MESSAGE";
const RESPONSE_TOKEN_REQUEST_STRING: &str = "REQUEST_STRING";

pub const SIGNING_SERVER_MAX_RESPONSE_BYTES: usize = 0x19000;

fn sysctl_string(name: &str) -> Option<String> {
    let key = std::ffi::CString::new(name).ok()?;
    let mut length: libc::size_t = 0;
    // Safety: NUL-terminated name; first call is size-only with a null buffer.
    let sized = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            std::ptr::null_mut(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if sized != 0 || length == 0 {
        return None;
    }
    let mut buffer = vec![0u8; length];
    let read = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    buffer.truncate(length);
    while buffer.last() == Some(&0) {
        buffer.pop();
    }
    String::from_utf8(buffer).ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningEnvelope {
    pub host_platform_info: String,
    pub version_info: String,
    pub uuid: Option<String>,
}

impl SigningEnvelope {
    pub fn for_this_host(version_info: &str, uuid: Option<String>) -> Result<Self, String> {
        let os_version = sysctl_string("kern.osversion")
            .ok_or_else(|| String::from("kern.osversion could not be read"))?;
        let hardware = sysctl_string("hw.product")
            .or_else(|| sysctl_string("hw.machine"))
            .ok_or_else(|| String::from("neither hw.product nor hw.machine could be read"))?;
        Ok(Self {
            host_platform_info: format!("mac/{os_version}/{hardware}"),
            version_info: version_info.to_string(),
            uuid,
        })
    }
}

#[must_use]
pub fn signing_server_body(
    request: &RecoveryOsLocalPolicyRequest,
    envelope: &SigningEnvelope,
) -> plist::Dictionary {
    let mut body = request.body();
    body.insert(
        KEY_HOST_PLATFORM_INFO.to_string(),
        plist::Value::String(envelope.host_platform_info.clone()),
    );
    body.insert(
        KEY_VERSION_INFO.to_string(),
        plist::Value::String(envelope.version_info.clone()),
    );
    body.insert(KEY_BB_TICKET.to_string(), plist::Value::Boolean(true));
    if let Some(uuid) = &envelope.uuid {
        body.insert(KEY_UUID.to_string(), plist::Value::String(uuid.clone()));
    }
    body
}

pub fn encode_signing_server_body(body: &plist::Dictionary) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    plist::Value::Dictionary(body.clone())
        .to_writer_xml(&mut bytes)
        .map_err(|error| format!("the request could not be written as an XML plist: {error}"))?;
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseRefusal {
    TooLarge { bytes: usize, maximum: usize },
    NoRequestString,
    NoStatus,
    Status { status: i64, message: String },
    RequestStringUnreadable { detail: String },
    RequestStringNotADictionary,
}

impl ResponseRefusal {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "recovery-os-local-policy-response-too-large",
            Self::NoRequestString | Self::NoStatus => "recovery-os-local-policy-response-malformed",
            Self::Status { .. } => "recovery-os-local-policy-response-status",
            Self::RequestStringUnreadable { .. } | Self::RequestStringNotADictionary => {
                "recovery-os-local-policy-response-unreadable"
            }
        }
    }
}

impl fmt::Display for ResponseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, maximum } => write!(
                f,
                "the signing server answered with {bytes} bytes where the submit caps a response at {maximum}"
            ),
            Self::NoRequestString => write!(
                f,
                "the signing server's answer carries no {RESPONSE_TOKEN_REQUEST_STRING} token, which is the half of it that holds the property list"
            ),
            Self::NoStatus => write!(
                f,
                "the signing server's answer carries no readable {RESPONSE_TOKEN_STATUS} token, so whether it succeeded cannot be told"
            ),
            Self::Status { status, message } => write!(
                f,
                "the signing server answered {RESPONSE_TOKEN_STATUS}={status}: {message}"
            ),
            Self::RequestStringUnreadable { detail } => write!(
                f,
                "the signing server's {RESPONSE_TOKEN_REQUEST_STRING} did not parse as a property list: {detail}"
            ),
            Self::RequestStringNotADictionary => write!(
                f,
                "the signing server's {RESPONSE_TOKEN_REQUEST_STRING} parsed as something other than a dictionary"
            ),
        }
    }
}

fn response_token<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=");
    let start = if body.starts_with(&needle) {
        needle.len()
    } else {
        body.find(&format!("&{needle}"))? + needle.len() + 1
    };
    let rest = &body[start..];
    let mut end = rest.len();
    for other in [
        RESPONSE_TOKEN_STATUS,
        RESPONSE_TOKEN_MESSAGE,
        RESPONSE_TOKEN_REQUEST_STRING,
    ] {
        if let Some(at) = rest.find(&format!("&{other}=")) {
            end = end.min(at);
        }
    }
    Some(&rest[..end])
}

pub fn parse_signing_server_response(
    body: &[u8],
) -> Result<plist::Dictionary, Box<ResponseRefusal>> {
    if body.len() > SIGNING_SERVER_MAX_RESPONSE_BYTES {
        return Err(Box::new(ResponseRefusal::TooLarge {
            bytes: body.len(),
            maximum: SIGNING_SERVER_MAX_RESPONSE_BYTES,
        }));
    }
    let text = String::from_utf8_lossy(body);
    let status = response_token(&text, RESPONSE_TOKEN_STATUS)
        .and_then(|value| value.trim().parse::<i64>().ok())
        .ok_or(ResponseRefusal::NoStatus)
        .map_err(Box::new)?;
    let message = response_token(&text, RESPONSE_TOKEN_MESSAGE)
        .unwrap_or("")
        .trim()
        .to_string();
    if status != 0 {
        return Err(Box::new(ResponseRefusal::Status { status, message }));
    }
    let request_string = response_token(&text, RESPONSE_TOKEN_REQUEST_STRING)
        .ok_or(ResponseRefusal::NoRequestString)
        .map_err(Box::new)?;
    let value = plist::Value::from_reader_xml(std::io::Cursor::new(request_string.as_bytes()))
        .map_err(|error| {
            Box::new(ResponseRefusal::RequestStringUnreadable {
                detail: error.to_string(),
            })
        })?;
    value
        .into_dictionary()
        .ok_or(ResponseRefusal::RequestStringNotADictionary)
        .map_err(Box::new)
}

pub trait SigningTransport: Send + Sync {
    fn name(&self) -> &'static str;

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Copy, Debug)]
pub struct CurlSigningTransport {
    pub connect_timeout_secs: u32,
    pub max_time_secs: u32,
}

impl Default for CurlSigningTransport {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 30,
            max_time_secs: 300,
        }
    }
}

impl SigningTransport for CurlSigningTransport {
    fn name(&self) -> &'static str {
        "curl"
    }

    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        use std::io::Write;

        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(format!(
                "the signing server URL {url:?} names a scheme the submit does not accept"
            ));
        }
        let mut payload = tempfile::NamedTempFile::new()
            .map_err(|error| format!("the request body could not be staged: {error}"))?;
        payload
            .write_all(body)
            .and_then(|()| payload.flush())
            .map_err(|error| format!("the request body could not be written: {error}"))?;
        let payload_argument = format!(
            "@{}",
            payload
                .path()
                .to_str()
                .ok_or_else(|| String::from("the staged request body path is not UTF-8"))?
        );
        let output = std::process::Command::new("curl")
            .args([
                "-sS",
                "--fail-with-body",
                "--connect-timeout",
                &self.connect_timeout_secs.to_string(),
                "--max-time",
                &self.max_time_secs.to_string(),
                "--header",
                &format!("Content-Type: {content_type}"),
                "--header",
                "Pragma: no-cache",
                "--data-binary",
                &payload_argument,
                url,
            ])
            .output()
            .map_err(|error| format!("curl could not be run: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "curl exited {}: {}",
                output
                    .status
                    .code()
                    .map_or_else(|| "on a signal".to_string(), |code| code.to_string()),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(output.stdout)
    }
}

pub struct SigningServerSigner<T: SigningTransport> {
    transport: T,
    base_url: String,
    envelope: SigningEnvelope,
}

impl<T: SigningTransport> SigningServerSigner<T> {
    #[must_use]
    pub fn new(transport: T, base_url: String, envelope: SigningEnvelope) -> Self {
        Self {
            transport,
            base_url,
            envelope,
        }
    }

    #[must_use]
    pub fn url(&self) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{base}/{SIGNING_SERVER_REQUEST_PATH}")
    }
}

impl<T: SigningTransport> RecoveryOsLocalPolicySigner for SigningServerSigner<T> {
    fn source(&self) -> &'static str {
        self.transport.name()
    }

    fn personalize(&self, request: &plist::Dictionary) -> Result<plist::Dictionary, String> {
        let mut body = request.clone();
        body.insert(
            KEY_HOST_PLATFORM_INFO.to_string(),
            plist::Value::String(self.envelope.host_platform_info.clone()),
        );
        body.insert(
            KEY_VERSION_INFO.to_string(),
            plist::Value::String(self.envelope.version_info.clone()),
        );
        body.insert(KEY_BB_TICKET.to_string(), plist::Value::Boolean(true));
        if let Some(uuid) = &self.envelope.uuid {
            body.insert(KEY_UUID.to_string(), plist::Value::String(uuid.clone()));
        }
        let encoded = encode_signing_server_body(&body)?;
        let answer = self
            .transport
            .post(&self.url(), SIGNING_SERVER_CONTENT_TYPE, &encoded)?;
        parse_signing_server_response(&answer).map_err(|refusal| refusal.to_string())
    }
}

pub const SIGNING_ENVELOPE_VERSION_INFO: &str =
    concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));

pub fn signing_server_signer(
    session_uuid: Option<String>,
) -> Result<std::sync::Arc<dyn RecoveryOsLocalPolicySigner>, String> {
    let envelope = SigningEnvelope::for_this_host(SIGNING_ENVELOPE_VERSION_INFO, session_uuid)?;
    Ok(std::sync::Arc::new(SigningServerSigner::new(
        CurlSigningTransport::default(),
        SIGNING_SERVER_DEFAULT_BASE_URL.to_string(),
        envelope,
    )))
}

#[derive(Clone, Debug, Default)]
pub struct LocalPolicyCensus {
    counts: BTreeMap<&'static str, u64>,
}

impl LocalPolicyCensus {
    pub fn record(&mut self, name: &'static str) -> u64 {
        let slot = self.counts.entry(name).or_insert(0);
        *slot += 1;
        *slot
    }

    #[must_use]
    pub fn count(&self, name: &str) -> u64 {
        self.counts.get(name).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn rendered(&self) -> String {
        self.counts
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(identifier: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = identifier.to_vec();
        let length = body.len();
        if length < 0x80 {
            out.push(length as u8);
        } else if length < 0x100 {
            out.push(0x81);
            out.push(length as u8);
        } else {
            assert!(
                length < 0x1_0000,
                "the test builder writes at most two length bytes"
            );
            out.push(0x82);
            out.push((length >> 8) as u8);
            out.push((length & 0xff) as u8);
        }
        out.extend_from_slice(body);
        out
    }

    fn private_identifier(code: &str) -> Vec<u8> {
        let bytes = code.as_bytes();
        let mut value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
        let mut groups = Vec::new();
        loop {
            groups.push((value & 0x7f) as u8);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        groups.reverse();
        let mut identifier = vec![0xff];
        for (index, group) in groups.iter().enumerate() {
            if index + 1 == groups.len() {
                identifier.push(*group);
            } else {
                identifier.push(group | 0x80);
            }
        }
        identifier
    }

    fn ia5(text: &str) -> Vec<u8> {
        der(&[0x16], text.as_bytes())
    }

    fn property(code: &str, value: Vec<u8>) -> Vec<u8> {
        let mut inner = ia5(code);
        inner.extend_from_slice(&value);
        der(&private_identifier(code), &der(&[0x30], &inner))
    }

    fn block(code: &str, properties: Vec<u8>) -> Vec<u8> {
        let mut inner = ia5(code);
        inner.extend_from_slice(&der(&[0x31], &properties));
        der(&private_identifier(code), &der(&[0x30], &inner))
    }

    fn integer(value: &[u8]) -> Vec<u8> {
        der(&[0x02], value)
    }

    fn boolean(value: bool) -> Vec<u8> {
        der(&[0x01], &[if value { 0xff } else { 0x00 }])
    }

    fn manifest_bytes(properties: Vec<u8>) -> Vec<u8> {
        let entries = block("MANP", properties);
        let mut top = ia5("IM4M");
        top.extend_from_slice(&der(&[0x02], &[0x00]));
        top.extend_from_slice(&der(&[0x31], &block("MANB", entries)));
        top.extend_from_slice(&der(&[0x04], &[0xAA; 8]));
        der(&[0x30], &top)
    }

    const RECORDED_CHIP: &[u8] = &[0x81, 0x03];
    const RECORDED_BOARD: &[u8] = &[0x22];

    fn personalised_manifest(ecid: &[u8], extra: Vec<u8>) -> Vec<u8> {
        let mut properties = property("BORD", integer(RECORDED_BOARD));
        properties.extend_from_slice(&property("CHIP", integer(RECORDED_CHIP)));
        properties.extend_from_slice(&property("CPRO", boolean(true)));
        properties.extend_from_slice(&property("CSEC", boolean(true)));
        properties.extend_from_slice(&property("ECID", integer(ecid)));
        properties.extend_from_slice(&property("SDOM", integer(&[0x01])));
        properties.extend_from_slice(&extra);
        manifest_bytes(properties)
    }

    fn global_manifest() -> Vec<u8> {
        let mut properties = property("BORD", integer(RECORDED_BOARD));
        properties.extend_from_slice(&property("CHIP", integer(RECORDED_CHIP)));
        properties.extend_from_slice(&property("CPRO", boolean(true)));
        properties.extend_from_slice(&property("CSEC", boolean(true)));
        properties.extend_from_slice(&property("SDOM", integer(&[0x01])));
        manifest_bytes(properties)
    }

    const RECORDED_VOLUME_UUID: &str = "3D3287DE-280D-4619-AAAB-D97469CA9C71";

    const RECORDED_NEXT_STAGE_SHA384: [u8; 48] = [
        0x5a, 0xc5, 0x95, 0xf5, 0x73, 0x04, 0x33, 0x4a, 0xbf, 0x7a, 0x05, 0x46, 0xfd, 0x4c, 0xa4,
        0x0b, 0x1f, 0x87, 0x2c, 0xc2, 0x83, 0xf4, 0xe5, 0x19, 0x5b, 0xd3, 0xf9, 0x60, 0xfe, 0x9e,
        0x53, 0xe0, 0xff, 0x00, 0xb3, 0x34, 0x3d, 0x8e, 0xcf, 0xcb, 0xfc, 0xe6, 0x7a, 0xac, 0x36,
        0x54, 0x8e, 0x91,
    ];

    fn recorded_arguments(policy_nonce: &[u8]) -> plist::Dictionary {
        let mut arguments = plist::Dictionary::new();
        arguments.insert(
            KEY_AP_RECOVERY_OS_POLICY_NONCE_HASH.to_string(),
            plist::Value::Data(policy_nonce.to_vec()),
        );
        arguments.insert(
            KEY_AP_VOLUME_UUID.to_string(),
            plist::Value::String(RECORDED_VOLUME_UUID.to_string()),
        );
        arguments.insert(
            KEY_AP_NEXT_STAGE_IM4M_HASH.to_string(),
            plist::Value::Data(RECORDED_NEXT_STAGE_SHA384.to_vec()),
        );
        arguments
    }

    fn policy_nonce() -> Vec<u8> {
        (0u8..48)
            .map(|index| index.wrapping_mul(7).wrapping_add(3))
            .collect()
    }

    struct RecordingSigner {
        response: plist::Dictionary,
        seen: std::sync::Mutex<Vec<plist::Dictionary>>,
    }

    impl RecoveryOsLocalPolicySigner for RecordingSigner {
        fn source(&self) -> &'static str {
            "test-recorder"
        }

        fn personalize(&self, request: &plist::Dictionary) -> Result<plist::Dictionary, String> {
            self.seen
                .lock()
                .expect("the recorder mutex is not held across a panic")
                .push(request.clone());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn the_constant_payload_hashes_to_the_digest_the_request_carries() {
        assert_eq!(
            sha384(&RECOVERY_OS_LOCAL_POLICY_IM4P)[..],
            RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384[..],
            "the Digest term is the SHA-384 of the payload the stitch uses"
        );
    }

    #[test]
    fn the_recorded_volume_uuid_renders_the_sixteen_bytes_the_request_carries() {
        let bytes = volume_uuid_bytes(RECORDED_VOLUME_UUID)
            .expect("the recorded volume UUID parses the way uuid_parse parses it");
        assert_eq!(
            bytes,
            [
                0x3D, 0x32, 0x87, 0xDE, 0x28, 0x0D, 0x46, 0x19, 0xAA, 0xAB, 0xD9, 0x74, 0x69, 0xCA,
                0x9C, 0x71
            ]
        );
    }

    #[test]
    fn a_global_manifest_names_no_part_and_the_refusal_says_so() {
        let refusal = LocalPolicyIdentity::from_root_ticket(&global_manifest())
            .expect_err("a manifest with no ECID cannot be personalised");
        assert_eq!(
            refusal.name(),
            "recovery-os-local-policy-identity-not-personalisable"
        );
        let detail = refusal.to_string();
        assert!(detail.contains("CHIP=0x8103"), "{detail}");
        assert!(detail.contains("BORD=0x22"), "{detail}");
    }

    #[test]
    fn a_manifest_that_names_a_part_yields_every_identity_term() {
        let identity = LocalPolicyIdentity::from_root_ticket(&personalised_manifest(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            Vec::new(),
        ))
        .expect("a manifest carrying ECID names a part");
        assert_eq!(
            identity,
            LocalPolicyIdentity {
                ecid: 0x0011_2233_4455_6677,
                chip_id: 0x8103,
                board_id: 0x22,
                security_domain: 1,
                production_mode: true,
                security_mode: true,
            }
        );
    }

    #[test]
    fn the_request_carries_every_term_the_host_sets_and_nothing_else() {
        let identity = LocalPolicyIdentity::from_root_ticket(&personalised_manifest(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            Vec::new(),
        ))
        .expect("a manifest carrying ECID names a part");
        let inputs = RecoveryOsLocalPolicyInputs::read(&recorded_arguments(&policy_nonce()))
            .expect("the recorded arguments are the three terms the guest sends");
        let body = RecoveryOsLocalPolicyRequest::new(identity, inputs).body();

        let mut names: Vec<&str> = body.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "@ApImg4Ticket",
                "Ap,LocalBoot",
                "Ap,LocalPolicy",
                "Ap,NextStageIM4MHash",
                "Ap,RecoveryOSPolicyNonceHash",
                "Ap,VolumeUUID",
                "ApBoardID",
                "ApChipID",
                "ApECID",
                "ApProductionMode",
                "ApSecurityDomain",
                "ApSecurityMode",
            ],
            "the twelve terms 0x284248 and 0x28446c set between them"
        );

        assert_eq!(body["@ApImg4Ticket"].as_boolean(), Some(true));
        assert_eq!(body["Ap,LocalBoot"].as_boolean(), Some(true));
        assert_eq!(body["ApChipID"].as_signed_integer(), Some(0x8103));
        assert_eq!(body["ApBoardID"].as_signed_integer(), Some(0x22));
        assert_eq!(
            body["ApECID"].as_unsigned_integer(),
            Some(0x0011_2233_4455_6677)
        );
        assert_eq!(body["ApSecurityDomain"].as_signed_integer(), Some(1));
        assert_eq!(body["ApProductionMode"].as_boolean(), Some(true));
        assert_eq!(body["ApSecurityMode"].as_boolean(), Some(true));
        assert_eq!(
            body["Ap,NextStageIM4MHash"].as_data(),
            Some(&RECORDED_NEXT_STAGE_SHA384[..])
        );
        assert_eq!(
            body["Ap,RecoveryOSPolicyNonceHash"].as_data(),
            Some(&policy_nonce()[..])
        );
        assert_eq!(
            body["Ap,VolumeUUID"].as_data(),
            Some(
                &[
                    0x3D, 0x32, 0x87, 0xDE, 0x28, 0x0D, 0x46, 0x19, 0xAA, 0xAB, 0xD9, 0x74, 0x69,
                    0xCA, 0x9C, 0x71
                ][..]
            ),
            "the host sends the sixteen raw bytes, not the text the guest sent"
        );

        let policy = body["Ap,LocalPolicy"]
            .as_dictionary()
            .expect("Ap,LocalPolicy is the nested dictionary 0x2842e8 builds");
        assert_eq!(
            policy["Digest"].as_data(),
            Some(&RECOVERY_OS_LOCAL_POLICY_IM4P_SHA384[..])
        );
        assert_eq!(policy["Trusted"].as_boolean(), Some(true));
    }

    #[test]
    fn an_argument_of_the_wrong_length_is_refused_by_name() {
        let mut arguments = recorded_arguments(&policy_nonce());
        arguments.insert(
            KEY_AP_NEXT_STAGE_IM4M_HASH.to_string(),
            plist::Value::Data(vec![0u8; 20]),
        );
        let refusal = RecoveryOsLocalPolicyInputs::read(&arguments)
            .expect_err("a 20 byte next stage hash is not the 0x30 the host requires");
        assert_eq!(
            refusal.name(),
            "recovery-os-local-policy-argument-wrong-length"
        );
        assert!(refusal.to_string().contains("20 bytes"), "{refusal}");
    }

    #[test]
    fn a_bound_manifest_is_stitched_over_the_constant_payload() {
        let ecid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let identity =
            LocalPolicyIdentity::from_root_ticket(&personalised_manifest(&ecid, Vec::new()))
                .expect("a manifest carrying ECID names a part");
        let nonce = policy_nonce();
        let inputs = RecoveryOsLocalPolicyInputs::read(&recorded_arguments(&nonce))
            .expect("the recorded arguments are the three terms the guest sends");
        let request = RecoveryOsLocalPolicyRequest::new(identity, inputs);

        let mut bound = property(RECOVERY_OS_POLICY_NONCE_TAG, der(&[0x04], &nonce));
        bound.extend_from_slice(&property(
            NEXT_STAGE_IM4M_HASH_TAG,
            der(&[0x04], &RECORDED_NEXT_STAGE_SHA384),
        ));
        bound.extend_from_slice(&property(
            VOLUME_UUID_TAG,
            der(
                &[0x04],
                &volume_uuid_bytes(RECORDED_VOLUME_UUID).expect("the recorded UUID parses"),
            ),
        ));
        let signed = personalised_manifest(&ecid, bound);
        let mut response = plist::Dictionary::new();
        response.insert(
            KEY_RESPONSE_AP_IMG4_TICKET.to_string(),
            plist::Value::Data(signed.clone()),
        );
        let signer = RecordingSigner {
            response,
            seen: std::sync::Mutex::new(Vec::new()),
        };

        let policy = personalize(&signer, &request).expect("a bound manifest stitches");
        assert_eq!(policy.manifest, signed, "the manifest is served unmodified");
        assert_eq!(
            policy.binding,
            BindingReport {
                ecid: Some(true),
                chip: Some(true),
                board: Some(true),
                policy_nonce: Some(true),
                next_stage: Some(true),
                volume_uuid: Some(true),
            }
        );
        assert!(
            policy
                .image
                .windows(RECOVERY_OS_LOCAL_POLICY_IM4P.len())
                .any(|window| window == RECOVERY_OS_LOCAL_POLICY_IM4P),
            "the stitched object carries the constant lpol payload"
        );
        assert!(
            policy
                .image
                .windows(signed.len())
                .any(|window| window == signed),
            "the stitched object carries the signed manifest"
        );
        assert_eq!(
            signer
                .seen
                .lock()
                .expect("the recorder mutex is not held across a panic")
                .len(),
            1,
            "the request was issued exactly once"
        );
    }

    #[test]
    fn a_manifest_signed_for_another_part_is_refused_by_name() {
        let identity = LocalPolicyIdentity::from_root_ticket(&personalised_manifest(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            Vec::new(),
        ))
        .expect("a manifest carrying ECID names a part");
        let nonce = policy_nonce();
        let inputs = RecoveryOsLocalPolicyInputs::read(&recorded_arguments(&nonce))
            .expect("the recorded arguments are the three terms the guest sends");
        let request = RecoveryOsLocalPolicyRequest::new(identity, inputs);

        let other = personalised_manifest(
            &[0x07, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77],
            property("ronh", der(&[0x04], &nonce)),
        );
        let mut response = plist::Dictionary::new();
        response.insert(
            KEY_RESPONSE_AP_IMG4_TICKET.to_string(),
            plist::Value::Data(other),
        );
        let signer = RecordingSigner {
            response,
            seen: std::sync::Mutex::new(Vec::new()),
        };

        let refusal = personalize(&signer, &request)
            .expect_err("a manifest naming a different ECID does not answer this request");
        assert_eq!(
            refusal.name(),
            "recovery-os-local-policy-response-manifest-unbound"
        );
        assert!(refusal.to_string().contains("ECID"), "{refusal}");
    }

    #[test]
    fn a_manifest_bound_to_another_nonce_is_refused_by_name() {
        let ecid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let identity =
            LocalPolicyIdentity::from_root_ticket(&personalised_manifest(&ecid, Vec::new()))
                .expect("a manifest carrying ECID names a part");
        let inputs = RecoveryOsLocalPolicyInputs::read(&recorded_arguments(&policy_nonce()))
            .expect("the recorded arguments are the three terms the guest sends");
        let request = RecoveryOsLocalPolicyRequest::new(identity, inputs);

        let stale: Vec<u8> = (0u8..48).collect();
        let signed = personalised_manifest(&ecid, property("ronh", der(&[0x04], &stale)));
        let mut response = plist::Dictionary::new();
        response.insert(
            KEY_RESPONSE_AP_IMG4_TICKET.to_string(),
            plist::Value::Data(signed),
        );
        let signer = RecordingSigner {
            response,
            seen: std::sync::Mutex::new(Vec::new()),
        };

        let refusal = personalize(&signer, &request)
            .expect_err("a manifest bound to a different nonce does not answer this request");
        assert_eq!(
            refusal.name(),
            "recovery-os-local-policy-response-manifest-unbound"
        );
        assert!(
            refusal.to_string().contains(RECOVERY_OS_POLICY_NONCE_TAG),
            "{refusal}"
        );
    }

    struct RecordingTransport {
        answer: Vec<u8>,
        posted: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
    }

    impl SigningTransport for RecordingTransport {
        fn name(&self) -> &'static str {
            "test-transport"
        }

        fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
            self.posted
                .lock()
                .expect("the transport mutex is not held across a panic")
                .push((url.to_string(), content_type.to_string(), body.to_vec()));
            Ok(self.answer.clone())
        }
    }

    fn test_envelope() -> SigningEnvelope {
        SigningEnvelope {
            host_platform_info: "mac/25G90/Mac14,3".to_string(),
            version_info: "libauthinstall-1.0".to_string(),
            uuid: Some("11111111-2222-3333-4444-555555555555".to_string()),
        }
    }

    fn response_body(status: i64, message: &str, request_string: &str) -> Vec<u8> {
        format!("STATUS={status}&MESSAGE={message}&REQUEST_STRING={request_string}").into_bytes()
    }

    fn signed_response_plist(manifest: &[u8]) -> String {
        let mut answer = plist::Dictionary::new();
        answer.insert(
            KEY_RESPONSE_AP_IMG4_TICKET.to_string(),
            plist::Value::Data(manifest.to_vec()),
        );
        let mut bytes = Vec::new();
        plist::Value::Dictionary(answer)
            .to_writer_xml(&mut bytes)
            .expect("a dictionary writes as an XML plist");
        String::from_utf8(bytes).expect("plist XML is UTF-8")
    }

    #[test]
    fn the_url_is_the_base_with_the_submit_path_appended() {
        let signer = SigningServerSigner::new(
            RecordingTransport {
                answer: Vec::new(),
                posted: std::sync::Mutex::new(Vec::new()),
            },
            SIGNING_SERVER_DEFAULT_BASE_URL.to_string(),
            test_envelope(),
        );
        assert_eq!(
            signer.url(),
            "https://gs.apple.com:443/TSS/controller?action=2"
        );
    }

    #[test]
    fn the_wire_body_carries_the_envelope_terms_the_sender_adds() {
        let identity = LocalPolicyIdentity::from_root_ticket(&personalised_manifest(
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            Vec::new(),
        ))
        .expect("a manifest carrying ECID names a part");
        let inputs = RecoveryOsLocalPolicyInputs::read(&recorded_arguments(&policy_nonce()))
            .expect("the recorded arguments are the three terms the guest sends");
        let request = RecoveryOsLocalPolicyRequest::new(identity, inputs);
        let body = signing_server_body(&request, &test_envelope());

        assert_eq!(
            body["@HostPlatformInfo"].as_string(),
            Some("mac/25G90/Mac14,3")
        );
        assert_eq!(body["@VersionInfo"].as_string(), Some("libauthinstall-1.0"));
        assert_eq!(body["@BBTicket"].as_boolean(), Some(true));
        assert_eq!(
            body["@UUID"].as_string(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(
            body["ApECID"].as_unsigned_integer(),
            Some(0x0011_2233_4455_6677),
            "the envelope is added around the request rather than replacing it"
        );

        let encoded = encode_signing_server_body(&body).expect("the body writes as an XML plist");
        let text = String::from_utf8(encoded).expect("plist XML is UTF-8");
        assert!(
            text.starts_with("<?xml"),
            "the submit posts XML, not binary"
        );
        assert!(
            text.contains("<key>Ap,RecoveryOSPolicyNonceHash</key>"),
            "{text}"
        );
    }

    #[test]
    fn a_signing_server_answer_is_read_back_into_the_response_dictionary() {
        let manifest = personalised_manifest(
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            Vec::new(),
        );
        let body = response_body(0, "SUCCESS", &signed_response_plist(&manifest));
        let response =
            parse_signing_server_response(&body).expect("a STATUS=0 answer carries the plist");
        assert_eq!(
            response[KEY_RESPONSE_AP_IMG4_TICKET].as_data(),
            Some(&manifest[..])
        );
    }

    #[test]
    fn an_answer_with_a_nonzero_status_is_refused_by_name_and_carries_its_message() {
        let body = response_body(
            94,
            "This device isn't eligible for the requested build.",
            "",
        );
        let refusal = parse_signing_server_response(&body)
            .expect_err("a nonzero STATUS is the server declining");
        assert_eq!(refusal.name(), "recovery-os-local-policy-response-status");
        let detail = refusal.to_string();
        assert!(detail.contains("STATUS=94"), "{detail}");
        assert!(
            detail.contains("This device isn't eligible for the requested build."),
            "{detail}"
        );
    }

    #[test]
    fn an_answer_past_the_submits_cap_is_refused_by_name() {
        let body = vec![b'x'; SIGNING_SERVER_MAX_RESPONSE_BYTES + 1];
        let refusal = parse_signing_server_response(&body)
            .expect_err("the submit caps a response at 0x19000 bytes");
        assert_eq!(
            refusal.name(),
            "recovery-os-local-policy-response-too-large"
        );
        assert!(
            refusal
                .to_string()
                .contains(&SIGNING_SERVER_MAX_RESPONSE_BYTES.to_string()),
            "{refusal}"
        );
    }

    #[test]
    fn the_signer_posts_the_xml_body_to_the_submit_url_and_stitches_the_answer() {
        let ecid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let identity =
            LocalPolicyIdentity::from_root_ticket(&personalised_manifest(&ecid, Vec::new()))
                .expect("a manifest carrying ECID names a part");
        let nonce = policy_nonce();
        let inputs = RecoveryOsLocalPolicyInputs::read(&recorded_arguments(&nonce))
            .expect("the recorded arguments are the three terms the guest sends");
        let request = RecoveryOsLocalPolicyRequest::new(identity, inputs);

        let mut bound = property(RECOVERY_OS_POLICY_NONCE_TAG, der(&[0x04], &nonce));
        bound.extend_from_slice(&property(
            NEXT_STAGE_IM4M_HASH_TAG,
            der(&[0x04], &RECORDED_NEXT_STAGE_SHA384),
        ));
        bound.extend_from_slice(&property(
            VOLUME_UUID_TAG,
            der(
                &[0x04],
                &volume_uuid_bytes(RECORDED_VOLUME_UUID).expect("the recorded UUID parses"),
            ),
        ));
        let signed = personalised_manifest(&ecid, bound);

        let transport = RecordingTransport {
            answer: response_body(0, "SUCCESS", &signed_response_plist(&signed)),
            posted: std::sync::Mutex::new(Vec::new()),
        };
        let signer = SigningServerSigner::new(
            transport,
            SIGNING_SERVER_DEFAULT_BASE_URL.to_string(),
            test_envelope(),
        );

        let policy = personalize(&signer, &request).expect("a bound answer stitches");
        assert_eq!(policy.manifest, signed);
        assert_eq!(policy.source, "test-transport");
        assert!(
            policy
                .image
                .windows(RECOVERY_OS_LOCAL_POLICY_IM4P.len())
                .any(|window| window == RECOVERY_OS_LOCAL_POLICY_IM4P)
        );
    }

    #[test]
    fn every_decline_is_counted_under_its_own_name() {
        let mut census = LocalPolicyCensus::default();
        assert_eq!(census.record(SigningRefusal::ServiceAbsent.name()), 1);
        assert_eq!(census.record(SigningRefusal::ServiceAbsent.name()), 2);
        assert_eq!(
            census.record(
                IdentityRefusal::NotPersonalisable {
                    chip: None,
                    board: None,
                    board_tag: None
                }
                .name()
            ),
            1
        );
        assert_eq!(
            census.count("recovery-os-local-policy-signing-service-absent"),
            2
        );
        assert_eq!(
            census.rendered(),
            "recovery-os-local-policy-identity-not-personalisable=1,recovery-os-local-policy-signing-service-absent=2"
        );
    }

    #[test]
    fn the_absent_service_decline_names_how_to_arm_it() {
        let rendered = SigningRefusal::ServiceAbsent.to_string();
        assert!(
            rendered.contains(SIGNING_OPT_IN_FLAG),
            "the decline names the command line flag: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "press {SIGNING_OPT_IN_KEY} on the recovery screen"
            )),
            "the decline names the screen key: {rendered}"
        );
        assert!(
            rendered.contains(SIGNING_SERVER_DEFAULT_BASE_URL),
            "the decline names where arming would send the request: {rendered}"
        );
        assert!(
            rendered.contains("ECID"),
            "the decline names what arming puts on the wire: {rendered}"
        );
        assert_eq!(
            SigningRefusal::ServiceAbsent.name(),
            "recovery-os-local-policy-signing-service-absent",
            "the name the decline is counted under does not move with its wording"
        );
    }

    #[test]
    fn the_armed_signer_is_built_from_this_host_without_issuing_anything() {
        let signer = signing_server_signer(Some("SESSION-UUID".to_string()))
            .expect("this host can read kern.osversion and its hardware name");
        assert_eq!(signer.source(), "curl");
        assert!(
            SIGNING_ENVELOPE_VERSION_INFO.starts_with(env!("CARGO_PKG_NAME")),
            "the version term is this binary's own: {SIGNING_ENVELOPE_VERSION_INFO}"
        );
    }
}
