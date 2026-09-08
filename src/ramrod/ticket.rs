use std::fmt;

pub const MANIFEST_BODY_TAG: &str = "MANB";

pub const MANIFEST_PROPERTIES_TAG: &str = "MANP";

pub const DIGEST_PROPERTY_TAG: &str = "DGST";

pub const CHIP_IDENTITY_PROPERTY_TAG: &str = "ECID";

pub const BOARD_TAG_PROPERTY_TAG: &str = "tagt";

pub const CHIP_PROPERTY_TAG: &str = "CHIP";

pub const BOARD_PROPERTY_TAG: &str = "BORD";

pub const RESTORE_FDR_TRUST_OBJECT_TAG: &str = "rfta";

pub const BOOTED_OS_FDR_TRUST_OBJECT_TAG: &str = "ftap";

pub const FDR_TRUST_OBJECT_TAGS: [&str; 2] =
    [RESTORE_FDR_TRUST_OBJECT_TAG, BOOTED_OS_FDR_TRUST_OBJECT_TAG];

pub const BOOT_NONCE_HASH_PROPERTY_TAG: &str = "BNCH";

pub const BOOT_NONCE_HASH_BYTES: usize = 32;

const CLASS_PRIVATE: u8 = 3;

const CLASS_UNIVERSAL: u8 = 0;

const TAG_BOOLEAN: u64 = 1;
const TAG_INTEGER: u64 = 2;
const TAG_OCTET_STRING: u64 = 4;
const TAG_NULL: u64 = 5;
const TAG_IA5_STRING: u64 = 22;
const TAG_SEQUENCE: u64 = 16;
const TAG_SET: u64 = 17;

const HIGH_TAG_NUMBER_FORM: u8 = 0x1f;

const MAX_LENGTH_BYTES: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum TicketError {
    Truncated {
        at: usize,
    },
    BadLength {
        at: usize,
    },
    Unexpected {
        at: usize,
        wanted: &'static str,
        found: String,
    },
    NotAManifest,
    TagMismatch {
        tag: String,
        inner: String,
    },
    NoManifestBody,
    NoManifestProperties,
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "manifest truncated at byte {at}"),
            Self::BadLength { at } => write!(f, "unusable DER length at byte {at}"),
            Self::Unexpected { at, wanted, found } => {
                write!(f, "wanted {wanted} at byte {at}, found {found}")
            }
            Self::NotAManifest => write!(f, "the bytes are not an IM4M manifest"),
            Self::TagMismatch { tag, inner } => {
                write!(f, "private tag {tag} wraps a body naming {inner}")
            }
            Self::NoManifestBody => write!(f, "the manifest carries no {MANIFEST_BODY_TAG} body"),
            Self::NoManifestProperties => write!(
                f,
                "the manifest body carries no {MANIFEST_PROPERTIES_TAG} properties block"
            ),
        }
    }
}

impl std::error::Error for TicketError {}

#[derive(Clone, Copy, Debug)]
struct Element {
    class: u8,
    constructed: bool,
    tag: u64,
    body: (usize, usize),
    end: usize,
}

impl Element {
    fn is(&self, class: u8, tag: u64) -> bool {
        self.class == class && self.tag == tag
    }

    fn describe(&self) -> String {
        match four_character_code(self.tag) {
            Some(code) if self.class == CLASS_PRIVATE => format!("private '{code}'"),
            _ => format!("class {} tag {}", self.class, self.tag),
        }
    }
}

fn read_element(bytes: &[u8], at: usize, limit: usize) -> Result<Element, TicketError> {
    let mut cursor = at;
    let identifier = *bytes.get(cursor).ok_or(TicketError::Truncated { at })?;
    cursor += 1;
    let class = identifier >> 6;
    let constructed = (identifier >> 5) & 1 == 1;
    let mut tag = u64::from(identifier & HIGH_TAG_NUMBER_FORM);
    if tag == u64::from(HIGH_TAG_NUMBER_FORM) {
        tag = 0;
        loop {
            let byte = *bytes
                .get(cursor)
                .ok_or(TicketError::Truncated { at: cursor })?;
            cursor += 1;
            if tag > u64::MAX >> 7 {
                return Err(TicketError::BadLength { at });
            }
            tag = (tag << 7) | u64::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let first_length = *bytes
        .get(cursor)
        .ok_or(TicketError::Truncated { at: cursor })?;
    cursor += 1;
    let length = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > MAX_LENGTH_BYTES {
            return Err(TicketError::BadLength { at: cursor - 1 });
        }
        let mut value = 0usize;
        for offset in 0..count {
            let byte = *bytes.get(cursor + offset).ok_or(TicketError::Truncated {
                at: cursor + offset,
            })?;
            value = (value << 8) | usize::from(byte);
        }
        cursor += count;
        value
    };
    let end = cursor
        .checked_add(length)
        .ok_or(TicketError::BadLength { at })?;
    if end > limit || end > bytes.len() {
        return Err(TicketError::BadLength { at });
    }
    Ok(Element {
        class,
        constructed,
        tag,
        body: (cursor, end),
        end,
    })
}

fn children(bytes: &[u8], body: (usize, usize)) -> Result<Vec<Element>, TicketError> {
    let (mut cursor, limit) = body;
    let mut found = Vec::new();
    while cursor < limit {
        let element = read_element(bytes, cursor, limit)?;
        cursor = element.end;
        found.push(element);
    }
    Ok(found)
}

fn four_character_code(tag: u64) -> Option<String> {
    if tag > u64::from(u32::MAX) {
        return None;
    }
    let word = tag as u32;
    let bytes = word.to_be_bytes();
    if bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropertyValue {
    Boolean(bool),
    Integer(Vec<u8>),
    Bytes(Vec<u8>),
    Text(String),
    Null,
    Other { der_tag: u64, bytes: Vec<u8> },
    Absent,
}

impl PropertyValue {
    #[must_use]
    pub fn is_present(&self) -> bool {
        !matches!(self, Self::Null | Self::Absent)
    }

    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_ascii_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Bytes(bytes) if is_printable_ascii(bytes) => std::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_integer(&self) -> Option<u64> {
        match self {
            Self::Integer(bytes) => {
                let trimmed: &[u8] = bytes.split_first().map_or(bytes, |(first, rest)| {
                    if *first == 0 && !rest.is_empty() {
                        rest
                    } else {
                        bytes
                    }
                });
                if trimmed.len() > 8 {
                    return None;
                }
                let mut value = 0u64;
                for byte in trimmed {
                    value = (value << 8) | u64::from(*byte);
                }
                Some(value)
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Boolean(value) => value.to_string(),
            Self::Integer(_) => self
                .as_integer()
                .map_or_else(|| "integer".to_string(), |value| format!("0x{value:x}")),
            Self::Bytes(bytes) => {
                if is_printable_ascii(bytes) {
                    String::from_utf8_lossy(bytes).into_owned()
                } else {
                    format!("{}-bytes", bytes.len())
                }
            }
            Self::Text(text) => text.clone(),
            Self::Null => "null".to_string(),
            Self::Other { der_tag, bytes } => format!("der{der_tag}-{}-bytes", bytes.len()),
            Self::Absent => "absent".to_string(),
        }
    }
}

fn is_printable_ascii(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| (0x20..0x7f).contains(byte))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Im4mProperty {
    pub tag: String,
    pub value: PropertyValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Im4mObject {
    pub tag: String,
    pub properties: Vec<Im4mProperty>,
}

impl Im4mObject {
    #[must_use]
    pub fn property(&self, tag: &str) -> Option<&Im4mProperty> {
        self.properties.iter().find(|property| property.tag == tag)
    }

    #[must_use]
    pub fn digest(&self) -> Option<&[u8]> {
        self.property(DIGEST_PROPERTY_TAG)
            .and_then(|property| property.value.as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Im4mManifest {
    pub properties: Vec<Im4mProperty>,
    pub objects: Vec<Im4mObject>,
}

impl Im4mManifest {
    #[must_use]
    pub fn property(&self, tag: &str) -> Option<&Im4mProperty> {
        self.properties.iter().find(|property| property.tag == tag)
    }

    #[must_use]
    pub fn object(&self, tag: &str) -> Option<&Im4mObject> {
        self.objects.iter().find(|object| object.tag == tag)
    }

    #[must_use]
    pub fn object_tags(&self) -> Vec<String> {
        self.objects
            .iter()
            .map(|object| object.tag.clone())
            .collect()
    }

    #[must_use]
    pub fn is_personalised(&self) -> bool {
        self.property(CHIP_IDENTITY_PROPERTY_TAG)
            .is_some_and(|property| property.value.is_present())
    }

    #[must_use]
    pub fn board_tag(&self) -> Option<&str> {
        self.property(BOARD_TAG_PROPERTY_TAG)
            .and_then(|property| property.value.as_ascii_text())
    }

    #[must_use]
    pub fn chip(&self) -> Option<u64> {
        self.property(CHIP_PROPERTY_TAG)
            .and_then(|property| property.value.as_integer())
    }

    #[must_use]
    pub fn board(&self) -> Option<u64> {
        self.property(BOARD_PROPERTY_TAG)
            .and_then(|property| property.value.as_integer())
    }

    #[must_use]
    pub fn boot_nonce_hash(&self) -> Option<&[u8]> {
        self.property(BOOT_NONCE_HASH_PROPERTY_TAG)
            .and_then(|property| property.value.as_bytes())
    }

    #[must_use]
    pub fn missing_objects<'a>(&self, required: &[&'a str]) -> Vec<&'a str> {
        required
            .iter()
            .copied()
            .filter(|tag| self.object(tag).is_none())
            .collect()
    }

    #[must_use]
    pub fn missing_fdr_trust_objects(&self) -> Vec<&'static str> {
        FDR_TRUST_OBJECT_TAGS
            .iter()
            .copied()
            .filter(|tag| {
                self.object(tag)
                    .is_none_or(|object| object.digest().is_none())
            })
            .collect()
    }
}

fn read_properties(bytes: &[u8], set: Element) -> Result<Vec<Im4mProperty>, TicketError> {
    let mut properties = Vec::new();
    for entry in children(bytes, set.body)? {
        if entry.class != CLASS_PRIVATE {
            return Err(TicketError::Unexpected {
                at: entry.body.0,
                wanted: "a private property tag",
                found: entry.describe(),
            });
        }
        let (tag, elements) = read_named_body(bytes, entry)?;
        let value = match elements.first() {
            None => PropertyValue::Absent,
            Some(element) => read_value(bytes, *element)?,
        };
        properties.push(Im4mProperty { tag, value });
    }
    Ok(properties)
}

fn read_value(bytes: &[u8], element: Element) -> Result<PropertyValue, TicketError> {
    let body = &bytes[element.body.0..element.body.1];
    if element.class == CLASS_UNIVERSAL {
        return Ok(match element.tag {
            TAG_BOOLEAN => PropertyValue::Boolean(body.first().is_some_and(|byte| *byte != 0)),
            TAG_INTEGER => PropertyValue::Integer(body.to_vec()),
            TAG_OCTET_STRING => PropertyValue::Bytes(body.to_vec()),
            TAG_NULL => PropertyValue::Null,
            TAG_IA5_STRING => PropertyValue::Text(String::from_utf8_lossy(body).into_owned()),
            other => PropertyValue::Other {
                der_tag: other,
                bytes: body.to_vec(),
            },
        });
    }
    if element.constructed {
        let inner = children(bytes, element.body)?;
        if inner.len() == 1 {
            return read_value(bytes, inner[0]);
        }
    }
    Ok(PropertyValue::Other {
        der_tag: element.tag,
        bytes: body.to_vec(),
    })
}

fn read_named_body(bytes: &[u8], element: Element) -> Result<(String, Vec<Element>), TicketError> {
    let tag_code = four_character_code(element.tag).ok_or_else(|| TicketError::Unexpected {
        at: element.body.0,
        wanted: "a four character code tag",
        found: element.describe(),
    })?;
    let inner = children(bytes, element.body)?;
    let sequence = inner
        .first()
        .copied()
        .ok_or(TicketError::Truncated { at: element.body.0 })?;
    if !sequence.is(CLASS_UNIVERSAL, TAG_SEQUENCE) {
        return Err(TicketError::Unexpected {
            at: sequence.body.0,
            wanted: "a SEQUENCE",
            found: sequence.describe(),
        });
    }
    let mut parts = children(bytes, sequence.body)?;
    if parts.is_empty() {
        return Err(TicketError::Truncated {
            at: sequence.body.0,
        });
    }
    let name = parts.remove(0);
    if !name.is(CLASS_UNIVERSAL, TAG_IA5_STRING) {
        return Err(TicketError::Unexpected {
            at: name.body.0,
            wanted: "an IA5String name",
            found: name.describe(),
        });
    }
    let inner_code = String::from_utf8_lossy(&bytes[name.body.0..name.body.1]).into_owned();
    if inner_code != tag_code {
        return Err(TicketError::TagMismatch {
            tag: tag_code,
            inner: inner_code,
        });
    }
    Ok((tag_code, parts))
}

pub fn read_manifest(bytes: &[u8]) -> Result<Im4mManifest, TicketError> {
    let outer = read_element(bytes, 0, bytes.len())?;
    if !outer.is(CLASS_UNIVERSAL, TAG_SEQUENCE) {
        return Err(TicketError::NotAManifest);
    }
    let top = children(bytes, outer.body)?;
    let names_itself = top.iter().any(|element| {
        element.is(CLASS_UNIVERSAL, TAG_IA5_STRING)
            && &bytes[element.body.0..element.body.1] == b"IM4M"
    });
    if !names_itself {
        return Err(TicketError::NotAManifest);
    }
    let body_tag = find_manifest_body(bytes, &top)?;
    let (_, parts) = read_named_body(bytes, body_tag)?;
    let set = parts.first().copied().ok_or(TicketError::NoManifestBody)?;
    if !set.is(CLASS_UNIVERSAL, TAG_SET) {
        return Err(TicketError::Unexpected {
            at: set.body.0,
            wanted: "a SET of manifest entries",
            found: set.describe(),
        });
    }

    let mut properties = Vec::new();
    let mut objects = Vec::new();
    for entry in children(bytes, set.body)? {
        if entry.class != CLASS_PRIVATE {
            return Err(TicketError::Unexpected {
                at: entry.body.0,
                wanted: "a private manifest entry",
                found: entry.describe(),
            });
        }
        let (tag, parts) = read_named_body(bytes, entry)?;
        let inner = parts
            .first()
            .copied()
            .ok_or(TicketError::Truncated { at: entry.body.0 })?;
        if !inner.is(CLASS_UNIVERSAL, TAG_SET) {
            return Err(TicketError::Unexpected {
                at: inner.body.0,
                wanted: "a SET of properties",
                found: inner.describe(),
            });
        }
        let decoded = read_properties(bytes, inner)?;
        if tag == MANIFEST_PROPERTIES_TAG {
            properties = decoded;
        } else {
            objects.push(Im4mObject {
                tag,
                properties: decoded,
            });
        }
    }
    Ok(Im4mManifest {
        properties,
        objects,
    })
}

fn find_manifest_body(bytes: &[u8], top: &[Element]) -> Result<Element, TicketError> {
    for element in top {
        if element.class == CLASS_PRIVATE
            && four_character_code(element.tag).as_deref() == Some(MANIFEST_BODY_TAG)
        {
            return Ok(*element);
        }
        if element.is(CLASS_UNIVERSAL, TAG_SET) {
            for inner in children(bytes, element.body)? {
                if inner.class == CLASS_PRIVATE
                    && four_character_code(inner.tag).as_deref() == Some(MANIFEST_BODY_TAG)
                {
                    return Ok(inner);
                }
            }
        }
    }
    Err(TicketError::NoManifestBody)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketFlavour {
    Personalised,
    Global,
}

impl TicketFlavour {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Personalised => "personalised",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketAudit {
    pub byte_len: usize,
    pub flavour: TicketFlavour,
    pub board_tag: Option<String>,
    pub chip: Option<u64>,
    pub object_tags: Vec<String>,
    pub missing: Vec<String>,
    pub boot_nonce_hash_len: Option<usize>,
}

impl TicketAudit {
    #[must_use]
    pub fn satisfies_requirements(&self) -> bool {
        self.missing.is_empty()
    }

    #[must_use]
    pub fn carries_boot_nonce_hash(&self) -> bool {
        self.boot_nonce_hash_len == Some(BOOT_NONCE_HASH_BYTES)
    }

    #[must_use]
    pub fn trace_fields(&self) -> String {
        format!(
            "flavour={} board={} chip={} bytes={} objects={} missing=[{}] boot_nonce={} meaning=\"the ticket on the wire is read back here so what it authorises is known at the moment it is served; missing names objects the restore will read out of it and not find, and any entry there fails the step that reads it long after this line; boot_nonce is the BNCH manifest property, absent on every global manifest, and its absence fails install_splat at checkpoint 0x06A6 with 'failed to get BNCH from SFR manifest'\" detail=\"tags=[{}]\"",
            self.flavour.label(),
            self.board_tag.as_deref().unwrap_or("none"),
            self.chip
                .map_or_else(|| "none".to_string(), |chip| format!("0x{chip:x}")),
            self.byte_len,
            self.object_tags.len(),
            self.missing.join(","),
            self.boot_nonce_hash_len
                .map_or_else(|| "absent".to_string(), |len| format!("{len}bytes")),
            self.object_tags.join(",")
        )
    }
}

pub fn audit_ticket(bytes: &[u8], required: &[&str]) -> Result<TicketAudit, TicketError> {
    let manifest = read_manifest(bytes)?;
    let missing = required
        .iter()
        .copied()
        .filter(|tag| {
            manifest
                .object(tag)
                .is_none_or(|object| object.digest().is_none())
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    Ok(TicketAudit {
        byte_len: bytes.len(),
        flavour: if manifest.is_personalised() {
            TicketFlavour::Personalised
        } else {
            TicketFlavour::Global
        },
        board_tag: manifest.board_tag().map(str::to_string),
        chip: manifest.chip(),
        object_tags: manifest.object_tags(),
        missing,
        boot_nonce_hash_len: manifest.boot_nonce_hash().map(<[u8]>::len),
    })
}

const DER_SEQUENCE_IDENTIFIER: u8 = 0x30;
const DER_SET_IDENTIFIER: u8 = 0x31;
const DER_IA5_IDENTIFIER: u8 = 0x16;
const DER_OCTET_IDENTIFIER: u8 = 0x04;

fn fourcc_private_identifier(code: &str) -> Vec<u8> {
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
    let mut identifier = vec![HIGH_TAG_NUMBER_FORM | (CLASS_PRIVATE << 6) | 0x20];
    for (index, group) in groups.iter().enumerate() {
        if index + 1 == groups.len() {
            identifier.push(*group);
        } else {
            identifier.push(group | 0x80);
        }
    }
    identifier
}

fn der_encode(identifier: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = identifier.to_vec();
    let length = body.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let digits = length.to_be_bytes();
        let first = digits
            .iter()
            .position(|digit| *digit != 0)
            .unwrap_or(digits.len() - 1);
        let significant = &digits[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(body);
    out
}

fn encode_fdr_trust_object(tag: &str, digest: &[u8; 32]) -> Vec<u8> {
    let digest_seq = {
        let mut body = der_encode(&[DER_IA5_IDENTIFIER], DIGEST_PROPERTY_TAG.as_bytes());
        body.extend_from_slice(&der_encode(&[DER_OCTET_IDENTIFIER], digest));
        der_encode(&[DER_SEQUENCE_IDENTIFIER], &body)
    };
    let digest_property = der_encode(&fourcc_private_identifier(DIGEST_PROPERTY_TAG), &digest_seq);
    let property_set = der_encode(&[DER_SET_IDENTIFIER], &digest_property);
    let mut object_seq_body = der_encode(&[DER_IA5_IDENTIFIER], tag.as_bytes());
    object_seq_body.extend_from_slice(&property_set);
    let object_seq = der_encode(&[DER_SEQUENCE_IDENTIFIER], &object_seq_body);
    der_encode(&fourcc_private_identifier(tag), &object_seq)
}

fn rebuild_manifest_body(
    bytes: &[u8],
    manb: &Element,
    add: &[&str],
    digest: &[u8; 32],
) -> Result<Vec<u8>, TicketError> {
    let (_, parts) = read_named_body(bytes, *manb)?;
    let set = parts.first().copied().ok_or(TicketError::NoManifestBody)?;
    if !set.is(CLASS_UNIVERSAL, TAG_SET) {
        return Err(TicketError::Unexpected {
            at: set.body.0,
            wanted: "a SET of manifest entries",
            found: set.describe(),
        });
    }
    let mut set_body = bytes[set.body.0..set.body.1].to_vec();
    for tag in add {
        set_body.extend_from_slice(&encode_fdr_trust_object(tag, digest));
    }
    let new_set = der_encode(&[DER_SET_IDENTIFIER], &set_body);
    let mut seq_body = der_encode(&[DER_IA5_IDENTIFIER], MANIFEST_BODY_TAG.as_bytes());
    seq_body.extend_from_slice(&new_set);
    let new_seq = der_encode(&[DER_SEQUENCE_IDENTIFIER], &seq_body);
    Ok(der_encode(
        &fourcc_private_identifier(MANIFEST_BODY_TAG),
        &new_seq,
    ))
}

fn child_spans(body_start: usize, kids: &[Element]) -> Vec<(usize, usize)> {
    let mut cursor = body_start;
    kids.iter()
        .map(|kid| {
            let span = (cursor, kid.end);
            cursor = kid.end;
            span
        })
        .collect()
}

fn carries_manifest_body(bytes: &[u8], element: &Element) -> Result<bool, TicketError> {
    if element.class == CLASS_PRIVATE
        && four_character_code(element.tag).as_deref() == Some(MANIFEST_BODY_TAG)
    {
        return Ok(true);
    }
    if element.is(CLASS_UNIVERSAL, TAG_SET) {
        for inner in children(bytes, element.body)? {
            if inner.class == CLASS_PRIVATE
                && four_character_code(inner.tag).as_deref() == Some(MANIFEST_BODY_TAG)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn add_fdr_trust_objects(bytes: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, TicketError> {
    let manifest = read_manifest(bytes)?;
    let missing: Vec<&str> = FDR_TRUST_OBJECT_TAGS
        .iter()
        .copied()
        .filter(|tag| manifest.object(tag).is_none())
        .collect();
    if missing.is_empty() {
        return Ok(bytes.to_vec());
    }
    rebuild_outer(bytes, |source, manb| {
        rebuild_manifest_body(source, manb, &missing, digest)
    })
}

fn rebuild_outer<F>(bytes: &[u8], rebuild_body: F) -> Result<Vec<u8>, TicketError>
where
    F: Fn(&[u8], &Element) -> Result<Vec<u8>, TicketError>,
{
    let outer = read_element(bytes, 0, bytes.len())?;
    if !outer.is(CLASS_UNIVERSAL, TAG_SEQUENCE) {
        return Err(TicketError::NotAManifest);
    }
    let kids = children(bytes, outer.body)?;
    let spans = child_spans(outer.body.0, &kids);

    let mut rebuilt = Vec::new();
    let mut replaced = false;
    for (kid, &(start, end)) in kids.iter().zip(spans.iter()) {
        if !replaced && carries_manifest_body(bytes, kid)? {
            if kid.class == CLASS_PRIVATE {
                rebuilt.extend_from_slice(&rebuild_body(bytes, kid)?);
            } else {
                let inner = children(bytes, kid.body)?;
                let inner_spans = child_spans(kid.body.0, &inner);
                let mut set_body = Vec::new();
                for (entry, &(estart, eend)) in inner.iter().zip(inner_spans.iter()) {
                    if entry.class == CLASS_PRIVATE
                        && four_character_code(entry.tag).as_deref() == Some(MANIFEST_BODY_TAG)
                    {
                        set_body.extend_from_slice(&rebuild_body(bytes, entry)?);
                    } else {
                        set_body.extend_from_slice(&bytes[estart..eend]);
                    }
                }
                rebuilt.extend_from_slice(&der_encode(&[DER_SET_IDENTIFIER], &set_body));
            }
            replaced = true;
        } else {
            rebuilt.extend_from_slice(&bytes[start..end]);
        }
    }
    if !replaced {
        return Err(TicketError::NoManifestBody);
    }
    Ok(der_encode(&[DER_SEQUENCE_IDENTIFIER], &rebuilt))
}

fn encode_octet_string_property(tag: &str, value: &[u8]) -> Vec<u8> {
    let mut sequence_body = der_encode(&[DER_IA5_IDENTIFIER], tag.as_bytes());
    sequence_body.extend_from_slice(&der_encode(&[DER_OCTET_IDENTIFIER], value));
    let sequence = der_encode(&[DER_SEQUENCE_IDENTIFIER], &sequence_body);
    der_encode(&fourcc_private_identifier(tag), &sequence)
}

fn rebuild_manifest_properties(
    bytes: &[u8],
    manp: &Element,
    nonce: &[u8; BOOT_NONCE_HASH_BYTES],
) -> Result<Vec<u8>, TicketError> {
    let (_, parts) = read_named_body(bytes, *manp)?;
    let set = parts
        .first()
        .copied()
        .ok_or(TicketError::NoManifestProperties)?;
    if !set.is(CLASS_UNIVERSAL, TAG_SET) {
        return Err(TicketError::Unexpected {
            at: set.body.0,
            wanted: "a SET of properties",
            found: set.describe(),
        });
    }
    let entries = children(bytes, set.body)?;
    let spans = child_spans(set.body.0, &entries);
    let staged = encode_octet_string_property(BOOT_NONCE_HASH_PROPERTY_TAG, nonce);
    let mut set_body = Vec::new();
    let mut written = false;
    for (entry, &(start, end)) in entries.iter().zip(spans.iter()) {
        let code = four_character_code(entry.tag);
        if code.as_deref() == Some(BOOT_NONCE_HASH_PROPERTY_TAG) {
            if !written {
                set_body.extend_from_slice(&staged);
                written = true;
            }
            continue;
        }
        if !written
            && code
                .as_deref()
                .is_some_and(|code| code > BOOT_NONCE_HASH_PROPERTY_TAG)
        {
            set_body.extend_from_slice(&staged);
            written = true;
        }
        set_body.extend_from_slice(&bytes[start..end]);
    }
    if !written {
        set_body.extend_from_slice(&staged);
    }
    let new_set = der_encode(&[DER_SET_IDENTIFIER], &set_body);
    let mut sequence_body = der_encode(&[DER_IA5_IDENTIFIER], MANIFEST_PROPERTIES_TAG.as_bytes());
    sequence_body.extend_from_slice(&new_set);
    let sequence = der_encode(&[DER_SEQUENCE_IDENTIFIER], &sequence_body);
    Ok(der_encode(
        &fourcc_private_identifier(MANIFEST_PROPERTIES_TAG),
        &sequence,
    ))
}

fn rebuild_manifest_body_with_boot_nonce(
    bytes: &[u8],
    manb: &Element,
    nonce: &[u8; BOOT_NONCE_HASH_BYTES],
) -> Result<Vec<u8>, TicketError> {
    let (_, parts) = read_named_body(bytes, *manb)?;
    let set = parts.first().copied().ok_or(TicketError::NoManifestBody)?;
    if !set.is(CLASS_UNIVERSAL, TAG_SET) {
        return Err(TicketError::Unexpected {
            at: set.body.0,
            wanted: "a SET of manifest entries",
            found: set.describe(),
        });
    }
    let entries = children(bytes, set.body)?;
    let spans = child_spans(set.body.0, &entries);
    let mut set_body = Vec::new();
    let mut replaced = false;
    for (entry, &(start, end)) in entries.iter().zip(spans.iter()) {
        if !replaced
            && entry.class == CLASS_PRIVATE
            && four_character_code(entry.tag).as_deref() == Some(MANIFEST_PROPERTIES_TAG)
        {
            set_body.extend_from_slice(&rebuild_manifest_properties(bytes, entry, nonce)?);
            replaced = true;
        } else {
            set_body.extend_from_slice(&bytes[start..end]);
        }
    }
    if !replaced {
        return Err(TicketError::NoManifestProperties);
    }
    let new_set = der_encode(&[DER_SET_IDENTIFIER], &set_body);
    let mut sequence_body = der_encode(&[DER_IA5_IDENTIFIER], MANIFEST_BODY_TAG.as_bytes());
    sequence_body.extend_from_slice(&new_set);
    let sequence = der_encode(&[DER_SEQUENCE_IDENTIFIER], &sequence_body);
    Ok(der_encode(
        &fourcc_private_identifier(MANIFEST_BODY_TAG),
        &sequence,
    ))
}

// AP root ticket only: the Image4 monitor re-verifies the RSA signature over `MANB`, so a stapled manifest must never reach the cryptex graft.
pub fn set_boot_nonce_hash(
    bytes: &[u8],
    nonce: &[u8; BOOT_NONCE_HASH_BYTES],
) -> Result<Vec<u8>, TicketError> {
    let manifest = read_manifest(bytes)?;
    if manifest.boot_nonce_hash() == Some(nonce.as_slice()) {
        return Ok(bytes.to_vec());
    }
    rebuild_outer(bytes, |source, manb| {
        rebuild_manifest_body_with_boot_nonce(source, manb, nonce)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FDR_TRUST_OBJECT_DIGEST: [u8; 32] = [0xA5; 32];

    fn der(identifier: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = identifier.to_vec();
        let length = body.len();
        if length < 0x80 {
            out.push(length as u8);
        } else if length <= 0xff {
            out.push(0x81);
            out.push(length as u8);
        } else {
            out.push(0x82);
            out.push((length >> 8) as u8);
            out.push((length & 0xff) as u8);
        }
        out.extend_from_slice(body);
        out
    }

    fn private_identifier(code: &str) -> Vec<u8> {
        let bytes = code.as_bytes();
        assert_eq!(bytes.len(), 4);
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

    fn octet(bytes: &[u8]) -> Vec<u8> {
        der(&[0x04], bytes)
    }

    fn integer(bytes: &[u8]) -> Vec<u8> {
        der(&[0x02], bytes)
    }

    fn null() -> Vec<u8> {
        vec![0x05, 0x00]
    }

    fn set(body: Vec<u8>) -> Vec<u8> {
        der(&[0x31], &body)
    }

    fn sequence(body: Vec<u8>) -> Vec<u8> {
        der(&[0x30], &body)
    }

    fn property(code: &str, value: Vec<u8>) -> Vec<u8> {
        let mut inner = ia5(code);
        inner.extend_from_slice(&value);
        der(&private_identifier(code), &sequence(inner))
    }

    fn block(code: &str, properties: Vec<u8>) -> Vec<u8> {
        let mut inner = ia5(code);
        inner.extend_from_slice(&set(properties));
        der(&private_identifier(code), &sequence(inner))
    }

    fn object(code: &str, digest: &[u8]) -> Vec<u8> {
        block(code, property(DIGEST_PROPERTY_TAG, octet(digest)))
    }

    fn manifest(properties: Vec<u8>, objects: Vec<Vec<u8>>) -> Vec<u8> {
        let mut entries = block(MANIFEST_PROPERTIES_TAG, properties);
        for object in objects {
            entries.extend_from_slice(&object);
        }
        let body = block(MANIFEST_BODY_TAG, entries);
        let mut top = ia5("IM4M");
        top.extend_from_slice(&integer(&[0x00]));
        top.extend_from_slice(&set(body));
        top.extend_from_slice(&octet(&[0xaa; 8]));
        sequence(top)
    }

    fn global_properties() -> Vec<u8> {
        let mut properties = property(BOARD_PROPERTY_TAG, integer(&[0x22]));
        properties.extend_from_slice(&property(CHIP_PROPERTY_TAG, integer(&[0x81, 0x03])));
        properties.extend_from_slice(&property(
            BOARD_TAG_PROPERTY_TAG,
            octet("J274AP".as_bytes()),
        ));
        properties.extend_from_slice(&property("prtp", octet("Macmini9,1".as_bytes())));
        properties
    }

    #[test]
    fn a_manifest_body_decodes_to_its_properties_and_objects() {
        let bytes = manifest(
            global_properties(),
            vec![object("krnl", &[1; 48]), object("ibot", &[2; 48])],
        );
        let decoded = read_manifest(&bytes).expect("the fixture reads back");
        assert_eq!(decoded.object_tags(), vec!["krnl", "ibot"]);
        assert_eq!(decoded.board_tag(), Some("J274AP"));
        assert_eq!(decoded.chip(), Some(0x8103));
        assert_eq!(decoded.board(), Some(0x22));
        assert_eq!(
            decoded
                .property("prtp")
                .and_then(|property| property.value.as_ascii_text()),
            Some("Macmini9,1")
        );
        assert_eq!(
            decoded.object("krnl").unwrap().digest(),
            Some(&[1u8; 48][..])
        );
    }

    #[test]
    fn a_manifest_without_a_chip_identity_is_global() {
        let bytes = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let decoded = read_manifest(&bytes).unwrap();
        assert!(!decoded.is_personalised());
    }

    #[test]
    fn a_manifest_carrying_a_chip_identity_is_personalised() {
        let mut properties = global_properties();
        properties.extend_from_slice(&property(
            CHIP_IDENTITY_PROPERTY_TAG,
            integer(&[0x3a, 0x68, 0x3d, 0x37, 0x1b, 0xd2, 0x29, 0x1b]),
        ));
        let bytes = manifest(properties, vec![object("krnl", &[1; 48])]);
        let decoded = read_manifest(&bytes).unwrap();
        assert!(decoded.is_personalised());
    }

    #[test]
    fn a_chip_identity_spelled_as_null_does_not_make_a_manifest_personalised() {
        let mut properties = global_properties();
        properties.extend_from_slice(&property(CHIP_IDENTITY_PROPERTY_TAG, null()));
        let bytes = manifest(properties, vec![object("krnl", &[1; 48])]);
        assert!(!read_manifest(&bytes).unwrap().is_personalised());
    }

    #[test]
    fn a_manifest_without_the_fdr_trust_objects_names_both() {
        let bytes = manifest(
            global_properties(),
            vec![object("krnl", &[1; 48]), object("trst", &[3; 48])],
        );
        let decoded = read_manifest(&bytes).unwrap();
        assert_eq!(
            decoded.missing_fdr_trust_objects(),
            vec![RESTORE_FDR_TRUST_OBJECT_TAG, BOOTED_OS_FDR_TRUST_OBJECT_TAG]
        );
    }

    #[test]
    fn a_manifest_carrying_both_fdr_trust_objects_names_none() {
        let bytes = manifest(
            global_properties(),
            vec![
                object("krnl", &[1; 48]),
                object(RESTORE_FDR_TRUST_OBJECT_TAG, &[4; 32]),
                object(BOOTED_OS_FDR_TRUST_OBJECT_TAG, &[5; 32]),
            ],
        );
        let decoded = read_manifest(&bytes).unwrap();
        assert!(decoded.missing_fdr_trust_objects().is_empty());
        assert_eq!(
            decoded
                .object(RESTORE_FDR_TRUST_OBJECT_TAG)
                .unwrap()
                .digest(),
            Some(&[4u8; 32][..])
        );
    }

    #[test]
    fn adding_the_trust_objects_makes_a_missing_manifest_complete() {
        let before = manifest(
            global_properties(),
            vec![object("krnl", &[1; 48]), object("trst", &[3; 48])],
        );
        assert_eq!(
            read_manifest(&before).unwrap().missing_fdr_trust_objects(),
            vec![RESTORE_FDR_TRUST_OBJECT_TAG, BOOTED_OS_FDR_TRUST_OBJECT_TAG]
        );

        let after = add_fdr_trust_objects(&before, &TEST_FDR_TRUST_OBJECT_DIGEST)
            .expect("the transform succeeds");
        let decoded = read_manifest(&after).expect("the result re-parses");

        assert!(decoded.missing_fdr_trust_objects().is_empty());
        assert_eq!(
            decoded
                .object(RESTORE_FDR_TRUST_OBJECT_TAG)
                .unwrap()
                .digest(),
            Some(&TEST_FDR_TRUST_OBJECT_DIGEST[..])
        );
        assert_eq!(
            decoded
                .object(BOOTED_OS_FDR_TRUST_OBJECT_TAG)
                .unwrap()
                .digest(),
            Some(&TEST_FDR_TRUST_OBJECT_DIGEST[..])
        );

        assert!(decoded.object("krnl").is_some());
        assert_eq!(
            decoded.object("krnl").unwrap().digest(),
            Some(&[1u8; 48][..])
        );
        assert!(decoded.object("trst").is_some());
        assert_eq!(decoded.board_tag(), Some("J274AP"));
        assert_eq!(decoded.chip(), Some(0x8103));
        assert!(!decoded.is_personalised());
    }

    #[test]
    fn adding_the_trust_objects_only_appends_the_ones_absent() {
        let before = manifest(
            global_properties(),
            vec![
                object("krnl", &[1; 48]),
                object(RESTORE_FDR_TRUST_OBJECT_TAG, &[7; 32]),
            ],
        );
        let after = add_fdr_trust_objects(&before, &TEST_FDR_TRUST_OBJECT_DIGEST).unwrap();
        let decoded = read_manifest(&after).unwrap();
        assert!(decoded.missing_fdr_trust_objects().is_empty());
        assert_eq!(
            decoded
                .object(RESTORE_FDR_TRUST_OBJECT_TAG)
                .unwrap()
                .digest(),
            Some(&[7u8; 32][..])
        );
        assert_eq!(
            decoded
                .object(BOOTED_OS_FDR_TRUST_OBJECT_TAG)
                .unwrap()
                .digest(),
            Some(&TEST_FDR_TRUST_OBJECT_DIGEST[..])
        );
    }

    #[test]
    fn adding_the_trust_objects_is_idempotent() {
        let before = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let once = add_fdr_trust_objects(&before, &TEST_FDR_TRUST_OBJECT_DIGEST).unwrap();
        let twice = add_fdr_trust_objects(&once, &TEST_FDR_TRUST_OBJECT_DIGEST).unwrap();
        assert_eq!(
            once, twice,
            "applying the transform twice equals applying it once"
        );
    }

    #[test]
    fn a_manifest_that_already_carries_both_is_returned_unchanged() {
        let before = manifest(
            global_properties(),
            vec![
                object("krnl", &[1; 48]),
                object(RESTORE_FDR_TRUST_OBJECT_TAG, &[4; 32]),
                object(BOOTED_OS_FDR_TRUST_OBJECT_TAG, &[5; 32]),
            ],
        );
        let after = add_fdr_trust_objects(&before, &TEST_FDR_TRUST_OBJECT_DIGEST).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn an_fdr_trust_object_without_a_digest_counts_as_missing() {
        let bytes = manifest(
            global_properties(),
            vec![
                block(
                    RESTORE_FDR_TRUST_OBJECT_TAG,
                    property("EPRO", vec![0x01, 0x01, 0xff]),
                ),
                object(BOOTED_OS_FDR_TRUST_OBJECT_TAG, &[5; 32]),
            ],
        );
        let decoded = read_manifest(&bytes).unwrap();
        assert_eq!(
            decoded.missing_fdr_trust_objects(),
            vec![RESTORE_FDR_TRUST_OBJECT_TAG]
        );
    }

    #[test]
    fn the_audit_reports_flavour_objects_and_what_is_missing() {
        let bytes = manifest(
            global_properties(),
            vec![object("krnl", &[1; 48]), object("trst", &[3; 48])],
        );
        let audit = audit_ticket(&bytes, &FDR_TRUST_OBJECT_TAGS).unwrap();
        assert_eq!(audit.flavour, TicketFlavour::Global);
        assert_eq!(audit.board_tag.as_deref(), Some("J274AP"));
        assert_eq!(audit.object_tags, vec!["krnl", "trst"]);
        assert_eq!(audit.missing, vec!["rfta", "ftap"]);
        assert_eq!(audit.chip, Some(0x8103));
        assert!(!audit.satisfies_requirements());
        let fields = audit.trace_fields();
        assert!(fields.contains("flavour=global"), "{fields}");
        assert!(fields.contains("board=J274AP"), "{fields}");
        assert!(fields.contains("chip=0x8103"), "{fields}");
        assert!(fields.contains("missing=[rfta,ftap]"), "{fields}");
        assert!(fields.contains("tags=[krnl,trst]"), "{fields}");
        assert!(fields.contains("boot_nonce=absent"), "{fields}");
    }

    #[test]
    fn a_global_manifest_carries_no_boot_nonce_and_the_audit_names_it() {
        let bytes = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let decoded = read_manifest(&bytes).unwrap();
        assert_eq!(decoded.boot_nonce_hash(), None);
        let audit = audit_ticket(&bytes, &[]).unwrap();
        assert_eq!(audit.boot_nonce_hash_len, None);
        assert!(!audit.carries_boot_nonce_hash());
    }

    #[test]
    fn a_personalised_manifest_reports_its_boot_nonce_and_its_width() {
        let mut properties = global_properties();
        properties.extend_from_slice(&property(
            BOOT_NONCE_HASH_PROPERTY_TAG,
            octet(&[0x5a; BOOT_NONCE_HASH_BYTES]),
        ));
        let bytes = manifest(properties, vec![object("krnl", &[1; 48])]);
        let decoded = read_manifest(&bytes).unwrap();
        assert_eq!(
            decoded.boot_nonce_hash(),
            Some(&[0x5a; BOOT_NONCE_HASH_BYTES][..])
        );
        let audit = audit_ticket(&bytes, &[]).unwrap();
        assert_eq!(audit.boot_nonce_hash_len, Some(BOOT_NONCE_HASH_BYTES));
        assert!(audit.carries_boot_nonce_hash());
        assert!(
            audit.trace_fields().contains("boot_nonce=32bytes"),
            "{}",
            audit.trace_fields()
        );
    }

    #[test]
    fn a_boot_nonce_of_the_wrong_width_is_reported_rather_than_accepted() {
        let mut properties = global_properties();
        properties.extend_from_slice(&property(BOOT_NONCE_HASH_PROPERTY_TAG, octet(&[0x5a; 20])));
        let bytes = manifest(properties, vec![object("krnl", &[1; 48])]);
        let audit = audit_ticket(&bytes, &[]).unwrap();
        assert_eq!(audit.boot_nonce_hash_len, Some(20));
        assert!(!audit.carries_boot_nonce_hash());
    }

    #[test]
    fn an_audit_with_nothing_required_still_reports_the_contents() {
        let bytes = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let audit = audit_ticket(&bytes, &[]).unwrap();
        assert!(audit.satisfies_requirements());
        assert_eq!(audit.object_tags, vec!["krnl"]);
        assert_eq!(audit.byte_len, bytes.len());
    }

    #[test]
    fn bytes_that_are_not_a_manifest_are_refused() {
        assert_eq!(
            read_manifest(&[]).unwrap_err(),
            TicketError::Truncated { at: 0 }
        );
        assert_eq!(
            read_manifest(&[0x04, 0x02, 0x01, 0x02]).unwrap_err(),
            TicketError::NotAManifest
        );
        let mut top = ia5("IM4P");
        top.extend_from_slice(&integer(&[0x00]));
        assert_eq!(
            read_manifest(&sequence(top)).unwrap_err(),
            TicketError::NotAManifest
        );
    }

    #[test]
    fn a_truncated_manifest_is_refused_rather_than_half_read() {
        let bytes = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        for cut in [4usize, 16, 32, bytes.len() - 1] {
            assert!(
                read_manifest(&bytes[..cut]).is_err(),
                "a manifest cut at {cut} must not read back"
            );
        }
    }

    #[test]
    fn a_length_claiming_more_than_the_element_holds_is_refused() {
        let mut bytes = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        bytes[2] = 0xff;
        bytes[3] = 0xff;
        assert!(matches!(
            read_manifest(&bytes),
            Err(TicketError::BadLength { .. })
        ));
    }

    #[test]
    fn a_private_tag_disagreeing_with_its_own_name_is_refused() {
        let mut inner = ia5("ibot");
        inner.extend_from_slice(&set(property(DIGEST_PROPERTY_TAG, octet(&[1; 48]))));
        let liar = der(&private_identifier("krnl"), &sequence(inner));
        let bytes = manifest(global_properties(), vec![liar]);
        assert!(matches!(
            read_manifest(&bytes),
            Err(TicketError::TagMismatch { .. })
        ));
    }

    #[test]
    fn the_private_tag_encoding_round_trips_the_four_character_code() {
        for code in ["MANB", "MANP", "rfta", "ftap", "krnl", "DGST"] {
            let identifier = private_identifier(code);
            let framed = der(&identifier, &[]);
            let element = read_element(&framed, 0, framed.len()).unwrap();
            assert_eq!(element.class, CLASS_PRIVATE);
            assert_eq!(four_character_code(element.tag).as_deref(), Some(code));
        }
    }

    const TEST_AP_NONCE: [u8; BOOT_NONCE_HASH_BYTES] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];

    #[test]
    fn the_staged_boot_nonce_reads_back_through_the_manifest_reader() {
        let before = manifest(
            global_properties(),
            vec![object("krnl", &[1; 48]), object("trst", &[3; 48])],
        );
        assert_eq!(read_manifest(&before).unwrap().boot_nonce_hash(), None);

        let after = set_boot_nonce_hash(&before, &TEST_AP_NONCE).unwrap();
        let decoded = read_manifest(&after).unwrap();
        assert_eq!(decoded.boot_nonce_hash(), Some(&TEST_AP_NONCE[..]));

        let audit = audit_ticket(&after, &[]).unwrap();
        assert_eq!(audit.boot_nonce_hash_len, Some(BOOT_NONCE_HASH_BYTES));
        assert!(audit.carries_boot_nonce_hash());
        assert!(
            audit.trace_fields().contains("boot_nonce=32bytes"),
            "{}",
            audit.trace_fields()
        );
    }

    #[test]
    fn staging_the_boot_nonce_leaves_every_other_property_and_object_alone() {
        let before = manifest(
            global_properties(),
            vec![
                object("krnl", &[1; 48]),
                object(RESTORE_FDR_TRUST_OBJECT_TAG, &TEST_FDR_TRUST_OBJECT_DIGEST),
                object(
                    BOOTED_OS_FDR_TRUST_OBJECT_TAG,
                    &TEST_FDR_TRUST_OBJECT_DIGEST,
                ),
            ],
        );
        let original = read_manifest(&before).unwrap();
        let after = set_boot_nonce_hash(&before, &TEST_AP_NONCE).unwrap();
        let decoded = read_manifest(&after).unwrap();

        assert_eq!(decoded.object_tags(), original.object_tags());
        assert_eq!(decoded.board_tag(), original.board_tag());
        assert_eq!(decoded.chip(), original.chip());
        assert_eq!(decoded.board(), original.board());
        assert!(decoded.missing_fdr_trust_objects().is_empty());
        assert_eq!(
            decoded
                .object(RESTORE_FDR_TRUST_OBJECT_TAG)
                .and_then(Im4mObject::digest),
            Some(&TEST_FDR_TRUST_OBJECT_DIGEST[..])
        );
        for property in &original.properties {
            assert_eq!(
                decoded.property(&property.tag),
                Some(property),
                "property {} changed",
                property.tag
            );
        }
        assert_eq!(
            decoded.properties.len(),
            original.properties.len() + 1,
            "only BNCH may be added"
        );
    }

    #[test]
    fn the_staged_boot_nonce_sits_where_a_genuine_ticket_carries_it() {
        let before = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let after = set_boot_nonce_hash(&before, &TEST_AP_NONCE).unwrap();
        let decoded = read_manifest(&after).unwrap();
        let tags: Vec<&str> = decoded
            .properties
            .iter()
            .map(|property| property.tag.as_str())
            .collect();
        assert_eq!(tags.first(), Some(&BOOT_NONCE_HASH_PROPERTY_TAG));
        let original: Vec<String> = read_manifest(&before)
            .unwrap()
            .properties
            .iter()
            .map(|property| property.tag.clone())
            .collect();
        assert_eq!(tags[1..], original[..]);
    }

    #[test]
    fn staging_the_same_boot_nonce_twice_changes_nothing() {
        let before = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let once = set_boot_nonce_hash(&before, &TEST_AP_NONCE).unwrap();
        let twice = set_boot_nonce_hash(&once, &TEST_AP_NONCE).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn a_boot_nonce_already_present_is_replaced_rather_than_doubled() {
        let mut properties = global_properties();
        properties.extend_from_slice(&property(
            BOOT_NONCE_HASH_PROPERTY_TAG,
            octet(&[0xde, 0xad, 0xbe, 0xef]),
        ));
        let before = manifest(properties, vec![object("krnl", &[1; 48])]);
        let after = set_boot_nonce_hash(&before, &TEST_AP_NONCE).unwrap();
        let decoded = read_manifest(&after).unwrap();
        assert_eq!(decoded.boot_nonce_hash(), Some(&TEST_AP_NONCE[..]));
        assert_eq!(
            decoded
                .properties
                .iter()
                .filter(|property| property.tag == BOOT_NONCE_HASH_PROPERTY_TAG)
                .count(),
            1
        );
    }

    #[test]
    fn the_two_transforms_compose_in_either_order_to_the_same_bytes() {
        let before = manifest(global_properties(), vec![object("krnl", &[1; 48])]);
        let nonce_then_objects = add_fdr_trust_objects(
            &set_boot_nonce_hash(&before, &TEST_AP_NONCE).unwrap(),
            &TEST_FDR_TRUST_OBJECT_DIGEST,
        )
        .unwrap();
        let objects_then_nonce = set_boot_nonce_hash(
            &add_fdr_trust_objects(&before, &TEST_FDR_TRUST_OBJECT_DIGEST).unwrap(),
            &TEST_AP_NONCE,
        )
        .unwrap();
        assert_eq!(nonce_then_objects, objects_then_nonce);
        let decoded = read_manifest(&nonce_then_objects).unwrap();
        assert_eq!(decoded.boot_nonce_hash(), Some(&TEST_AP_NONCE[..]));
        assert!(decoded.missing_fdr_trust_objects().is_empty());
    }

    #[test]
    fn stapling_a_boot_nonce_moves_the_manb_digest_the_image4_monitor_verifies() {
        use crate::crypto::sha384;

        fn manb_set_digest(bytes: &[u8]) -> [u8; 48] {
            let outer = read_element(bytes, 0, bytes.len()).expect("outer SEQUENCE reads");
            let mut start = outer.body.0;
            for element in children(bytes, outer.body).expect("outer children read") {
                if element.is(CLASS_UNIVERSAL, TAG_SET) {
                    return sha384(&bytes[start..element.end]);
                }
                start = element.end;
            }
            panic!("the fixture carries no MANB SET");
        }

        let before = manifest(global_properties(), vec![object("trcs", &[0x11; 48])]);
        assert_eq!(read_manifest(&before).unwrap().boot_nonce_hash(), None);
        let signed_digest = manb_set_digest(&before);

        let after = set_boot_nonce_hash(&before, &TEST_AP_NONCE).expect("the staple succeeds");
        let decoded = read_manifest(&after).unwrap();

        assert_eq!(
            decoded.object("trcs").and_then(Im4mObject::digest),
            Some(&[0x11u8; 48][..])
        );
        assert_eq!(decoded.boot_nonce_hash(), Some(&TEST_AP_NONCE[..]));

        assert_ne!(
            manb_set_digest(&after),
            signed_digest,
            "stapling BNCH moves the MANB digest, which is why a stapled manifest fails the graft"
        );
    }

    #[test]
    fn a_manifest_with_no_properties_block_is_refused_rather_than_given_one() {
        let body = block(MANIFEST_BODY_TAG, object("krnl", &[1; 48]));
        let mut top = ia5("IM4M");
        top.extend_from_slice(&integer(&[0x00]));
        top.extend_from_slice(&set(body));
        let bytes = sequence(top);
        assert_eq!(
            set_boot_nonce_hash(&bytes, &TEST_AP_NONCE).unwrap_err(),
            TicketError::NoManifestProperties
        );
    }
}
