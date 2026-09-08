use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const TRUST_OBJECT_KEY: &str = "trustobject-current";

pub const SEAL_CLASS: &str = "seal";

pub const INSTANCE_IDENTIFIER_CHARS: usize = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdrStoreError {
    UnreadableChipId { value: String },
}

impl std::fmt::Display for FdrStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnreadableChipId { value } => {
                write!(f, "the chip id {value:?} is not a readable number")
            }
        }
    }
}

impl std::error::Error for FdrStoreError {}

// A bare token is hexadecimal, never decimal: 8103 read as decimal names another machine.
pub fn numeric_chip_id(text: &str) -> Result<u32, FdrStoreError> {
    let unreadable = || FdrStoreError::UnreadableChipId {
        value: text.to_string(),
    };
    let trimmed = text.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .or_else(|| trimmed.strip_prefix('t'))
        .or_else(|| trimmed.strip_prefix('T'))
        .unwrap_or(trimmed);
    if body.is_empty() {
        return Err(unreadable());
    }
    u32::from_str_radix(body, 16).map_err(|_| unreadable())
}

#[must_use]
pub fn instance_identifier(chip_id: u32, unique_chip_id: u64) -> String {
    format!("{chip_id:08X}-{unique_chip_id:016X}")
}

pub fn machine_instance_identifier(
    chip_id: &str,
    unique_chip_id: u64,
) -> Result<String, FdrStoreError> {
    Ok(instance_identifier(
        numeric_chip_id(chip_id)?,
        unique_chip_id,
    ))
}

#[must_use]
pub fn class_instance_key(class: &str, instance: &str) -> String {
    format!("{class}-{instance}")
}

#[must_use]
pub fn seal_key(instance: &str) -> String {
    class_instance_key(SEAL_CLASS, instance)
}

pub const SIK_INSTANCE_PREFIX: &str = "sik-";

// The device refuses its own result at 0xd3 characters.
pub const SIK_INSTANCE_MAX_CHARS: usize = 0xd2;

pub const RESOURCE_SEPARATOR: char = ':';

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataResource {
    pub class: String,
    pub instance: String,
}

impl DataResource {
    #[must_use]
    pub fn new(class: &str, instance: &str) -> Option<Self> {
        if class.is_empty() || instance.is_empty() {
            return None;
        }
        Some(Self {
            class: class.to_string(),
            instance: instance.to_string(),
        })
    }

    #[must_use]
    pub fn parse(target: &str) -> Option<Self> {
        let (class, instance) = target.split_once(RESOURCE_SEPARATOR)?;
        Self::new(class, instance)
    }

    #[must_use]
    pub fn key(&self) -> String {
        class_instance_key(&self.class, &self.instance)
    }

    #[must_use]
    pub fn sik_instance(&self) -> Option<SikInstance> {
        SikInstance::parse(&self.instance)
    }

    #[must_use]
    pub fn plain_instance(&self) -> String {
        self.sik_instance()
            .map_or_else(|| self.instance.clone(), |sik| sik.instance)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SikInstance {
    pub instance: String,
    pub public_key: Vec<u8>,
}

impl SikInstance {
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let body = text.strip_prefix(SIK_INSTANCE_PREFIX)?;
        let (instance, tail) = body.rsplit_once('-')?;
        if instance.is_empty() || tail.is_empty() || tail.len() % 2 != 0 {
            return None;
        }
        let mut public_key = Vec::with_capacity(tail.len() / 2);
        let bytes = tail.as_bytes();
        for pair in bytes.as_chunks::<2>().0 {
            let text = std::str::from_utf8(pair).ok()?;
            public_key.push(u8::from_str_radix(text, 16).ok()?);
        }
        Some(Self {
            instance: instance.to_string(),
            public_key,
        })
    }

    #[must_use]
    pub fn looks_uncompressed(&self) -> bool {
        self.public_key.first() == Some(&0x04) && self.public_key.len() % 2 == 1
    }
}

const RECORD_MAGIC: &[u8] = b"APPLEUTILSFDRSTORE1\n";

const RECORD_EXTENSION: &str = "fdrrec";

#[derive(Debug)]
pub struct FdrDataStore {
    directory: Option<PathBuf>,
    records: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl FdrDataStore {
    pub fn open(directory: &Path) -> io::Result<Self> {
        let mut records = BTreeMap::new();
        if directory.is_dir() {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path();
                if path.extension().and_then(|text| text.to_str()) != Some(RECORD_EXTENSION) {
                    continue;
                }
                let (key, value) = decode_record(&fs::read(&path)?).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} is not a record this store wrote", path.display()),
                    )
                })?;
                records.insert(key, value);
            }
        }
        Ok(Self {
            directory: Some(directory.to_path_buf()),
            records: Mutex::new(records),
        })
    }

    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            directory: None,
            records: Mutex::new(BTreeMap::new()),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.held().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.held().keys().cloned().collect()
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.held().get(key).cloned()
    }

    pub fn put(&self, key: &str, value: &[u8]) -> io::Result<()> {
        self.held().insert(key.to_string(), value.to_vec());
        let Some(directory) = &self.directory else {
            return Ok(());
        };
        fs::create_dir_all(directory)?;
        fs::write(
            directory.join(record_file_name(key)),
            encode_record(key, value),
        )
    }

    pub fn remove(&self, key: &str) -> io::Result<bool> {
        let held = self.held().remove(key).is_some();
        if let Some(directory) = &self.directory {
            let path = directory.join(record_file_name(key));
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        Ok(held)
    }
}

// The key cannot be the file name: a sik instance runs to 210 characters and its hyphen run folds on a case insensitive filesystem.
fn record_file_name(key: &str) -> String {
    let forward = fnv1a(key.as_bytes().iter().copied());
    let backward = fnv1a(key.as_bytes().iter().rev().copied());
    format!("{forward:016x}{backward:016x}.{RECORD_EXTENSION}")
}

fn fnv1a(bytes: impl Iterator<Item = u8>) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn encode_record(key: &str, value: &[u8]) -> Vec<u8> {
    let key = key.as_bytes();
    let mut out = Vec::with_capacity(RECORD_MAGIC.len() + 4 + key.len() + value.len());
    out.extend_from_slice(RECORD_MAGIC);
    out.extend_from_slice(&u32::try_from(key.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    out
}

fn decode_record(bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    let body = bytes.strip_prefix(RECORD_MAGIC)?;
    let (length, rest) = body.split_at_checked(4)?;
    let length = usize::try_from(u32::from_le_bytes(length.try_into().ok()?)).ok()?;
    let (key, value) = rest.split_at_checked(length)?;
    Some((String::from_utf8(key.to_vec()).ok()?, value.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_CHIP_ID: u32 = 0x8103;
    const EXAMPLE_UNIQUE_CHIP_ID: u64 = 0x1122_3344_5566_7788;
    const EXAMPLE_INSTANCE: &str = "00008103-1122334455667788";

    #[test]
    fn the_instance_identifier_renders_the_chip_id_and_ecid_pair() {
        let instance = instance_identifier(EXAMPLE_CHIP_ID, EXAMPLE_UNIQUE_CHIP_ID);
        assert_eq!(instance, EXAMPLE_INSTANCE);
        assert_eq!(instance.len(), INSTANCE_IDENTIFIER_CHARS);
    }

    #[test]
    fn the_seal_key_is_the_class_then_the_instance() {
        let instance = instance_identifier(EXAMPLE_CHIP_ID, EXAMPLE_UNIQUE_CHIP_ID);
        assert_eq!(seal_key(&instance), "seal-00008103-1122334455667788");
        assert_eq!(
            class_instance_key("appv", &instance),
            "appv-00008103-1122334455667788"
        );
        assert_eq!(
            seal_key(&instance),
            class_instance_key(SEAL_CLASS, &instance)
        );
    }

    #[test]
    fn the_identifier_is_upper_case_and_zero_padded_on_both_halves() {
        assert_eq!(instance_identifier(0x1, 0x2), "00000001-0000000000000002");
        assert_eq!(
            instance_identifier(u32::MAX, u64::MAX),
            "FFFFFFFF-FFFFFFFFFFFFFFFF"
        );
        let instance = instance_identifier(0x8103, 0x1122_3344_5566_7788);
        assert!(!instance.contains(|c: char| c.is_ascii_lowercase()));
    }

    #[test]
    fn both_configured_chip_id_forms_read_as_the_same_number() {
        for text in ["0x8103", "0X8103", "t8103", "T8103", "8103", " t8103 "] {
            assert_eq!(numeric_chip_id(text), Ok(0x8103), "reading {text:?}");
        }
    }

    #[test]
    fn an_unreadable_chip_id_is_refused_rather_than_guessed() {
        for text in [
            "",
            "0x",
            "t",
            "  ",
            "zzzz",
            "0xg",
            "1_0000_0000",
            "0x100000000",
        ] {
            assert!(
                numeric_chip_id(text).is_err(),
                "{text:?} must not read as a chip id"
            );
        }
    }

    #[test]
    fn the_identifier_matches_the_device_udid_shape() {
        assert_eq!(
            instance_identifier(EXAMPLE_CHIP_ID, EXAMPLE_UNIQUE_CHIP_ID),
            "00008103-1122334455667788"
        );
    }

    #[test]
    fn a_primitive_machine_identity_builds_the_same_identifier() {
        assert_eq!(
            machine_instance_identifier("0x8103", EXAMPLE_UNIQUE_CHIP_ID),
            Ok(String::from("00008103-1122334455667788"))
        );
    }

    const EXAMPLE_SIK_KEY: &str = "040102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40";

    fn example_sik_instance() -> String {
        format!("{SIK_INSTANCE_PREFIX}{EXAMPLE_INSTANCE}-{EXAMPLE_SIK_KEY}")
    }

    #[test]
    fn a_sik_resource_decomposes_into_its_parts() {
        let target = format!("{SEAL_CLASS}:{}", example_sik_instance());
        let resource = DataResource::parse(&target).expect("resource");
        assert_eq!(resource.class, SEAL_CLASS);
        assert_eq!(resource.instance, example_sik_instance());
        assert_eq!(resource.plain_instance(), EXAMPLE_INSTANCE);
        assert_eq!(resource.key(), seal_key(&example_sik_instance()));

        let sik = resource.sik_instance().expect("sik form");
        assert_eq!(sik.instance, EXAMPLE_INSTANCE);
        assert_eq!(sik.public_key.len(), 65);
        assert_eq!(sik.public_key[0], 0x04);
        assert!(sik.looks_uncompressed());
        assert!(example_sik_instance().chars().count() <= SIK_INSTANCE_MAX_CHARS);
    }

    #[test]
    fn a_plain_instance_is_not_read_as_a_sik_one() {
        let resource =
            DataResource::parse(&format!("{SEAL_CLASS}:{EXAMPLE_INSTANCE}")).expect("resource");
        assert_eq!(resource.sik_instance(), None);
        assert_eq!(resource.plain_instance(), EXAMPLE_INSTANCE);
    }

    #[test]
    fn a_sik_instance_with_an_unreadable_tail_is_refused_rather_than_guessed() {
        for tail in ["", "0", "abc", "zz", "04ff0"] {
            let text = format!("{SIK_INSTANCE_PREFIX}{EXAMPLE_INSTANCE}-{tail}");
            assert_eq!(SikInstance::parse(&text), None, "reading {text:?}");
        }
        assert_eq!(SikInstance::parse(EXAMPLE_INSTANCE), None);
        assert_eq!(SikInstance::parse("sik-"), None);
    }

    #[test]
    fn a_resource_with_no_separator_names_nothing() {
        assert_eq!(DataResource::parse("seal"), None);
        assert_eq!(DataResource::parse(":inst"), None);
        assert_eq!(DataResource::parse("seal:"), None);
    }

    #[test]
    fn an_instance_holding_a_colon_keeps_all_of_it() {
        let resource = DataResource::parse("seal:a:b").expect("resource");
        assert_eq!(resource.class, "seal");
        assert_eq!(resource.instance, "a:b");
    }

    #[test]
    fn the_store_reads_back_what_was_put_in_it() {
        let store = FdrDataStore::in_memory();
        let key = seal_key(&example_sik_instance());
        assert_eq!(store.get(&key), None);
        assert!(store.is_empty());
        store.put(&key, b"IM4M-bytes").expect("put");
        assert_eq!(store.get(&key), Some(b"IM4M-bytes".to_vec()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.keys(), vec![key.clone()]);
        assert!(store.remove(&key).expect("remove"));
        assert_eq!(store.get(&key), None);
        assert!(!store.remove(&key).expect("remove twice"));
    }

    #[test]
    fn a_record_file_round_trips_through_its_header() {
        let key = seal_key(&example_sik_instance());
        let encoded = encode_record(&key, b"\x00\x01\x02payload");
        assert_eq!(
            decode_record(&encoded),
            Some((key.clone(), b"\x00\x01\x02payload".to_vec()))
        );
        assert_eq!(decode_record(b"not a record"), None);
        let name = record_file_name(&key);
        assert_eq!(name.len(), 32 + 1 + RECORD_EXTENSION.len());
        assert_ne!(name, record_file_name(&seal_key(EXAMPLE_INSTANCE)));
    }

    #[test]
    fn the_trust_object_key_is_not_per_class() {
        assert_eq!(TRUST_OBJECT_KEY, "trustobject-current");
        assert!(!TRUST_OBJECT_KEY.contains(EXAMPLE_INSTANCE));
    }
}
