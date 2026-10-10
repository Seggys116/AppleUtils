//! Plain-English descriptions of IPSW entries, built from the BuildManifest and falling back
//! to what an entry's name reveals. Nothing here fails; unknown shapes are skipped.

use std::collections::{BTreeMap, BTreeSet};

use plist::{Dictionary, Value};

use crate::ramrod::boards::{board_chip, describe_board};

const SEPARATOR: &str = " · ";

/// Most to least significant; an entry referenced by several components is titled by the earliest.
const PRIORITY: &[&str] = &[
    "OS",
    "Cryptex1,SystemOS",
    "Cryptex1,AppOS",
    "RestoreRamDisk",
    "BaseSystem",
    "RecoveryOSASRImage",
    "KernelCache",
    "RestoreKernelCache",
    "iBoot",
    "iBootData",
    "iBEC",
    "iBSS",
    "LLB",
    "DeviceTree",
    "RestoreDeviceTree",
    "SEP",
    "RestoreSEP",
    "StaticTrustCache",
    "RestoreTrustCache",
    "SystemVolume",
    "Ap,SystemVolumeCanonicalMetadata",
    "Cryptex1,SystemTrustCache",
    "Cryptex1,AppTrustCache",
    "Cryptex1,SystemVolume",
    "Cryptex1,AppVolume",
];

const FIRMWARE_STEMS: &[(&str, &str)] = &[
    ("iboot", "iBoot"),
    ("ibec", "iBEC"),
    ("ibss", "iBSS"),
    ("llb", "LLB"),
    ("devicetree", "DeviceTree"),
    ("sep-firmware", "SEP"),
];

const BOOT_SCREEN_PREFIXES: &[&str] = &[
    "batterycharging",
    "batterylow",
    "batteryfull",
    "applelogo",
    "recoverymode",
    "recoveryoslogo",
    "glyphplugin",
];

const FIRMWARE_FOLDERS: &[(&str, &str)] = &[
    ("aop", "Always-on processor firmware"),
    ("aop2", "Always-on processor firmware"),
    ("dcp", "Display coprocessor firmware"),
    ("agx", "GPU firmware"),
    ("ane", "Neural Engine firmware"),
    ("ave", "Video encoder firmware"),
    ("isp_bni", "Camera ISP firmware"),
    ("pmp", "Power manager firmware"),
    ("displaycalibration", "Display calibration"),
    ("embeddedaudioresources", "Audio resources"),
    ("dp855", "DisplayPort controller firmware"),
    ("ace3", "USB-C controller firmware"),
    ("sep-patches", "Secure Enclave patches"),
    ("ibootdatastage1", "iBoot data (stage 1)"),
    ("se", "Secure Element firmware"),
    ("ps190", "DisplayPort-to-HDMI converter firmware"),
    ("rt15m", "Accessory firmware (UARP)"),
    ("volchok", "Volchok firmware"),
];

const EFI_FOLDERS: &[(&str, &str)] = &[
    ("usbcupdater", "USB-C controller firmware (Intel Macs)"),
    ("amdfirmware", "AMD GPU firmware (Intel Macs)"),
    ("applessdfirmware", "SSD firmware (Intel Macs)"),
    ("applesdfirmware", "SD card reader firmware (Intel Macs)"),
    ("dp2hdmiupdater", "HDMI adapter firmware (Intel Macs)"),
    ("smcpayloads", "SMC firmware (Intel Macs)"),
    ("efipayloads", "EFI firmware (Intel Macs)"),
    ("multiupdater", "Firmware updater (Intel Macs)"),
];

const BOOTABILITY_LABEL: &str = "Bootability bundle (restore preflight)";
const INTEL_FIRMWARE_LABEL: &str = "Intel Mac firmware";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Description {
    pub title: String,
    pub summary: String,
    pub devices: Vec<String>,
    pub boards: Vec<String>,
    pub chips: Vec<String>,
    pub install: Option<String>,
    pub components: Vec<String>,
    pub from_manifest: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behavior {
    Erase,
    Update,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Use {
    key: String,
    board: Option<String>,
    behavior: Option<Behavior>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpswCatalog {
    uses: BTreeMap<String, Vec<Use>>,
    boards: BTreeSet<String>,
    board_product: BTreeMap<String, String>,
    os_name: String,
}

impl IpswCatalog {
    pub fn from_manifest(manifest: &Dictionary) -> Self {
        let mut catalog = Self::default();
        let identities = manifest
            .get("BuildIdentities")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for identity in identities.iter().filter_map(Value::as_dictionary) {
            let info = identity.get("Info").and_then(Value::as_dictionary);
            let board = info
                .and_then(|info| string_of(info, "DeviceClass"))
                .map(|class| class.to_ascii_lowercase());
            let behavior = info
                .and_then(|info| string_of(info, "RestoreBehavior"))
                .and_then(|text| match text.to_ascii_lowercase().as_str() {
                    "erase" => Some(Behavior::Erase),
                    "update" => Some(Behavior::Update),
                    _ => None,
                });
            if let Some(board) = &board {
                catalog.boards.insert(board.clone());
                if let Some(product) = string_of(identity, "Ap,ProductType") {
                    catalog
                        .board_product
                        .entry(board.clone())
                        .or_insert_with(|| product.to_string());
                }
            }
            let Some(components) = identity.get("Manifest").and_then(Value::as_dictionary) else {
                continue;
            };
            for (key, component) in components {
                let path = component
                    .as_dictionary()
                    .and_then(|component| component.get("Info"))
                    .and_then(Value::as_dictionary)
                    .and_then(|info| string_of(info, "Path"));
                let Some(path) = path else {
                    continue;
                };
                catalog.uses.entry(path.to_string()).or_default().push(Use {
                    key: key.clone(),
                    board: board.clone(),
                    behavior,
                });
            }
        }
        let mut product_types: Vec<&str> =
            catalog.board_product.values().map(String::as_str).collect();
        if let Some(listed) = manifest
            .get("SupportedProductTypes")
            .and_then(Value::as_array)
        {
            product_types.extend(listed.iter().filter_map(Value::as_string));
        }
        catalog.os_name = os_name_for(&product_types).to_string();
        catalog
    }

    pub fn describe(&self, name: &str) -> Option<Description> {
        if let Some(uses) = self.uses.get(name) {
            return Some(self.describe_uses(uses));
        }
        self.describe_by_name(name)
    }

    pub fn boards(&self) -> Vec<(String, String)> {
        let mut boards: Vec<(String, String)> = self
            .boards
            .iter()
            .map(|class| (class.clone(), device_title(class)))
            .collect();
        boards.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
        boards
    }

    pub fn product_name(&self, product_type: &str) -> Option<String> {
        self.board_product
            .iter()
            .filter(|(_, product)| product.as_str() == product_type)
            .find_map(|(class, _)| known_board_title(class))
    }

    pub fn search_text(&self, name: &str) -> String {
        let Some(description) = self.describe(name) else {
            return String::new();
        };
        let mut parts = vec![description.title, description.summary];
        parts.extend(description.devices);
        parts.extend(description.boards);
        parts.extend(description.components);
        parts.join(" ").to_lowercase()
    }

    fn describe_uses(&self, uses: &[Use]) -> Description {
        let components: BTreeSet<&str> = uses.iter().map(|used| used.key.as_str()).collect();
        // A file used by both `X` and `RestoreX` is titled from `X`.
        let titled_by = |restore_ok: bool| {
            components
                .iter()
                .copied()
                .filter(|key| {
                    restore_ok
                        || without_restore(key)
                            .is_none_or(|twin| !components.contains(twin.as_str()))
                })
                .min_by_key(|key| (priority(key), *key))
        };
        let top = titled_by(false)
            .or_else(|| titled_by(true))
            .unwrap_or_default();
        let title = self.label(top);
        let boards: BTreeSet<String> = uses.iter().filter_map(|used| used.board.clone()).collect();
        let boards: Vec<String> = boards.into_iter().collect();
        let install = install_of(uses.iter().map(|used| used.behavior));
        let devices = device_titles(&boards);
        Description {
            summary: self.compose_summary(&title, install, &boards, &devices),
            title,
            devices,
            chips: chips_of(&boards),
            boards,
            install: install.map(install_text),
            components: components.into_iter().map(str::to_string).collect(),
            from_manifest: true,
        }
    }

    fn describe_by_name(&self, name: &str) -> Option<Description> {
        let base = name.rsplit('/').next().unwrap_or(name);
        if name == "BuildManifest.plist" {
            return Some(plain("Build manifest"));
        }
        if name == "Restore.plist" {
            return Some(plain("Restore information"));
        }
        let top_level_label = match name {
            "PlatformSupport.plist" => Some("Supported platforms"),
            "RestoreVersion.plist" => Some("Restore version"),
            "SystemVersion.plist" => Some("macOS version"),
            "usr/standalone/bootcaches.plist" => Some("Boot caches list"),
            _ => None,
        };
        if let Some(label) = top_level_label {
            return Some(plain(label));
        }
        if base.eq_ignore_ascii_case("apfs.efi") {
            return Some(plain("APFS EFI driver (Intel Macs)"));
        }
        let lower = base.to_ascii_lowercase();
        let path_lower = name.to_ascii_lowercase();
        if let Some((base_len, kind, x86)) = sidecar_parts(&lower) {
            // Names are ASCII-lowercased, so byte lengths match between `lower` and `base`.
            let base_path = &name[..name.len() - (lower.len() - base_len)];
            return Some(self.describe_sidecar(base_path, kind, x86));
        }
        let dirs: Vec<&str> = {
            let mut parts: Vec<&str> = name.split('/').collect();
            parts.pop();
            parts
        };
        if let Some(label) = path_label(&dirs, false) {
            return Some(with_board(label, board_in_text(&path_lower)));
        }
        if lower.ends_with(".im4m") {
            let install = if name.contains("Customer Erase Install") {
                Some(Behavior::Erase)
            } else if name.contains("Customer Upgrade Install") {
                Some(Behavior::Update)
            } else {
                None
            };
            return Some(simple("Signed manifest (IM4M)", install, None));
        }
        if lower == "kernelcache" || lower.starts_with("kernelcache.") {
            return Some(with_board("Kernelcache", board_in_text(&lower)));
        }
        if lower.ends_with(".sefw") {
            return Some(with_board(
                "Secure Element firmware",
                board_in_text(&path_lower),
            ));
        }
        if let Some(rest) = lower
            .strip_suffix(".im4p")
            .or_else(|| lower.strip_suffix(".img4"))
        {
            if BOOT_SCREEN_PREFIXES
                .iter()
                .any(|prefix| rest.starts_with(prefix))
            {
                return Some(with_board("Boot screen image", board_in_text(&path_lower)));
            }
            let stem = rest.split('.').next().unwrap_or_default();
            let (_, key) = FIRMWARE_STEMS.iter().find(|(known, _)| *known == stem)?;
            return Some(with_board(&self.label(key), board_in_text(rest)));
        }
        if lower.starts_with("applediagnostics") {
            return Some(plain("Apple Diagnostics"));
        }
        if lower.starts_with("bridgeversion") {
            return Some(plain("T2 bridge version (Intel Macs)"));
        }
        if lower.ends_with(".dmg.aea") {
            return Some(plain("Encrypted disk image"));
        }
        if lower.ends_with(".dmg") {
            return Some(plain("Disk image"));
        }
        None
    }

    fn describe_sidecar(&self, base_path: &str, kind: Sidecar, x86: bool) -> Description {
        let base_name = base_path.rsplit('/').next().unwrap_or(base_path);
        let base = self
            .uses
            .iter()
            .find(|(path, _)| {
                path.rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(base_name))
            })
            .map(|(_, uses)| self.describe_uses(uses))
            .or_else(|| self.describe_by_name(base_path));
        let title = sidecar_title(kind, base.as_ref().map(|base| base.title.as_str()), x86);
        let Some(base) = base else {
            return plain(&title);
        };
        let install = match base.install.as_deref() {
            Some("erase") => Some(Behavior::Erase),
            Some("update") => Some(Behavior::Update),
            _ => None,
        };
        Description {
            summary: self.compose_summary(&title, install, &base.boards, &base.devices),
            title,
            devices: base.devices,
            chips: base.chips,
            boards: base.boards,
            install: base.install,
            components: Vec::new(),
            from_manifest: false,
        }
    }

    pub fn describe_folder(&self, path: &str) -> Option<String> {
        let dirs: Vec<&str> = path.trim_matches('/').split('/').collect();
        path_label(&dirs, true).map(str::to_string)
    }

    pub fn device_families(&self) -> Vec<(String, usize)> {
        let titles: BTreeSet<String> = self
            .boards
            .iter()
            .map(|class| device_title(class))
            .collect();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for title in titles {
            let family = title.split(" (").next().unwrap_or(&title).to_string();
            *counts.entry(family).or_default() += 1;
        }
        let mut families: Vec<(String, usize)> = counts.into_iter().collect();
        families.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        families
    }

    fn compose_summary(
        &self,
        title: &str,
        install: Option<Behavior>,
        boards: &[String],
        devices: &[String],
    ) -> String {
        let mut parts = vec![title.to_string()];
        if let Some(install) = install {
            parts.push(install_text(install));
        }
        if let Some(phrase) = self.devices_phrase(boards, devices) {
            parts.push(phrase);
        }
        parts.join(SEPARATOR)
    }

    fn devices_phrase(&self, boards: &[String], devices: &[String]) -> Option<String> {
        match (boards.len(), devices.len()) {
            (0, _) | (_, 0) => None,
            (1, _) | (_, 1) => Some(devices[0].clone()),
            // Boards can share a title (j514cap and j514map), so count what the user sees.
            _ if boards.len() == self.boards.len() => {
                Some(format!("all {} devices", devices.len()))
            }
            (_, 2) => Some(format!("{}, {}", devices[0], devices[1])),
            (_, count) => Some(format!(
                "{}, {} +{} more",
                devices[0],
                devices[1],
                count - 2
            )),
        }
    }

    fn label(&self, key: &str) -> String {
        if key == "OS" {
            let os = if self.os_name.is_empty() {
                "OS"
            } else {
                &self.os_name
            };
            return format!("{os} system volume");
        }
        component_label(key)
    }
}

pub fn component_label(key: &str) -> String {
    if let Some(label) = known_label(key) {
        return label.to_string();
    }
    let key = strip_index(key);
    if let Some(label) = known_label(key).or_else(|| family_label(key)) {
        return label.to_string();
    }
    if let Some(label) = numbered_label(key) {
        return label;
    }
    if let Some(twin) = without_restore(key)
        && let Some(label) = known_label(&twin).or_else(|| family_label(&twin))
    {
        return format!("Restore {}", lower_first(label));
    }
    prettify(key)
}

fn strip_index(mut key: &str) -> &str {
    while let Some((head, tail)) = key.rsplit_once(',')
        && !tail.is_empty()
        && tail.chars().all(|ch| ch.is_ascii_digit())
    {
        key = head;
    }
    key
}

fn numbered_label(key: &str) -> Option<String> {
    let rest = key.strip_prefix("Ap,")?;
    let rest = rest.strip_prefix("Restore").unwrap_or(rest);
    let number = |text: &str| {
        (!text.is_empty() && text.chars().all(|ch| ch.is_ascii_digit())).then(|| text.to_string())
    };
    if let Some(n) = rest.strip_prefix("ANE").and_then(number) {
        return Some(format!("Neural Engine firmware ({n})"));
    }
    let n = rest
        .strip_prefix("GFX")?
        .strip_suffix("Firmware")
        .and_then(number)?;
    Some(format!("GPU firmware ({n})"))
}

fn family_label(key: &str) -> Option<&'static str> {
    let (prefix, rest) = key.split_once(',')?;
    match (
        prefix.trim_end_matches(|ch: char| ch.is_ascii_digit()),
        rest,
    ) {
        ("USBPortController", "USBFirmware") => Some("USB-C port controller firmware"),
        ("Wireless", _) => Some("Wi-Fi and Bluetooth firmware"),
        _ => None,
    }
}

fn known_label(key: &str) -> Option<&'static str> {
    let known = match key {
        "AOP" | "AOP2" => "Always-on processor firmware",
        "ANS" | "RestoreANS" => "NAND storage controller firmware",
        "ISP" => "Camera ISP firmware",
        "DCP" | "RestoreDCP" => "Display coprocessor firmware",
        "Ap,DCP2" | "Ap,RestoreDCP2" => "Display coprocessor firmware (2)",
        "Ap,CIO" => "Thunderbolt / USB4 controller firmware",
        "Ap,SecurePageTableMonitor" => "SPTM (secure page table monitor)",
        "Ap,TrustedExecutionMonitor" => "TXM (trusted execution monitor)",
        "Ap,cL4" => "Exclave L4 kernel (cL4)",
        "Ap,SecureM3Firmware" => "Secure M3 firmware",
        "Ap,SCodec" => "SCodec firmware",
        "Ap,AppleTypeCPhyFirmware" => "USB-C PHY firmware",
        "Timer,AppleTypeCPhyFirmware" => "USB-C PHY timer firmware",
        "Timer,RTKitOS" | "Timer,RestoreRTKitOS" => "RTKit timer firmware",
        "Ap,ApplePMCFirmware" => "Power management controller firmware",
        "Ap,MSRFirmware" => "MSR firmware",
        "Ap,XHC" => "USB host controller firmware (XHC)",
        "Ap,GFX1Firmware" => "GPU firmware (1)",
        "Ap,ANE1" => "Neural Engine firmware (1)",
        "Ap,rOSLogo1" | "Ap,rOSLogo2" => "Recovery boot logo",
        "Ap,DisplayVendorCalibration" => "Display calibration",
        "Ap,AudioPowerAttachChime" => "Power attach chime",
        "InputDevice" => "Input device firmware",
        "Multitouch" => "Multitouch firmware",
        "MtpFirmware" => "Multitouch (MTP) firmware",
        "iBootDataStage1" => "iBoot data (stage 1)",
        "SepStage1" => "Secure Enclave stage 1",
        "Baobab,TCON" => "Display timing controller (TCON) firmware",
        "SE,UpdatePayload" => "Secure Element update",
        "Ap,TMU" => "TMU firmware",
        "OS" => "OS system volume",
        "BaseSystem" => "Recovery base system",
        "RecoveryOSASRImage" => "Recovery OS image",
        "RestoreRamDisk" => "Restore ramdisk",
        "KernelCache" => "Kernelcache",
        "RestoreKernelCache" => "Restore kernelcache",
        "DeviceTree" => "DeviceTree",
        "RestoreDeviceTree" => "Restore DeviceTree",
        "iBoot" => "iBoot",
        "iBootData" => "iBoot data",
        "iBEC" => "iBEC (DFU bootloader)",
        "iBSS" => "iBSS (DFU bootloader)",
        "LLB" => "LLB (low-level bootloader)",
        "SEP" => "Secure Enclave firmware",
        "RestoreSEP" => "Restore Secure Enclave firmware",
        "StaticTrustCache" => "Trust cache",
        "RestoreTrustCache" => "Restore trust cache",
        "Cryptex1,SystemOS" => "System cryptex",
        "Cryptex1,AppOS" => "App cryptex",
        "Cryptex1,SystemTrustCache" => "System cryptex trust cache",
        "Cryptex1,AppTrustCache" => "App cryptex trust cache",
        "Cryptex1,SystemVolume" => "System cryptex root hash",
        "Cryptex1,AppVolume" => "App cryptex root hash",
        "SystemVolume" => "System volume root hash",
        "Ap,SystemVolumeCanonicalMetadata" => "System volume metadata",
        "GFX" => "GPU firmware",
        "PMP" => "Power manager firmware",
        "SIO" => "SIO firmware",
        "ANE" => "Neural Engine firmware",
        "AVE" => "Video encoder firmware",
        "Ap,AudioBootChime" => "Boot chime",
        "AppleLogo" => "Boot logo",
        "RecoveryMode" => "Recovery screen",
        _ => return None,
    };
    Some(known)
}

fn prettify(key: &str) -> String {
    let key = strip_index(key.trim());
    let mut words: Vec<String> = Vec::new();
    let segments: Vec<&str> = key.split(',').collect();
    for (index, segment) in segments.iter().enumerate() {
        let is_prefix = index + 1 < segments.len();
        match *segment {
            "Ap" if is_prefix => {}
            "Cryptex1" => words.push("Cryptex".to_string()),
            other => {
                let other = if is_prefix {
                    other.trim_end_matches(|ch: char| ch.is_ascii_digit())
                } else {
                    other
                };
                words.extend(split_camel_case(other));
            }
        }
    }
    let mut out = String::new();
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let acronym = !word.chars().any(char::is_lowercase);
        if index == 0 || acronym {
            out.push_str(word);
        } else {
            out.push_str(&word.to_lowercase());
        }
    }
    if out.is_empty() { key.to_string() } else { out }
}

fn split_camel_case(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();
    for (index, &ch) in chars.iter().enumerate() {
        if let Some(&prev) = index.checked_sub(1).and_then(|at| chars.get(at)) {
            let next_lower = chars.get(index + 1).is_some_and(|next| next.is_lowercase());
            let boundary = ch.is_uppercase()
                && ((prev.is_lowercase() || prev.is_ascii_digit())
                    || (prev.is_uppercase() && next_lower));
            if boundary && !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    // A leading lowercase run belongs to the next word: "iBoot", "cL4".
    if words.len() > 1 && words[0].chars().all(char::is_lowercase) {
        let next = words.remove(1);
        words[0].push_str(&next);
    }
    words
}

fn without_restore(key: &str) -> Option<String> {
    let mut found = false;
    let parts: Vec<&str> = key
        .split(',')
        .map(|part| match part.strip_prefix("Restore") {
            Some(rest) if !found && !rest.is_empty() => {
                found = true;
                rest
            }
            _ => part,
        })
        .collect();
    found.then(|| parts.join(","))
}

fn priority(key: &str) -> usize {
    PRIORITY
        .iter()
        .position(|known| *known == key)
        .unwrap_or(PRIORITY.len())
}

fn string_of<'a>(dict: &'a Dictionary, key: &str) -> Option<&'a str> {
    dict.get(key)
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn os_name_for(product_types: &[&str]) -> &'static str {
    let any = |prefixes: &[&str]| {
        product_types
            .iter()
            .any(|product| prefixes.iter().any(|prefix| product.starts_with(*prefix)))
    };
    if any(&["Mac", "VirtualMac"]) {
        "macOS"
    } else if any(&["iPhone"]) {
        "iOS"
    } else if any(&["iPad"]) {
        "iPadOS"
    } else {
        "OS"
    }
}

fn install_of(behaviors: impl Iterator<Item = Option<Behavior>>) -> Option<Behavior> {
    let mut common: Option<Behavior> = None;
    let mut any = false;
    for behavior in behaviors {
        let behavior = behavior?;
        if any && common != Some(behavior) {
            return None;
        }
        common = Some(behavior);
        any = true;
    }
    common
}

fn install_text(behavior: Behavior) -> String {
    match behavior {
        Behavior::Erase => "erase",
        Behavior::Update => "update",
    }
    .to_string()
}

/// The bundled data names virtual machine boards after their CPU feature set, so they are
/// just "Virtual Mac".
fn device_title(class: &str) -> String {
    if class.trim().to_ascii_lowercase().starts_with("vma") {
        return "Virtual Mac".to_string();
    }
    describe_board(class, None).title
}

fn known_board_title(class: &str) -> Option<String> {
    let title = device_title(class);
    (title != class).then_some(title)
}

fn device_titles(boards: &[String]) -> Vec<String> {
    let titles: BTreeSet<String> = boards.iter().map(|class| device_title(class)).collect();
    titles.into_iter().collect()
}

fn chips_of(boards: &[String]) -> Vec<String> {
    let mut ordered: Vec<(String, &String)> = boards
        .iter()
        .map(|class| (device_title(class), class))
        .collect();
    ordered.sort();
    let mut chips: Vec<String> = Vec::new();
    for (_, class) in ordered {
        if class.starts_with("vma") {
            continue;
        }
        if let Some(chip) = board_chip(class)
            && !chips.contains(&chip)
        {
            chips.push(chip);
        }
    }
    chips
}

/// Firmware names drop the "ap" suffix or turn it into "aop" (`aopfw-j773gaop` is for `j773gap`).
fn board_in_text(text: &str) -> Option<(String, String)> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .find_map(|token| {
            let token = token.to_ascii_lowercase();
            let mut candidates = vec![token.clone(), format!("{token}ap")];
            if let Some(stem) = token.strip_suffix("aop").filter(|stem| !stem.is_empty()) {
                candidates.push(format!("{stem}ap"));
            }
            candidates
                .into_iter()
                .find_map(|class| known_board_title(&class).map(|title| (class, title)))
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sidecar {
    TrustCache,
    RootHash,
    Mtree,
    IntegrityCatalog,
    Info,
}

fn sidecar_parts(lower: &str) -> Option<(usize, Sidecar, bool)> {
    for (suffix, kind) in [
        (".trustcache", Sidecar::TrustCache),
        (".root_hash", Sidecar::RootHash),
        (".mtree", Sidecar::Mtree),
        (".integrity_catalog", Sidecar::IntegrityCatalog),
    ] {
        if let Some(rest) = lower.strip_suffix(suffix) {
            let (rest, x86) = match rest.strip_suffix(".x86") {
                Some(rest) => (rest, true),
                None => (rest, false),
            };
            if !rest.is_empty() {
                return Some((rest.len(), kind, x86));
            }
        }
    }
    let rest = lower.strip_suffix(".plist")?;
    (rest.ends_with(".im4p") || rest.ends_with(".sefw")).then_some((
        rest.len(),
        Sidecar::Info,
        false,
    ))
}

fn sidecar_title(kind: Sidecar, base_title: Option<&str>, x86: bool) -> String {
    let tag = if x86 { " (x86)" } else { "" };
    let noun = match kind {
        Sidecar::TrustCache => "trust cache",
        Sidecar::RootHash => "root hash",
        Sidecar::Mtree => "file tree (mtree)",
        Sidecar::IntegrityCatalog => "integrity catalog",
        Sidecar::Info => "info",
    };
    match (kind, base_title) {
        (Sidecar::Info, Some(base)) => format!("Info for {base}"),
        (Sidecar::Info, None) => "Firmware info".to_string(),
        (_, Some(base)) if base.ends_with("system volume") => {
            format!("System volume {noun}{tag}")
        }
        (_, Some(base)) => format!("{} for {}{tag}", capitalize(noun), lower_first(base)),
        (_, None) => format!("{}{tag}", capitalize(noun)),
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn path_label(dirs: &[&str], for_folder: bool) -> Option<&'static str> {
    let first = dirs.first()?.to_ascii_lowercase();
    let second = dirs.get(1).map(|dir| dir.to_ascii_lowercase());
    match (first.as_str(), second.as_deref()) {
        ("efi", None) => Some(INTEL_FIRMWARE_LABEL),
        ("efi", Some(folder)) => Some(
            EFI_FOLDERS
                .iter()
                .find(|(known, _)| *known == folder)
                .map_or(INTEL_FIRMWARE_LABEL, |(_, label)| *label),
        ),
        ("bootabilitybundle", _) => Some(BOOTABILITY_LABEL),
        ("firmware", Some(folder)) => {
            if let Some((_, label)) = FIRMWARE_FOLDERS.iter().find(|(known, _)| *known == folder) {
                return Some(*label);
            }
            if !for_folder || dirs.len() > 2 {
                return None;
            }
            match folder {
                "all_flash" => Some("Boot firmware"),
                "dfu" => Some("DFU-mode bootloaders"),
                "manifests" => Some("Signed manifests"),
                _ => None,
            }
        }
        _ => None,
    }
}

fn plain(title: &str) -> Description {
    simple(title, None, None)
}

fn with_board(title: &str, board: Option<(String, String)>) -> Description {
    simple(title, None, board)
}

fn simple(title: &str, install: Option<Behavior>, board: Option<(String, String)>) -> Description {
    let (boards, devices) = match board {
        Some((class, device)) => (vec![class], vec![device]),
        None => (Vec::new(), Vec::new()),
    };
    let mut parts = vec![title.to_string()];
    parts.extend(install.map(install_text));
    parts.extend(devices.iter().cloned());
    Description {
        title: title.to_string(),
        summary: parts.join(SEPARATOR),
        devices,
        chips: chips_of(&boards),
        boards,
        install: install.map(install_text),
        components: Vec::new(),
        from_manifest: false,
    }
}

fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    let other_capitals = text
        .split(' ')
        .skip(1)
        .any(|word| word.chars().next().is_some_and(char::is_uppercase));
    match (chars.next(), chars.next()) {
        (Some(first), Some(second))
            if first.is_uppercase() && second.is_lowercase() && !other_capitals =>
        {
            let mut out: String = first.to_lowercase().collect();
            out.push(second);
            out.extend(chars);
            out
        }
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsw_fixture::realistic_manifest_plist;

    fn s(text: &str) -> Value {
        Value::String(text.to_string())
    }

    fn dict(pairs: Vec<(&str, Value)>) -> Dictionary {
        Dictionary::from_iter(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value)),
        )
    }

    fn identity(
        board: &str,
        behavior: Option<&str>,
        product: Option<&str>,
        components: &[(&str, &str)],
    ) -> Value {
        let mut info = vec![("DeviceClass", s(board))];
        if let Some(behavior) = behavior {
            info.push(("RestoreBehavior", s(behavior)));
        }
        let manifest = components
            .iter()
            .map(|(key, path)| {
                (
                    *key,
                    Value::Dictionary(dict(vec![(
                        "Info",
                        Value::Dictionary(dict(vec![("Path", s(path))])),
                    )])),
                )
            })
            .collect();
        let mut pairs = vec![
            ("Info", Value::Dictionary(dict(info))),
            ("Manifest", Value::Dictionary(dict(manifest))),
        ];
        if let Some(product) = product {
            pairs.push(("Ap,ProductType", s(product)));
        }
        Value::Dictionary(dict(pairs))
    }

    fn manifest(identities: Vec<Value>) -> Dictionary {
        dict(vec![("BuildIdentities", Value::Array(identities))])
    }

    fn title_of(class: &str) -> String {
        describe_board(class, None).title
    }

    fn realistic() -> IpswCatalog {
        let value = Value::from_reader(std::io::Cursor::new(realistic_manifest_plist())).unwrap();
        IpswCatalog::from_manifest(value.as_dictionary().unwrap())
    }

    #[test]
    fn realistic_manifest_describes_the_restore_ramdisks() {
        let catalog = realistic();
        let erase = catalog.describe("090-12345-003.dmg").unwrap();
        assert_eq!(erase.title, "Restore ramdisk");
        assert_eq!(erase.install.as_deref(), Some("erase"));
        assert_eq!(erase.summary, "Restore ramdisk · erase · all 2 devices");
        assert_eq!(erase.components, vec!["RestoreRamDisk"]);
        assert!(erase.from_manifest);
        let update = catalog.describe("090-12345-004.dmg").unwrap();
        assert_eq!(update.summary, "Restore ramdisk · update · all 2 devices");
        assert_eq!(update.boards, vec!["j414cap", "j473ap"]);
    }

    #[test]
    fn the_os_label_follows_the_product_family() {
        let catalog = realistic();
        let os = catalog.describe("090-12345-001.dmg.aea").unwrap();
        assert_eq!(os.title, "macOS system volume");
        assert_eq!(os.install, None, "used by both erase and update identities");
        assert_eq!(os.summary, "macOS system volume · all 2 devices");
        let cryptex = catalog.describe("090-12345-005.dmg.aea").unwrap();
        assert_eq!(cryptex.title, "System cryptex");
        assert_eq!(
            catalog.describe("090-12345-006.dmg").unwrap().title,
            "App cryptex"
        );

        let phone = IpswCatalog::from_manifest(&manifest(vec![identity(
            "d83ap",
            Some("Erase"),
            Some("iPhone16,1"),
            &[("OS", "os.dmg")],
        )]));
        assert_eq!(phone.describe("os.dmg").unwrap().title, "iOS system volume");
        let pad = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j617ap",
            Some("Erase"),
            Some("iPad14,5"),
            &[("OS", "os.dmg")],
        )]));
        assert_eq!(
            pad.describe("os.dmg").unwrap().title,
            "iPadOS system volume"
        );
        let unknown = IpswCatalog::from_manifest(&manifest(vec![identity(
            "x1ap",
            None,
            None,
            &[("OS", "os.dmg")],
        )]));
        assert_eq!(
            unknown.describe("os.dmg").unwrap().title,
            "OS system volume"
        );
        let virtual_mac = IpswCatalog::from_manifest(&manifest(vec![identity(
            "vma2macosap",
            None,
            Some("VirtualMac2,1"),
            &[("OS", "os.dmg")],
        )]));
        assert_eq!(
            virtual_mac.describe("os.dmg").unwrap().title,
            "macOS system volume"
        );
    }

    #[test]
    fn per_board_files_name_their_device() {
        let catalog = realistic();
        let kernel = catalog.describe("kernelcache.release.mac14j").unwrap();
        assert_eq!(kernel.title, "Kernelcache");
        assert_eq!(kernel.boards, vec!["j473ap"]);
        assert_eq!(kernel.devices, vec![title_of("j473ap")]);
        assert!(kernel.devices[0].contains("Mac mini"));
        assert_eq!(
            kernel.summary,
            format!("Kernelcache · {}", title_of("j473ap"))
        );
        assert_eq!(kernel.install, None);
        let ibec = catalog
            .describe("Firmware/dfu/iBEC.j473.RELEASE.im4p")
            .unwrap();
        assert_eq!(ibec.title, "iBEC (DFU bootloader)");
        assert!(ibec.summary.starts_with("iBEC (DFU bootloader) · Mac mini"));
    }

    #[test]
    fn the_most_significant_component_names_a_shared_entry() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            Some("Erase"),
            Some("Mac14,3"),
            &[
                ("StaticTrustCache", "shared.img4"),
                ("RestoreKernelCache", "shared.img4"),
                ("KernelCache", "shared.img4"),
                ("Zeta,Thing", "shared.img4"),
            ],
        )]));
        let shared = catalog.describe("shared.img4").unwrap();
        assert_eq!(shared.title, "Kernelcache");
        assert_eq!(
            shared.components,
            vec![
                "KernelCache",
                "RestoreKernelCache",
                "StaticTrustCache",
                "Zeta,Thing"
            ]
        );
        let unlisted_only = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            None,
            None,
            &[("Zed,Two", "x.bin"), ("Alpha,One", "x.bin")],
        )]));
        assert_eq!(unlisted_only.describe("x.bin").unwrap().title, "Alpha one");
    }

    #[test]
    fn install_kind_needs_every_identity_to_agree() {
        let uses = |behaviors: &[Option<&str>]| {
            let identities = behaviors
                .iter()
                .enumerate()
                .map(|(index, behavior)| {
                    identity(
                        &format!("j{index}ap"),
                        *behavior,
                        None,
                        &[("RestoreRamDisk", "r.dmg")],
                    )
                })
                .collect();
            IpswCatalog::from_manifest(&manifest(identities))
                .describe("r.dmg")
                .unwrap()
                .install
        };
        assert_eq!(
            uses(&[Some("Erase"), Some("Erase")]).as_deref(),
            Some("erase")
        );
        assert_eq!(uses(&[Some("Update")]).as_deref(), Some("update"));
        assert_eq!(uses(&[Some("erase"), Some("UPDATE")]), None);
        assert_eq!(uses(&[Some("Erase"), None]), None);
        assert_eq!(uses(&[Some("Restore")]), None);
    }

    fn many_boards(users: &[&str]) -> IpswCatalog {
        let all = ["j473ap", "j274ap", "j313ap", "j414cap"];
        let identities = all
            .iter()
            .map(|board| {
                let components: Vec<(&str, &str)> = if users.contains(board) {
                    vec![("RestoreRamDisk", "r.dmg")]
                } else {
                    vec![("KernelCache", "other")]
                };
                identity(board, Some("Erase"), None, &components)
            })
            .collect();
        IpswCatalog::from_manifest(&manifest(identities))
    }

    #[test]
    fn the_devices_phrase_scales_with_the_boards() {
        let titles = |classes: &[&str]| {
            let mut titles: Vec<String> = classes.iter().map(|class| title_of(class)).collect();
            titles.sort();
            titles
        };
        let phrase = |users: &[&str]| many_boards(users).describe("r.dmg").unwrap().summary;
        let one = titles(&["j473ap"]);
        assert_eq!(
            phrase(&["j473ap"]),
            format!("Restore ramdisk · erase · {}", one[0])
        );
        let two = titles(&["j473ap", "j274ap"]);
        assert_eq!(
            phrase(&["j473ap", "j274ap"]),
            format!("Restore ramdisk · erase · {}, {}", two[0], two[1])
        );
        let three = titles(&["j473ap", "j274ap", "j313ap"]);
        assert_eq!(
            phrase(&["j473ap", "j274ap", "j313ap"]),
            format!(
                "Restore ramdisk · erase · {}, {} +1 more",
                three[0], three[1]
            )
        );
        assert_eq!(
            phrase(&["j473ap", "j274ap", "j313ap", "j414cap"]),
            "Restore ramdisk · erase · all 4 devices"
        );
        let description = many_boards(&["j473ap", "j274ap", "j313ap"])
            .describe("r.dmg")
            .unwrap();
        assert_eq!(description.devices, three);
    }

    #[test]
    fn a_single_board_manifest_names_the_device_rather_than_all() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            Some("Erase"),
            None,
            &[("RestoreRamDisk", "r.dmg")],
        )]));
        let summary = catalog.describe("r.dmg").unwrap().summary;
        assert_eq!(
            summary,
            format!("Restore ramdisk · erase · {}", title_of("j473ap"))
        );
    }

    #[test]
    fn unknown_boards_keep_their_class() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![
            identity(
                "zz999ap",
                Some("Erase"),
                None,
                &[("iBoot", "Firmware/iBoot.zz999.im4p")],
            ),
            identity(
                "j473ap",
                Some("Erase"),
                None,
                &[("iBoot", "Firmware/iBoot.j473.im4p")],
            ),
        ]));
        let description = catalog.describe("Firmware/iBoot.zz999.im4p").unwrap();
        assert_eq!(description.devices, vec!["zz999ap"]);
        assert!(
            description.summary.ends_with("zz999ap"),
            "{}",
            description.summary
        );
        let boards = catalog.boards();
        assert!(boards.contains(&("zz999ap".to_string(), "zz999ap".to_string())));
        assert_eq!(catalog.product_name("Mac99,9"), None);
        let paired = IpswCatalog::from_manifest(&manifest(vec![identity(
            "zz999ap",
            None,
            Some("Mac99,9"),
            &[],
        )]));
        assert_eq!(
            paired.product_name("Mac99,9"),
            None,
            "an unknown board gives no name"
        );
    }

    #[test]
    fn unknown_component_keys_are_prettified() {
        assert_eq!(component_label("FooBarBaz"), "Foo bar baz");
        assert_eq!(component_label("Ap,FooBar"), "Foo bar");
        assert_eq!(component_label("Cryptex1,WidgetOS"), "Cryptex widget OS");
        assert_eq!(
            component_label("Cryptex1,AppTrustCache"),
            "App cryptex trust cache"
        );
        assert_eq!(component_label("OSASRImage"), "OSASR image");
        assert_eq!(component_label("Solo"), "Solo");
        assert_eq!(component_label(""), "");
        assert_eq!(component_label("Other,thing"), "Other thing");
    }

    #[test]
    fn every_documented_label_is_present() {
        let expected = [
            ("OS", "OS system volume"),
            ("BaseSystem", "Recovery base system"),
            ("RecoveryOSASRImage", "Recovery OS image"),
            ("RestoreRamDisk", "Restore ramdisk"),
            ("KernelCache", "Kernelcache"),
            ("RestoreKernelCache", "Restore kernelcache"),
            ("DeviceTree", "DeviceTree"),
            ("RestoreDeviceTree", "Restore DeviceTree"),
            ("iBoot", "iBoot"),
            ("iBootData", "iBoot data"),
            ("iBEC", "iBEC (DFU bootloader)"),
            ("iBSS", "iBSS (DFU bootloader)"),
            ("LLB", "LLB (low-level bootloader)"),
            ("SEP", "Secure Enclave firmware"),
            ("RestoreSEP", "Restore Secure Enclave firmware"),
            ("StaticTrustCache", "Trust cache"),
            ("RestoreTrustCache", "Restore trust cache"),
            ("Cryptex1,SystemOS", "System cryptex"),
            ("Cryptex1,AppOS", "App cryptex"),
            ("Cryptex1,SystemTrustCache", "System cryptex trust cache"),
            ("Cryptex1,SystemVolume", "System cryptex root hash"),
            ("Cryptex1,AppVolume", "App cryptex root hash"),
            ("SystemVolume", "System volume root hash"),
            ("Ap,SystemVolumeCanonicalMetadata", "System volume metadata"),
            ("GFX", "GPU firmware"),
            ("PMP", "Power manager firmware"),
            ("SIO", "SIO firmware"),
            ("ANE", "Neural Engine firmware"),
            ("AVE", "Video encoder firmware"),
            ("Ap,AudioBootChime", "Boot chime"),
            ("AppleLogo", "Boot logo"),
            ("RecoveryMode", "Recovery screen"),
        ];
        for (key, label) in expected {
            assert_eq!(component_label(key), label, "{key}");
        }
    }

    #[test]
    fn names_the_manifest_does_not_mention_fall_back_to_their_shape() {
        let catalog = realistic();
        let sep = catalog
            .describe("Firmware/all_flash/sep-firmware.j473.RELEASE.im4p")
            .unwrap();
        assert_eq!(sep.title, "Secure Enclave firmware");
        assert!(!sep.from_manifest);
        assert_eq!(sep.boards, vec!["j473ap"]);
        assert!(sep.summary.contains("Mac mini"), "{}", sep.summary);
        let tree = IpswCatalog::default();
        assert_eq!(
            tree.describe("Firmware/all_flash/DeviceTree.j473ap.im4p")
                .unwrap()
                .title,
            "DeviceTree"
        );
        assert_eq!(
            tree.describe("Firmware/dfu/iBSS.j414c.RELEASE.img4")
                .unwrap()
                .title,
            "iBSS (DFU bootloader)"
        );
        assert_eq!(
            tree.describe("Firmware/all_flash/LLB.j414c.DEVELOPMENT.im4p")
                .unwrap()
                .title,
            "LLB (low-level bootloader)"
        );
        assert_eq!(
            tree.describe("kernelcache.release.mac14j").unwrap().summary,
            "Kernelcache"
        );
        assert_eq!(tree.describe("kernelcache").unwrap().title, "Kernelcache");
        assert_eq!(tree.describe("a/b.dmg").unwrap().title, "Disk image");
        assert_eq!(
            tree.describe("a/b.dmg.aea").unwrap().title,
            "Encrypted disk image"
        );
        assert_eq!(
            tree.describe("a/b.trustcache").unwrap().title,
            "Trust cache"
        );
        assert_eq!(
            tree.describe("BuildManifest.plist").unwrap().summary,
            "Build manifest"
        );
        assert_eq!(
            tree.describe("Restore.plist").unwrap().title,
            "Restore information"
        );
    }

    #[test]
    fn entries_with_nothing_to_say_have_no_description() {
        let tree = IpswCatalog::default();
        for name in [
            "Firmware/notes.txt",
            "Firmware/Manifests/restore/info.plist",
            "Firmware/all_flash/mystery.j473.im4p",
            "Firmware",
            "",
            "readme",
        ] {
            assert_eq!(tree.describe(name), None, "{name}");
            assert_eq!(tree.search_text(name), "", "{name}");
        }
    }

    #[test]
    fn an_undescribed_trust_cache_inherits_its_disk_images_role() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![
            identity(
                "j473ap",
                Some("Erase"),
                None,
                &[("RestoreRamDisk", "090-1.dmg")],
            ),
            identity(
                "j414cap",
                Some("Erase"),
                None,
                &[("RestoreRamDisk", "090-1.dmg")],
            ),
        ]));
        let cache = catalog.describe("Firmware/090-1.dmg.trustcache").unwrap();
        assert_eq!(cache.title, "Trust cache for restore ramdisk");
        assert_eq!(
            cache.summary,
            "Trust cache for restore ramdisk · erase · all 2 devices"
        );
        assert_eq!(cache.install.as_deref(), Some("erase"));
        assert!(!cache.from_manifest);
        assert_eq!(cache.boards, vec!["j414cap", "j473ap"]);
        assert_eq!(
            catalog
                .describe("Firmware/zzz.dmg.trustcache")
                .unwrap()
                .summary,
            "Trust cache for disk image"
        );
        assert_eq!(
            catalog.describe("Firmware/zzz.trustcache").unwrap().summary,
            "Trust cache"
        );
        let os = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            None,
            Some("Mac14,3"),
            &[("OS", "os.dmg.aea")],
        )]));
        assert_eq!(
            os.describe("os.dmg.aea.trustcache").unwrap().title,
            "System volume trust cache"
        );
    }

    fn real_shaped() -> IpswCatalog {
        let boards = ["j456ap", "j457ap", "j514cap", "j514map", "j473ap"];
        let identities = boards
            .iter()
            .map(|board| {
                identity(
                    board,
                    Some("Erase"),
                    Some("Mac14,3"),
                    &[
                        ("OS", "094-56453-088.dmg.aea"),
                        ("RestoreRamDisk", "094-55986-096.dmg"),
                    ],
                )
            })
            .collect();
        IpswCatalog::from_manifest(&manifest(identities))
    }

    #[test]
    fn the_device_count_counts_distinct_titles() {
        let catalog = real_shaped();
        let description = catalog.describe("094-56453-088.dmg.aea").unwrap();
        assert_eq!(description.boards.len(), 5);
        assert_eq!(description.devices.len(), 3);
        assert_eq!(
            description.summary,
            "macOS system volume · erase · all 3 devices"
        );
    }

    #[test]
    fn sidecars_inherit_the_role_of_their_base_file() {
        let catalog = real_shaped();
        for (name, title) in [
            (
                "Firmware/094-56453-088.dmg.aea.x86.trustcache",
                "System volume trust cache (x86)",
            ),
            (
                "Firmware/094-56453-088.dmg.aea.trustcache",
                "System volume trust cache",
            ),
            (
                "Firmware/094-56453-088.dmg.aea.x86.root_hash",
                "System volume root hash (x86)",
            ),
            (
                "Firmware/094-56453-088.dmg.aea.x86.mtree",
                "System volume file tree (mtree) (x86)",
            ),
            (
                "Firmware/094-56453-088.dmg.aea.integrity_catalog",
                "System volume integrity catalog",
            ),
            (
                "Firmware/094-55986-096.dmg.x86.trustcache",
                "Trust cache for restore ramdisk (x86)",
            ),
        ] {
            let description = catalog.describe(name).unwrap();
            assert_eq!(description.title, title, "{name}");
            assert!(!description.from_manifest, "{name}");
            assert_eq!(description.install.as_deref(), Some("erase"), "{name}");
            assert_eq!(description.boards.len(), 5, "{name}");
            assert!(description.summary.ends_with("all 3 devices"), "{name}");
        }
        assert!(
            catalog
                .search_text("Firmware/094-55986-096.dmg.x86.trustcache")
                .contains("restore ramdisk")
        );
    }

    #[test]
    fn firmware_plists_describe_the_image_beside_them() {
        let catalog = IpswCatalog::default();
        let plist = catalog
            .describe("Firmware/all_flash/sep-firmware.j473.RELEASE.im4p.plist")
            .unwrap();
        assert_eq!(
            plist.summary,
            format!("Info for Secure Enclave firmware · {}", title_of("j473ap"))
        );
        assert_eq!(plist.boards, vec!["j473ap"]);
        let element = catalog
            .describe("Firmware/SE/chip.j473.sefw.plist")
            .unwrap();
        assert_eq!(element.title, "Info for Secure Element firmware");
        assert_eq!(
            catalog.describe("Firmware/Manifests/restore/info.plist"),
            None
        );
        let named = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            Some("Erase"),
            None,
            &[("StaticTrustCache", "x.dmg.x86.trustcache")],
        )]));
        assert_eq!(
            named.describe("x.dmg.x86.trustcache").unwrap().title,
            "Trust cache"
        );
    }

    #[test]
    fn chips_follow_the_sorted_device_titles() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![
            identity("j473ap", None, None, &[("KernelCache", "k")]),
            identity("j274ap", None, None, &[("KernelCache", "k")]),
            identity("j313ap", None, None, &[("KernelCache", "k")]),
        ]));
        let description = catalog.describe("k").unwrap();
        assert_eq!(description.chips, vec!["M1", "M2"]);
        let one = IpswCatalog::default()
            .describe("Firmware/all_flash/iBoot.j473.RELEASE.im4p")
            .unwrap();
        assert_eq!(one.chips, vec!["M2"]);
        assert!(
            IpswCatalog::default()
                .describe("a.dmg")
                .unwrap()
                .chips
                .is_empty()
        );
    }

    #[test]
    fn device_families_count_distinct_devices() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![
            identity("j473ap", None, None, &[]),
            identity("j274ap", None, None, &[]),
            identity("j456ap", None, None, &[]),
            identity("j457ap", None, None, &[]),
            identity("j414cap", None, None, &[]),
        ]));
        assert_eq!(
            catalog.device_families(),
            vec![
                ("Mac mini".to_string(), 2),
                ("MacBook Pro".to_string(), 1),
                ("iMac".to_string(), 1),
            ]
        );
        assert!(IpswCatalog::default().device_families().is_empty());
    }

    #[test]
    fn virtual_machine_boards_are_called_virtual_mac() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![
            identity(
                "vma2macosap",
                Some("Erase"),
                Some("VirtualMac2,1"),
                &[("KernelCache", "k")],
            ),
            identity("j473ap", Some("Erase"), None, &[("KernelCache", "k")]),
        ]));
        let boards = catalog.boards();
        assert!(boards.contains(&("vma2macosap".to_string(), "Virtual Mac".to_string())));
        assert_eq!(
            catalog.product_name("VirtualMac2,1").as_deref(),
            Some("Virtual Mac")
        );
        let description = catalog.describe("k").unwrap();
        assert!(description.devices.contains(&"Virtual Mac".to_string()));
        assert_eq!(description.chips, vec!["M2"], "the VM's VCPU is not a chip");
        assert_eq!(catalog.device_families().len(), 2);
    }

    #[test]
    fn real_archive_names_are_described_without_the_manifest() {
        let catalog = IpswCatalog::default();
        let summary = |name: &str| catalog.describe(name).map(|d| d.summary);
        assert_eq!(
            summary("AppleDiagnostics.dmg").as_deref(),
            Some("Apple Diagnostics")
        );
        assert_eq!(
            summary("BridgeVersion.plist").as_deref(),
            Some("T2 bridge version (Intel Macs)")
        );
        assert_eq!(
            summary("BridgeVersion.bin").as_deref(),
            Some("T2 bridge version (Intel Macs)")
        );
        assert_eq!(
            summary("Firmware/SE/x.sefw").as_deref(),
            Some("Secure Element firmware")
        );
        assert_eq!(
            summary("BootabilityBundle/Restore/Bootability/x.bin").as_deref(),
            Some("Bootability bundle (restore preflight)")
        );
        let erase = catalog
            .describe("Firmware/Manifests/restore/Customer Erase Install (IPSW)/x.im4m")
            .unwrap();
        assert_eq!(erase.title, "Signed manifest (IM4M)");
        assert_eq!(erase.install.as_deref(), Some("erase"));
        assert_eq!(erase.summary, "Signed manifest (IM4M) · erase");
        let upgrade = catalog
            .describe("Firmware/Manifests/restore/Customer Upgrade Install (IPSW)/x.im4m")
            .unwrap();
        assert_eq!(upgrade.install.as_deref(), Some("update"));
        assert_eq!(
            summary("a/plain.im4m").as_deref(),
            Some("Signed manifest (IM4M)")
        );
        for (name, label) in [
            (
                "Firmware/AOP/aopfw-j473aop.im4p",
                "Always-on processor firmware",
            ),
            ("Firmware/AOP2/x.im4p", "Always-on processor firmware"),
            ("Firmware/dcp/x.im4p", "Display coprocessor firmware"),
            ("Firmware/agx/x.im4p", "GPU firmware"),
            ("Firmware/ane/x.im4p", "Neural Engine firmware"),
            ("Firmware/ave/x.im4p", "Video encoder firmware"),
            ("Firmware/isp_bni/x.im4p", "Camera ISP firmware"),
            ("Firmware/pmp/x.im4p", "Power manager firmware"),
            ("Firmware/DisplayCalibration/x.bin", "Display calibration"),
            ("Firmware/EmbeddedAudioResources/x.bin", "Audio resources"),
            ("Firmware/DP855/x.bin", "DisplayPort controller firmware"),
            ("Firmware/Ace3/x.bin", "USB-C controller firmware"),
            ("Firmware/sep-patches/x.bin", "Secure Enclave patches"),
            ("Firmware/iBootDataStage1/x.bin", "iBoot data (stage 1)"),
            (
                "EFI/USBCUpdater/x.bin",
                "USB-C controller firmware (Intel Macs)",
            ),
            ("EFI/AMDFirmware/x.bin", "AMD GPU firmware (Intel Macs)"),
            ("EFI/AppleSSDFirmware/x.bin", "SSD firmware (Intel Macs)"),
            (
                "EFI/AppleSDFirmware/x.bin",
                "SD card reader firmware (Intel Macs)",
            ),
            (
                "EFI/DP2HDMIUpdater/x.bin",
                "HDMI adapter firmware (Intel Macs)",
            ),
            ("EFI/SMCPayloads/x.bin", "SMC firmware (Intel Macs)"),
            ("EFI/EFIPayloads/x.bin", "EFI firmware (Intel Macs)"),
            ("EFI/MultiUpdater/x.bin", "Firmware updater (Intel Macs)"),
            ("EFI/Mystery/x.bin", "Intel Mac firmware"),
        ] {
            assert_eq!(catalog.describe(name).unwrap().title, label, "{name}");
        }
        let aop = catalog.describe("Firmware/AOP/aopfw-j473aop.im4p").unwrap();
        assert_eq!(aop.boards, vec!["j473ap"]);
        let isp = catalog
            .describe("Firmware/isp_bni/image4/j473/x.im4p")
            .unwrap();
        assert_eq!(isp.boards, vec!["j473ap"]);
        for name in [
            "Firmware/all_flash/batterycharging0@2x.j473.RELEASE.im4p",
            "Firmware/all_flash/applelogo@2x.RELEASE.im4p",
            "Firmware/all_flash/recoverymode@3x.im4p",
            "Firmware/all_flash/glyphplugin.j473.im4p",
            "Firmware/all_flash/recoveryoslogo.im4p",
            "Firmware/all_flash/batterylow1.im4p",
            "Firmware/all_flash/batteryfull.im4p",
        ] {
            assert_eq!(
                catalog.describe(name).unwrap().title,
                "Boot screen image",
                "{name}"
            );
        }
    }

    #[test]
    fn real_manifest_keys_have_readable_labels() {
        for (key, label) in [
            ("AOP", "Always-on processor firmware"),
            ("AOP2", "Always-on processor firmware"),
            ("ANS", "NAND storage controller firmware"),
            ("RestoreANS", "NAND storage controller firmware"),
            ("ISP", "Camera ISP firmware"),
            ("DCP", "Display coprocessor firmware"),
            ("RestoreDCP", "Display coprocessor firmware"),
            ("Ap,DCP2", "Display coprocessor firmware (2)"),
            ("Ap,RestoreDCP2", "Display coprocessor firmware (2)"),
            ("Ap,CIO", "Thunderbolt / USB4 controller firmware"),
            (
                "Ap,SecurePageTableMonitor",
                "SPTM (secure page table monitor)",
            ),
            (
                "Ap,TrustedExecutionMonitor",
                "TXM (trusted execution monitor)",
            ),
            ("Ap,cL4", "Exclave L4 kernel (cL4)"),
            ("Ap,SecureM3Firmware", "Secure M3 firmware"),
            ("Ap,SCodec", "SCodec firmware"),
            ("Ap,AppleTypeCPhyFirmware", "USB-C PHY firmware"),
            ("Timer,AppleTypeCPhyFirmware,1", "USB-C PHY timer firmware"),
            ("Timer,RTKitOS,1", "RTKit timer firmware"),
            ("Timer,RestoreRTKitOS,2", "RTKit timer firmware"),
            (
                "Ap,ApplePMCFirmware",
                "Power management controller firmware",
            ),
            ("Ap,MSRFirmware", "MSR firmware"),
            ("Ap,XHC", "USB host controller firmware (XHC)"),
            ("Ap,GFX1Firmware", "GPU firmware (1)"),
            ("Ap,ANE1", "Neural Engine firmware (1)"),
            ("Ap,rOSLogo1", "Recovery boot logo"),
            ("Ap,rOSLogo2", "Recovery boot logo"),
            ("Ap,DisplayVendorCalibration", "Display calibration"),
            ("Ap,AudioPowerAttachChime", "Power attach chime"),
            ("InputDevice", "Input device firmware"),
            ("Multitouch", "Multitouch firmware"),
            ("MtpFirmware", "Multitouch (MTP) firmware"),
            ("iBootDataStage1", "iBoot data (stage 1)"),
            ("SepStage1", "Secure Enclave stage 1"),
            ("Baobab,TCON", "Display timing controller (TCON) firmware"),
            (
                "USBPortController1,USBFirmware",
                "USB-C port controller firmware",
            ),
            (
                "USBPortController4,USBFirmware",
                "USB-C port controller firmware",
            ),
            ("Wireless1,ACIBT", "Wi-Fi and Bluetooth firmware"),
            ("Wireless2,Anything", "Wi-Fi and Bluetooth firmware"),
            ("SE,UpdatePayload", "Secure Element update"),
            ("Ap,TMU", "TMU firmware"),
            ("Ap,RestoreTMU", "Restore TMU firmware"),
            ("Ap,RestorecL4", "Restore Exclave L4 kernel (cL4)"),
            (
                "Ap,RestoreSecurePageTableMonitor",
                "Restore SPTM (secure page table monitor)",
            ),
        ] {
            assert_eq!(component_label(key), label, "{key}");
        }
    }

    #[test]
    fn the_prettifier_keeps_leading_lowercase_runs_and_never_emits_lone_lowercase_letters() {
        assert_eq!(component_label("Ap,iBootFoo"), "iBoot foo");
        assert_eq!(component_label("Ap,cL4Foo"), "cL4 foo");
        assert_eq!(component_label("Ap,rOSLogo9"), "rOS logo9");
        assert_eq!(
            component_label("Ap,AppleTypeCPhyOther"),
            "Apple type C phy other"
        );
        assert_eq!(component_label("Timer,Mystery,7"), "Timer mystery");
        assert_eq!(component_label("Unknown3,Thing"), "Unknown thing");
        assert_eq!(component_label("Ap,FooBar,12"), "Foo bar");
        for key in [
            "iBootDataStage1",
            "SepStage1",
            "Ap,cL4",
            "Ap,RestorecL4",
            "Ap,rOSLogo2",
            "Ap,SCodec",
            "MtpFirmware",
            "Timer,AppleTypeCPhyFirmware,1",
            "Timer,RTKitOS,1",
            "Wireless1,ACIBT",
            "USBPortController1,USBFirmware",
            "Ap,ANE1",
            "AOP",
            "AOP2",
            "ISP",
            "ANS",
            "Ap,DCP2",
            "Ap,CIO",
            "Ap,XHC",
            "Ap,SCodecX",
            "Ap,SomethingNewC",
        ] {
            let label = component_label(key);
            for word in label.split(' ') {
                let lone_lowercase =
                    word.chars().count() == 1 && word.chars().all(char::is_lowercase);
                assert!(!lone_lowercase, "{key} -> {label}");
            }
            assert!(
                !label.contains(",1") && !label.contains("  "),
                "{key} -> {label}"
            );
        }
    }

    #[test]
    fn a_file_used_by_a_key_and_its_restore_twin_is_titled_from_the_plain_key() {
        let catalog = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            Some("Erase"),
            None,
            &[
                ("Ap,RestoreTMU", "tmu.im4p"),
                ("Ap,TMU", "tmu.im4p"),
                ("Ap,RestoreDCP2", "dcp.im4p"),
                ("Ap,DCP2", "dcp.im4p"),
                ("RestoreANS", "ans.im4p"),
            ],
        )]));
        let tmu = catalog.describe("tmu.im4p").unwrap();
        assert_eq!(tmu.title, "TMU firmware");
        assert_eq!(tmu.components, vec!["Ap,RestoreTMU", "Ap,TMU"]);
        assert_eq!(
            catalog.describe("dcp.im4p").unwrap().title,
            "Display coprocessor firmware (2)"
        );
        assert_eq!(
            catalog.describe("ans.im4p").unwrap().title,
            "NAND storage controller firmware"
        );
        let only_restore = IpswCatalog::from_manifest(&manifest(vec![identity(
            "j473ap",
            None,
            None,
            &[("Ap,RestoreTMU", "only.im4p")],
        )]));
        assert_eq!(
            only_restore.describe("only.im4p").unwrap().title,
            "Restore TMU firmware"
        );
    }

    #[test]
    fn numbered_chips_and_remaining_folders_are_labelled() {
        for (key, label) in [
            ("Ap,ANE1", "Neural Engine firmware (1)"),
            ("Ap,ANE2", "Neural Engine firmware (2)"),
            ("Ap,RestoreANE3", "Neural Engine firmware (3)"),
            ("Ap,GFX1Firmware", "GPU firmware (1)"),
            ("Ap,GFX3Firmware", "GPU firmware (3)"),
            ("Ap,RestoreGFX2Firmware", "GPU firmware (2)"),
        ] {
            assert_eq!(component_label(key), label, "{key}");
        }
        assert!(!component_label("Ap,ANEx").starts_with("Neural"));
        let catalog = IpswCatalog::default();
        for (name, label) in [
            (
                "Firmware/usr/standalone/i386/apfs.efi",
                "APFS EFI driver (Intel Macs)",
            ),
            ("Firmware/rt15m/accessory.uarp", "Accessory firmware (UARP)"),
            (
                "Firmware/rt15m/accessory.uarp.plist",
                "Accessory firmware (UARP)",
            ),
            ("Firmware/Volchok/blob.bin", "Volchok firmware"),
            ("Firmware/Volchok/blob.plist", "Volchok firmware"),
        ] {
            assert_eq!(catalog.describe(name).unwrap().title, label, "{name}");
        }
        assert_eq!(
            catalog.describe_folder("Firmware/rt15m").as_deref(),
            Some("Accessory firmware (UARP)")
        );
        assert_eq!(
            catalog.describe_folder("Firmware/Volchok").as_deref(),
            Some("Volchok firmware")
        );
    }

    #[test]
    fn small_top_level_files_are_described() {
        let catalog = IpswCatalog::default();
        for (name, label) in [
            ("PlatformSupport.plist", "Supported platforms"),
            ("RestoreVersion.plist", "Restore version"),
            ("SystemVersion.plist", "macOS version"),
            ("usr/standalone/bootcaches.plist", "Boot caches list"),
            (
                "Firmware/ps190/ps190.bin",
                "DisplayPort-to-HDMI converter firmware",
            ),
            (
                "Firmware/ps190/ps190.bin.plist",
                "DisplayPort-to-HDMI converter firmware",
            ),
        ] {
            assert_eq!(catalog.describe(name).unwrap().title, label, "{name}");
        }
        assert_eq!(
            catalog.describe_folder("Firmware/ps190").as_deref(),
            Some("DisplayPort-to-HDMI converter firmware")
        );
        assert_eq!(catalog.describe("usr/standalone/other.plist"), None);
    }

    #[test]
    fn folders_have_labels_too() {
        let catalog = IpswCatalog::default();
        let folder = |path: &str| catalog.describe_folder(path);
        assert_eq!(folder("EFI").as_deref(), Some("Intel Mac firmware"));
        assert_eq!(
            folder("EFI/SMCPayloads").as_deref(),
            Some("SMC firmware (Intel Macs)")
        );
        assert_eq!(
            folder("BootabilityBundle").as_deref(),
            Some("Bootability bundle (restore preflight)")
        );
        assert_eq!(
            folder("Firmware/all_flash").as_deref(),
            Some("Boot firmware")
        );
        assert_eq!(
            folder("Firmware/dfu").as_deref(),
            Some("DFU-mode bootloaders")
        );
        assert_eq!(
            folder("Firmware/Manifests").as_deref(),
            Some("Signed manifests")
        );
        assert_eq!(
            folder("Firmware/AOP").as_deref(),
            Some("Always-on processor firmware")
        );
        assert_eq!(
            folder("Firmware/SE").as_deref(),
            Some("Secure Element firmware")
        );
        assert_eq!(folder("Firmware/Manifests/restore"), None);
        assert_eq!(folder("Firmware"), None);
        assert_eq!(folder("Elsewhere"), None);
        assert_eq!(folder(""), None);
        assert_eq!(catalog.describe("Firmware/dfu/notes.txt"), None);
    }

    #[test]
    fn a_manifest_that_does_mention_the_trust_cache_wins() {
        let catalog = realistic();
        let cache = catalog
            .describe("Firmware/090-12345-003.dmg.trustcache")
            .unwrap();
        assert!(cache.from_manifest);
        assert_eq!(cache.title, "Restore trust cache");
        assert_eq!(cache.install.as_deref(), Some("erase"));
    }

    #[test]
    fn odd_manifest_shapes_never_panic() {
        let weird = dict(vec![(
            "BuildIdentities",
            Value::Array(vec![
                s("not a dict"),
                Value::Integer(7_i64.into()),
                Value::Dictionary(Dictionary::new()),
                Value::Dictionary(dict(vec![(
                    "Manifest",
                    Value::Dictionary(dict(vec![
                        (
                            "KernelCache",
                            Value::Dictionary(dict(vec![(
                                "Info",
                                Value::Dictionary(dict(vec![("Path", s("kc.img4"))])),
                            )])),
                        ),
                        ("Dict", s("component is not a dict")),
                        ("NoInfo", Value::Dictionary(Dictionary::new())),
                        (
                            "InfoNotDict",
                            Value::Dictionary(dict(vec![("Info", s("nope"))])),
                        ),
                        (
                            "NoPath",
                            Value::Dictionary(dict(vec![(
                                "Info",
                                Value::Dictionary(dict(vec![("Other", s("x"))])),
                            )])),
                        ),
                        (
                            "EmptyPath",
                            Value::Dictionary(dict(vec![(
                                "Info",
                                Value::Dictionary(dict(vec![("Path", s("  "))])),
                            )])),
                        ),
                        (
                            "IntPath",
                            Value::Dictionary(dict(vec![(
                                "Info",
                                Value::Dictionary(dict(vec![(
                                    "Path",
                                    Value::Integer(3_i64.into()),
                                )])),
                            )])),
                        ),
                    ])),
                )])),
                Value::Dictionary(dict(vec![("Info", s("bad")), ("Manifest", s("bad"))])),
                Value::Dictionary(dict(vec![(
                    "Info",
                    Value::Dictionary(dict(vec![("DeviceClass", Value::Boolean(true))])),
                )])),
            ]),
        )]);
        let catalog = IpswCatalog::from_manifest(&weird);
        let kernel = catalog.describe("kc.img4").unwrap();
        assert_eq!(kernel.title, "Kernelcache");
        assert!(kernel.boards.is_empty());
        assert!(kernel.devices.is_empty());
        assert_eq!(kernel.install, None);
        assert_eq!(kernel.summary, "Kernelcache");
        assert!(catalog.boards().is_empty());
        assert_eq!(catalog.describe("x"), None);

        for odd in [
            dict(vec![("BuildIdentities", s("not an array"))]),
            dict(vec![("BuildIdentities", Value::Array(Vec::new()))]),
            dict(vec![(
                "SupportedProductTypes",
                Value::Integer(1_i64.into()),
            )]),
            Dictionary::new(),
        ] {
            let catalog = IpswCatalog::from_manifest(&odd);
            assert!(catalog.boards().is_empty());
            assert_eq!(catalog.describe("kc.img4"), None);
        }
    }

    #[test]
    fn boards_are_listed_by_device_title() {
        let boards = realistic().boards();
        assert_eq!(boards.len(), 2);
        let titles: Vec<&str> = boards.iter().map(|(_, title)| title.as_str()).collect();
        let mut sorted = titles.clone();
        sorted.sort();
        assert_eq!(titles, sorted);
        assert!(boards.contains(&("j473ap".to_string(), title_of("j473ap"))));
        assert!(boards.contains(&("j414cap".to_string(), title_of("j414cap"))));
    }

    #[test]
    fn product_types_map_to_device_titles() {
        let catalog = realistic();
        assert_eq!(catalog.product_name("Mac14,3"), Some(title_of("j473ap")));
        assert_eq!(catalog.product_name("Mac14,5"), Some(title_of("j414cap")));
        assert_eq!(catalog.product_name("Mac1,1"), None);
        assert_eq!(IpswCatalog::default().product_name("Mac14,3"), None);
    }

    #[test]
    fn search_text_finds_devices_install_kinds_and_components() {
        let catalog = realistic();
        let ramdisk = catalog.search_text("090-12345-003.dmg");
        assert!(ramdisk.contains("erase"), "{ramdisk}");
        assert!(ramdisk.contains("restore ramdisk"), "{ramdisk}");
        assert!(ramdisk.contains("restoreramdisk"), "{ramdisk}");
        assert!(ramdisk.contains("j473ap"), "{ramdisk}");
        let kernel = catalog.search_text("kernelcache.release.mac14j");
        assert!(kernel.contains("mac mini"), "{kernel}");
        assert!(!kernel.contains("macbook"), "{kernel}");
        let cryptex = catalog.search_text("090-12345-005.dmg.aea");
        assert!(cryptex.contains("cryptex"), "{cryptex}");
        assert!(cryptex.contains("cryptex1,systemos"), "{cryptex}");
        assert_eq!(cryptex, cryptex.to_lowercase());
        assert_eq!(catalog.search_text("not/in/the/archive.txt"), "");
    }
}
