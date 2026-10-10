//! Synthetic IPSW archives and a fake `ipsw` command, shared by unit tests, integration tests
//! and previews. Nothing here touches the network or a real IPSW.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};

pub const FIXTURE_VERSION: &str = "26.0";
pub const FIXTURE_BUILD: &str = "25A1";
pub const FIXTURE_DEVICES: [&str; 2] = ["Mac14,2", "Mac15,6"];

const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const UNIX_HOST: u16 = 3;
const MODE_FILE: u32 = 0o100_644;
const MODE_EXECUTABLE: u32 = 0o100_755;
const MODE_SYMLINK: u32 = 0o120_777;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureKind {
    File,
    Executable,
    /// `data` is the link target.
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub deflate: bool,
    pub kind: FixtureKind,
}

impl FixtureEntry {
    pub fn file(name: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
            deflate: false,
            kind: FixtureKind::File,
        }
    }

    pub fn deflated(name: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            deflate: true,
            ..Self::file(name, data)
        }
    }

    pub fn symlink(name: impl Into<String>, target: impl Into<String>) -> Self {
        let target: String = target.into();
        Self {
            kind: FixtureKind::Symlink,
            ..Self::file(name, target.into_bytes())
        }
    }

    pub fn executable(name: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: FixtureKind::Executable,
            ..Self::file(name, data)
        }
    }

    fn mode(&self) -> u32 {
        match self.kind {
            FixtureKind::File => MODE_FILE,
            FixtureKind::Executable => MODE_EXECUTABLE,
            FixtureKind::Symlink => MODE_SYMLINK,
        }
    }
}

pub fn build_ipsw(entries: &[FixtureEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let (method, body) = if entry.deflate {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&entry.data).expect("in-memory deflate");
            (8u16, encoder.finish().expect("in-memory deflate"))
        } else {
            (0u16, entry.data.clone())
        };
        let mut crc = Crc::new();
        crc.update(&entry.data);
        let crc = crc.sum();
        let offset = out.len() as u32;
        let name = entry.name.as_bytes();

        out.extend_from_slice(&LOCAL_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&body);

        central.extend_from_slice(&CENTRAL_SIGNATURE.to_le_bytes());
        central.extend_from_slice(&((UNIX_HOST << 8) | 20).to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0; 4]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(body.len() as u32).to_le_bytes());
        central.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&(entry.mode() << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn write_ipsw(path: &Path, entries: &[FixtureEntry]) -> io::Result<()> {
    fs::write(path, build_ipsw(entries))
}

pub fn build_manifest_plist() -> Vec<u8> {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "ProductVersion".into(),
        plist::Value::String(FIXTURE_VERSION.into()),
    );
    dict.insert(
        "ProductBuildVersion".into(),
        plist::Value::String(FIXTURE_BUILD.into()),
    );
    dict.insert(
        "SupportedProductTypes".into(),
        plist::Value::Array(
            FIXTURE_DEVICES
                .iter()
                .map(|device| plist::Value::String((*device).into()))
                .collect(),
        ),
    );
    let mut out = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_xml(&mut out)
        .expect("in-memory plist");
    out
}

/// The fake CLI "decompresses" this by dropping the 12 header bytes.
pub fn fake_im4p(payload: &[u8]) -> Vec<u8> {
    let length = (payload.len() + 6) as u32;
    let mut out = vec![0x30, 0x84];
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&[0x16, 0x04]);
    out.extend_from_slice(b"IM4P");
    out.extend_from_slice(payload);
    out
}

/// The fake CLI does not understand this form beyond the shared header, so use it only where
/// the CLI is never reached.
pub fn fake_im4p_der(payload: &[u8], encrypted: bool) -> Vec<u8> {
    fake_im4p_der_with_version(payload, b"1.0", encrypted)
}

/// Real firmware carries a long version string (kilobytes for SEP), which pushes the payload
/// far from the start of the file.
pub fn fake_im4p_der_with_version(payload: &[u8], version: &[u8], encrypted: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x16, 0x04]);
    body.extend_from_slice(b"IM4P");
    body.extend_from_slice(&[0x16, 0x04]);
    body.extend_from_slice(b"sepi");
    body.push(0x16);
    if version.len() < 0x80 {
        body.push(version.len() as u8);
    } else {
        body.push(0x84);
        body.extend_from_slice(&(version.len() as u32).to_be_bytes());
    }
    body.extend_from_slice(version);
    body.extend_from_slice(&[0x04, 0x84]);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(payload);
    if encrypted {
        body.extend_from_slice(&[0x04, 0x04]);
        body.extend_from_slice(b"KBAG");
    }
    let mut out = vec![0x30, 0x84];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

pub fn fake_im4p_encrypted(payload: &[u8]) -> Vec<u8> {
    fake_im4p_der(payload, true)
}

pub fn sample_entries() -> Vec<FixtureEntry> {
    let restore_plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<plist version=\"1.0\"><dict><key>RestoreKey</key><string>value</string></dict></plist>\n";
    let mut aea = b"AEA1".to_vec();
    aea.extend_from_slice(b"PLAIN-SYSTEM-IMAGE");
    vec![
        FixtureEntry::file("BuildManifest.plist", build_manifest_plist()),
        FixtureEntry::file("Restore.plist", restore_plist.to_vec()),
        FixtureEntry::deflated("kernelcache.release.mac14j", fake_im4p(b"KERNEL-PAYLOAD")),
        FixtureEntry::file(
            "Firmware/all_flash/iBoot.j414c.RELEASE.im4p",
            fake_im4p(b"IBOOT-PAYLOAD"),
        ),
        FixtureEntry::file(
            "Firmware/all_flash/LLB.j414c.RELEASE.im4p",
            fake_im4p(b"LLB-PAYLOAD"),
        ),
        FixtureEntry::file(
            "Firmware/dfu/iBEC.j414c.RELEASE.im4p",
            fake_im4p(b"IBEC-PAYLOAD"),
        ),
        FixtureEntry::file(
            "Firmware/Manifests/restore/info.plist",
            restore_plist.to_vec(),
        ),
        FixtureEntry::file("090-12345-001.dmg.aea", aea),
        FixtureEntry::deflated("090-12345-002.dmg", b"PLAIN-DMG".to_vec()),
        FixtureEntry::file("Firmware/notes.txt", b"hello".to_vec()),
        FixtureEntry::symlink("Firmware/latest", "notes.txt"),
    ]
}

const REALISTIC_BOARDS: [(&str, &str, &str, &str); 2] = [
    ("j473ap", "j473", "Mac14,3", "kernelcache.release.mac14j"),
    ("j414cap", "j414c", "Mac14,5", "kernelcache.release.mac14g"),
];

fn plist_string(text: &str) -> plist::Value {
    plist::Value::String(text.to_string())
}

fn manifest_component(path: &str) -> plist::Value {
    let mut info = plist::Dictionary::new();
    info.insert("Path".into(), plist_string(path));
    let mut component = plist::Dictionary::new();
    component.insert("Info".into(), plist::Value::Dictionary(info));
    plist::Value::Dictionary(component)
}

fn realistic_identity(
    board: (&str, &str, &str, &str),
    behavior: &str,
    ramdisk: &str,
    trust_cache: &str,
) -> plist::Value {
    let (class, stem, product, kernel) = board;
    let mut info = plist::Dictionary::new();
    info.insert("DeviceClass".into(), plist_string(class));
    info.insert("Variant".into(), plist_string("macOS Customer"));
    info.insert("RestoreBehavior".into(), plist_string(behavior));
    let mut manifest = plist::Dictionary::new();
    let components = [
        ("OS", "090-12345-001.dmg.aea".to_string()),
        ("Cryptex1,SystemOS", "090-12345-005.dmg.aea".to_string()),
        ("Cryptex1,AppOS", "090-12345-006.dmg".to_string()),
        ("RestoreRamDisk", ramdisk.to_string()),
        ("RestoreTrustCache", trust_cache.to_string()),
        ("KernelCache", kernel.to_string()),
        (
            "iBoot",
            format!("Firmware/all_flash/iBoot.{stem}.RELEASE.im4p"),
        ),
        ("LLB", format!("Firmware/all_flash/LLB.{stem}.RELEASE.im4p")),
        ("iBEC", format!("Firmware/dfu/iBEC.{stem}.RELEASE.im4p")),
        ("iBSS", format!("Firmware/dfu/iBSS.{stem}.RELEASE.im4p")),
        (
            "DeviceTree",
            format!("Firmware/all_flash/DeviceTree.{stem}ap.im4p"),
        ),
    ];
    for (key, path) in components {
        manifest.insert(key.into(), manifest_component(&path));
    }
    let mut identity = plist::Dictionary::new();
    identity.insert("Info".into(), plist::Value::Dictionary(info));
    identity.insert("Ap,ProductType".into(), plist_string(product));
    identity.insert("Manifest".into(), plist::Value::Dictionary(manifest));
    plist::Value::Dictionary(identity)
}

pub fn realistic_manifest_plist() -> Vec<u8> {
    let mut identities = Vec::new();
    for board in REALISTIC_BOARDS {
        for (behavior, ramdisk) in [
            ("Erase", "090-12345-003.dmg"),
            ("Update", "090-12345-004.dmg"),
        ] {
            let trust_cache = format!("Firmware/{ramdisk}.trustcache");
            identities.push(realistic_identity(board, behavior, ramdisk, &trust_cache));
        }
    }
    let mut dict = plist::Dictionary::new();
    dict.insert("ProductVersion".into(), plist_string(FIXTURE_VERSION));
    dict.insert("ProductBuildVersion".into(), plist_string(FIXTURE_BUILD));
    dict.insert(
        "SupportedProductTypes".into(),
        plist::Value::Array(
            REALISTIC_BOARDS
                .iter()
                .map(|(_, _, product, _)| plist_string(product))
                .collect(),
        ),
    );
    dict.insert("BuildIdentities".into(), plist::Value::Array(identities));
    let mut out = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_xml(&mut out)
        .expect("in-memory plist");
    out
}

pub fn realistic_entries() -> Vec<FixtureEntry> {
    let restore_plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<plist version=\"1.0\"><dict><key>RestoreKey</key><string>value</string></dict></plist>\n";
    let aea = |body: &[u8]| {
        let mut data = b"AEA1".to_vec();
        data.extend_from_slice(body);
        data
    };
    let mut entries = vec![
        FixtureEntry::file("BuildManifest.plist", realistic_manifest_plist()),
        FixtureEntry::file("Restore.plist", restore_plist.to_vec()),
        FixtureEntry::file("090-12345-001.dmg.aea", aea(b"PLAIN-SYSTEM-IMAGE")),
        FixtureEntry::file("090-12345-005.dmg.aea", aea(b"SYSTEM-CRYPTEX")),
        FixtureEntry::deflated("090-12345-006.dmg", b"APP-CRYPTEX".to_vec()),
        FixtureEntry::deflated("090-12345-003.dmg", b"ERASE-RAMDISK".to_vec()),
        FixtureEntry::deflated("090-12345-004.dmg", b"UPDATE-RAMDISK".to_vec()),
        FixtureEntry::file(
            "Firmware/090-12345-003.dmg.trustcache",
            b"TRUST-ERASE".to_vec(),
        ),
        FixtureEntry::file(
            "Firmware/090-12345-004.dmg.trustcache",
            b"TRUST-UPDATE".to_vec(),
        ),
    ];
    for (_, stem, _, kernel) in REALISTIC_BOARDS {
        let upper = stem.to_ascii_uppercase();
        entries.push(FixtureEntry::deflated(
            kernel,
            fake_im4p(format!("KERNEL-{upper}").as_bytes()),
        ));
        for (folder, component) in [
            ("all_flash", "iBoot"),
            ("all_flash", "LLB"),
            ("dfu", "iBEC"),
            ("dfu", "iBSS"),
        ] {
            entries.push(FixtureEntry::file(
                format!("Firmware/{folder}/{component}.{stem}.RELEASE.im4p"),
                fake_im4p(format!("{component}-{upper}").as_bytes()),
            ));
        }
        entries.push(FixtureEntry::file(
            format!("Firmware/all_flash/DeviceTree.{stem}ap.im4p"),
            fake_im4p(format!("DTREE-{upper}").as_bytes()),
        ));
    }
    entries.push(FixtureEntry::file(
        "Firmware/all_flash/sep-firmware.j473.RELEASE.im4p",
        fake_im4p(b"SEP-J473"),
    ));
    entries
}

const FAKE_CLI: &str = r#"#!/bin/sh
# Stand-in for `ipsw`: emulates the few subcommands the exporter uses.
dir=$(cd "$(dirname "$0")" && pwd)
printf '%s\n' "$*" >> "$dir/args.log"
if [ "$1" = "--no-color" ]; then shift; fi
case "$1 $2" in
  "fw aea") shift 2; mode=aea ;;
  "img4 im4p")
    if [ "$3" = "extract" ]; then shift 3; mode=im4p; else exit 2; fi ;;
  *)
    if [ "$1" = "extract" ]; then shift; mode=extract; else exit 2; fi ;;
esac
out=""
key=""
device=""
flags=""
input=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -b) key="$2"; shift 2 ;;
    --device) device="$2"; shift 2 ;;
    -*) flags="$flags $1"; shift ;;
    *) input="$1"; shift ;;
  esac
done
case "$mode" in
  aea)
    base=$(basename "$input")
    if [ "$(head -c 4 "$input")" = "FAIL" ]; then
      printf '   ⨯ failed to parse AEA: bad key\n' >&2
      exit 1
    fi
    case "$base" in *slow*) sleep 30 ;; esac
    if [ -n "$key" ]; then printf '%s' "$key" > "$out/../aea-key-seen"; fi
    tail -c +5 "$input" > "$out/${base%.aea}"
    ;;
  im4p)
    if [ "$(head -c 1 "$input" | od -An -tx1 | tr -d ' \n')" != "30" ]; then
      printf '   ⨯ failed to parse IM4P\n' >&2
      exit 1
    fi
    tail -c +13 "$input" > "$out"
    ;;
  extract)
    # Like the real tool, refuse --device with components it does not apply to.
    if [ -n "$device" ]; then
      for f in $flags; do
        case "$f" in
          --kernel|--dyld|--driverkit|--fcs-key|--dmg|--files) ;;
          *)
            printf '   ⨯ --device can only be used with --kernel, --dyld, --dmg, --files, or --fcs-key\n' >&2
            exit 1
            ;;
        esac
      done
    fi
    d="${device:-Mac14,2}"
    for f in $flags; do
      case "$f" in
        --kernel)
          mkdir -p "$out/25A1__$d"
          printf 'KERNEL-FROM-CLI' > "$out/25A1__$d/kernelcache.release.$d"
          ;;
        --dtree)
          printf '   ⨯ failed to extract files matching pattern from ZIP: no files found\n' >&2
          exit 1
          ;;
        *)
          n="${f#--}"
          mkdir -p "$out/25A1__Mac14,2"
          printf '%s' "$n" > "$out/25A1__Mac14,2/$n.bin"
          ;;
      esac
    done
    ;;
esac
exit 0
"#;

/// Every invocation of the fake appends its arguments as one line to `dir/args.log`.
pub fn write_fake_cli(dir: &Path) -> io::Result<PathBuf> {
    let path = dir.join("ipsw");
    fs::write(&path, FAKE_CLI)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(path)
}
