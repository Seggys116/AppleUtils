use serde::Deserialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct VendorFirmwareInputs<'a> {
    pub installer_root: &'a Path,
    pub installer_digest: &'a str,
    pub fud_directory: &'a Path,
    pub kernelcache_im4p: &'a Path,
    pub recovery_root: &'a Path,
    pub target_calibration: Option<&'a Path>,
    pub requires_als_calibration: bool,
}

#[derive(Debug, Deserialize)]
pub struct VendorFirmwareFile {
    pub path: String,
    pub sha256: String,
    pub length: u64,
}

pub struct VendorFirmwarePackage {
    pub directory: tempfile::TempDir,
    pub files: Vec<VendorFirmwareFile>,
    pub installer_digest: String,
}

const RUNNER: &str = r#"
import sys,json,pathlib,hashlib,os,contextlib
args=json.load(sys.stdin)
protocol_stdout=sys.stdout
log_redirect=contextlib.redirect_stdout(sys.stderr)
log_redirect.__enter__()
sys.dont_write_bytecode=True
sys.path.insert(0,args['installer'])
from asahi_firmware.core import FWPackage, FWFile
from asahi_firmware.wifi import WiFiFWCollection
from asahi_firmware.bluetooth import BluetoothFWCollection
from asahi_firmware.multitouch import device_key_to_kind, DEVICE_KIND_UNKNOWN, FIRMWARE_NAME_TEMPLATES, plist_to_bin, load_plist_xml
from asahi_firmware.asmedia import extract_asmedia
from asahi_firmware.isp import ISPFWCollection
from asahi_firmware.als import AlsFWCollection
output=pathlib.Path(args['output'])
collections=[WiFiFWCollection(args['wifi']),BluetoothFWCollection(args['bluetooth']),
    ISPFWCollection(args['isp'])]
if args['calibration'] is not None:
    collections.append(AlsFWCollection(args['calibration']))
files={}
def add(name,fw):
    p=pathlib.PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or not name.isascii() or any(c.isspace() for c in name):
        raise ValueError('unsafe firmware output path '+name)
    if name in files and files[name].data!=fw.data:
        raise ValueError('conflicting firmware output '+name)
    files[name]=fw
for collection in collections:
    for name,fw in sorted(collection.files()):
        add(name,fw)
for fw in extract_asmedia(pathlib.Path(args['kernel']).read_bytes()):
    add(fw.name,fw)
for machine,xml_path in args['multitouch']:
    plist=load_plist_xml(pathlib.Path(xml_path).read_bytes().rstrip(b'\x00'))
    collected=set()
    for key,val in plist.items():
        kind=device_key_to_kind(key)
        if kind==DEVICE_KIND_UNKNOWN:
            continue
        name=FIRMWARE_NAME_TEMPLATES[kind] % machine
        if name in collected:
            raise ValueError('Tried to collect firmware '+name+' twice!')
        collected.add(name)
        add(name,FWFile(name,plist_to_bin[kind](val)))
if not files: raise ValueError('collectors produced no firmware')
if args['calibration'] is not None and 'apple/aop-als-cal.bin' not in files:
    raise ValueError('target calibration was not collected')
package=FWPackage(str(output))
package.add_files(sorted(files.items()))
package.close()
result=[]
for path in sorted(output.rglob('*')):
    if path.is_file():
        data=path.read_bytes()
        result.append({'path':str(path.relative_to(output)),'length':len(data),'sha256':hashlib.sha256(data).hexdigest()})
print(json.dumps(result),file=protocol_stdout)
"#;

fn decode_multitouch(fud: &Path, output: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(fud).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF8 FUD machine name")?;
        if !name.starts_with('j') {
            continue;
        }
        let source = entry.path().join("Multitouch.im4p");
        if !source.exists() {
            continue;
        }
        let source = existing(&source, false)?;
        if !source.starts_with(fud) {
            return Err("multitouch source escapes selected FUD directory".into());
        }
        let bytes = std::fs::read(source).map_err(|e| e.to_string())?;
        let decoded = crate::asahi_kernel::decode_im4p(&bytes, 1024 * 1024 * 1024)?;
        if decoded.payload_type != *b"mtfw" {
            return Err(format!("{name} Multitouch IM4P type is not mtfw"));
        }
        let path = output.join(format!("multitouch-{}.xml", result.len()));
        std::fs::write(&path, decoded.bytes).map_err(|e| e.to_string())?;
        result.push((name, path));
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

fn existing(path: &Path, directory: bool) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("missing firmware input {}: {e}", path.display()))?;
    if (directory && !path.is_dir()) || (!directory && !path.is_file()) {
        return Err(format!("wrong firmware input type: {}", path.display()));
    }
    Ok(path)
}

fn confined_tree(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let mut seen = std::collections::HashSet::new();
    while let Some(path) = pending.pop() {
        let canonical = path.canonicalize().map_err(|e| e.to_string())?;
        if !canonical.starts_with(root) {
            return Err(format!(
                "firmware input escapes selected tree: {}",
                path.display()
            ));
        }
        if !seen.insert(canonical.clone()) {
            continue;
        }
        if canonical.is_dir() {
            for entry in std::fs::read_dir(&canonical).map_err(|e| e.to_string())? {
                pending.push(entry.map_err(|e| e.to_string())?.path());
            }
        }
    }
    Ok(())
}

pub fn build_vendor_firmware(
    inputs: &VendorFirmwareInputs<'_>,
) -> Result<VendorFirmwarePackage, String> {
    if inputs.installer_digest.len() != 64
        || !inputs
            .installer_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("verified installer SHA256 is required".into());
    }
    if inputs.requires_als_calibration && inputs.target_calibration.is_none() {
        return Err("target requires an explicit ALS calibration export".into());
    }
    let installer = existing(inputs.installer_root, true)?;
    for module in [
        "core",
        "cpio",
        "wifi",
        "bluetooth",
        "multitouch",
        "asmedia",
        "isp",
        "als",
        "img4",
        "asn1",
    ] {
        let path = existing(
            &installer.join(format!("asahi_firmware/{module}.py")),
            false,
        )?;
        if !path.starts_with(&installer) {
            return Err("installer module escapes verified root".into());
        }
    }
    let recovery = existing(inputs.recovery_root, true)?;
    let wifi = existing(&recovery.join("usr/share/firmware/wifi"), true)?;
    let bluetooth = existing(&recovery.join("usr/share/firmware/bluetooth"), true)?;
    let isp = existing(&recovery.join("usr/sbin/appleh13camerad"), false)?;
    let fud = existing(inputs.fud_directory, true)?;
    let kernel = existing(inputs.kernelcache_im4p, false)?;
    let calibration = inputs
        .target_calibration
        .map(|p| existing(p, true))
        .transpose()?;
    if let Some(path) = &calibration {
        existing(&path.join("apple/aop-als-cal.bin"), false)?;
    }
    for path in [&wifi, &bluetooth, &fud] {
        confined_tree(path)?;
    }
    if !wifi.starts_with(&recovery)
        || !bluetooth.starts_with(&recovery)
        || !isp.starts_with(&recovery)
    {
        return Err("firmware path escapes selected RecoveryOS".into());
    }
    if let Some(path) = &calibration {
        confined_tree(path)?;
    }
    let decoded = tempfile::tempdir().map_err(|e| e.to_string())?;
    let raw_kernel = decoded.path().join("kernel.raw");
    let kernel_bytes = std::fs::read(&kernel).map_err(|e| e.to_string())?;
    let kernel_bytes = crate::asahi_kernel::decode_kernel_im4p(&kernel_bytes, 1024 * 1024 * 1024)?;
    std::fs::write(&raw_kernel, kernel_bytes).map_err(|e| e.to_string())?;
    let multitouch = decode_multitouch(&fud, decoded.path())?;
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let request = serde_json::json!({"installer":installer,"wifi":wifi,"bluetooth":bluetooth,"isp":isp,
        "multitouch":multitouch,"kernel":raw_kernel,"calibration":calibration,"output":directory.path()});
    let mut child = Command::new("python3")
        .args(["-I", "-c", RUNNER])
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start official firmware collectors: {e}"))?;
    let written = child
        .stdin
        .take()
        .ok_or("missing collector input")?
        .write_all(request.to_string().as_bytes());
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    written.map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "official firmware collection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let files: Vec<VendorFirmwareFile> = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid collector result: {e}"))?;
    for required in ["firmware.cpio", "firmware.tar", "manifest.txt"] {
        if !files
            .iter()
            .any(|file| file.path == required && file.length > 0)
        {
            return Err(format!("official package lacks {required}"));
        }
    }
    Ok(VendorFirmwarePackage {
        directory,
        files,
        installer_digest: inputs.installer_digest.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires MX_ASAHI_INSTALLER_ARCHIVE for the real official packer"]
    fn official_packer_roundtrips_payloads_and_hardlinks() {
        let archive = std::env::var_os("MX_ASAHI_INSTALLER_ARCHIVE").expect("installer archive");
        let root = tempfile::tempdir().unwrap();
        let status = Command::new("tar")
            .args(["-xf"])
            .arg(archive)
            .arg("-C")
            .arg(root.path())
            .arg("./asahi_firmware")
            .status()
            .unwrap();
        assert!(status.success());
        let script = r#"
import sys,pathlib,tarfile,hashlib,contextlib,io
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
with contextlib.redirect_stdout(sys.stderr):
    from asahi_firmware.core import FWFile,FWPackage
    from asahi_firmware.asmedia import extract_asmedia
    from asahi_firmware.multitouch import device_key_to_kind, DEVICE_KIND_UNKNOWN, FIRMWARE_NAME_TEMPLATES, plist_to_bin, load_plist_xml
    from asahi_firmware.wifi import WiFiFWCollection
    from asahi_firmware.bluetooth import BluetoothFWCollection
    from asahi_firmware.isp import ISPFWCollection
    from asahi_firmware.als import AlsFWCollection
    from asahi_firmware.img4 import img4p_extract
    payload=bytes(range(37))
    def tlv(tag,data): return bytes([tag,len(data)])+data
    image=tlv(0x30,tlv(0x16,b'IM4P')+tlv(0x16,b'krnl')+tlv(0x16,b'test')+tlv(4,payload))
    assert img4p_extract(image)==('krnl',payload)
    out=pathlib.Path(sys.argv[1])/'package';out.mkdir()
    p=FWPackage(str(out));p.add_file('apple/a.bin',FWFile('a',payload));p.add_file('apple/b.bin',FWFile('b',payload));p.close()
    with tarfile.open(out/'firmware.tar') as t:
        assert t.extractfile('apple/a.bin').read()==payload
        assert t.getmember('apple/b.bin').islnk()
        assert t.getmember('apple/b.bin').linkname=='apple/a.bin'
    manifest=(out/'manifest.txt').read_text()
    assert 'FILE apple/a.bin SHA256 '+hashlib.sha256(payload).hexdigest() in manifest
    assert 'LINK apple/b.bin apple/a.bin' in manifest
    data=(out/'firmware.cpio').read_bytes();pos=0;records={}
    while pos<len(data):
        pos=(pos+3)&~3
        assert data[pos:pos+6]==b'070701'
        h=[int(data[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
        name=data[pos+110:pos+110+h[11]-1].decode();pos=(pos+110+h[11]+3)&~3
        body=data[pos:pos+h[6]];pos+=h[6];records[name]=(h,body)
        if name=='TRAILER!!!':break
    a=records['vendorfw/apple/a.bin'];b=records['vendorfw/apple/b.bin']
    assert a[1]==payload and b[1]==b'' and a[0][0]==b[0][0] and a[0][4]==b[0][4]==2
    assert records['vendorfw/.vendorfw.manifest'][1].decode()==manifest
print('official package verified')
"#;
        let result = Command::new("python3")
            .args(["-I", "-c", script])
            .arg(root.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            String::from_utf8(result.stdout).unwrap().trim(),
            "official package verified"
        );
    }

    #[test]
    fn portable_multitouch_decode_preserves_original_and_exact_device_scope() {
        let source = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let machine = source.path().join("jtest");
        std::fs::create_dir(&machine).unwrap();
        let mut body = Vec::new();
        for (tag, data) in [
            (0x16, b"IM4P".as_slice()),
            (0x16, b"mtfw".as_slice()),
            (0x16, b"test".as_slice()),
            (4, b"<dict/>\0".as_slice()),
        ] {
            body.extend(crate::ramrod::der::tlv(&[tag], data));
        }
        let image = crate::ramrod::der::tlv(&[0x30], &body);
        let path = machine.join("Multitouch.im4p");
        std::fs::write(&path, &image).unwrap();
        let canonical = source.path().canonicalize().unwrap();
        let decoded = decode_multitouch(&canonical, output.path()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, "jtest");
        assert_eq!(std::fs::read(&decoded[0].1).unwrap(), b"<dict/>\0");
        assert_eq!(std::fs::read(&path).unwrap(), image);
        let mut wrong = image;
        let index = wrong.windows(4).position(|bytes| bytes == b"mtfw").unwrap();
        wrong[index..index + 4].copy_from_slice(b"krnl");
        std::fs::write(path, wrong).unwrap();
        assert!(decode_multitouch(&canonical, output.path()).is_err());
    }

    #[test]
    fn required_target_calibration_never_falls_back_to_host() {
        let path = Path::new("/unavailable-test-input");
        let inputs = VendorFirmwareInputs {
            installer_root: path,
            installer_digest: &"a".repeat(64),
            fud_directory: path,
            kernelcache_im4p: path,
            recovery_root: path,
            target_calibration: None,
            requires_als_calibration: true,
        };
        assert!(
            build_vendor_firmware(&inputs)
                .err()
                .unwrap()
                .contains("explicit ALS")
        );
    }
}
