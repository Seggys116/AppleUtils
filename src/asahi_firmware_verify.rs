use super::{CheckStatus, Finding};
use crate::asahi_firmware::{BoundFirmware, Version, bind_restore_identity};
use std::path::Path;

pub(super) fn inspect(path: &Path) -> Option<Finding> {
    let object = crate::asahi_ops::load_custom_boot_object(path, None).ok()?;
    if !recognizes(&object) {
        return None;
    }
    let result = (|| {
        let files = crate::asahi_ops::read_efi_files(
            path,
            &[
                "asahi/firmware.json",
                "vendorfw/firmware.tar",
                "vendorfw/firmware.cpio",
                "vendorfw/manifest.txt",
            ],
        )
        .map_err(|error| error.to_string())?;
        validate(&files)?;
        let bound: BoundFirmware = serde_json::from_slice(&files[0]).map_err(|e| e.to_string())?;
        let provenance = crate::asahi_ops::validate_installed_restore_bundle(path, &bound)
            .map_err(|e| e.to_string())?;
        require_machine_provenance(provenance)
    })();
    Some(finding(result))
}

fn require_machine_provenance(verified: bool) -> Result<(), String> {
    if verified {
        Ok(())
    } else {
        Err("Machine firmware provenance is unavailable: the selected OS manifest has no SEP and SourceBuildManifest.plist is missing; completeness cannot be verified".into())
    }
}

fn finding(result: Result<(), String>) -> Finding {
    Finding {
        id: "asahi-firmware-contract".into(),
        status: if result.is_ok() { CheckStatus::Pass } else { CheckStatus::Fail },
        summary: "Asahi installed firmware contract".into(),
        detail: match result {
            Ok(()) => "Stored identity, native Preboot restore components, and vendor archive contents agree. This does not establish firmware authenticity, target compatibility, or boot validity.".into(),
            Err(error) => format!("{error}. Regenerate with firmware provisioned for the intended target; firmware cannot be inferred or repaired from APFS structure."),
        },
        repairable: false,
    }
}

fn recognizes(object: &[u8]) -> bool {
    [
        b"##m1n1_ver##".as_slice(),
        b"chosen.asahi,efi-system-partition=",
        b"chainload=",
    ]
    .iter()
    .all(|marker| object.windows(marker.len()).any(|part| part == *marker))
}

fn validate(files: &[Vec<u8>]) -> Result<(), String> {
    if files.len() != 4 {
        return Err("firmware contract files are missing".into());
    }
    let bound: BoundFirmware =
        serde_json::from_slice(&files[0]).map_err(|e| format!("invalid firmware binding: {e}"))?;
    bind_restore_identity(bound.selection.clone(), bound.restore.clone())?;
    for version in [
        &bound.selection.entry.version,
        &bound.selection.entry.min_macos,
        &bound.selection.entry.min_iboot,
        &bound.selection.entry.min_sfr,
    ] {
        Version::parse(version)?;
    }
    if bound.selection.board.trim().is_empty()
        || bound.selection.provenance.source_uri.trim().is_empty()
        || bound.selection.provenance.revision.trim().is_empty()
        || bound.selection.entry.restore_url.trim().is_empty()
        || bound
            .selection
            .entry
            .devices
            .as_ref()
            .is_some_and(|devices| !devices.contains(&bound.selection.board))
    {
        return Err("firmware selection has invalid target or provenance".into());
    }
    for digest in [
        &bound.restore.manifest_digest,
        &bound.restore.archive_digest,
    ] {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("firmware identity has malformed SHA256 digest".into());
        }
    }
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    for (name, bytes) in ["firmware.tar", "firmware.cpio", "manifest.txt"]
        .iter()
        .zip(&files[1..])
    {
        std::fs::write(dir.path().join(name), bytes).map_err(|e| e.to_string())?;
    }
    let output = std::process::Command::new("python3")
        .args(["-I", "-c", VERIFY])
        .arg(dir.path())
        .output()
        .map_err(|e| format!("cannot verify firmware archives: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "firmware archive verification failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

const VERIFY: &str = r#"
import sys,pathlib,tarfile,hashlib
root=pathlib.Path(sys.argv[1])
def safe(name):
    p=pathlib.PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts: raise ValueError('unsafe firmware path')
    return name
manifest=(root/'manifest.txt').read_bytes()
expected={}
for line in manifest.decode('utf-8').splitlines():
    fields=line.split()
    if not fields: continue
    if len(fields)==4 and fields[0]=='FILE' and fields[2]=='SHA256':
        name=safe(fields[1]); kind=('file',fields[3])
        if len(fields[3])!=64 or any(c not in '0123456789abcdefABCDEF' for c in fields[3]): raise ValueError('invalid manifest digest')
    elif len(fields)==3 and fields[0]=='LINK': name=safe(fields[1]);kind=('link',safe(fields[2]))
    else: raise ValueError('invalid manifest record')
    if name in expected: raise ValueError('duplicate manifest path')
    expected[name]=kind
if not expected or not any(v[0]=='file' for v in expected.values()): raise ValueError('empty firmware manifest')
with tarfile.open(root/'firmware.tar',mode='r:') as archive:
    members={}
    for member in archive:
        name=safe(member.name)
        if member.isdir(): continue
        if name in members: raise ValueError('duplicate tar member')
        members[name]=member
    if set(members)!=set(expected): raise ValueError('tar inventory differs from manifest')
    for name,(kind,value) in expected.items():
        member=members[name]
        if kind=='link':
            if not member.islnk() or member.linkname!=value or value not in expected or expected[value][0]!='file': raise ValueError('invalid tar hardlink')
        else:
            if not member.isfile() or hashlib.sha256(archive.extractfile(member).read()).hexdigest()!=value.lower(): raise ValueError('tar digest mismatch '+name)
data=(root/'firmware.cpio').read_bytes();pos=0;records={};inodes={};trailer=False
while pos<len(data):
    pos=(pos+3)&~3
    if data[pos:pos+6]!=b'070701' or pos+110>len(data): raise ValueError('invalid cpio header')
    h=[int(data[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
    start=pos+110;end=start+h[11]
    if h[11]<1 or end>len(data) or data[end-1]!=0: raise ValueError('invalid cpio name')
    name=data[start:end-1].decode();pos=(end+3)&~3;end=pos+h[6]
    if end>len(data): raise ValueError('truncated cpio data')
    body=data[pos:end];pos=end
    if name=='TRAILER!!!': trailer=True;break
    safe(name)
    if name in records: raise ValueError('duplicate cpio path')
    records[name]=(h,body)
    if h[1]&0o170000==0o100000 and body:
        key=(h[7],h[8],h[0])
        if key in inodes and inodes[key]!=body: raise ValueError('conflicting cpio inode')
        inodes[key]=body
if not trailer: raise ValueError('missing cpio trailer')
if records.get('vendorfw/.vendorfw.manifest',(None,None))[1]!=manifest: raise ValueError('cpio manifest mismatch')
actual={name[len('vendorfw/'):] for name,(h,b) in records.items() if h[1]&0o170000!=0o040000 and name!='vendorfw/.vendorfw.manifest'}
if actual!=set(expected): raise ValueError('cpio inventory differs from manifest')
def contents(name):
    h,body=records['vendorfw/'+name]
    if h[1]&0o170000!=0o100000: raise ValueError('unsupported cpio entry type')
    return body or inodes.get((h[7],h[8],h[0]),b'')
for name,(kind,value) in expected.items():
    if kind=='file':
        if hashlib.sha256(contents(name)).hexdigest()!=value.lower(): raise ValueError('cpio digest mismatch '+name)
    else:
        if contents(name)!=contents(value): raise ValueError('cpio link mismatch '+name)
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_machine_provenance_cannot_pass_repair() {
        let result = finding(require_machine_provenance(false));
        assert!(matches!(result.status, CheckStatus::Fail));
        assert!(result.detail.contains("completeness cannot be verified"));
        assert!(result.detail.contains("Regenerate"));
        assert!(!result.repairable);
        assert!(matches!(
            finding(require_machine_provenance(true)).status,
            CheckStatus::Pass
        ));
    }

    #[test]
    fn only_asahi_stage_one_is_recognized() {
        assert!(!recognizes(b"ordinary APFS content"));
        assert!(!recognizes(b"##m1n1_ver##stage2"));
        assert!(recognizes(
            b"##m1n1_ver##chosen.asahi,efi-system-partition=x\nchainload=x"
        ));
    }
    #[test]
    fn archive_verifier_detects_content_corruption_and_missing_members() {
        let dir = tempfile::tempdir().unwrap();
        let setup = r#"
import sys,pathlib,tarfile,io,hashlib
root=pathlib.Path(sys.argv[1]);payload=b'actual firmware bytes'
manifest=('FILE apple/test.bin SHA256 '+hashlib.sha256(payload).hexdigest()+'\n').encode()
(root/'manifest.txt').write_bytes(manifest)
with tarfile.open(root/'firmware.tar','w') as t:
    entry=tarfile.TarInfo('apple/test.bin');entry.size=len(payload);t.addfile(entry,io.BytesIO(payload))
cpio=bytearray()
def add(name,body,ino):
    global cpio
    name=name.encode()+b'\0';h=[ino,0o100644,0,0,1,0,len(body),0,0,0,0,len(name),0]
    cpio+=b'070701'+''.join('%08x'%v for v in h).encode()+name
    cpio+=b'\0'*(-len(cpio)%4);cpio+=body;cpio+=b'\0'*(-len(cpio)%4)
add('vendorfw/apple/test.bin',payload,1);add('vendorfw/.vendorfw.manifest',manifest,2);add('TRAILER!!!',b'',3)
(root/'firmware.cpio').write_bytes(cpio)
"#;
        assert!(
            std::process::Command::new("python3")
                .args(["-I", "-c", setup])
                .arg(dir.path())
                .status()
                .unwrap()
                .success()
        );
        let verify = || {
            std::process::Command::new("python3")
                .args(["-I", "-c", VERIFY])
                .arg(dir.path())
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(verify());
        let cpio_path = dir.path().join("firmware.cpio");
        let original = std::fs::read(&cpio_path).unwrap();
        let mut corrupt = original.clone();
        let position = corrupt
            .windows(6)
            .position(|bytes| bytes == b"actual")
            .unwrap();
        corrupt[position] ^= 1;
        std::fs::write(&cpio_path, corrupt).unwrap();
        assert!(!verify());
        std::fs::write(&cpio_path, original).unwrap();
        std::fs::write(dir.path().join("manifest.txt"), b"").unwrap();
        assert!(!verify());
    }

    #[test]
    fn missing_or_malformed_contract_is_rejected() {
        assert!(validate(&[]).is_err());
        assert!(validate(&[b"{}".to_vec(), vec![], vec![], vec![]]).is_err());
    }
}
