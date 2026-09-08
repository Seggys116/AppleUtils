#![cfg(target_os = "macos")]

use std::path::Path;
use std::process::Command;

const FSCK_APFS: &str = "/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs";
const HDIUTIL: &str = "/usr/bin/hdiutil";
const DISKUTIL: &str = "/usr/sbin/diskutil";

const STUB_BYTES: u64 = 2560 * (1 << 20);

struct Attached {
    dev: String,
}

impl Drop for Attached {
    fn drop(&mut self) {
        let _ = Command::new(HDIUTIL)
            .args(["detach", &self.dev, "-force"])
            .output();
    }
}

fn attach(image: &Path) -> Attached {
    let out = Command::new(HDIUTIL)
        .args([
            "attach",
            "-nomount",
            "-imagekey",
            "diskimage-class=CRawDiskImage",
            image.to_str().expect("image path is UTF-8"),
        ])
        .output()
        .expect("hdiutil attach failed to run");
    assert!(
        out.status.success(),
        "hdiutil attach failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let dev = stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .filter(|dev| dev.starts_with("/dev/"))
        .unwrap_or_else(|| panic!("hdiutil returned no device, stdout: {stdout}"))
        .to_string();
    Attached { dev }
}

fn stub_container() -> Vec<u8> {
    let stage1 = vec![0x5Au8; 3_000_000];
    apple_utils::apfs_write::create(STUB_BYTES, "Fedora Asahi Remix 44", &stage1)
        .expect("apfs_write::create")
}

#[test]
fn created_container_passes_apple_fsck_apfs() {
    let image = tempfile::Builder::new()
        .suffix(".img")
        .tempfile()
        .expect("tempfile");
    std::fs::write(image.path(), stub_container()).expect("write image");

    let attached = attach(image.path());
    let out = Command::new(FSCK_APFS)
        .args(["-n", &attached.dev])
        .output()
        .expect("fsck_apfs failed to run");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // fsck_apfs halts at the first problem, so an "error:" line is fatal even when the exit status is not.
    assert!(
        !report.contains("error:"),
        "fsck_apfs reported errors:\n{report}"
    );
    assert!(
        out.status.success(),
        "fsck_apfs exited {:?}:\n{report}",
        out.status.code()
    );
}

#[test]
fn updated_container_passes_apple_fsck_apfs() {
    let created = stub_container();

    let replacement = vec![0xA5u8; 4_500_000];
    let updated =
        apple_utils::apfs_update::update(&created, &replacement).expect("apfs_update::update");
    assert_eq!(
        updated.len(),
        created.len(),
        "update must not change the container's byte length"
    );

    let image = tempfile::Builder::new()
        .suffix(".img")
        .tempfile()
        .expect("tempfile");
    std::fs::write(image.path(), &updated).expect("write image");

    let attached = attach(image.path());
    let out = Command::new(FSCK_APFS)
        .args(["-n", &attached.dev])
        .output()
        .expect("fsck_apfs failed to run");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !report.contains("error:"),
        "fsck_apfs reported errors on the updated container:\n{report}"
    );
    assert!(
        out.status.success(),
        "fsck_apfs exited {:?} on the updated container:\n{report}",
        out.status.code()
    );
}

#[test]
fn created_container_is_recognised_by_diskutil() {
    let image = tempfile::Builder::new()
        .suffix(".img")
        .tempfile()
        .expect("tempfile");
    std::fs::write(image.path(), stub_container()).expect("write image");

    let attached = attach(image.path());

    // `diskutil apfs list <raw device>` answers "is not an APFS Container" even for a genuine container; the synthesized container reference must be resolved first.
    let info = Command::new(DISKUTIL)
        .args(["info", "-plist", &attached.dev])
        .output()
        .expect("diskutil info failed to run");
    let plist = String::from_utf8_lossy(&info.stdout).into_owned();
    let reference = plist
        .split("<key>APFSContainerReference</key>")
        .nth(1)
        .and_then(|rest| rest.split("<string>").nth(1))
        .and_then(|rest| rest.split("</string>").next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("diskutil info reported no APFSContainerReference:\n{plist}"));

    let out = Command::new(DISKUTIL)
        .args(["apfs", "list", &reference])
        .output()
        .expect("diskutil failed to run");
    let listing = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // A sound-but-unreadable container surfaces as an error code plus "No Volumes" rather than a non-zero exit.
    assert!(
        !listing.contains("ERROR"),
        "kernel APFS driver rejected the container:\n{listing}"
    );
    assert!(
        !listing.contains("No Volumes"),
        "kernel APFS driver enumerated no volumes:\n{listing}"
    );
    assert!(
        out.status.success(),
        "diskutil apfs list exited {:?}:\n{listing}",
        out.status.code()
    );

    for expected in [
        "Fedora Asahi Remix 44 Data",
        "Fedora Asahi Remix 44",
        "Preboot",
        "Recovery",
    ] {
        assert!(
            listing.contains(expected),
            "volume {expected:?} missing from diskutil listing:\n{listing}"
        );
    }
}
