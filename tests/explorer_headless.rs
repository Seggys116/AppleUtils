use std::process::Command;

use apple_utils::apfs_fixture::{
    self, FIXTURE_DIR, FIXTURE_FILE, FIXTURE_FILE_BYTES, FIXTURE_SYMLINK, FIXTURE_SYMLINK_TARGET,
    ImageWrap,
};

#[test]
fn binary_dumps_a_gpt_fixture_identically_twice() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.img");
    apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).expect("write gpt fixture");

    let bin = env!("CARGO_BIN_EXE_apple-utils");
    let run = || {
        Command::new(bin)
            .args(["explorer", image.to_str().unwrap()])
            .output()
            .expect("run explorer")
    };
    let first = run();
    let second = run();
    assert!(
        first.status.success(),
        "explorer failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout, "two identical invocations");
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.contains("bootable[0]=false"), "{stdout}");
    assert!(
        stdout.lines().any(|line| line == "picker="),
        "empty picker line missing in {stdout}"
    );
    assert!(
        stdout.contains(&format!("entry: /{FIXTURE_DIR}  kind=directory")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("entry: /{FIXTURE_DIR}/{FIXTURE_FILE}  kind=file")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "contents: {}",
            std::str::from_utf8(FIXTURE_FILE_BYTES).unwrap()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "entry: /{FIXTURE_DIR}/{FIXTURE_SYMLINK}  kind=symlink  target={FIXTURE_SYMLINK_TARGET}"
        )),
        "{stdout}"
    );
}

#[test]
fn binary_dumps_qcow2_and_dmg_wraps() {
    let dir = tempfile::tempdir().unwrap();
    let qcow = dir.path().join("disk.qcow2");
    let dmg = dir.path().join("disk.dmg");
    apfs_fixture::write_fixture(&qcow, ImageWrap::Qcow2).expect("qcow2");
    apfs_fixture::write_fixture(&dmg, ImageWrap::Dmg).expect("dmg");

    let bin = env!("CARGO_BIN_EXE_apple-utils");
    for (path, backend) in [(&qcow, "qcow2"), (&dmg, "dmg")] {
        let out = Command::new(bin)
            .args(["explorer", path.to_str().unwrap()])
            .output()
            .expect("run explorer");
        assert!(
            out.status.success(),
            "{backend} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains(&format!("backend={backend}")), "{stdout}");
        assert!(
            stdout.contains(&format!("entry: /{FIXTURE_DIR}  kind=directory")),
            "{stdout}"
        );
        assert!(
            stdout.contains(std::str::from_utf8(FIXTURE_FILE_BYTES).unwrap()),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("kind=symlink  target={FIXTURE_SYMLINK_TARGET}")),
            "{stdout}"
        );
    }
}

#[test]
fn binary_exports_and_inserts_through_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.img");
    apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).expect("fixture");
    let out = dir.path().join("got.txt");
    let bin = env!("CARGO_BIN_EXE_apple-utils");
    let extract = Command::new(bin)
        .args([
            "explorer",
            image.to_str().unwrap(),
            "--extract",
            &format!("/{FIXTURE_DIR}/{FIXTURE_FILE}"),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("extract");
    assert!(
        extract.status.success(),
        "{}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), FIXTURE_FILE_BYTES);

    let incoming = dir.path().join("cli-in.txt");
    std::fs::write(&incoming, b"cli-inserted").unwrap();
    let insert = Command::new(bin)
        .args([
            "explorer",
            image.to_str().unwrap(),
            "--insert",
            incoming.to_str().unwrap(),
            "--at",
            &format!("/{FIXTURE_DIR}"),
        ])
        .output()
        .expect("insert");
    assert!(
        insert.status.success(),
        "{}",
        String::from_utf8_lossy(&insert.stderr)
    );
    let list = Command::new(bin)
        .args([
            "explorer",
            image.to_str().unwrap(),
            "--list",
            &format!("/{FIXTURE_DIR}"),
        ])
        .output()
        .expect("list");
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("cli-in.txt"), "{stdout}");
}
