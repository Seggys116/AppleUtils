use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use apple_utils::apfs_fixture::{FIXTURE_VOL_APSB_PADDR, ImageWrap, write_fixture};
use apple_utils::repair_ops::{
    apply, format_dump, inject_checksum_fault, inject_volume_magic_fault, sweep,
};

const QCOW_MAGIC: u32 = 0x5146_49FB;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_apple-utils")
}

fn volume_magic_id() -> String {
    format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}")
}

fn write_mutated_qcow2(path: &Path) {
    write_fixture(path, ImageWrap::Qcow2).expect("write qcow2 fixture");
    inject_checksum_fault(path, 0).expect("inject checksum:0");
    inject_volume_magic_fault(path, FIXTURE_VOL_APSB_PADDR).expect("inject volume-magic");
}

fn assert_qcow2_v3(path: &Path) {
    let bytes = std::fs::read(path).expect("read qcow2");
    assert!(bytes.len() >= 8, "qcow2 header is truncated");
    assert_eq!(&bytes[0..4], &QCOW_MAGIC.to_be_bytes(), "qcow2 magic");
    assert_eq!(&bytes[4..8], &3u32.to_be_bytes(), "qcow2 version 3");
}

fn run_repair(path: &Path, extra: &[&str]) -> Output {
    let image = path.to_str().expect("utf-8 image path");
    let mut args = Vec::with_capacity(2 + extra.len());
    args.push("repair");
    args.push(image);
    args.extend_from_slice(extra);
    Command::new(bin())
        .args(&args)
        .output()
        .expect("run repair")
}

fn assert_success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn stdout_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn dump(path: &Path) -> String {
    let out = run_repair(path, &["--dump"]);
    assert_success(&out, "repair --dump");
    stdout_text(&out)
}

fn line_has_fail_id(line: &str, id: &str) -> bool {
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.contains(&"FAIL") && toks.contains(&id)
}

fn dump_fails(dump: &str, id: &str) -> bool {
    dump.lines().any(|line| line_has_fail_id(line, id))
}

fn assert_named_fail(dump: &str, id: &str) {
    assert!(dump.contains("FAIL"), "dump should name FAIL:\n{dump}");
    assert!(dump.contains(id), "dump should name {id}:\n{dump}");
    assert!(dump_fails(dump, id), "dump should FAIL {id}:\n{dump}");
}

fn assert_not_named_fail(dump: &str, id: &str) {
    assert!(
        !dump.contains(&format!("FAIL  {id}")),
        "dump still has FAIL  {id}:\n{dump}"
    );
    assert!(!dump_fails(dump, id), "dump still FAILs {id}:\n{dump}");
}

fn assert_only_container_structure_fails(dump: &str) {
    for line in dump.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.contains(&"FAIL") {
            assert!(
                toks.contains(&"container-structure"),
                "unexpected FAIL line on the explorer fixture: {line}\n{dump}"
            );
        }
    }
}

#[test]
fn binary_dumps_a_qcow2_v3_fixture_identically_twice() {
    let dir = tempfile::tempdir().unwrap();
    let qcow = dir.path().join("disk.qcow2");
    write_mutated_qcow2(&qcow);
    assert_qcow2_v3(&qcow);

    let first = run_repair(&qcow, &["--dump"]);
    let second = run_repair(&qcow, &["--dump"]);
    assert_success(&first, "repair --dump (first)");
    assert_success(&second, "repair --dump (second)");
    assert_eq!(first.stdout, second.stdout, "two identical invocations");

    let stdout = stdout_text(&first);
    eprint!("{stdout}");
    let volume_magic = volume_magic_id();
    assert!(stdout.contains("FAIL"), "{stdout}");
    assert!(stdout.contains("checksum:0"), "{stdout}");
    assert!(stdout.contains(&volume_magic), "{stdout}");
    assert_named_fail(&stdout, "checksum:0");
    assert_named_fail(&stdout, &volume_magic);
}

#[test]
fn binary_apply_selected_then_all_on_qcow2() {
    let dir = tempfile::tempdir().unwrap();
    let qcow = dir.path().join("disk.qcow2");
    write_mutated_qcow2(&qcow);
    assert_qcow2_v3(&qcow);

    let volume_magic = volume_magic_id();

    let applied = run_repair(&qcow, &["--apply", "checksum:0"]);
    assert_success(&applied, "repair --apply checksum:0");
    let applied_stdout = stdout_text(&applied);
    eprint!("{applied_stdout}");

    let after_one = dump(&qcow);
    eprint!("{after_one}");
    assert_not_named_fail(&after_one, "checksum:0");
    assert_named_fail(&after_one, &volume_magic);

    let applied_all = run_repair(&qcow, &["--apply", "all"]);
    assert_success(&applied_all, "repair --apply all");
    eprint!("{}", stdout_text(&applied_all));

    let after_all = dump(&qcow);
    eprint!("{after_all}");
    assert_not_named_fail(&after_all, "checksum:0");
    assert_not_named_fail(&after_all, &volume_magic);
}

#[test]
fn binary_interactive_applies_piped_selection() {
    let dir = tempfile::tempdir().unwrap();
    let qcow = dir.path().join("disk.qcow2");
    write_mutated_qcow2(&qcow);
    assert_qcow2_v3(&qcow);

    let mut child = Command::new(bin())
        .args(["repair", qcow.to_str().unwrap(), "--interactive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn interactive repair");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"checksum:0\n").expect("write pick line");
    }
    let out = child.wait_with_output().expect("wait interactive");
    assert!(
        out.status.success(),
        "interactive failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprint!("{stdout}");
    assert!(stdout.contains("FAIL"), "{stdout}");
    assert!(stdout.contains("checksum:0"), "{stdout}");
    assert!(stdout.contains("applied: checksum:0"), "{stdout}");

    let after = dump(&qcow);
    assert_not_named_fail(&after, "checksum:0");
    assert_named_fail(&after, &volume_magic_id());
}

#[test]
fn binary_dumps_raw_gpt_and_qcow2() {
    let dir = tempfile::tempdir().unwrap();
    let gpt = dir.path().join("disk.img");
    let qcow = dir.path().join("disk.qcow2");
    write_fixture(&gpt, ImageWrap::RawGpt).expect("write gpt fixture");
    write_fixture(&qcow, ImageWrap::Qcow2).expect("write qcow2 fixture");
    assert_qcow2_v3(&qcow);

    let gpt_dump = dump(&gpt);
    assert!(gpt_dump.contains("PASS"), "{gpt_dump}");
    assert_only_container_structure_fails(&gpt_dump);

    let qcow_dump = dump(&qcow);
    assert!(qcow_dump.contains("backend=qcow2"), "{qcow_dump}");
    assert!(qcow_dump.contains("PASS"), "{qcow_dump}");
    assert_only_container_structure_fails(&qcow_dump);
}

#[test]
fn lib_sweep_apply_and_format_dump_on_qcow2() {
    let dir = tempfile::tempdir().unwrap();
    let qcow = dir.path().join("disk.qcow2");
    write_mutated_qcow2(&qcow);

    let volume_magic = volume_magic_id();
    let dumped = format_dump(&sweep(&qcow).expect("sweep"));
    assert!(dumped.contains("FAIL"), "{dumped}");
    assert!(dumped.contains("checksum:0"), "{dumped}");
    assert!(dumped.contains(&volume_magic), "{dumped}");
    assert_named_fail(&dumped, "checksum:0");
    assert_named_fail(&dumped, &volume_magic);

    apply(&qcow, &["checksum:0".to_string()]).expect("apply checksum:0");
    let after_one = format_dump(&sweep(&qcow).expect("sweep after checksum:0"));
    assert_not_named_fail(&after_one, "checksum:0");
    assert_named_fail(&after_one, &volume_magic);

    apply(&qcow, std::slice::from_ref(&volume_magic)).expect("apply volume-magic");
    let after_all = format_dump(&sweep(&qcow).expect("sweep after volume-magic"));
    assert_not_named_fail(&after_all, "checksum:0");
    assert_not_named_fail(&after_all, &volume_magic);
}
