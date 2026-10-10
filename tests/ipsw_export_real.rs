//! Runs the IPSW exporter against the real `ipsw` command, building its inputs in a temp folder.
//! Run with `cargo test --test ipsw_export_real -- --ignored`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

use apple_utils::app::{App, Screen};
use apple_utils::banner::BannerOrder;
use apple_utils::ipsw_app::IpswPhase;
use apple_utils::ipsw_export::{
    Component, ExportOptions, ExportReport, ExportRequest, Outcome, run_export,
};
use apple_utils::ipsw_fixture::{FixtureEntry, write_ipsw};
use apple_utils::ipsw_tree::{IpswTree, find_ipsw_cli};
use apple_utils::ui::GlyphPack;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::Position;

const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

const KERNEL_NAME: &str = "kernelcache.release.j274";
const IBOOT_NAME: &str = "Firmware/all_flash/iBoot.test.RELEASE.im4p";
const IMAGE_NAME: &str = "090-test-001.dmg.aea";

const BUILD_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>ProductVersion</key><string>26.0</string><key>ProductBuildVersion</key><string>25A1</string><key>SupportedProductTypes</key><array><string>Mac14,2</string></array><key>BuildIdentities</key><array><dict><key>ApBoardID</key><string>0x20</string><key>ApChipID</key><string>0x8112</string><key>Info</key><dict><key>DeviceClass</key><string>j413ap</string><key>Variant</key><string>macOS Customer</string><key>RestoreBehavior</key><string>Erase</string></dict><key>Manifest</key><dict><key>KernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release.j274</string></dict></dict></dict></dict></array></dict></plist>"#;

fn require_cli() -> PathBuf {
    find_ipsw_cli().unwrap_or_else(|| {
        panic!(
            "the ipsw command is not installed: these tests need blacktop/ipsw on PATH \
             (or in /opt/homebrew/bin or /usr/local/bin)"
        )
    })
}

fn varied_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 32);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        if state.is_multiple_of(5) {
            out.extend_from_slice(b"apple-utils export payload ");
        } else {
            out.extend_from_slice(&state.to_le_bytes());
        }
    }
    out.truncate(len);
    out
}

fn run_cli(cli: &Path, args: &[&str]) {
    let output = Command::new(cli)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("could not run {}: {error}", cli.display()));
    assert!(
        output.status.success(),
        "ipsw {args:?} failed ({}):\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn as_str(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

struct Inputs {
    dir: tempfile::TempDir,
    cli: PathBuf,
    archive: PathBuf,
    kernel_payload: Vec<u8>,
    iboot_payload: Vec<u8>,
    image_payload: Vec<u8>,
    encrypted: Vec<u8>,
}

fn build_inputs(archive_name: &str) -> Inputs {
    let cli = require_cli();
    let dir = tempfile::tempdir().expect("temp dir");
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();

    let kernel_payload = varied_bytes(1, 300 * 1024);
    let iboot_payload = varied_bytes(2, 280 * 1024);
    let image_payload = varied_bytes(3, 200 * 1024);

    let kernel_plain = work.join("payload.bin");
    fs::write(&kernel_plain, &kernel_payload).unwrap();
    let kernel_im4p = work.join("k.im4p");
    run_cli(
        &cli,
        &[
            "img4",
            "im4p",
            "create",
            "-t",
            "krnl",
            "-c",
            "lzss",
            "-o",
            as_str(&kernel_im4p),
            as_str(&kernel_plain),
        ],
    );

    let iboot_plain = work.join("payload-iboot.bin");
    fs::write(&iboot_plain, &iboot_payload).unwrap();
    let iboot_im4p = work.join("iboot.im4p");
    run_cli(
        &cli,
        &[
            "img4",
            "im4p",
            "create",
            "-t",
            "krnl",
            "-c",
            "lzfse",
            "-o",
            as_str(&iboot_im4p),
            as_str(&iboot_plain),
        ],
    );

    let image_plain = work.join("payload2.bin");
    fs::write(&image_plain, &image_payload).unwrap();
    let aea_dir = work.join("aea-out");
    fs::create_dir(&aea_dir).unwrap();
    run_cli(
        &cli,
        &[
            "--no-color",
            "fw",
            "aea",
            "-e",
            "-b",
            KEY,
            "-o",
            as_str(&aea_dir),
            as_str(&image_plain),
        ],
    );
    let encrypted = fs::read(aea_dir.join("payload2.bin.aea"))
        .expect("ipsw fw aea -e should write payload2.bin.aea");

    let kernel_bytes = fs::read(&kernel_im4p).unwrap();
    let iboot_bytes = fs::read(&iboot_im4p).unwrap();
    assert_ne!(
        kernel_bytes, kernel_payload,
        "the IM4P must not be the raw payload"
    );
    assert_ne!(
        iboot_bytes, iboot_payload,
        "the IM4P must not be the raw payload"
    );
    assert_ne!(
        encrypted, image_payload,
        "the AEA must not be the raw payload"
    );

    let archive = dir.path().join(archive_name);
    write_ipsw(
        &archive,
        &[
            FixtureEntry::file("BuildManifest.plist", BUILD_MANIFEST.as_bytes().to_vec()),
            FixtureEntry::file(KERNEL_NAME, kernel_bytes),
            FixtureEntry::file(IBOOT_NAME, iboot_bytes),
            FixtureEntry::file(IMAGE_NAME, encrypted.clone()),
        ],
    )
    .unwrap();

    Inputs {
        dir,
        cli,
        archive,
        kernel_payload,
        iboot_payload,
        image_payload,
        encrypted,
    }
}

fn request(inputs: &Inputs, output: PathBuf, files: &[&str]) -> ExportRequest {
    assert!(
        inputs.archive.is_file(),
        "the synthetic IPSW was not written"
    );
    ExportRequest {
        files: files.iter().map(|name| name.to_string()).collect(),
        components: Vec::new(),
        device: None,
        output,
        options: ExportOptions {
            aea_key: Some(KEY.to_string()),
            ..ExportOptions::default()
        },
    }
}

fn wrong_key() -> String {
    format!("{}=", "A".repeat(43))
}

fn run(inputs: &Inputs, request: &ExportRequest) -> ExportReport {
    let tree = IpswTree::open(&inputs.archive).expect("open the synthetic IPSW");
    let cancel = AtomicBool::new(false);
    run_export(
        &tree,
        Some(inputs.cli.as_path()),
        request,
        &cancel,
        &mut |_| {},
    )
    .expect("run_export")
}

fn outcome_of(report: &ExportReport, name: &str) -> Outcome {
    report
        .items
        .iter()
        .find(|item| item.name == name)
        .unwrap_or_else(|| panic!("no report item named {name}: {:?}", report.items))
        .outcome
        .clone()
}

fn assert_no_work_dir(output: &Path) {
    let leftovers: Vec<String> = fs::read_dir(output)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".apple-utils-export-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "work folders left behind: {leftovers:?}"
    );
}

#[test]
#[ignore = "needs the ipsw command"]
fn real_tool_decrypts_the_aea_and_decompresses_both_im4p_payloads_byte_for_byte() {
    let inputs = build_inputs("Real_26.0.ipsw");
    let output = inputs.dir.path().join("out");
    let request = request(
        &inputs,
        output.clone(),
        &[IMAGE_NAME, KERNEL_NAME, IBOOT_NAME],
    );
    let report = run(&inputs, &request);

    assert!(!report.cancelled);
    let counts = report.counts();
    assert_eq!(
        (
            counts.decrypted,
            counts.decompressed,
            counts.kept,
            counts.failed
        ),
        (1, 2, 0, 0),
        "{:?}",
        report.items
    );

    assert_eq!(
        fs::read(output.join("090-test-001.dmg")).expect("decrypted image"),
        inputs.image_payload,
        "AEA decryption must reproduce the original bytes"
    );
    assert!(
        !output.join(IMAGE_NAME).exists(),
        "the encrypted original is not kept"
    );
    assert_eq!(
        fs::read(output.join(KERNEL_NAME)).expect("decompressed kernelcache"),
        inputs.kernel_payload,
        "LZSS decompression must reproduce the original bytes"
    );
    assert_eq!(
        fs::read(output.join("Firmware/all_flash/iBoot.test.RELEASE")).expect("decompressed iBoot"),
        inputs.iboot_payload,
        "LZFSE decompression must reproduce the original bytes"
    );
    assert!(
        !output.join(IBOOT_NAME).exists(),
        "the .im4p original is not kept"
    );

    assert_no_work_dir(&output);
    let mut stray = Vec::new();
    collect(&output, &output, &mut stray);
    assert!(
        stray.iter().all(|path| !path.ends_with(".part")),
        "partial files left behind: {stray:?}"
    );
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        out.push(
            path.strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        if entry.file_type().unwrap().is_dir() {
            collect(root, &path, out);
        }
    }
}

#[test]
#[ignore = "needs the ipsw command"]
fn keeping_originals_beside_the_real_decoded_files() {
    let inputs = build_inputs("Real_26.0.ipsw");
    let output = inputs.dir.path().join("out");
    let mut request = request(&inputs, output.clone(), &[IMAGE_NAME, KERNEL_NAME]);
    request.options.keep_originals = true;
    let report = run(&inputs, &request);
    assert_eq!(
        report.counts().failed + report.counts().kept,
        0,
        "{:?}",
        report.items
    );

    assert_eq!(
        fs::read(output.join("090-test-001.dmg")).unwrap(),
        inputs.image_payload
    );
    assert_eq!(fs::read(output.join(IMAGE_NAME)).unwrap(), inputs.encrypted);
    assert_eq!(
        fs::read(output.join("kernelcache.release.j274.decompressed")).unwrap(),
        inputs.kernel_payload
    );
    assert!(
        fs::read(output.join(KERNEL_NAME)).unwrap() != inputs.kernel_payload,
        "the original IM4P is kept under its own name"
    );
    assert_no_work_dir(&output);
}

#[test]
#[ignore = "needs the ipsw command"]
fn a_wrong_key_keeps_the_encrypted_original_with_a_warning() {
    let inputs = build_inputs("Real_26.0.ipsw");
    let output = inputs.dir.path().join("out");
    let mut request = request(&inputs, output.clone(), &[IMAGE_NAME]);
    request.options.aea_key = Some(wrong_key());
    let report = run(&inputs, &request);

    match outcome_of(&report, IMAGE_NAME) {
        Outcome::Kept { path, warning } => {
            assert!(
                !warning.trim().is_empty(),
                "the warning must say what went wrong"
            );
            assert_eq!(path, output.join(IMAGE_NAME));
        }
        other => panic!("expected Kept, got {other:?}"),
    }
    assert_eq!(
        fs::read(output.join(IMAGE_NAME)).unwrap(),
        inputs.encrypted,
        "the encrypted original is still at its own name, untouched"
    );
    assert!(
        !output.join("090-test-001.dmg").exists(),
        "no decrypted file may appear for a wrong key"
    );
    assert_eq!(report.counts().kept, 1);
    assert_no_work_dir(&output);
}

#[test]
#[ignore = "needs the ipsw command"]
fn real_components_kernel_is_produced_and_device_tree_fails_with_the_tools_message() {
    let inputs = build_inputs("Real_26.0.ipsw");
    let output = inputs.dir.path().join("out");
    let mut request = request(&inputs, output.clone(), &[]);
    request.components = vec![Component::Kernel, Component::DeviceTree];
    let report = run(&inputs, &request);

    match outcome_of(&report, "Kernelcache") {
        Outcome::Produced { paths } => {
            assert_eq!(paths.len(), 1, "{paths:?}");
            let path = &paths[0];
            assert!(path.starts_with(&output), "{path:?}");
            assert_eq!(
                path.file_name().unwrap().to_string_lossy(),
                "kernelcache.release.Mac14,2"
            );
            assert_eq!(
                path.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy(),
                "25A1__Mac14,2"
            );
            assert_eq!(
                fs::read(path).unwrap(),
                inputs.kernel_payload,
                "ipsw extract --kernel writes the decompressed kernelcache"
            );
        }
        other => panic!("expected Produced, got {other:?}"),
    }
    match outcome_of(&report, "DeviceTree") {
        Outcome::Failed { reason } => {
            assert!(reason.contains("no files found"), "reason was {reason:?}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(report.counts().produced, 1);
    assert_eq!(report.counts().failed, 1);
    assert_no_work_dir(&output);
}

fn press(app: &mut App, code: KeyCode) {
    let mut event = KeyEvent::new(code, KeyModifiers::NONE);
    event.kind = KeyEventKind::Press;
    app.handle_event(Event::Key(event));
}

fn draw(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    terminal
        .draw(|frame| apple_utils::ui::render(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    let area = buffer.area();
    let mut out = String::new();
    for y in 0..area.height {
        for x in 0..area.width {
            out.push_str(buffer[Position::new(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[test]
#[ignore = "needs the ipsw command"]
fn full_tui_flow_with_the_real_tool_open_select_all_key_export_done() {
    let inputs = build_inputs("Real_26.0.ipsw");
    let mut app = App::with_banner_order(BannerOrder::sequential());
    app.glyph_pack = GlyphPack::Instrument;
    app.set_ipsw_cli(Some(inputs.cli.clone()));
    app.screen = Screen::Ipsw;
    app.open_ipsw(as_str(&inputs.archive));
    app.drain_ipsw_job();
    assert_eq!(app.ipsw.phase, IpswPhase::Browse, "{:?}", app.ipsw.error);

    let screen = draw(&mut app);
    assert!(screen.contains("26.0 (25A1)"), "{screen}");
    assert!(screen.contains("Mac14,2"), "{screen}");

    press(&mut app, KeyCode::Char('a'));
    let all: BTreeSet<String> = ["BuildManifest.plist", KERNEL_NAME, IBOOT_NAME, IMAGE_NAME]
        .iter()
        .map(|name| name.to_string())
        .collect();
    assert_eq!(app.ipsw.selected, all);

    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Home);
    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(app.ipsw.aea_editing);
    for c in KEY.chars() {
        press(&mut app, KeyCode::Char(c));
    }
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.options.aea_key.as_deref(), Some(KEY));
    let screen = draw(&mut app);
    assert!(
        !screen.contains(&KEY[..KEY.len() - 4]),
        "the key must be masked on screen:\n{screen}"
    );

    press(&mut app, KeyCode::Char('e'));
    assert_eq!(app.ipsw.phase, IpswPhase::Output, "{:?}", app.ipsw.error);
    app.clip.file = None;
    app.clip.raw.clear();
    press(&mut app, KeyCode::Enter);
    app.drain_ipsw_job();
    assert_eq!(app.ipsw.phase, IpswPhase::Done, "{:?}", app.ipsw.error);

    let output = inputs.dir.path().join("Real_26.0-export");
    assert_eq!(
        fs::read(output.join("090-test-001.dmg")).unwrap(),
        inputs.image_payload
    );
    assert_eq!(
        fs::read(output.join(KERNEL_NAME)).unwrap(),
        inputs.kernel_payload
    );
    assert_eq!(
        fs::read(output.join("Firmware/all_flash/iBoot.test.RELEASE")).unwrap(),
        inputs.iboot_payload
    );
    assert_eq!(
        fs::read(output.join("BuildManifest.plist")).unwrap(),
        BUILD_MANIFEST.as_bytes()
    );
    assert_no_work_dir(&output);

    let screen = draw(&mut app);
    assert!(screen.contains("Export finished"), "{screen}");
    assert!(
        screen.contains("written 1   decrypted 1   decompressed 2   linked 0"),
        "{screen}"
    );
    assert!(
        screen.contains("kept with warnings 0   skipped 0   failed 0"),
        "{screen}"
    );
    assert!(screen.contains("Real_26.0-export"), "{screen}");
}
