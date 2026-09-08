use std::fs;
use std::io;
use std::path::Path;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Position;
use ratatui::style::Color;

use crate::app::{
    App, AsahiAction, AsahiSource, AsahiStep, ExplorerPhase, RepairStep, Screen, Suggestion,
};
use crate::clip::{FileInfo, FileKind};
use crate::recovery_model::{
    DeviceState, FileRequestSpec, RecoveryDevice, RecoveryEvent, RestoreProgress, SizeRange,
};
use crate::theme;
use crate::ui;

struct Shot {
    name: &'static str,
    file: &'static str,
    width: u16,
    height: u16,
    build: fn() -> App,
    tick: u64,
}

pub fn write_previews() -> io::Result<()> {
    let out = Path::new("target/preview");
    fs::create_dir_all(out)?;

    let shots = [
        Shot {
            name: "Picker",
            file: "picker.html",
            width: 120,
            height: 40,
            build: picker,
            tick: 0,
        },
        Shot {
            name: "Picker compact",
            file: "picker-compact.html",
            width: 80,
            height: 18,
            build: picker,
            tick: 0,
        },
        Shot {
            name: "Recovery",
            file: "recovery.html",
            width: 100,
            height: 32,
            build: recovery,
            tick: 14,
        },
        Shot {
            name: "Explorer · path",
            file: "explorer-path.html",
            width: 100,
            height: 32,
            build: explorer_path,
            tick: 4,
        },
        Shot {
            name: "Explorer · opening",
            file: "explorer-loading.html",
            width: 100,
            height: 32,
            build: explorer_loading,
            tick: 8,
        },
        Shot {
            name: "Explorer · browse",
            file: "explorer-browse.html",
            width: 100,
            height: 32,
            build: explorer_browse,
            tick: 0,
        },
        Shot {
            name: "Repair · path",
            file: "repair-path.html",
            width: 100,
            height: 32,
            build: repair_path,
            tick: 4,
        },
        Shot {
            name: "Repair · detection",
            file: "repair-detection.html",
            width: 100,
            height: 32,
            build: repair_detection,
            tick: 14,
        },
        Shot {
            name: "Repair · suggestions",
            file: "repair-suggestions.html",
            width: 100,
            height: 32,
            build: repair_suggestions,
            tick: 0,
        },
        Shot {
            name: "Repair · apply",
            file: "repair-apply.html",
            width: 100,
            height: 32,
            build: repair_apply,
            tick: 0,
        },
        Shot {
            name: "Repair · narrow chain",
            file: "repair-narrow.html",
            width: 60,
            height: 24,
            build: repair_detection,
            tick: 0,
        },
        Shot {
            name: "Asahi · menu",
            file: "asahi-menu.html",
            width: 100,
            height: 32,
            build: asahi_menu,
            tick: 0,
        },
        Shot {
            name: "Asahi · size",
            file: "asahi-size.html",
            width: 100,
            height: 32,
            build: asahi_size,
            tick: 0,
        },
        Shot {
            name: "Asahi · source",
            file: "asahi-source.html",
            width: 100,
            height: 32,
            build: asahi_source,
            tick: 0,
        },
        Shot {
            name: "Asahi · wait file",
            file: "asahi-wait.html",
            width: 100,
            height: 32,
            build: asahi_wait,
            tick: 4,
        },
    ];

    let mut index = String::from(INDEX_HEAD);
    for shot in shots {
        let mut app = (shot.build)();
        app.tick = shot.tick;
        let (html, text) = render_shot(&mut app, shot.width, shot.height, shot.name)?;
        fs::write(out.join(shot.file), html)?;
        fs::write(out.join(shot.file.replace(".html", ".txt")), text)?;
        index.push_str(&format!(
            "<a class=\"card\" href=\"{file}\"><span>{name}</span><small>{w}×{h}</small></a>",
            file = shot.file,
            name = shot.name,
            w = shot.width,
            h = shot.height
        ));
    }
    index.push_str("</div></body></html>");
    fs::write(out.join("index.html"), index)?;
    eprintln!("wrote previews to {}", out.display());
    Ok(())
}

fn picker() -> App {
    App::with_banner_order(crate::banner::BannerOrder::sequential())
}

fn recovery() -> App {
    let mut app = App::new();
    app.screen = Screen::Recovery;
    app.tick = 14;
    app.clip.set_file(FileInfo {
        path: "/tmp/BuildManifest.plist".into(),
        name: "BuildManifest.plist".into(),
        kind: FileKind::File,
        size: Some(128),
        modified: Some("just now".into()),
    });
    app.recovery
        .model
        .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
            id: "dev-1".into(),
            title: "Recovery Device".into(),
            detail: "DFU iPhone15,3".into(),
            connection: "127.0.0.1:9123".into(),
            state: DeviceState::Available,
            connected: true,
        }));
    app.recovery
        .model
        .apply_event(RecoveryEvent::ClaimAccepted {
            device_id: "dev-1".into(),
            note: Some("Device claimed".into()),
        });
    app.recovery
        .model
        .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
            request_id: "manifest".into(),
            role: "BuildManifest".into(),
            preferred_name: Some("BuildManifest.plist".into()),
            accepted_names: vec!["BuildManifest.plist".into()],
            allowed_extensions: vec!["plist".into()],
            accept_directory: false,
            expected_size: Some(SizeRange { min: 32, max: 512 }),
            expected_hash: None,
            detail: Some("Parse build plan".into()),
            required: true,
        }));
    let file = app.clip.file.clone().expect("clipboard");
    app.recovery
        .model
        .note_clipboard_assignment(&file, "queued".into());
    app.recovery
        .model
        .apply_event(RecoveryEvent::Progress(RestoreProgress {
            stage: "ramdisk".into(),
            detail: "Uploading".into(),
            fraction: Some(0.42),
        }));
    app
}

fn explorer_path() -> App {
    let mut app = App::new();
    app.screen = Screen::Explorer;
    app.explorer_phase = ExplorerPhase::Path;
    app.clip.set_file(FileInfo {
        path: "/tmp/apfs.qcow2".into(),
        name: "apfs.qcow2".into(),
        kind: FileKind::File,
        size: Some(8 << 30),
        modified: Some("2 days ago".into()),
    });
    app
}

fn explorer_loading() -> App {
    let mut app = App::new();
    app.screen = Screen::Explorer;
    app.explorer_phase = ExplorerPhase::Loading;
    app.explorer_confirmed = "target.qcow2".into();
    app.explorer_status = "opening target.qcow2".into();
    app.tick = 8;
    app
}

fn explorer_browse() -> App {
    let mut app = App::new();
    app.screen = Screen::Explorer;
    app.explorer_phase = ExplorerPhase::Browse;
    app.explorer_confirmed = "fixture.img".into();
    app.explorer_pane = crate::app::ExplorerPane::Files;
    app.explorer_view = Some(crate::explorer_image::ExplorerView {
        path: "fixture.img".into(),
        backend: crate::explorer_image::BackendKind::Gpt,
        volumes: vec![crate::explorer_image::VolumeInfo {
            name: crate::apfs_fixture::FIXTURE_VOLUME.into(),
            role: "volume".into(),
            sealed: false,
            encrypted: false,
            container_index: 0,
            partition_name: "container".into(),
            bootable: false,
            volume_group_id: [0u8; 16],
            system_version: None,
        }],
        volume_index: 0,
        volume_cursor: 0,
        cwd: format!("/{}", crate::apfs_fixture::FIXTURE_DIR),
        entries: vec![
            crate::explorer_image::ListedEntry {
                name: crate::apfs_fixture::FIXTURE_NESTED.into(),
                kind: crate::explorer_image::EntryKind::Directory,
                size: None,
                symlink_target: None,
            },
            crate::explorer_image::ListedEntry {
                name: crate::apfs_fixture::FIXTURE_FILE.into(),
                kind: crate::explorer_image::EntryKind::File,
                size: Some(crate::apfs_fixture::FIXTURE_FILE_BYTES.len() as u64),
                symlink_target: None,
            },
            crate::explorer_image::ListedEntry {
                name: crate::apfs_fixture::FIXTURE_SYMLINK.into(),
                kind: crate::explorer_image::EntryKind::Symlink,
                size: Some(crate::apfs_fixture::FIXTURE_SYMLINK_TARGET.len() as u64),
                symlink_target: Some(crate::apfs_fixture::FIXTURE_SYMLINK_TARGET.into()),
            },
        ],
        cursor: 2,
        preview: Some(
            std::str::from_utf8(crate::apfs_fixture::FIXTURE_FILE_BYTES)
                .unwrap()
                .into(),
        ),
        error: None,
        message: None,
    });
    app
}

fn repair_path() -> App {
    let mut app = App::new();
    app.screen = Screen::Repair;
    app.repair_step = RepairStep::Path;
    app
}

fn repair_findings() -> Vec<crate::repair_ops::Finding> {
    vec![
        crate::repair_ops::Finding {
            id: "checksum:0".into(),
            status: crate::repair_ops::CheckStatus::Fail,
            summary: "fletcher64 mismatch at nxsb".into(),
            detail: "block 0".into(),
            repairable: true,
        },
        crate::repair_ops::Finding {
            id: "container-magic".into(),
            status: crate::repair_ops::CheckStatus::Pass,
            summary: "NXSB magic present".into(),
            detail: "offset 0".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "volume-magic:21".into(),
            status: crate::repair_ops::CheckStatus::Fail,
            summary: "volume superblock magic missing".into(),
            detail: "block 21".into(),
            repairable: true,
        },
        crate::repair_ops::Finding {
            id: "snapshot-count:21".into(),
            status: crate::repair_ops::CheckStatus::NotApplicable,
            summary: "volume has no snapshots".into(),
            detail: "declared=0".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "volume-seal:21".into(),
            status: crate::repair_ops::CheckStatus::NotApplicable,
            summary: "volume is not sealed".into(),
            detail: "flag=false".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "blessing:21".into(),
            status: crate::repair_ops::CheckStatus::NotApplicable,
            summary: "no sealed root snapshot to bless".into(),
            detail: "root_snapshots=0".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "checkpoint".into(),
            status: crate::repair_ops::CheckStatus::Pass,
            summary: "checkpoint superblock present".into(),
            detail: "descriptor".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "object-map".into(),
            status: crate::repair_ops::CheckStatus::Pass,
            summary: "container object map present".into(),
            detail: "paddr=17".into(),
            repairable: false,
        },
    ]
}

fn repair_detection() -> App {
    let mut app = App::new();
    app.screen = Screen::Repair;
    app.repair_step = RepairStep::Detection;
    app.repair_confirmed = "/dev/disk3s1".into();
    app.detection_progress = Some(1.0);
    app.repair_backend = "gpt".into();
    app.repair_findings = repair_findings();
    app
}

fn repair_suggestions() -> App {
    let mut app = App::new();
    app.screen = Screen::Repair;
    app.repair_step = RepairStep::Suggestions;
    app.repair_confirmed = "/dev/disk3s1".into();
    app.repair_backend = "gpt".into();
    app.detection_progress = Some(0.75);
    app.repair_findings = repair_findings();
    app.repair_pane = crate::app::RepairPane::Main;
    app.suggestions = vec![
        Suggestion {
            id: "checksum:0".into(),
            label: "rewrite container checksum".into(),
            detail: "seal nxsb fletcher64".into(),
            enabled: true,
        },
        Suggestion {
            id: "volume-magic:21".into(),
            label: "restore volume magic".into(),
            detail: "write APSB at block 21".into(),
            enabled: false,
        },
    ];
    app
}

fn repair_apply() -> App {
    let mut app = App::new();
    app.screen = Screen::Repair;
    app.repair_step = RepairStep::Apply;
    app.repair_confirmed = "/dev/disk3s1".into();
    app.repair_backend = "gpt".into();
    app.apply_progress = Some(0.5);
    app.repair_apply_log = vec![
        "applied checksum:0".into(),
        "failed volume-magic:21: still invalid".into(),
    ];
    app.repair_findings = vec![
        crate::repair_ops::Finding {
            id: "checksum:0".into(),
            status: crate::repair_ops::CheckStatus::Pass,
            summary: "fletcher64 matches nxsb".into(),
            detail: "block 0".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "container-magic".into(),
            status: crate::repair_ops::CheckStatus::Pass,
            summary: "NXSB magic present".into(),
            detail: "offset 0".into(),
            repairable: false,
        },
        crate::repair_ops::Finding {
            id: "volume-magic:21".into(),
            status: crate::repair_ops::CheckStatus::Fail,
            summary: "volume superblock magic missing".into(),
            detail: "block 21".into(),
            repairable: true,
        },
    ];
    app
}

fn asahi_menu() -> App {
    let mut app = App::new();
    app.screen = Screen::Asahi;
    app.asahi_step = AsahiStep::Menu;
    app.asahi_action = AsahiAction::Update;
    app.asahi_action_cursor = 0;
    app
}

fn asahi_size() -> App {
    let mut app = App::new();
    app.screen = Screen::Asahi;
    app.asahi_step = AsahiStep::Size;
    app.asahi_action = AsahiAction::Install;
    app.asahi_size_gb = crate::asahi_ops::SLIDER_DEFAULT_GB;
    app
}

fn asahi_source() -> App {
    let mut app = App::new();
    app.screen = Screen::Asahi;
    app.asahi_step = AsahiStep::Source;
    app.asahi_action = AsahiAction::Install;
    app.asahi_source = AsahiSource::Latest;
    app.asahi_source_cursor = 0;
    app
}

fn asahi_wait() -> App {
    let mut app = App::new();
    app.screen = Screen::Asahi;
    app.asahi_step = AsahiStep::WaitFile;
    app.asahi_action = AsahiAction::Update;
    app
}

fn render_shot(
    app: &mut App,
    width: u16,
    height: u16,
    title: &str,
) -> io::Result<(String, String)> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).map_err(io::Error::other)?;
    terminal
        .draw(|frame| ui::render(frame, app))
        .map_err(io::Error::other)?;
    let buffer = terminal.backend().buffer();
    Ok((
        buffer_to_html(buffer, title, width, height),
        buffer_to_text(buffer, width, height),
    ))
}

fn buffer_to_text(buffer: &Buffer, width: u16, height: u16) -> String {
    let mut out = String::new();
    for y in 0..height {
        for x in 0..width {
            out.push_str(buffer[Position::new(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn buffer_to_html(buffer: &Buffer, title: &str, width: u16, height: u16) -> String {
    let mut rows = String::new();
    for y in 0..height {
        rows.push_str("<div class=\"row\">");
        for x in 0..width {
            let cell = &buffer[Position::new(x, y)];
            let ch = escape(cell.symbol());
            let fg = css_color(cell.fg, theme::SILVER);
            let bg = css_color(cell.bg, theme::BG);
            rows.push_str(&format!(
                "<span style=\"color:{fg};background:{bg}\">{ch}</span>"
            ));
        }
        rows.push_str("</div>\n");
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title} · Apple Utils</title>
<style>
  html, body {{
    margin: 0;
    background: #111111;
    color: #d2d2d2;
    font-family: ui-sans-serif, system-ui, sans-serif;
  }}
  main {{
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 32px 16px 48px;
    gap: 16px;
  }}
  h1 {{
    font-size: 13px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    font-weight: 600;
    color: #8a8a8a;
    margin: 0;
  }}
  .term {{
    background: #121212;
    border: 1px solid #3a3a3a;
    border-radius: 12px;
    padding: 18px 20px;
    box-shadow: 0 24px 60px rgba(0,0,0,0.45);
    line-height: 1;
  }}
  .row {{
    display: flex;
    white-space: pre;
    font: 13px/1.25 "Iosevka Term", "JetBrains Mono", "SF Mono", ui-monospace, monospace;
  }}
  .row span {{
    display: inline-block;
    width: 8.2px;
    text-align: center;
  }}
</style>
</head>
<body>
<main>
  <h1>{title}</h1>
  <div class="term">{rows}</div>
</main>
</body>
</html>
"#
    )
}

fn css_color(color: Color, fallback: Color) -> String {
    match color {
        Color::Reset => css_color(fallback, fallback),
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::Black => "#000000".into(),
        Color::White => "#ffffff".into(),
        Color::Gray => "#9a9a9a".into(),
        Color::DarkGray => "#4a4a4a".into(),
        Color::Red => "#c45b5b".into(),
        Color::Green => "#6aae7a".into(),
        Color::Yellow => "#d4a574".into(),
        Color::Blue => "#8ec8e0".into(),
        Color::Magenta => "#b48ead".into(),
        Color::Cyan => "#8ec8e0".into(),
        Color::LightRed => "#e07a7a".into(),
        Color::LightGreen => "#8fd19a".into(),
        Color::LightYellow => "#e6c08a".into(),
        Color::LightBlue => "#9ecce4".into(),
        Color::LightMagenta => "#d0a8c8".into(),
        Color::LightCyan => "#9ed4e0".into(),
        Color::Indexed(i) => format!("#{i:02x}{i:02x}{i:02x}"),
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace(' ', "&nbsp;")
}

const INDEX_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Apple Utils previews</title>
<style>
  body { margin: 0; background: #111111; color: #d2d2d2; font: 15px/1.4 ui-sans-serif, system-ui, sans-serif; }
  main { max-width: 720px; margin: 0 auto; padding: 48px 24px; }
  h1 { font-size: 13px; letter-spacing: 0.18em; text-transform: uppercase; color: #8a8a8a; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
  .card { display: flex; flex-direction: column; gap: 4px; padding: 16px; border: 1px solid #3a3a3a; border-radius: 10px; color: inherit; text-decoration: none; background: #1c1c1c; }
  .card:hover { border-color: #8ec8e0; }
  small { color: #8a8a8a; }
</style>
</head>
<body>
<main>
<h1>Apple Utils · screen previews</h1>
<div class="grid">
"#;
