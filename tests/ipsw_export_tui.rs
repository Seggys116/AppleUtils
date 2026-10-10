//! End-to-end tests for the IPSW Export tool, driven through `App::handle_event` with a fake `ipsw`.
//! Set `APPLE_UTILS_UI_DUMP=<dir>` to write every rendered screen to that folder as text.

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use apple_utils::app::{App, Screen, Tool};
use apple_utils::banner::BannerOrder;
use apple_utils::ipsw_app::{IpswPane, IpswPhase, Mark, OPTION_COUNT};
use apple_utils::ipsw_export::{Component, ExportOptions, ExportReport, Outcome};
use apple_utils::ipsw_fixture::{
    FIXTURE_DEVICES, FixtureEntry, fake_im4p, sample_entries, write_fake_cli, write_ipsw,
};
use apple_utils::ui::GlyphPack;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};

const AEA: &str = "090-12345-001.dmg.aea";
const KERNEL: &str = "kernelcache.release.mac14j";
const IBOOT: &str = "Firmware/all_flash/iBoot.j414c.RELEASE.im4p";
const LLB: &str = "Firmware/all_flash/LLB.j414c.RELEASE.im4p";
const NOTES: &str = "Firmware/notes.txt";
const LATEST: &str = "Firmware/latest";
const SLOW: &str = "slow-image.dmg.aea";

const ALL_ENTRIES: [&str; 11] = [
    "090-12345-001.dmg.aea",
    "090-12345-002.dmg",
    "BuildManifest.plist",
    "Firmware/Manifests/restore/info.plist",
    "Firmware/all_flash/LLB.j414c.RELEASE.im4p",
    "Firmware/all_flash/iBoot.j414c.RELEASE.im4p",
    "Firmware/dfu/iBEC.j414c.RELEASE.im4p",
    "Firmware/latest",
    "Firmware/notes.txt",
    "Restore.plist",
    "kernelcache.release.mac14j",
];

const ON: &str = "●";
const OFF: &str = "○";
const HALF: &str = "◐";

struct Rig {
    dir: tempfile::TempDir,
    cli: PathBuf,
    archive: PathBuf,
}

impl Rig {
    fn new() -> Self {
        Self::with_entries(&sample_entries())
    }

    fn with_entries(entries: &[FixtureEntry]) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let bin = dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let cli = write_fake_cli(&bin).unwrap();
        let archive = dir.path().join("Fixture_26.0.ipsw");
        write_ipsw(&archive, entries).unwrap();
        Self { dir, cli, archive }
    }

    fn archive_str(&self) -> &str {
        self.archive.to_str().unwrap()
    }

    fn default_out(&self) -> PathBuf {
        self.dir.path().join("Fixture_26.0-export")
    }

    fn picker_app(&self) -> App {
        let mut app = new_app();
        app.set_ipsw_cli(Some(self.cli.clone()));
        app
    }

    fn app(&self) -> App {
        let mut app = self.picker_app();
        app.screen = Screen::Ipsw;
        app
    }

    fn browse(&self) -> App {
        let mut app = self.app();
        app.open_ipsw(self.archive_str());
        app.drain_ipsw_job();
        assert_eq!(
            app.ipsw.phase,
            IpswPhase::Browse,
            "the archive did not open: {:?}",
            app.ipsw.error
        );
        app
    }

    fn cli_calls(&self) -> Vec<String> {
        fs::read_to_string(self.dir.path().join("bin/args.log"))
            .map(|log| log.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }
}

fn new_app() -> App {
    let mut app = App::with_banner_order(BannerOrder::sequential());
    app.glyph_pack = GlyphPack::Instrument;
    app
}

fn press(app: &mut App, code: KeyCode) -> bool {
    let mut event = KeyEvent::new(code, KeyModifiers::NONE);
    event.kind = KeyEventKind::Press;
    app.handle_event(Event::Key(event))
}

fn ch(app: &mut App, c: char) -> bool {
    press(app, KeyCode::Char(c))
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

fn mouse(app: &mut App, kind: MouseEventKind, column: u16, row: u16) -> bool {
    app.handle_event(Event::Mouse(MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }))
}

fn click(app: &mut App, column: u16, row: u16) {
    mouse(app, MouseEventKind::Down(MouseButton::Left), column, row);
}

fn draw(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
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

fn dump_ui(name: &str, text: &str) {
    if let Ok(dir) = std::env::var("APPLE_UTILS_UI_DUMP") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).expect("ui dump folder");
        fs::write(dir.join(name), text).expect("ui dump");
    }
}

fn shot(app: &mut App, name: &str, width: u16, height: u16) -> String {
    let screen = draw(app, width, height);
    dump_ui(name, &screen);
    screen
}

const WIDE: (u16, u16) = (120, 40);

fn view(app: &mut App, name: &str) -> String {
    shot(app, name, WIDE.0, WIDE.1)
}

#[track_caller]
fn assert_has(screen: &str, needle: &str) {
    assert!(
        screen.contains(needle),
        "expected {needle:?} on screen:\n{screen}"
    );
}

#[track_caller]
fn assert_lacks(screen: &str, needle: &str) {
    assert!(
        !screen.contains(needle),
        "did not expect {needle:?} on screen:\n{screen}"
    );
}

fn rect_text(screen: &str, rect: Rect) -> String {
    let line: Vec<char> = screen
        .lines()
        .nth(rect.y as usize)
        .unwrap_or_default()
        .chars()
        .collect();
    line.iter()
        .skip(rect.x as usize)
        .take(rect.width as usize)
        .collect()
}

fn tree_rows(app: &App, screen: &str) -> Vec<String> {
    app.hits
        .ipsw_tree_rows
        .iter()
        .map(|rect| rect_text(screen, *rect))
        .collect()
}

fn option_rows(app: &App, screen: &str) -> Vec<String> {
    app.hits
        .ipsw_option_rows
        .iter()
        .map(|rect| rect_text(screen, *rect))
        .collect()
}

#[track_caller]
fn row_with(rows: &[String], label: &str, screen: &str) -> String {
    rows.iter()
        .find(|row| row.contains(label))
        .cloned()
        .unwrap_or_else(|| panic!("no row contains {label:?}; rows {rows:#?}\n{screen}"))
}

fn mark_char(row: &str) -> char {
    row.chars()
        .find(|c| !c.is_whitespace() && *c != '›')
        .expect("a mark")
}

fn label_col(row: &str, label: &str) -> usize {
    let at = row
        .find(label)
        .unwrap_or_else(|| panic!("{label:?} not in {row:?}"));
    row[..at].chars().count()
}

fn glyph(on: bool) -> &'static str {
    if on { ON } else { OFF }
}

fn select(app: &mut App, names: &[&str]) {
    for name in names {
        ch(app, '/');
        type_text(app, name);
        press(app, KeyCode::Enter);
        ch(app, ' ');
        press(app, KeyCode::Esc);
        assert!(
            app.ipsw.selected.contains(*name),
            "{name} was not selected; selection {:?}",
            app.ipsw.selected
        );
        assert!(app.ipsw.filter.is_empty(), "Esc should clear the filter");
        assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    }
}

fn option_focus(app: &mut App, index: usize) {
    if app.ipsw.pane != IpswPane::Options {
        press(app, KeyCode::Tab);
    }
    assert_eq!(app.ipsw.pane, IpswPane::Options);
    press(app, KeyCode::Home);
    for _ in 0..index {
        press(app, KeyCode::Down);
    }
    assert_eq!(app.ipsw.option_cursor, index);
}

fn toggle_option(app: &mut App, index: usize) {
    option_focus(app, index);
    ch(app, ' ');
}

const OPT_KEEP: usize = 2;
const OPT_PRESERVE: usize = 3;
const OPT_OVERWRITE: usize = 4;
const OPT_KEY: usize = 5;
const OPT_DEVICE: usize = 6;

fn component_option(component: Component) -> usize {
    apple_utils::ipsw_app::FIRST_COMPONENT_OPTION
        + Component::ALL
            .iter()
            .position(|candidate| *candidate == component)
            .unwrap()
}

fn go_to_output(app: &mut App) {
    ch(app, 'e');
    assert_eq!(
        app.ipsw.phase,
        IpswPhase::Output,
        "e did not reach the output step; error {:?}",
        app.ipsw.error
    );
    app.clip.file = None;
    app.clip.raw.clear();
}

fn finish_export(app: &mut App) {
    app.drain_ipsw_job();
    assert_eq!(
        app.ipsw.phase,
        IpswPhase::Done,
        "the export did not finish; error {:?}",
        app.ipsw.error
    );
}

fn export_default(app: &mut App) {
    go_to_output(app);
    press(app, KeyCode::Enter);
    finish_export(app);
}

fn export_to(app: &mut App, output: &Path) {
    go_to_output(app);
    let typed = output.to_str().unwrap();
    type_text(app, typed);
    assert_eq!(app.path_input, typed);
    press(app, KeyCode::Enter);
    finish_export(app);
}

fn report(app: &App) -> ExportReport {
    app.ipsw.report.clone().expect("a finished report")
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

fn list_tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            out.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn sorted(items: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(|item| item.to_string()).collect();
    out.sort();
    out
}

#[track_caller]
fn assert_no_debris(output: &Path) {
    for path in list_tree(output) {
        assert!(
            !path.contains(".apple-utils-export-"),
            "work folder left behind: {path}"
        );
        assert!(!path.ends_with(".part"), "partial file left behind: {path}");
    }
}

#[derive(Debug, Clone)]
struct Proc {
    pgid: i32,
    command: String,
}

fn processes() -> Vec<Proc> {
    let output = Command::new("ps")
        .args(["-axww", "-o", "pid=", "-o", "pgid=", "-o", "command="])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line.split_once(char::is_whitespace)?;
            let _pid: i32 = pid.parse().ok()?;
            let rest = rest.trim_start();
            let (pgid, command) = rest.split_once(char::is_whitespace)?;
            Some(Proc {
                pgid: pgid.parse().ok()?,
                command: command.trim().to_string(),
            })
        })
        .collect()
}

struct Watchdog(Arc<AtomicBool>);

impl Watchdog {
    fn start(label: &'static str, limit: Duration) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&done);
        std::thread::spawn(move || {
            let deadline = Instant::now() + limit;
            while Instant::now() < deadline {
                if seen.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            eprintln!("watchdog: {label} did not finish within {limit:?}");
            std::process::exit(101);
        });
        Self(done)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct Running {
    rig: Rig,
    app: App,
    out: PathBuf,
    groups: Vec<i32>,
}

fn start_slow_export() -> Running {
    let mut entries = sample_entries();
    entries.push(FixtureEntry::file(SLOW, b"AEA1slow-data".to_vec()));
    let rig = Rig::with_entries(&entries);
    let mut app = rig.browse();
    // NOTES sorts before SLOW, so it is fully placed before the slow decrypt starts.
    select(&mut app, &[NOTES, SLOW]);
    go_to_output(&mut app);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.phase, IpswPhase::Exporting);
    assert!(app.ipsw_busy());

    let needle = rig.dir.path().to_string_lossy().into_owned();
    let deadline = Instant::now() + Duration::from_secs(15);
    let groups = loop {
        app.ipsw.poll_job();
        assert_eq!(
            app.ipsw.phase,
            IpswPhase::Exporting,
            "the export ended before the slow tool was seen: {:?}",
            app.ipsw.error
        );
        let mut groups: Vec<i32> = processes()
            .iter()
            .filter(|proc| proc.command.contains(&needle))
            .map(|proc| proc.pgid)
            .collect();
        groups.sort_unstable();
        groups.dedup();
        if !groups.is_empty() {
            break groups;
        }
        assert!(
            Instant::now() < deadline,
            "the fake ipsw never showed up in ps"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    app.ipsw.poll_job();
    let out = rig.default_out();
    Running {
        rig,
        app,
        out,
        groups,
    }
}

fn wait_for_done(app: &mut App, limit: Duration) {
    let deadline = Instant::now() + limit;
    while app.ipsw.phase == IpswPhase::Exporting {
        app.ipsw.poll_job();
        if app.ipsw.phase != IpswPhase::Exporting {
            break;
        }
        assert!(Instant::now() < deadline, "the export did not stop in time");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        app.ipsw.phase,
        IpswPhase::Done,
        "error {:?}",
        app.ipsw.error
    );
}

#[track_caller]
fn assert_clean_after_cancel(rig: &Rig, out: &Path, groups: &[i32]) {
    assert_eq!(
        list_tree(out),
        sorted(&["Firmware", "Firmware/notes.txt"]),
        "only the fully placed file may remain in the output"
    );
    assert_eq!(fs::read(out.join(NOTES)).unwrap(), b"hello");
    assert!(!out.join("slow-image.dmg").exists());
    assert!(!out.join(SLOW).exists());

    let needle = rig.dir.path().to_string_lossy().into_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let survivors: Vec<Proc> = processes()
            .into_iter()
            .filter(|proc| proc.command.contains(&needle) || groups.contains(&proc.pgid))
            .collect();
        if survivors.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "processes outlived the export: {survivors:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn picker_without_cli_has_four_cards_and_digit_five_is_inert() {
    let mut app = new_app();
    assert_eq!(app.available_tools().len(), 4);
    let screen = shot(&mut app, "ipsw_picker_no_cli.txt", 100, 32);
    for name in [
        "Recovery",
        "APFS Explorer",
        "APFS Repair",
        "Asahi Linux tooling",
    ] {
        assert_has(&screen, name);
    }
    assert_lacks(&screen, "IPSW Export");
    let cards = app
        .hits
        .cards
        .iter()
        .filter(|rect| rect.width > 0 && rect.height > 0)
        .count();
    assert_eq!(cards, 4, "{screen}");

    let before = app.selected;
    ch(&mut app, '5');
    assert_eq!(app.screen, Screen::Picker);
    assert_eq!(app.selected, before);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);

    for _ in 0..4 {
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(app.selected, before);
}

#[test]
fn picker_with_cli_shows_the_card_and_digit_five_opens_it() {
    assert_eq!(Tool::ALL.len(), 5);
    assert_eq!(Tool::ALL[4], Tool::Ipsw);
    assert_eq!(Tool::Ipsw.name(), "IPSW Export");

    let rig = Rig::new();
    let mut app = rig.picker_app();
    assert_eq!(app.available_tools().len(), 5);
    let screen = shot(&mut app, "ipsw_picker.txt", 100, 32);
    assert_has(&screen, "IPSW Export");
    assert_has(&screen, "Browse an IPSW");
    let cards = app
        .hits
        .cards
        .iter()
        .filter(|rect| rect.width > 0 && rect.height > 0)
        .count();
    assert_eq!(cards, 5, "{screen}");

    ch(&mut app, '5');
    assert_eq!(app.screen, Screen::Ipsw);
    assert_eq!(app.selected, 4);
    assert_eq!(app.current_tool(), Tool::Ipsw);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.screen, Screen::Picker);
    ch(&mut app, '6');
    assert_eq!(app.screen, Screen::Picker, "there is no sixth card");
}

#[test]
fn arrows_then_enter_reach_ipsw_and_up_wraps_to_it() {
    let rig = Rig::new();

    let mut app = rig.picker_app();
    for _ in 0..4 {
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(app.selected, 4);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Ipsw);

    let mut app = rig.picker_app();
    assert_eq!(app.selected, 0);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.selected, 4);
    assert_eq!(app.current_tool(), Tool::Ipsw);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Ipsw);

    let mut app = rig.picker_app();
    ch(&mut app, 'k');
    assert_eq!(app.selected, 4);
    ch(&mut app, 'j');
    assert_eq!(app.selected, 0);
    ch(&mut app, 'k');
    ch(&mut app, ' ');
    assert_eq!(app.screen, Screen::Ipsw);
}

#[test]
fn mouse_click_on_the_fifth_card_opens_ipsw_and_hover_and_wheel_move_the_selection() {
    let rig = Rig::new();
    let mut app = rig.picker_app();
    let screen = draw(&mut app, 100, 32);
    let cards = app.hits.cards;
    assert!(
        cards.iter().all(|rect| rect.width > 0 && rect.height > 0),
        "{screen}"
    );
    for pair in cards.windows(2) {
        assert!(
            pair[1].y >= pair[0].y + pair[0].height,
            "cards overlap: {pair:?}"
        );
    }
    let fifth = cards[4];

    mouse(
        &mut app,
        MouseEventKind::Moved,
        fifth.x + fifth.width / 2,
        fifth.y + fifth.height / 2,
    );
    assert_eq!(app.selected, 4);
    assert_eq!(app.screen, Screen::Picker);

    app.selected = 0;
    for expected in [1, 2, 3, 4, 0] {
        mouse(&mut app, MouseEventKind::ScrollDown, 1, 1);
        assert_eq!(app.selected, expected);
    }
    mouse(&mut app, MouseEventKind::ScrollUp, 1, 1);
    assert_eq!(app.selected, 4);

    app.selected = 0;
    click(
        &mut app,
        fifth.x + fifth.width / 2,
        fifth.y + fifth.height / 2,
    );
    assert_eq!(app.screen, Screen::Ipsw);
    assert_eq!(app.selected, 4);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
}

#[test]
fn clearing_the_cli_while_on_the_fifth_card_clamps_the_selection() {
    let rig = Rig::new();
    let mut app = rig.picker_app();
    for _ in 0..4 {
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(app.current_tool(), Tool::Ipsw);

    app.set_ipsw_cli(None);
    assert_eq!(
        app.selected, 3,
        "the selection must land on a card that exists"
    );
    assert_eq!(app.current_tool(), Tool::Asahi);
    let screen = draw(&mut app, 100, 32);
    assert_lacks(&screen, "IPSW Export");
    assert_has(&screen, "Asahi Linux tooling");

    app.set_ipsw_cli(Some(rig.cli.clone()));
    assert_eq!(app.selected, 3);

    app.set_ipsw_cli(None);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.screen, Screen::Asahi);

    let mut app = rig.picker_app();
    press(&mut app, KeyCode::Down);
    app.set_ipsw_cli(None);
    assert_eq!(app.selected, 1);
}

#[test]
fn five_cards_all_render_in_an_80_by_18_terminal() {
    let rig = Rig::new();
    let mut app = rig.picker_app();
    let screen = shot(&mut app, "ipsw_picker_80x18.txt", 80, 18);
    for name in [
        "Recovery",
        "APFS Explorer",
        "APFS Repair",
        "Asahi Linux tooling",
        "IPSW Export",
    ] {
        assert_has(&screen, name);
    }
    let cards = app.hits.cards;
    assert!(
        cards
            .iter()
            .all(|rect| rect.width > 0 && rect.height > 0 && rect.y + rect.height <= 18),
        "cards leave the terminal: {cards:?}\n{screen}"
    );
    let fifth = cards[4];
    click(&mut app, fifth.x + 1, fifth.y);
    assert_eq!(app.screen, Screen::Ipsw);
}

#[test]
fn the_header_names_the_ipsw_screen() {
    let rig = Rig::new();
    let mut app = rig.picker_app();
    ch(&mut app, '5');
    let screen = shot(&mut app, "ipsw_path.txt", 100, 32);
    let top = screen.lines().next().unwrap();
    assert!(top.contains("A P P L E"), "{screen}");
    assert!(top.contains("IPSW"), "{screen}");
    assert_has(&screen, "ipsw export");

    let mut app = rig.browse();
    let screen = view(&mut app, "ipsw_header_browse.txt");
    assert!(screen.lines().next().unwrap().contains("IPSW"), "{screen}");
}

#[test]
fn esc_walks_back_through_every_phase() {
    let rig = Rig::new();
    let mut app = rig.picker_app();

    ch(&mut app, '5');
    assert_eq!(
        (app.screen, app.ipsw.phase),
        (Screen::Ipsw, IpswPhase::Path)
    );
    ch(&mut app, '/');
    assert!(app.path_editing);
    press(&mut app, KeyCode::Esc);
    assert!(!app.path_editing);
    assert!(app.path_input.is_empty());
    assert_eq!(app.screen, Screen::Ipsw);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.screen, Screen::Picker);

    ch(&mut app, '5');
    app.open_ipsw(rig.archive_str());
    app.drain_ipsw_job();
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    select(&mut app, &[NOTES]);
    press(&mut app, KeyCode::Esc);
    assert_eq!(
        (app.screen, app.ipsw.phase),
        (Screen::Ipsw, IpswPhase::Path)
    );
    assert!(app.ipsw.selected.is_empty());
    assert!(app.ipsw.tree.is_none());

    app.open_ipsw(rig.archive_str());
    app.drain_ipsw_job();
    select(&mut app, &[NOTES]);
    go_to_output(&mut app);
    let screen = view(&mut app, "ipsw_output.txt");
    assert_has(&screen, "destination");
    assert_has(&screen, "Fixture_26.0-export");
    assert_has(&screen, "a folder that does not exist yet is created");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert_eq!(app.ipsw.selected.len(), 1);
    assert!(app.ipsw.selected.contains(NOTES));
    assert!(app.ipsw.error.is_none());

    export_default(&mut app);
    let screen = view(&mut app, "ipsw_done_notes.txt");
    assert_has(&screen, "Export finished");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert!(app.ipsw.report.is_none());
    assert!(app.ipsw.selected.contains(NOTES));

    export_default(&mut app);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert!(app.ipsw.selected.contains(NOTES));

    export_default(&mut app);
    ch(&mut app, 'n');
    assert_eq!(
        (app.screen, app.ipsw.phase),
        (Screen::Ipsw, IpswPhase::Path)
    );
    assert!(app.ipsw.selected.is_empty());
    assert!(app.ipsw.report.is_none());
    assert!(app.ipsw.tree.is_none());

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.screen, Screen::Picker);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
}

#[test]
fn typing_the_archive_path_opens_it_and_bad_paths_are_refused() {
    let rig = Rig::new();
    let mut app = rig.picker_app();
    ch(&mut app, '5');

    type_text(&mut app, rig.archive_str());
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.phase, IpswPhase::Loading);
    let screen = view(&mut app, "ipsw_loading.txt");
    assert_has(&screen, "opening");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    assert!(!app.ipsw_busy());
    assert!(app.ipsw.archive.is_none());

    type_text(&mut app, rig.archive_str());
    press(&mut app, KeyCode::Enter);
    app.drain_ipsw_job();
    assert_eq!(app.ipsw.phase, IpswPhase::Browse, "{:?}", app.ipsw.error);
    assert_eq!(
        fs::canonicalize(app.ipsw.archive.as_ref().unwrap()).unwrap(),
        fs::canonicalize(&rig.archive).unwrap()
    );

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    type_text(&mut app, rig.dir.path().to_str().unwrap());
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    assert_eq!(
        app.ipsw.error.as_deref(),
        Some("choose an IPSW file, not a folder")
    );
    let screen = view(&mut app, "ipsw_path_folder_error.txt");
    assert_has(&screen, "choose an IPSW file, not a folder");

    press(&mut app, KeyCode::Esc);
    let junk = rig.dir.path().join("junk.ipsw");
    fs::write(&junk, b"this is not a zip archive").unwrap();
    type_text(&mut app, junk.to_str().unwrap());
    press(&mut app, KeyCode::Enter);
    app.drain_ipsw_job();
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    assert!(app.ipsw.tree.is_none());
    assert!(
        app.ipsw.error.as_deref().is_some_and(|e| !e.is_empty()),
        "an unreadable archive must report an error"
    );
}

#[test]
fn browse_header_shows_version_build_devices_and_entry_count() {
    let rig = Rig::new();
    let mut app = rig.browse();
    let screen = view(&mut app, "ipsw_browse.txt");
    assert_has(&screen, "Fixture_26.0.ipsw");
    assert_has(&screen, "26.0 (25A1)");
    assert_has(
        &screen,
        &format!("{}, {}", FIXTURE_DEVICES[0], FIXTURE_DEVICES[1]),
    );
    assert_has(&screen, "0 files");
    assert_has(&screen, "0 components");
    assert_has(&screen, "archive  11");

    let plain = Rig::with_entries(&[FixtureEntry::file("a/b.txt", b"hi".to_vec())]);
    let mut app = plain.browse();
    assert!(app.ipsw.info.is_none());
    let screen = view(&mut app, "ipsw_browse_no_manifest.txt");
    assert_has(&screen, "no BuildManifest.plist");
    assert_has(&screen, "devices unknown");
    option_focus(&mut app, OPT_DEVICE);
    press(&mut app, KeyCode::Right);
    assert_eq!(app.ipsw.device, None);
    let screen = view(&mut app, "ipsw_browse_no_manifest_device.txt");
    assert_has(&screen, "< all >");
}

#[test]
fn folders_expand_and_collapse_with_right_left_and_enter_and_children_are_indented() {
    let rig = Rig::new();
    let mut app = rig.browse();

    let screen = view(&mut app, "ipsw_tree_collapsed.txt");
    let rows = tree_rows(&app, &screen);
    assert_eq!(
        rows.len(),
        6,
        "Firmware plus five top-level files\n{screen}"
    );
    assert_has(&row_with(&rows, "Firmware/", &screen), "▸ Firmware/");
    let top_col = label_col(&row_with(&rows, "Firmware/", &screen), "Firmware/");

    press(&mut app, KeyCode::Right);
    assert!(app.ipsw.expanded.contains("Firmware"));
    let screen = view(&mut app, "ipsw_tree_expanded.txt");
    let rows = tree_rows(&app, &screen);
    assert_has(&row_with(&rows, "Firmware/", &screen), "▾ Firmware/");
    let firmware_col = label_col(&row_with(&rows, "Firmware/", &screen), "Firmware/");
    assert_eq!(firmware_col, top_col);
    for folder in ["all_flash/", "dfu/", "Manifests/"] {
        let row = row_with(&rows, folder, &screen);
        assert_eq!(
            label_col(&row, folder),
            firmware_col + 2,
            "{folder} is one level in\n{screen}"
        );
    }
    for file in ["latest", "notes.txt"] {
        let row = row_with(&rows, file, &screen);
        assert_eq!(
            label_col(&row, file),
            firmware_col + 2,
            "{file} is one level in\n{screen}"
        );
    }
    let top_file = row_with(&rows, "Restore.plist", &screen);
    assert_eq!(label_col(&top_file, "Restore.plist"), firmware_col);

    press(&mut app, KeyCode::Right);
    assert_eq!(app.ipsw.cursor, 1);
    press(&mut app, KeyCode::Right);
    assert!(app.ipsw.expanded.contains("Firmware/all_flash"));
    let screen = view(&mut app, "ipsw_tree_expanded_deep.txt");
    let rows = tree_rows(&app, &screen);
    let deep = row_with(&rows, "iBoot.j414c.RELEASE.im4p", &screen);
    assert_eq!(
        label_col(&deep, "iBoot.j414c.RELEASE.im4p"),
        firmware_col + 4
    );

    press(&mut app, KeyCode::Left);
    assert!(!app.ipsw.expanded.contains("Firmware/all_flash"));
    assert_eq!(app.ipsw.cursor, 1);
    press(&mut app, KeyCode::Left);
    assert_eq!(app.ipsw.cursor, 0);
    press(&mut app, KeyCode::Left);
    assert!(!app.ipsw.expanded.contains("Firmware"));
    let screen = view(&mut app, "ipsw_tree_recollapsed.txt");
    assert_lacks(&screen, "notes.txt");
    assert_eq!(tree_rows(&app, &screen).len(), 6);

    press(&mut app, KeyCode::Enter);
    assert!(app.ipsw.expanded.contains("Firmware"));
    press(&mut app, KeyCode::Enter);
    assert!(!app.ipsw.expanded.contains("Firmware"));
    assert!(app.ipsw.selected.is_empty());
}

#[test]
fn tags_and_sizes_are_drawn_on_each_row() {
    let rig = Rig::new();
    let mut app = rig.browse();
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Right);
    let screen = view(&mut app, "ipsw_tags.txt");
    let rows = tree_rows(&app, &screen);
    let tokens = |label: &str| -> Vec<String> {
        row_with(&rows, label, &screen)
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    let has = |tokens: &[String], want: &[&str]| {
        tokens.windows(want.len()).any(|window| {
            window
                .iter()
                .zip(want)
                .all(|(have, want)| have.as_str() == *want)
        })
    };

    let aea = tokens(AEA);
    assert!(aea.contains(&"aea".to_string()), "{aea:?}\n{screen}");
    assert!(has(&aea, &["22", "B"]), "{aea:?}\n{screen}");

    let iboot = tokens("iBoot.j414c.RELEASE.im4p");
    assert!(iboot.contains(&"im4p".to_string()), "{iboot:?}\n{screen}");
    assert!(has(&iboot, &["25", "B"]), "{iboot:?}\n{screen}");

    let kernel = tokens(KERNEL);
    assert!(kernel.contains(&"im4p".to_string()), "{kernel:?}\n{screen}");
    assert!(has(&kernel, &["26", "B"]), "{kernel:?}\n{screen}");

    let dmg = tokens("090-12345-002.dmg");
    assert!(has(&dmg, &["9", "B"]), "{dmg:?}");
    assert!(
        !dmg.iter()
            .any(|t| ["aea", "im4p", "link"].contains(&t.as_str())),
        "{dmg:?}"
    );

    app.ipsw.expanded.insert("Firmware".into());
    let screen = view(&mut app, "ipsw_tags_links.txt");
    let rows = tree_rows(&app, &screen);
    let latest: Vec<String> = row_with(&rows, "latest", &screen)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(latest.contains(&"link".to_string()), "{latest:?}");
    assert!(
        has(&latest, &["9", "B"]),
        "the link is 9 bytes long: {latest:?}"
    );
    let notes: Vec<String> = row_with(&rows, "notes.txt", &screen)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(has(&notes, &["5", "B"]), "{notes:?}");
    assert!(
        !notes
            .iter()
            .any(|t| ["aea", "im4p", "link"].contains(&t.as_str())),
        "{notes:?}"
    );
}

#[test]
fn sizes_scale_through_kb_and_mb_and_folders_sum_their_files() {
    let rig = Rig::with_entries(&[
        FixtureEntry::file("d/x.bin", vec![1u8; 2048]),
        FixtureEntry::file("d/y.bin", vec![2u8; 1024]),
        FixtureEntry::file("big.bin", vec![3u8; 3000]),
        FixtureEntry::file("mid.bin", vec![4u8; 5 * 1024 * 1024]),
        FixtureEntry::file("tiny.bin", vec![5u8; 7]),
    ]);
    let mut app = rig.browse();
    let screen = view(&mut app, "ipsw_sizes.txt");
    let rows = tree_rows(&app, &screen);
    assert_has(&row_with(&rows, "d/", &screen), "3.0 KB");
    assert_has(&row_with(&rows, "big.bin", &screen), "2.9 KB");
    assert_has(&row_with(&rows, "mid.bin", &screen), "5.0 MB");
    assert_has(&row_with(&rows, "tiny.bin", &screen), "7 B");

    select(&mut app, &["big.bin", "tiny.bin"]);
    let screen = view(&mut app, "ipsw_sizes_selected.txt");
    assert_has(&screen, "2 files · 2.9 KB selected, 0 components");
}

#[test]
fn marks_go_none_partial_full_as_files_are_selected_inside_a_folder() {
    let rig = Rig::new();
    let mut app = rig.browse();
    press(&mut app, KeyCode::Right);

    let marks = |app: &mut App, name: &str| -> Vec<(String, char)> {
        let screen = view(app, name);
        let rows = tree_rows(app, &screen);
        [
            "Firmware/",
            "all_flash/",
            "dfu/",
            "Manifests/",
            "latest",
            "notes.txt",
            "Restore.plist",
        ]
        .iter()
        .map(|label| {
            (
                label.to_string(),
                mark_char(&row_with(&rows, label, &screen)),
            )
        })
        .collect()
    };
    let mark_of = |marks: &[(String, char)], label: &str| -> String {
        marks
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, mark)| mark.to_string())
            .unwrap()
    };

    let none = marks(&mut app, "ipsw_marks_none.txt");
    for (label, mark) in &none {
        assert_eq!(mark.to_string(), OFF, "{label} starts unmarked");
    }

    let notes_row = app
        .ipsw
        .rows()
        .iter()
        .position(|r| r.name == NOTES)
        .unwrap();
    for _ in 0..notes_row {
        press(&mut app, KeyCode::Down);
    }
    ch(&mut app, ' ');
    let partial = marks(&mut app, "ipsw_marks_partial.txt");
    assert_eq!(mark_of(&partial, "Firmware/"), HALF);
    assert_eq!(mark_of(&partial, "notes.txt"), ON);
    assert_eq!(mark_of(&partial, "latest"), OFF);
    assert_eq!(mark_of(&partial, "all_flash/"), OFF);
    assert_eq!(mark_of(&partial, "Restore.plist"), OFF);
    assert_eq!(app.ipsw.rows()[0].mark, Mark::Partial);

    press(&mut app, KeyCode::Home);
    ch(&mut app, ' ');
    let full = marks(&mut app, "ipsw_marks_full.txt");
    for label in [
        "Firmware/",
        "all_flash/",
        "dfu/",
        "Manifests/",
        "latest",
        "notes.txt",
    ] {
        assert_eq!(
            mark_of(&full, label),
            ON,
            "{label} after selecting the folder"
        );
    }
    assert_eq!(mark_of(&full, "Restore.plist"), OFF, "outside the folder");
    assert_eq!(app.ipsw.rows()[0].mark, Mark::Full);

    ch(&mut app, ' ');
    let cleared = marks(&mut app, "ipsw_marks_cleared.txt");
    for (label, mark) in &cleared {
        assert_eq!(mark.to_string(), OFF, "{label} after clearing");
    }
    assert!(app.ipsw.selected.is_empty());

    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Down);
    ch(&mut app, ' ');
    let one = marks(&mut app, "ipsw_marks_nested_one.txt");
    assert_eq!(mark_of(&one, "all_flash/"), HALF);
    assert_eq!(mark_of(&one, "Firmware/"), HALF);
    press(&mut app, KeyCode::Down);
    ch(&mut app, ' ');
    let both = marks(&mut app, "ipsw_marks_nested_both.txt");
    assert_eq!(mark_of(&both, "all_flash/"), ON);
    assert_eq!(mark_of(&both, "Firmware/"), HALF);
    assert_eq!(app.ipsw.selected.len(), 2);
    assert!(app.ipsw.selected.contains(IBOOT) && app.ipsw.selected.contains(LLB));
}

#[test]
fn filter_narrows_to_a_flat_list_and_esc_clears_it() {
    let rig = Rig::new();
    let mut app = rig.browse();

    ch(&mut app, '/');
    assert!(app.ipsw.filter_editing);
    let screen = view(&mut app, "ipsw_filter_empty.txt");
    assert_has(&screen, "type to filter");
    type_text(&mut app, "IM4P");
    assert_eq!(app.ipsw.filter, "IM4P");
    assert_eq!(
        app.ipsw.phase,
        IpswPhase::Browse,
        "typed letters are filter text"
    );

    let screen = view(&mut app, "ipsw_filter_editing.txt");
    assert_has(&screen, "matches  3");
    assert_has(&screen, "filter");
    let rows = tree_rows(&app, &screen);
    assert_eq!(rows.len(), 3, "{screen}");
    let expected = [
        "Firmware/all_flash/LLB.j414c.RELEASE.im4p",
        "Firmware/all_flash/iBoot.j414c.RELEASE.im4p",
        "Firmware/dfu/iBEC.j414c.RELEASE.im4p",
    ];
    let mut cols = Vec::new();
    for name in expected {
        let row = row_with(&rows, name, &screen);
        cols.push(label_col(&row, name));
        assert_has(&row, "im4p");
    }
    assert!(
        cols.windows(2).all(|pair| pair[0] == pair[1]),
        "flat list: {cols:?}"
    );
    assert!(
        app.ipsw
            .rows()
            .iter()
            .all(|row| row.depth == 0 && !row.is_dir)
    );
    assert_lacks(&screen, "Restore.plist");

    press(&mut app, KeyCode::Enter);
    assert!(!app.ipsw.filter_editing);
    assert_eq!(app.ipsw.filter, "IM4P");
    let screen = view(&mut app, "ipsw_filter_applied.txt");
    assert_lacks(&screen, "type to filter");
    assert_has(&screen, "matches  3");

    ch(&mut app, 'a');
    let want: std::collections::BTreeSet<String> = expected.iter().map(|n| n.to_string()).collect();
    assert_eq!(app.ipsw.selected, want);

    press(&mut app, KeyCode::Esc);
    assert!(app.ipsw.filter.is_empty());
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert_eq!(app.ipsw.selected, want);
    let screen = view(&mut app, "ipsw_filter_cleared.txt");
    assert_has(&screen, "archive  11");
    let rows = tree_rows(&app, &screen);
    assert_eq!(rows.len(), 6);
    assert_has(&row_with(&rows, "Firmware/", &screen), HALF);

    ch(&mut app, '/');
    type_text(&mut app, "notes");
    press(&mut app, KeyCode::Esc);
    assert!(!app.ipsw.filter_editing);
    assert_eq!(app.ipsw.filter, "notes");
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    press(&mut app, KeyCode::Esc);
    assert!(app.ipsw.filter.is_empty());

    app.ipsw.selected.clear();
    ch(&mut app, '/');
    type_text(&mut app, "zzzz");
    press(&mut app, KeyCode::Enter);
    let screen = view(&mut app, "ipsw_filter_none.txt");
    assert_has(&screen, "no entries match the filter");
    assert_has(&screen, "matches  0");
    ch(&mut app, ' ');
    ch(&mut app, 'a');
    assert!(app.ipsw.selected.is_empty());
    press(&mut app, KeyCode::Esc);
    assert!(app.ipsw.filter.is_empty());
}

#[test]
fn space_on_a_folder_selects_everything_below_and_a_toggles_all() {
    let rig = Rig::new();
    let mut app = rig.browse();

    ch(&mut app, ' ');
    let firmware: std::collections::BTreeSet<String> = [
        "Firmware/Manifests/restore/info.plist",
        "Firmware/all_flash/LLB.j414c.RELEASE.im4p",
        "Firmware/all_flash/iBoot.j414c.RELEASE.im4p",
        "Firmware/dfu/iBEC.j414c.RELEASE.im4p",
        "Firmware/latest",
        "Firmware/notes.txt",
    ]
    .iter()
    .map(|n| n.to_string())
    .collect();
    assert_eq!(app.ipsw.selected, firmware);
    let screen = view(&mut app, "ipsw_select_folder.txt");
    assert_has(&screen, "6 files ·");

    ch(&mut app, 'a');
    let everything: std::collections::BTreeSet<String> =
        ALL_ENTRIES.iter().map(|n| n.to_string()).collect();
    assert_eq!(app.ipsw.selected, everything);
    let screen = view(&mut app, "ipsw_select_all.txt");
    assert_has(&screen, "11 files ·");

    ch(&mut app, 'a');
    assert!(app.ipsw.selected.is_empty());
    let screen = view(&mut app, "ipsw_select_none.txt");
    assert_has(&screen, "0 files ·");
}

#[test]
fn every_toggle_flips_from_the_keyboard_and_the_render_follows() {
    let rig = Rig::new();
    let mut app = rig.browse();
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.ipsw.pane, IpswPane::Options);
    let screen = view(&mut app, "ipsw_options.txt");
    let rows = option_rows(&app, &screen);
    assert_eq!(
        rows.len(),
        OPTION_COUNT,
        "every option is on screen\n{screen}"
    );
    assert_has(&screen, "Components (ipsw extract)");

    let labels = [
        "Decrypt .aea images",
        "Decompress IM4P payloads",
        "Keep originals too",
        "Keep folder structure",
        "Overwrite existing",
    ];
    let getters: [fn(&ExportOptions) -> bool; 5] = [
        |o| o.decrypt_aea,
        |o| o.decompress_im4p,
        |o| o.keep_originals,
        |o| o.preserve_paths,
        |o| o.overwrite,
    ];
    let defaults = [true, true, false, true, false];
    for (index, label) in labels.iter().enumerate() {
        assert!(
            rows[index].contains(label),
            "row {index}: {:?}",
            rows[index]
        );
        assert_eq!(getters[index](&app.ipsw.options), defaults[index]);
        assert_has(&rows[index], &format!("{} {label}", glyph(defaults[index])));
    }
    assert_has(&rows[OPT_KEY], "AEA key");
    assert_has(&rows[OPT_KEY], "fetch from Apple");
    assert_has(&rows[OPT_DEVICE], "Device");
    assert_has(&rows[OPT_DEVICE], "< all >");

    for flipped in 0..labels.len() {
        option_focus(&mut app, flipped);
        press(
            &mut app,
            if flipped % 2 == 0 {
                KeyCode::Char(' ')
            } else {
                KeyCode::Enter
            },
        );
        let screen = view(&mut app, &format!("ipsw_options_flip_{flipped}.txt"));
        let rows = option_rows(&app, &screen);
        for index in 0..labels.len() {
            let want = if index <= flipped {
                !defaults[index]
            } else {
                defaults[index]
            };
            assert_eq!(
                getters[index](&app.ipsw.options),
                want,
                "option {index} after flipping up to {flipped}"
            );
            assert_has(&rows[index], &format!("{} {}", glyph(want), labels[index]));
        }
    }

    for index in 0..labels.len() {
        toggle_option(&mut app, index);
        assert_eq!(getters[index](&app.ipsw.options), defaults[index]);
    }
    let screen = view(&mut app, "ipsw_options_restored.txt");
    let rows = option_rows(&app, &screen);
    for (index, label) in labels.iter().enumerate() {
        assert_has(&rows[index], &format!("{} {label}", glyph(defaults[index])));
    }

    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.ipsw.option_cursor, 0);
    press(&mut app, KeyCode::End);
    assert_eq!(app.ipsw.option_cursor, OPTION_COUNT - 1);
    press(&mut app, KeyCode::Down);
    assert_eq!(app.ipsw.option_cursor, OPTION_COUNT - 1);
    press(&mut app, KeyCode::PageUp);
    assert_eq!(app.ipsw.option_cursor, OPTION_COUNT - 6);
}

#[test]
fn the_aea_key_is_masked_except_for_the_last_four_characters() {
    let rig = Rig::new();
    let mut app = rig.browse();
    option_focus(&mut app, OPT_KEY);
    press(&mut app, KeyCode::Enter);
    assert!(app.ipsw.aea_editing);

    let quit = type_keys(&mut app, "qe/+x AAAA");
    assert!(!quit, "q while editing a key must not quit");
    assert_eq!(app.ipsw.options.aea_key.as_deref(), Some("qe/+xAAAA"));
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert!(app.ipsw.filter.is_empty() && !app.ipsw.filter_editing);

    type_text(&mut app, "bbbb1234");
    let full_key = "qe/+xAAAAbbbb1234";
    assert_eq!(app.ipsw.options.aea_key.as_deref(), Some(full_key));
    let masked = format!("{}1234", "•".repeat(full_key.len() - 4));

    let screen = view(&mut app, "ipsw_key_editing.txt");
    let row = row_with(&option_rows(&app, &screen), "AEA key", &screen);
    assert_has(&row, &masked);
    assert_has(&row, "_");
    assert_lacks(&screen, "qe/+x");
    assert_lacks(&screen, "AAAAbbbb");
    assert_lacks(&screen, full_key);

    press(&mut app, KeyCode::Backspace);
    assert_eq!(
        app.ipsw.options.aea_key.as_deref(),
        Some("qe/+xAAAAbbbb123")
    );
    let screen = view(&mut app, "ipsw_key_backspace.txt");
    let row = row_with(&option_rows(&app, &screen), "AEA key", &screen);
    assert_has(&row, &format!("{}b123", "•".repeat(12)));
    type_text(&mut app, "4");

    press(&mut app, KeyCode::Enter);
    assert!(!app.ipsw.aea_editing);
    assert_eq!(app.ipsw.options.aea_key.as_deref(), Some(full_key));
    let screen = view(&mut app, "ipsw_key_masked.txt");
    let row = row_with(&option_rows(&app, &screen), "AEA key", &screen);
    assert_has(&row, &masked);
    assert_lacks(&row, "_");
    assert_lacks(&screen, "qe/+x");

    press(&mut app, KeyCode::Enter);
    assert!(app.ipsw.aea_editing);
    press(&mut app, KeyCode::Esc);
    assert!(!app.ipsw.aea_editing);
    assert_eq!(app.screen, Screen::Ipsw);
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert_eq!(app.ipsw.options.aea_key.as_deref(), Some(full_key));
    assert!(
        ch(&mut app, 'q'),
        "q quits again once the key field is closed"
    );

    press(&mut app, KeyCode::Enter);
    for _ in 0..full_key.len() {
        press(&mut app, KeyCode::Backspace);
    }
    assert_eq!(app.ipsw.options.aea_key, None);
    press(&mut app, KeyCode::Esc);
    let screen = view(&mut app, "ipsw_key_cleared.txt");
    assert_has(&screen, "fetch from Apple");
}

fn type_keys(app: &mut App, text: &str) -> bool {
    let mut quit = false;
    for c in text.chars() {
        quit |= press(app, KeyCode::Char(c));
    }
    quit
}

#[test]
fn the_device_cycles_through_the_fixture_devices() {
    let rig = Rig::new();
    let mut app = rig.browse();
    option_focus(&mut app, OPT_DEVICE);
    let device_row = |app: &mut App, name: &str| -> String {
        let screen = view(app, name);
        row_with(&option_rows(app, &screen), "Device", &screen)
    };
    assert_has(&device_row(&mut app, "ipsw_device_all.txt"), "< all >");

    press(&mut app, KeyCode::Right);
    assert_eq!(app.ipsw.device.as_deref(), Some(FIXTURE_DEVICES[0]));
    assert_has(
        &device_row(&mut app, "ipsw_device_first.txt"),
        &format!("< {} >", FIXTURE_DEVICES[0]),
    );
    press(&mut app, KeyCode::Right);
    assert_eq!(app.ipsw.device.as_deref(), Some(FIXTURE_DEVICES[1]));
    assert_has(
        &device_row(&mut app, "ipsw_device_second.txt"),
        &format!("< {} >", FIXTURE_DEVICES[1]),
    );
    press(&mut app, KeyCode::Right);
    assert_eq!(
        app.ipsw.device, None,
        "after the last device comes 'all' again"
    );
    assert_has(&device_row(&mut app, "ipsw_device_wrapped.txt"), "< all >");
    press(&mut app, KeyCode::Left);
    assert_eq!(app.ipsw.device.as_deref(), Some(FIXTURE_DEVICES[1]));
    ch(&mut app, 'h');
    assert_eq!(app.ipsw.device.as_deref(), Some(FIXTURE_DEVICES[0]));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.device.as_deref(), Some(FIXTURE_DEVICES[1]));
    ch(&mut app, ' ');
    assert_eq!(app.ipsw.device, None);
    option_focus(&mut app, 0);
    press(&mut app, KeyCode::Right);
    assert_eq!(app.ipsw.device, None);
}

#[test]
fn components_toggle_in_the_options_pane() {
    let rig = Rig::new();
    let mut app = rig.browse();
    option_focus(&mut app, component_option(Component::Kernel));

    let component_row = |app: &mut App, name: &str, label: &str| -> String {
        let screen = view(app, name);
        row_with(&option_rows(app, &screen), label, &screen)
    };
    assert_has(
        &component_row(&mut app, "ipsw_component_off.txt", "Kernelcache"),
        &format!("{OFF} Kernelcache"),
    );

    ch(&mut app, ' ');
    assert!(app.ipsw.components.contains(&Component::Kernel));
    assert_eq!(app.ipsw.components.len(), 1);
    assert_has(
        &component_row(&mut app, "ipsw_component_on.txt", "Kernelcache"),
        &format!("{ON} Kernelcache"),
    );
    let screen = view(&mut app, "ipsw_component_summary.txt");
    assert_has(&screen, "0 files · 0 B selected, 1 component");

    toggle_option(&mut app, component_option(Component::DeviceTree));
    toggle_option(&mut app, component_option(Component::Keybags));
    let expected: std::collections::BTreeSet<Component> =
        [Component::Kernel, Component::DeviceTree, Component::Keybags].into();
    assert_eq!(app.ipsw.components, expected);
    assert_has(
        &component_row(&mut app, "ipsw_component_three.txt", "DeviceTree"),
        &format!("{ON} DeviceTree"),
    );
    assert_has(
        &component_row(&mut app, "ipsw_component_keybags.txt", "IM4P keybags"),
        &format!("{ON} IM4P keybags"),
    );
    let screen = view(&mut app, "ipsw_component_summary3.txt");
    assert_has(&screen, "3 components");

    toggle_option(&mut app, component_option(Component::Kernel));
    assert!(!app.ipsw.components.contains(&Component::Kernel));
    assert_has(
        &component_row(&mut app, "ipsw_component_kernel_off.txt", "Kernelcache"),
        &format!("{OFF} Kernelcache"),
    );
}

#[test]
fn mouse_clicks_move_then_activate_rows_and_toggle_options() {
    let rig = Rig::new();
    let mut app = rig.browse();
    let screen = view(&mut app, "ipsw_mouse.txt");
    let rects = app.hits.ipsw_tree_rows.clone();
    assert_eq!(rects.len(), 6, "{screen}");
    assert_eq!(app.ipsw.cursor, 0);

    let second = rects[2];
    click(&mut app, second.x + 4, second.y);
    assert_eq!(app.ipsw.cursor, 2);
    assert!(app.ipsw.selected.is_empty());

    click(&mut app, second.x + 4, second.y);
    let name = app.ipsw.rows()[2].name.clone();
    assert_eq!(name, "090-12345-002.dmg");
    assert!(app.ipsw.selected.contains(&name));
    click(&mut app, second.x + 4, second.y);
    assert!(
        app.ipsw.selected.is_empty(),
        "a third click deselects again"
    );

    let first = rects[0];
    click(&mut app, first.x + 4, first.y);
    assert_eq!(app.ipsw.cursor, 0);
    assert!(!app.ipsw.expanded.contains("Firmware"));
    click(&mut app, first.x + 4, first.y);
    assert!(app.ipsw.expanded.contains("Firmware"));

    let screen = view(&mut app, "ipsw_mouse_options.txt");
    let rows = option_rows(&app, &screen);
    let keep = rows
        .iter()
        .position(|row| row.contains("Keep originals too"))
        .unwrap();
    let rect = app.hits.ipsw_option_rows[keep];
    click(&mut app, rect.x + 3, rect.y);
    assert!(app.ipsw.options.keep_originals);
    assert_eq!(app.ipsw.pane, IpswPane::Options);
    assert_eq!(app.ipsw.option_cursor, OPT_KEEP);
    click(&mut app, rect.x + 3, rect.y);
    assert!(!app.ipsw.options.keep_originals);

    let tree_rect = app.hits.ipsw_tree_rows[0];
    app.ipsw.cursor = 0;
    mouse(
        &mut app,
        MouseEventKind::ScrollDown,
        tree_rect.x + 2,
        tree_rect.y,
    );
    assert_eq!(app.ipsw.cursor, 1);
    mouse(
        &mut app,
        MouseEventKind::ScrollUp,
        tree_rect.x + 2,
        tree_rect.y,
    );
    assert_eq!(app.ipsw.cursor, 0);
    mouse(&mut app, MouseEventKind::ScrollDown, rect.x + 2, rect.y);
    assert_eq!(app.ipsw.option_cursor, OPT_KEEP + 1);

    let before = (
        app.ipsw.cursor,
        app.ipsw.selected.clone(),
        app.ipsw.options.clone(),
    );
    click(&mut app, 3, 0);
    assert_eq!(
        before,
        (
            app.ipsw.cursor,
            app.ipsw.selected.clone(),
            app.ipsw.options.clone()
        )
    );
}

#[test]
fn export_with_nothing_selected_shows_the_error_and_stays_in_browse() {
    let rig = Rig::new();
    let mut app = rig.browse();
    ch(&mut app, 'e');
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert_eq!(
        app.ipsw.error.as_deref(),
        Some("select files or components first")
    );
    let screen = view(&mut app, "ipsw_error_nothing_selected.txt");
    assert_has(&screen, "select files or components first");

    press(&mut app, KeyCode::Down);
    assert!(app.ipsw.error.is_none());
    let screen = view(&mut app, "ipsw_error_cleared.txt");
    assert_lacks(&screen, "select files or components first");
    ch(&mut app, ' ');
    ch(&mut app, 'e');
    assert_eq!(app.ipsw.phase, IpswPhase::Output);

    let mut app = rig.browse();
    toggle_option(&mut app, component_option(Component::Kernel));
    ch(&mut app, 'e');
    assert_eq!(app.ipsw.phase, IpswPhase::Output);
}

#[test]
fn flattening_a_name_clash_blocks_the_export_with_a_message() {
    let rig = Rig::with_entries(&[
        FixtureEntry::file("a/x.bin", b"1".to_vec()),
        FixtureEntry::file("b/x.bin", b"2".to_vec()),
        FixtureEntry::file("c/y.bin", b"3".to_vec()),
    ]);
    let mut app = rig.browse();
    toggle_option(&mut app, OPT_PRESERVE);
    assert!(!app.ipsw.options.preserve_paths);
    press(&mut app, KeyCode::Tab);
    ch(&mut app, 'a');
    assert_eq!(app.ipsw.selected.len(), 3);
    ch(&mut app, 'e');
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    let message = app.ipsw.error.clone().expect("a clash message");
    assert!(message.contains("x.bin"), "{message}");
    assert!(!message.contains("y.bin"), "{message}");
    let screen = view(&mut app, "ipsw_error_clash.txt");
    assert_has(&screen, "same place");
    assert_has(&screen, "x.bin");

    toggle_option(&mut app, OPT_PRESERVE);
    ch(&mut app, 'e');
    assert_eq!(app.ipsw.phase, IpswPhase::Output);
}

#[test]
fn x_clears_files_and_components() {
    let rig = Rig::new();
    let mut app = rig.browse();
    select(&mut app, &[NOTES, AEA]);
    toggle_option(&mut app, component_option(Component::Kernel));
    assert_eq!(app.ipsw.selected.len(), 2);
    assert_eq!(app.ipsw.components.len(), 1);
    ch(&mut app, 'x');
    assert!(app.ipsw.selected.is_empty());
    assert!(app.ipsw.components.is_empty());
    let screen = view(&mut app, "ipsw_cleared.txt");
    assert_has(&screen, "0 files");
    assert_has(&screen, "0 components");
}

#[test]
fn full_export_with_defaults_decrypts_decompresses_and_recreates_the_link() {
    let rig = Rig::new();
    let mut app = rig.browse();
    select(&mut app, &[AEA, KERNEL, IBOOT, NOTES, LATEST]);
    assert_eq!(app.ipsw.selected.len(), 5);

    go_to_output(&mut app);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.phase, IpswPhase::Exporting);
    let screen = view(&mut app, "ipsw_exporting_start.txt");
    assert_has(&screen, "exporting");
    finish_export(&mut app);

    let out = rig.default_out();
    assert_eq!(app.ipsw.output.as_deref(), Some(out.as_path()));

    assert_eq!(
        fs::read(out.join("090-12345-001.dmg")).unwrap(),
        b"PLAIN-SYSTEM-IMAGE"
    );
    assert!(!out.join(AEA).exists());
    assert_eq!(fs::read(out.join(KERNEL)).unwrap(), b"KERNEL-PAYLOAD");
    assert_eq!(
        fs::read(out.join("Firmware/all_flash/iBoot.j414c.RELEASE")).unwrap(),
        b"IBOOT-PAYLOAD"
    );
    assert!(!out.join(IBOOT).exists());
    assert_eq!(fs::read(out.join(NOTES)).unwrap(), b"hello");
    assert_eq!(
        fs::read_link(out.join(LATEST)).unwrap(),
        Path::new("notes.txt")
    );
    assert_eq!(fs::read(out.join(LATEST)).unwrap(), b"hello");

    assert_eq!(
        list_tree(&out),
        sorted(&[
            "090-12345-001.dmg",
            "Firmware",
            "Firmware/all_flash",
            "Firmware/all_flash/iBoot.j414c.RELEASE",
            "Firmware/latest",
            "Firmware/notes.txt",
            "kernelcache.release.mac14j",
        ])
    );
    assert_no_debris(&out);
    assert_eq!(
        list_tree(rig.dir.path())
            .into_iter()
            .filter(|path| !path.contains('/'))
            .collect::<Vec<_>>(),
        sorted(&["Fixture_26.0-export", "Fixture_26.0.ipsw", "bin"])
    );

    let calls = rig.cli_calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(calls.iter().filter(|c| c.contains("fw aea")).count(), 1);
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.contains("img4 im4p extract"))
            .count(),
        2
    );
    assert!(
        calls
            .iter()
            .all(|call| !call.split_whitespace().any(|token| token == "-b")),
        "no key was set: {calls:?}"
    );

    let report = report(&app);
    assert!(!report.cancelled);
    let counts = report.counts();
    assert_eq!(
        (
            counts.decrypted,
            counts.decompressed,
            counts.written,
            counts.linked
        ),
        (1, 2, 1, 1)
    );
    assert_eq!(
        (counts.kept, counts.skipped, counts.produced, counts.failed),
        (0, 0, 0, 0)
    );

    let screen = view(&mut app, "ipsw_done_full.txt");
    assert_has(&screen, "Export finished");
    assert_has(&screen, "done");
    assert_has(&screen, "Fixture_26.0-export");
    assert_has(
        &screen,
        "written 1   decrypted 1   decompressed 2   linked 1",
    );
    assert_has(
        &screen,
        "produced 0   kept with warnings 0   skipped 0   failed 0",
    );
    for name in [AEA, KERNEL, NOTES, LATEST] {
        assert_has(&screen, name);
    }
    assert_has(&screen, "n new archive");
}

#[test]
fn export_to_a_new_nested_folder_with_originals_kept_and_flat_names() {
    let rig = Rig::new();
    let mut app = rig.browse();
    select(&mut app, &[AEA, KERNEL, LLB, NOTES, LATEST]);
    toggle_option(&mut app, OPT_KEEP);
    toggle_option(&mut app, OPT_PRESERVE);
    assert!(app.ipsw.options.keep_originals);
    assert!(!app.ipsw.options.preserve_paths);
    let screen = view(&mut app, "ipsw_options_flat_keep.txt");
    let rows = option_rows(&app, &screen);
    assert_has(&rows[OPT_KEEP], &format!("{ON} Keep originals too"));
    assert_has(&rows[OPT_PRESERVE], &format!("{OFF} Keep folder structure"));

    let out = rig.dir.path().join("nested/deeper/export-target");
    assert!(!out.exists());
    export_to(&mut app, &out);
    assert_eq!(app.ipsw.output.as_deref(), Some(out.as_path()));

    assert_eq!(
        list_tree(&out),
        sorted(&[
            "090-12345-001.dmg",
            "090-12345-001.dmg.aea",
            "LLB.j414c.RELEASE",
            "LLB.j414c.RELEASE.im4p",
            "kernelcache.release.mac14j",
            "kernelcache.release.mac14j.decompressed",
            "notes.txt",
        ])
    );
    assert_eq!(
        fs::read(out.join("090-12345-001.dmg")).unwrap(),
        b"PLAIN-SYSTEM-IMAGE"
    );
    assert_eq!(
        fs::read(out.join("090-12345-001.dmg.aea")).unwrap(),
        b"AEA1PLAIN-SYSTEM-IMAGE"
    );
    assert_eq!(
        fs::read(out.join("kernelcache.release.mac14j.decompressed")).unwrap(),
        b"KERNEL-PAYLOAD"
    );
    assert_eq!(
        fs::read(out.join(KERNEL)).unwrap(),
        fake_im4p(b"KERNEL-PAYLOAD")
    );
    assert_eq!(
        fs::read(out.join("LLB.j414c.RELEASE")).unwrap(),
        b"LLB-PAYLOAD"
    );
    assert_eq!(
        fs::read(out.join("LLB.j414c.RELEASE.im4p")).unwrap(),
        fake_im4p(b"LLB-PAYLOAD")
    );
    assert_eq!(fs::read(out.join("notes.txt")).unwrap(), b"hello");

    assert!(fs::symlink_metadata(out.join("latest")).is_err());
    let report = report(&app);
    assert!(matches!(
        outcome_of(&report, LATEST),
        Outcome::Skipped { .. }
    ));
    let counts = report.counts();
    assert_eq!(
        (
            counts.decrypted,
            counts.decompressed,
            counts.written,
            counts.skipped
        ),
        (1, 2, 1, 1)
    );
    assert_eq!((counts.failed, counts.kept), (0, 0));
    match outcome_of(&report, AEA) {
        Outcome::Decrypted { path, original } => {
            assert_eq!(path, out.join("090-12345-001.dmg"));
            assert_eq!(original, Some(out.join("090-12345-001.dmg.aea")));
        }
        other => panic!("{other:?}"),
    }
    assert_no_debris(&out);

    let screen = view(&mut app, "ipsw_done_flat_keep.txt");
    assert_has(&screen, "skipped 1");
    assert_has(&screen, "decompressed 2");
    assert_has(&screen, "export-target");
    assert_has(&screen, "Firmware/latest");
}

#[test]
fn a_second_export_skips_existing_files_unless_overwrite_is_on() {
    let rig = Rig::new();
    let mut app = rig.browse();
    select(&mut app, &[KERNEL, NOTES, LATEST]);
    export_default(&mut app);
    let out = rig.default_out();
    assert_eq!(report(&app).counts().decompressed, 1);
    assert_eq!(rig.cli_calls().len(), 1);

    fs::write(out.join(NOTES), b"edited by the user").unwrap();
    fs::write(out.join(KERNEL), b"edited kernel").unwrap();

    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert_eq!(app.ipsw.selected.len(), 3);
    export_default(&mut app);
    let counts = report(&app).counts();
    assert_eq!(counts.skipped, 3, "{:?}", report(&app).items);
    assert_eq!(
        (
            counts.written,
            counts.decompressed,
            counts.linked,
            counts.failed
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(fs::read(out.join(NOTES)).unwrap(), b"edited by the user");
    assert_eq!(fs::read(out.join(KERNEL)).unwrap(), b"edited kernel");
    assert_eq!(
        fs::read_link(out.join(LATEST)).unwrap(),
        Path::new("notes.txt")
    );
    assert_eq!(
        rig.cli_calls().len(),
        1,
        "a skipped file must not run the tool again"
    );
    let screen = view(&mut app, "ipsw_done_skipped.txt");
    assert_has(&screen, "skipped 3");
    assert_has(&screen, "already exists");
    assert_no_debris(&out);

    press(&mut app, KeyCode::Enter);
    toggle_option(&mut app, OPT_OVERWRITE);
    assert!(app.ipsw.options.overwrite);
    export_default(&mut app);
    let counts = report(&app).counts();
    assert_eq!(
        (
            counts.decompressed,
            counts.written,
            counts.linked,
            counts.skipped
        ),
        (1, 1, 1, 0),
        "{:?}",
        report(&app).items
    );
    assert_eq!(fs::read(out.join(NOTES)).unwrap(), b"hello");
    assert_eq!(fs::read(out.join(KERNEL)).unwrap(), b"KERNEL-PAYLOAD");
    assert_eq!(
        fs::read_link(out.join(LATEST)).unwrap(),
        Path::new("notes.txt")
    );
    assert_eq!(fs::read(out.join(LATEST)).unwrap(), b"hello");
    assert_eq!(
        list_tree(&out),
        sorted(&[
            "Firmware",
            "Firmware/latest",
            "Firmware/notes.txt",
            "kernelcache.release.mac14j"
        ])
    );
    assert_no_debris(&out);
}

#[test]
fn the_aea_key_reaches_the_command_and_stays_off_the_done_screen() {
    let rig = Rig::new();
    let mut app = rig.browse();
    select(&mut app, &[AEA, NOTES]);
    option_focus(&mut app, OPT_KEY);
    press(&mut app, KeyCode::Enter);
    let key = "qe/+xAAAAbbbb1234";
    type_text(&mut app, key);
    press(&mut app, KeyCode::Enter);
    export_default(&mut app);

    let calls = rig.cli_calls();
    let aea: Vec<&String> = calls.iter().filter(|c| c.contains("fw aea")).collect();
    assert_eq!(aea.len(), 1, "{calls:?}");
    assert!(
        aea[0].ends_with(&format!(" -b {key}")),
        "the key follows -b: {}",
        aea[0]
    );
    assert_eq!(
        fs::read(rig.default_out().join("090-12345-001.dmg")).unwrap(),
        b"PLAIN-SYSTEM-IMAGE"
    );
    let screen = view(&mut app, "ipsw_done_key.txt");
    assert_lacks(&screen, key);
    assert_lacks(&screen, "AAAAbbbb");

    let mut app = rig.browse();
    select(&mut app, &[AEA]);
    toggle_option(&mut app, OPT_OVERWRITE);
    option_focus(&mut app, OPT_KEY);
    press(&mut app, KeyCode::Enter);
    app.handle_event(Event::Paste("  pasted+key==\n".into()));
    assert_eq!(app.ipsw.options.aea_key.as_deref(), Some("pasted+key=="));
    press(&mut app, KeyCode::Enter);
    export_default(&mut app);
    let calls = rig.cli_calls();
    assert!(
        calls.last().unwrap().ends_with(" -b pasted+key=="),
        "{calls:?}"
    );
}

#[test]
fn components_run_with_the_device_and_report_produced_and_failed() {
    let rig = Rig::new();
    let mut app = rig.browse();
    option_focus(&mut app, OPT_DEVICE);
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Right);
    assert_eq!(app.ipsw.device.as_deref(), Some(FIXTURE_DEVICES[1]));
    toggle_option(&mut app, component_option(Component::Kernel));
    toggle_option(&mut app, component_option(Component::DeviceTree));
    assert!(app.ipsw.selected.is_empty());
    let expected: std::collections::BTreeSet<Component> =
        [Component::Kernel, Component::DeviceTree].into();
    assert_eq!(app.ipsw.components, expected);
    let screen = view(&mut app, "ipsw_components_selected.txt");
    assert_has(&screen, "2 components");

    export_default(&mut app);
    let out = rig.default_out();
    let report = report(&app);
    match outcome_of(&report, "Kernelcache") {
        Outcome::Produced { paths } => {
            assert_eq!(
                paths,
                vec![out.join("25A1__Mac15,6/kernelcache.release.Mac15,6")]
            );
            assert_eq!(fs::read(&paths[0]).unwrap(), b"KERNEL-FROM-CLI");
        }
        other => panic!("{other:?}"),
    }
    match outcome_of(&report, "DeviceTree") {
        Outcome::Failed { reason } => assert!(reason.contains("no files found"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        list_tree(&out),
        sorted(&["25A1__Mac15,6", "25A1__Mac15,6/kernelcache.release.Mac15,6"])
    );
    assert_no_debris(&out);

    let calls = rig.cli_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let archive = rig.archive_str();
    assert!(
        calls[0].contains("extract --kernel --device Mac15,6 -o") && calls[0].ends_with(archive),
        "{}",
        calls[0]
    );
    assert!(
        calls[1].contains("extract --dtree -o")
            && !calls[1].contains("--device")
            && calls[1].ends_with(archive),
        "{}",
        calls[1]
    );

    let screen = view(&mut app, "ipsw_done_components.txt");
    assert_has(&screen, "produced 1");
    assert_has(&screen, "failed 1");
    assert_has(&screen, "DeviceTree");
    assert_has(&screen, "Kernelcache");
    assert_has(&screen, "no files found");
    let failed_at = screen
        .lines()
        .position(|l| l.contains("DeviceTree"))
        .unwrap();
    let produced_at = screen
        .lines()
        .position(|l| l.contains("Kernelcache"))
        .unwrap();
    assert!(
        failed_at < produced_at,
        "failures are listed first\n{screen}"
    );
    assert_has(&screen, "1 file");
}

#[test]
fn an_abandoned_work_folder_is_removed_by_the_next_export_and_live_ones_are_left() {
    let rig = Rig::new();
    let out = rig.default_out();
    fs::create_dir_all(&out).unwrap();

    let stale = out.join(".apple-utils-export-StaleA");
    fs::create_dir_all(stale.join("item-3/in")).unwrap();
    fs::write(stale.join(".apple-utils-lock"), b"").unwrap();
    fs::write(stale.join("item-3/in/half.part"), b"partial").unwrap();

    let live = out.join(".apple-utils-export-LiveB");
    fs::create_dir_all(&live).unwrap();
    let lock = File::create(live.join(".apple-utils-lock")).unwrap();
    // SAFETY: the descriptor belongs to `lock`, which outlives the call.
    let status = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(status, 0, "could not take the test lock");
    fs::write(live.join("in-progress"), b"mine").unwrap();

    fs::create_dir_all(out.join("keep-me")).unwrap();
    fs::write(out.join("keep-me/file.txt"), b"user data").unwrap();

    let mut app = rig.browse();
    select(&mut app, &[NOTES]);
    export_default(&mut app);

    assert!(
        !stale.exists(),
        "the abandoned work folder must be reclaimed"
    );
    assert!(
        live.join("in-progress").exists(),
        "a live work folder must survive"
    );
    assert_eq!(
        fs::read(out.join("keep-me/file.txt")).unwrap(),
        b"user data"
    );
    assert_eq!(fs::read(out.join(NOTES)).unwrap(), b"hello");
    let work_dirs: Vec<String> = list_tree(&out)
        .into_iter()
        .filter(|path| path.starts_with(".apple-utils-export-") && !path.contains('/'))
        .collect();
    assert_eq!(work_dirs, vec![".apple-utils-export-LiveB".to_string()]);
    drop(lock);
}

fn cancel_with(key: KeyCode) {
    let _watchdog = Watchdog::start("cancelling a running export", Duration::from_secs(90));
    let Running {
        rig,
        mut app,
        out,
        groups,
    } = start_slow_export();

    assert_eq!(app.ipsw.run.current, SLOW);
    let screen = view(&mut app, "ipsw_exporting.txt");
    assert_has(&screen, "exporting");
    assert_has(&screen, "decrypting");
    assert_has(&screen, SLOW);
    assert_has(&screen, "item 2 of 2");
    assert_has(&screen, "esc/x cancel");
    assert_lacks(&screen, "stopping the running command");

    let started = Instant::now();
    assert!(!press(&mut app, key), "cancelling must not quit");
    assert!(app.ipsw.run.cancelling);
    assert_eq!(
        app.ipsw.phase,
        IpswPhase::Exporting,
        "stopping takes a moment"
    );
    let screen = view(&mut app, "ipsw_cancelling.txt");
    assert_has(&screen, "cancelling");
    assert_has(&screen, "stopping the running command");

    wait_for_done(&mut app, Duration::from_secs(10));
    assert!(started.elapsed() < Duration::from_secs(10));
    let finished = report(&app);
    assert!(finished.cancelled);
    assert_eq!(
        finished.items.len(),
        1,
        "nothing is recorded after the cancel"
    );
    assert!(matches!(
        outcome_of(&finished, NOTES),
        Outcome::Written { .. }
    ));
    let screen = view(&mut app, "ipsw_cancelled.txt");
    assert_has(&screen, "cancelled");
    assert_has(&screen, "Export cancelled");
    assert_has(&screen, "cancelled - partial files were removed");
    assert_lacks(&screen, "Export finished");

    assert_clean_after_cancel(&rig, &out, &groups);
}

#[test]
fn esc_cancels_a_running_export_and_leaves_nothing_behind() {
    cancel_with(KeyCode::Esc);
}

#[test]
fn x_cancels_a_running_export_and_leaves_nothing_behind() {
    cancel_with(KeyCode::Char('x'));
}

#[test]
fn q_quits_and_dropping_the_app_cancels_the_export_and_cleans_up() {
    let _watchdog = Watchdog::start(
        "dropping an app with a running export",
        Duration::from_secs(90),
    );
    let Running {
        rig,
        mut app,
        out,
        groups,
    } = start_slow_export();

    assert!(
        press(&mut app, KeyCode::Char('q')),
        "q asks the loop to quit"
    );
    assert_eq!(
        app.ipsw.phase,
        IpswPhase::Exporting,
        "q alone does not touch the job; dropping the app does"
    );
    let started = Instant::now();
    drop(app);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "dropping the app took {:?}",
        started.elapsed()
    );
    assert_clean_after_cancel(&rig, &out, &groups);
}

#[test]
fn ctrl_c_during_an_export_quits_and_drop_cleans_up() {
    let _watchdog = Watchdog::start("ctrl-c during an export", Duration::from_secs(90));
    let Running {
        rig,
        mut app,
        out,
        groups,
    } = start_slow_export();
    let mut event = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    event.kind = KeyEventKind::Press;
    assert!(app.handle_event(Event::Key(event)));
    let started = Instant::now();
    drop(app);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_clean_after_cancel(&rig, &out, &groups);
}

#[test]
fn opening_another_archive_mid_export_cancels_it_and_cleans_up() {
    let _watchdog = Watchdog::start("switching archives mid-export", Duration::from_secs(90));
    let Running {
        rig,
        mut app,
        out,
        groups,
    } = start_slow_export();

    let started = Instant::now();
    app.open_ipsw(rig.archive_str());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "switching took {:?}",
        started.elapsed()
    );
    assert_eq!(app.ipsw.phase, IpswPhase::Loading);
    assert!(app.ipsw.selected.is_empty());
    assert!(app.ipsw.report.is_none());
    assert_clean_after_cancel(&rig, &out, &groups);

    app.drain_ipsw_job();
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert!(app.ipsw.selected.is_empty(), "the new session starts empty");
}

#[test]
fn leaving_the_tool_mid_export_cancels_it_and_cleans_up() {
    let _watchdog = Watchdog::start("leaving the tool mid-export", Duration::from_secs(90));
    let Running {
        rig,
        mut app,
        out,
        groups,
    } = start_slow_export();

    let started = Instant::now();
    app.ipsw.reset_session();
    app.screen = Screen::Picker;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    assert!(!app.ipsw_busy());
    assert!(app.ipsw.selected.is_empty());
    assert_clean_after_cancel(&rig, &out, &groups);

    let screen = draw(&mut app, 100, 32);
    assert_has(&screen, "IPSW Export");
    ch(&mut app, '5');
    assert_eq!(app.screen, Screen::Ipsw);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    assert!(app.ipsw.report.is_none());
}

#[test]
fn esc_all_the_way_out_after_a_cancel_returns_to_the_picker_clean() {
    let _watchdog = Watchdog::start(
        "escaping out of a cancelled export",
        Duration::from_secs(90),
    );
    let Running {
        rig,
        mut app,
        out,
        groups,
    } = start_slow_export();

    press(&mut app, KeyCode::Esc);
    wait_for_done(&mut app, Duration::from_secs(10));
    assert!(report(&app).cancelled);
    assert_clean_after_cancel(&rig, &out, &groups);

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ipsw.phase, IpswPhase::Browse);
    assert_eq!(
        app.ipsw.selected.len(),
        2,
        "the selection survives a cancel"
    );
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ipsw.phase, IpswPhase::Path);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.screen, Screen::Picker);
    assert!(!app.ipsw_busy());
    assert_clean_after_cancel(&rig, &out, &groups);

    let mut app = rig.app();
    app.open_ipsw(rig.archive_str());
    app.drain_ipsw_job();
    select(&mut app, &[NOTES]);
    export_default(&mut app);
    assert_eq!(
        report(&app).counts().skipped,
        1,
        "the file from the first run is still there"
    );
}
