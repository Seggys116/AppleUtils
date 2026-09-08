use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, ExplorerPane, ExplorerPhase, Screen};
use crate::clip::format_size;
use crate::explorer_image::{EntryKind, ExplorerView, ListedEntry, VolumeInfo};
use crate::theme;
use crate::ui;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.screen != Screen::Explorer {
        return;
    }

    match app.explorer_phase {
        ExplorerPhase::Path => ui::render_file_picker(frame, area, app, "apfs explorer"),
        ExplorerPhase::Loading => render_loading(frame, area, app),
        ExplorerPhase::Browse => render_browse(frame, area, app),
    }
}

#[derive(Clone, Debug)]
pub enum FileRow {
    Parent,
    Entry(ListedEntry),
    None,
}

pub fn file_row_count(view: &ExplorerView) -> usize {
    let parent = usize::from(view.cwd != "/");
    parent + view.entries.len()
}

pub fn file_row_at(view: &ExplorerView, cursor: usize) -> FileRow {
    if view.cwd != "/" {
        if cursor == 0 {
            return FileRow::Parent;
        }
        return view
            .entries
            .get(cursor - 1)
            .cloned()
            .map(FileRow::Entry)
            .unwrap_or(FileRow::None);
    }
    view.entries
        .get(cursor)
        .cloned()
        .map(FileRow::Entry)
        .unwrap_or(FileRow::None)
}

fn render_loading(frame: &mut Frame, area: Rect, app: &App) {
    let stage = if app.explorer_status.is_empty() {
        "reading the disc"
    } else {
        app.explorer_status.as_str()
    };
    let path = ui::truncate_middle(&app.explorer_confirmed, 48);
    let mut spec = ui::WaitPlate::opening(stage, Some(path.as_str()), app.tick);
    spec.fill = app.explorer_progress.or(Some(0.0));
    ui::render_wait_plate(frame, area, spec);
}

fn render_browse(frame: &mut Frame, area: Rect, app: &mut App) {
    app.hits.explorer_volume_rows.clear();
    app.hits.explorer_file_rows.clear();

    let [chrome, panes] =
        Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(area);
    let [path_row, status_row, bar_row] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(chrome);

    let path = if app.explorer_confirmed.is_empty() {
        "Not selected"
    } else {
        &app.explorer_confirmed
    };
    let backend = app
        .explorer_view
        .as_ref()
        .map(|view| view.backend.as_str())
        .unwrap_or("—");
    let path_budget = path_row.width.saturating_sub(18);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" image ", Style::new().fg(theme::DIM)),
            Span::styled(ui::truncate_middle(path, path_budget), theme::list_text()),
            Span::styled(format!("  {backend}"), theme::ice()),
        ])),
        path_row,
    );

    if !app.explorer_status.is_empty() {
        ui::render_status_wait(
            frame,
            status_row,
            Some(bar_row),
            app.tick,
            &app.explorer_status,
            app.explorer_progress,
            ui::WAIT_BAR,
        );
    } else {
        let status = status_line(app.explorer_view.as_ref(), app.explorer_pane);
        frame.render_widget(Paragraph::new(status), status_row);
    }

    let side_w = (area.width / 3).clamp(22, 36);
    let [sidebar, main] = Layout::horizontal([Constraint::Length(side_w), Constraint::Fill(1)])
        .spacing(1)
        .areas(panes);

    let volume_focus = app.explorer_pane == ExplorerPane::Volumes;
    render_sidebar(frame, sidebar, app, volume_focus);
    render_listing(frame, main, app, !volume_focus);
}

fn status_line(view: Option<&ExplorerView>, pane: ExplorerPane) -> Line<'static> {
    let Some(view) = view else {
        return Line::from(Span::styled(" no image open", theme::dim()));
    };
    let volume = view.volume_name().to_string();
    let count = view.entries.len();
    let entries = if count == 1 {
        "1 entry".to_string()
    } else {
        format!("{count} entries")
    };
    let flag = view.volume().and_then(VolumeInfo::flag_label).unwrap_or("");
    let picker_n = view.volumes.iter().filter(|volume| volume.bootable).count();
    let focus = match pane {
        ExplorerPane::Volumes => "volumes",
        ExplorerPane::Files => "files",
    };
    let mut spans = vec![
        Span::styled(" ", theme::dim()),
        Span::styled(volume, theme::title()),
        Span::styled("  ", theme::dim()),
        Span::styled(view.cwd.clone(), theme::ice()),
        Span::styled("  ", theme::dim()),
        Span::styled(entries, theme::mute()),
    ];
    if !flag.is_empty() {
        spans.push(Span::styled(format!("  {flag}"), theme::wait()));
    }
    if picker_n > 0 {
        let picker = if picker_n == 1 {
            "1 picker-visible".to_string()
        } else {
            format!("{picker_n} picker-visible")
        };
        spans.push(Span::styled(format!("  {picker}"), theme::mute()));
    }
    spans.push(Span::styled(format!("    focus {focus}"), theme::dim()));
    if let Some(message) = view.message.as_deref() {
        spans.push(Span::styled("    ", theme::dim()));
        spans.push(Span::styled(message.to_string(), theme::ice()));
    }
    Line::from(spans)
}

fn render_sidebar(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    let count = app
        .explorer_view
        .as_ref()
        .map(|view| view.volumes.len())
        .unwrap_or(0);
    let title = format!("volumes  {count}");
    let block = ui::pane(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(view) = app.explorer_view.as_ref() else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("no image", theme::dim()))),
            inner,
        );
        return;
    };
    if view.volumes.is_empty() {
        let msg = if view.error.is_some() {
            "open failed"
        } else {
            "no volumes"
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(msg, theme::wait()))),
            inner,
        );
        return;
    }

    if focused {
        app.explorer_page_rows = inner.height as usize;
    }
    let items = sidebar_items(&view.volumes);
    let height = inner.height as usize;
    let focus_visual = visual_index_of(&items, view.volume_cursor).unwrap_or(0);
    let start = scroll_start(items.len(), focus_visual, height);
    app.hits.explorer_volume_rows = vec![Rect::default(); view.volumes.len()];
    let mut lines = Vec::new();
    for (offset, item) in items.iter().skip(start).take(height).enumerate() {
        match item {
            SideItem::Header(title) => {
                let label = ui::truncate_middle(title, inner.width.saturating_sub(1));
                let mut text = format!(" {label}");
                pad_to_width(&mut text, inner.width as usize);
                lines.push(Line::from(Span::styled(text, theme::dim())));
            }
            SideItem::Volume(index) => {
                let volume = &view.volumes[*index];
                let loaded = *index == view.volume_index;
                let hovered = *index == view.volume_cursor;
                let keyboard = focused && hovered;
                let marker = if hovered {
                    ui::glyphs().focus
                } else if loaded {
                    ui::glyphs().loaded
                } else {
                    ui::glyphs().idle
                };
                let indent = if items.iter().any(|item| matches!(item, SideItem::Header(_))) {
                    ui::glyphs().idle
                } else {
                    ""
                };
                let flags = volume_flags(volume);
                let name_budget = inner
                    .width
                    .saturating_sub(marker.chars().count() as u16)
                    .saturating_sub(indent.len() as u16)
                    .saturating_sub(flags.len() as u16);
                let name = ui::truncate_middle(&volume.name, name_budget);
                let mut text = format!("{marker}{indent}{name}{flags}");
                pad_to_width(&mut text, inner.width as usize);
                let style = if keyboard {
                    theme::focus_row()
                } else if loaded {
                    theme::selected_row()
                } else {
                    theme::list_text()
                };
                lines.push(Line::from(Span::styled(text, style)));
                app.hits.explorer_volume_rows[*index] = Rect {
                    x: inner.x,
                    y: inner.y + offset as u16,
                    width: inner.width,
                    height: 1,
                };
            }
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

enum SideItem {
    Header(String),
    Volume(usize),
}

fn sidebar_items(volumes: &[VolumeInfo]) -> Vec<SideItem> {
    let multi = volumes
        .iter()
        .map(|volume| volume.container_index)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        > 1;
    if !multi {
        return (0..volumes.len()).map(SideItem::Volume).collect();
    }
    let mut items = Vec::new();
    let mut last = None;
    for (index, volume) in volumes.iter().enumerate() {
        if last != Some(volume.container_index) {
            let title = if volume.partition_name.trim().is_empty() {
                format!("container {}", volume.container_index + 1)
            } else {
                volume.partition_name.clone()
            };
            items.push(SideItem::Header(title));
            last = Some(volume.container_index);
        }
        items.push(SideItem::Volume(index));
    }
    items
}

fn visual_index_of(items: &[SideItem], volume_index: usize) -> Option<usize> {
    items
        .iter()
        .position(|item| matches!(item, SideItem::Volume(index) if *index == volume_index))
}

fn volume_role_tag(volume: &VolumeInfo) -> Option<&str> {
    let role = volume.role.trim();
    if role.is_empty() || role.eq_ignore_ascii_case("volume") {
        return None;
    }
    if role.eq_ignore_ascii_case(volume.name.trim()) {
        return None;
    }
    Some(role)
}

fn volume_flags(volume: &VolumeInfo) -> String {
    let mut flags = String::new();
    if let Some(role) = volume_role_tag(volume) {
        flags.push(' ');
        flags.push_str(role);
    }
    if volume.bootable {
        flags.push_str("  bootable");
    }
    if volume.encrypted {
        flags.push_str("  encrypted");
    } else if volume.sealed {
        flags.push_str("  sealed");
    }
    flags
}

fn render_listing(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    let cwd = app
        .explorer_view
        .as_ref()
        .map(|view| view.cwd.as_str())
        .unwrap_or("/");
    let count = app
        .explorer_view
        .as_ref()
        .map(|view| view.entries.len())
        .unwrap_or(0);
    let title = format!(
        "files  {}  {count}",
        ui::truncate_middle(cwd, area.width.saturating_sub(16))
    );
    let block = ui::pane(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(view) = app.explorer_view.as_ref() else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "copy a disc image to browse it",
                theme::dim(),
            ))),
            inner,
        );
        return;
    };
    if let Some(err) = view.error.as_deref() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("could not open this image", theme::wait())),
                Line::from(Span::styled(
                    ui::truncate_middle(err, inner.width.saturating_sub(2)),
                    theme::list_text(),
                )),
                Line::from(""),
                Line::from(Span::styled("esc returns to the path card", theme::dim())),
            ]),
            inner,
        );
        return;
    }

    let detail_h = 6.min(inner.height / 3).max(3);
    let [header, list, detail] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(detail_h),
    ])
    .areas(inner);

    if focused {
        app.explorer_page_rows = list.height as usize;
    }
    frame.render_widget(column_header(header.width), header);

    let rows = file_row_count(view);
    app.hits.explorer_file_rows = vec![Rect::default(); rows.max(1)];
    if rows == 0 {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "no catalog entries on this volume",
                    theme::list_text(),
                )),
                Line::from(Span::styled(
                    format!("the filesystem tree at {} lists no files", view.cwd),
                    theme::mute(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "tab focuses the volume list, then j/k and enter open another",
                    theme::dim(),
                )),
            ]),
            list,
        );
    } else {
        let height = list.height as usize;
        let start = scroll_start(rows, view.cursor, height);
        let mut lines = Vec::new();
        for (offset, index) in (start..rows).take(height).enumerate() {
            let selected = index == view.cursor;
            let keyboard = focused && selected;
            lines.push(file_line(view, index, list.width, keyboard, selected));
            app.hits.explorer_file_rows[index] = Rect {
                x: list.x,
                y: list.y + offset as u16,
                width: list.width,
                height: 1,
            };
        }
        frame.render_widget(Paragraph::new(lines), list);
    }

    frame.render_widget(detail_panel(view, detail.width), detail);
}

fn column_header(width: u16) -> Paragraph<'static> {
    Paragraph::new(Line::from(Span::styled(
        format!(
            "  {}",
            columns("name", "kind", "size", width.saturating_sub(2))
        ),
        Style::new().fg(theme::DIM),
    )))
}

fn file_line(
    view: &ExplorerView,
    index: usize,
    width: u16,
    keyboard: bool,
    current: bool,
) -> Line<'static> {
    let marker = if current {
        ui::glyphs().focus
    } else {
        ui::glyphs().idle
    };
    let (name, kind, size, entry_kind) = match file_row_at(view, index) {
        FileRow::Parent => (
            "..".to_string(),
            "dir".to_string(),
            String::new(),
            EntryKind::Directory,
        ),
        FileRow::Entry(entry) => (
            match entry.kind {
                EntryKind::Directory => format!("{}/", entry.name),
                _ => entry.name,
            },
            match entry.kind {
                EntryKind::Directory => "dir".into(),
                EntryKind::File => "file".into(),
                EntryKind::Symlink => "symlink".into(),
                EntryKind::Other => "other".into(),
            },
            match entry.kind {
                EntryKind::Symlink => entry
                    .symlink_target
                    .map(|target| format!("-> {target}"))
                    .unwrap_or_default(),
                EntryKind::File => entry.size.map(format_size).unwrap_or_default(),
                _ => String::new(),
            },
            entry.kind,
        ),
        FileRow::None => (
            String::new(),
            String::new(),
            String::new(),
            EntryKind::Other,
        ),
    };
    let body_w = width.saturating_sub(marker.chars().count() as u16);
    let body = columns(&name, &kind, &size, body_w);
    let mut text = format!("{marker}{body}");
    pad_to_width(&mut text, width as usize);
    if keyboard {
        return Line::from(Span::styled(text, theme::focus_row()));
    }
    if current {
        return Line::from(Span::styled(text, theme::selected_row()));
    }
    let name_style = match entry_kind {
        EntryKind::Directory => theme::ice(),
        EntryKind::Symlink => theme::mute(),
        _ => theme::list_text(),
    };
    let kind_at = marker.chars().count();
    let name_w = columns_name_width(body_w) as usize;
    let chars: Vec<char> = text.chars().collect();
    let split = (kind_at + name_w).min(chars.len());
    let head: String = chars[..split].iter().collect();
    let tail: String = chars[split..].iter().collect();
    Line::from(vec![
        Span::styled(head, name_style),
        Span::styled(tail, theme::dim()),
    ])
}

fn columns_name_width(width: u16) -> u16 {
    if width < 28 {
        width
    } else {
        width.saturating_sub(10 + 8 + 2)
    }
}

fn columns(name: &str, kind: &str, size: &str, width: u16) -> String {
    if width < 28 {
        return ui::truncate_middle(name, width);
    }
    let size_w = 10u16;
    let kind_w = 8u16;
    let name_w = columns_name_width(width);
    let name = ui::truncate_middle(name, name_w);
    let kind = ui::truncate_middle(kind, kind_w);
    let size = ui::truncate_middle(size, size_w);
    format!(
        "{name:<name_w$} {kind:<kind_w$} {size:>size_w$}",
        name_w = name_w as usize,
        kind_w = kind_w as usize,
        size_w = size_w as usize
    )
}

fn detail_panel(view: &ExplorerView, width: u16) -> Paragraph<'static> {
    let rule = ui::glyphs().rule_line(width);
    let mut lines = vec![Line::from(Span::styled(rule, theme::dim()))];
    match file_row_at(view, view.cursor) {
        FileRow::Parent => {
            lines.push(Line::from(Span::styled("..", theme::title())));
            lines.push(Line::from(Span::styled(
                "parent directory  ·  enter or backspace",
                theme::mute(),
            )));
        }
        FileRow::Entry(entry) => {
            lines.push(Line::from(Span::styled(
                ui::truncate_middle(&entry.name, width.saturating_sub(1)),
                theme::title(),
            )));
            let meta = match entry.kind {
                EntryKind::Directory => "directory  ·  enter or → to open".to_string(),
                EntryKind::File => match entry.size {
                    Some(n) => format!("file  ·  {}  ·  e exports", format_size(n)),
                    None => "file  ·  e exports".into(),
                },
                EntryKind::Symlink => format!(
                    "symlink  ·  {}",
                    entry.symlink_target.as_deref().unwrap_or("?")
                ),
                EntryKind::Other => "item".into(),
            };
            lines.push(Line::from(Span::styled(meta, theme::mute())));
            if matches!(entry.kind, EntryKind::File | EntryKind::Symlink)
                && let Some(preview) = view.preview.as_deref()
                && let Some(first) = preview.lines().next()
            {
                lines.push(Line::from(Span::styled(
                    ui::truncate_middle(first, width.saturating_sub(1)),
                    theme::ice(),
                )));
            }
        }
        FileRow::None => {
            if view.entries.is_empty() {
                lines.push(Line::from(Span::styled(
                    view.volume_name().to_string(),
                    theme::title(),
                )));
                lines.push(Line::from(Span::styled(
                    "no catalog entries at this path",
                    theme::mute(),
                )));
                lines.push(Line::from(Span::styled("tab  volume list", theme::dim())));
            }
        }
    }
    Paragraph::new(lines)
}

fn pad_to_width(text: &mut String, width: usize) {
    let chars = text.chars().count();
    if chars < width {
        text.extend(std::iter::repeat_n(' ', width - chars));
    }
}

fn scroll_start(len: usize, cursor: usize, height: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    if cursor < height {
        0
    } else {
        (cursor + 1).saturating_sub(height).min(len - height)
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use ratatui::layout::Position;

    use super::*;
    use crate::apfs_fixture::{
        self, FIXTURE_DIR, FIXTURE_FILE, FIXTURE_NESTED, FIXTURE_SYMLINK, FIXTURE_SYMLINK_TARGET,
        FIXTURE_VOLUME, ImageWrap,
    };
    use crate::app::{App, ExplorerPane, ExplorerPhase, Screen};
    use crate::explorer_image::{self, BackendKind, VolumeInfo};

    fn buffer_text(backend: &TestBackend) -> String {
        let buffer = backend.buffer();
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

    fn draw(app: &mut App) -> String {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, app))
            .unwrap();
        buffer_text(terminal.backend())
    }

    fn press(app: &mut App, code: KeyCode) {
        send_key(app, code);
        app.drain_explorer_load();
    }

    fn send_key(app: &mut App, code: KeyCode) {
        let mut event = KeyEvent::new(code, KeyModifiers::NONE);
        event.kind = KeyEventKind::Press;
        app.handle_event(Event::Key(event));
    }

    fn shows_in_place_wait(text: &str) -> bool {
        text.contains("reading")
            || text.contains("exporting")
            || text.contains("inserting")
            || text.contains(ui::glyphs().bar_fill)
            || text.contains(ui::glyphs().bar_track)
            || ui::glyphs().spinner.iter().any(|ch| text.contains(*ch))
    }

    fn dump_ui(name: &str, text: &str) {
        if let Ok(dir) = std::env::var("APPLE_UTILS_UI_DUMP") {
            let path = std::path::Path::new(&dir).join(name);
            std::fs::write(path, text).expect("ui dump");
        }
    }

    fn browse_app(image: &std::path::Path, cwd: &str) -> App {
        let view = explorer_image::load_view(image, cwd, 0).expect("listing");
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Browse;
        app.explorer_pane = ExplorerPane::Files;
        app.explorer_confirmed = image.to_string_lossy().into_owned();
        app.explorer_view = Some(view);
        app
    }

    #[test]
    fn path_card_offers_clipboard_and_typed_entry() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        let text = draw(&mut app);
        assert!(text.contains("clipboard"), "{text}");
        assert!(text.contains("paste a file or folder path"), "{text}");
        send_key(&mut app, KeyCode::Char('/'));
        send_key(&mut app, KeyCode::Char('t'));
        send_key(&mut app, KeyCode::Char('m'));
        send_key(&mut app, KeyCode::Char('p'));
        let text = draw(&mut app);
        assert!(text.contains("/tmp"), "{text}");
        assert!(text.contains("type a path"), "{text}");
    }

    #[test]
    fn browse_view_shows_sidebar_volumes_and_fixture_entries() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, "/");
        let text = draw(&mut app);
        assert!(text.contains("volumes"), "{text}");
        assert!(text.contains("files"), "{text}");
        assert!(text.contains(FIXTURE_VOLUME), "{text}");
        assert!(text.contains(&format!("{FIXTURE_DIR}/")), "{text}");
        assert!(text.contains("dir"), "{text}");
        assert!(text.contains(ui::glyphs().focus.trim()), "{text}");
        assert!(text.contains("focus files"), "{text}");
        assert!(!text.contains("not implemented"), "{text}");
        assert!(!text.contains("empty directory"), "{text}");
    }

    #[test]
    fn browse_listing_shows_file_directory_and_symlink_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, &format!("/{FIXTURE_DIR}"));
        let text = draw(&mut app);
        assert!(text.contains("volumes"), "{text}");
        assert!(text.contains(FIXTURE_VOLUME), "{text}");
        assert!(text.contains(FIXTURE_FILE), "{text}");
        assert!(text.contains("file"), "{text}");
        assert!(text.contains(&format!("{FIXTURE_NESTED}/")), "{text}");
        assert!(text.contains(".."), "{text}");
        assert!(text.contains(FIXTURE_SYMLINK), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(text.contains(FIXTURE_SYMLINK_TARGET), "{text}");
        assert!(!text.contains("not implemented"), "{text}");
    }

    #[test]
    fn browse_enter_directory_updates_the_listing() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, "/");
        {
            let view = app.explorer_view.as_mut().expect("view");
            view.cursor = view
                .entries
                .iter()
                .position(|entry| entry.name == FIXTURE_DIR)
                .expect("docs directory");
        }
        press(&mut app, KeyCode::Enter);
        let view = app.explorer_view.as_ref().expect("view after enter");
        assert_eq!(view.cwd, format!("/{FIXTURE_DIR}"));
        let names: Vec<&str> = view.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&FIXTURE_FILE), "{names:?}");
        assert!(names.contains(&FIXTURE_SYMLINK), "{names:?}");

        let text = draw(&mut app);
        assert!(text.contains(FIXTURE_FILE), "{text}");
        assert!(text.contains(FIXTURE_SYMLINK), "{text}");
        assert!(text.contains("symlink"), "{text}");
        assert!(!text.contains("not implemented"), "{text}");
    }

    #[test]
    fn tab_moves_focus_between_volumes_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, "/");
        assert_eq!(app.explorer_pane, ExplorerPane::Files);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.explorer_pane, ExplorerPane::Volumes);
        let text = draw(&mut app);
        assert!(text.contains("focus volumes"), "{text}");
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.explorer_pane, ExplorerPane::Files);
    }

    #[test]
    fn empty_volume_explains_the_gap_and_keeps_volumes_usable() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Browse;
        app.explorer_pane = ExplorerPane::Volumes;
        app.explorer_confirmed = "asahi.qcow2".into();
        app.explorer_view = Some(ExplorerView {
            path: "asahi.qcow2".into(),
            backend: BackendKind::Qcow2,
            volumes: vec![
                VolumeInfo {
                    name: "Asahi Linux".into(),
                    role: "System".into(),
                    sealed: false,
                    encrypted: false,
                    container_index: 0,
                    partition_name: "Asahi Linux".into(),
                    bootable: true,
                    volume_group_id: [1u8; 16],
                    system_version: Some("15.0 (stub)".into()),
                },
                VolumeInfo {
                    name: "Preboot".into(),
                    role: "Preboot".into(),
                    sealed: false,
                    encrypted: false,
                    container_index: 0,
                    partition_name: "Asahi Linux".into(),
                    bootable: false,
                    volume_group_id: [0u8; 16],
                    system_version: None,
                },
            ],
            volume_index: 0,
            volume_cursor: 0,
            cwd: "/".into(),
            entries: vec![],
            cursor: 0,
            preview: None,
            error: None,
            message: None,
        });
        let text = draw(&mut app);
        assert!(text.contains("Asahi Linux"), "{text}");
        assert!(text.contains("Preboot"), "{text}");
        assert!(text.contains("bootable"), "{text}");
        assert!(text.contains("picker-visible"), "{text}");
        assert!(text.contains("no catalog entries"), "{text}");
        assert!(text.contains("focus volumes"), "{text}");
        assert!(
            text.contains("tab focuses the volume list") || text.contains("volume list"),
            "{text}"
        );
        assert!(!text.contains("empty directory"), "{text}");
        assert!(!text.contains("not implemented"), "{text}");
        assert!(
            !text.contains("Preboot Preboot"),
            "role must not repeat a volume's own name: {text}"
        );
    }

    #[test]
    fn volume_role_is_omitted_when_it_matches_the_name() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Browse;
        app.explorer_pane = ExplorerPane::Volumes;
        app.explorer_view = Some(ExplorerView {
            path: "disk.img".into(),
            backend: BackendKind::Qcow2,
            volumes: vec![
                VolumeInfo {
                    name: "Recovery".into(),
                    role: "Recovery".into(),
                    sealed: false,
                    encrypted: false,
                    container_index: 0,
                    partition_name: "Macintosh HD".into(),
                    bootable: false,
                    volume_group_id: [0u8; 16],
                    system_version: None,
                },
                VolumeInfo {
                    name: "Macintosh HD".into(),
                    role: "System".into(),
                    sealed: false,
                    encrypted: false,
                    container_index: 0,
                    partition_name: "Macintosh HD".into(),
                    bootable: true,
                    volume_group_id: [1u8; 16],
                    system_version: Some("15.0".into()),
                },
                VolumeInfo {
                    name: "xART".into(),
                    role: "xART".into(),
                    sealed: false,
                    encrypted: false,
                    container_index: 1,
                    partition_name: "iSCPreboot".into(),
                    bootable: false,
                    volume_group_id: [2u8; 16],
                    system_version: None,
                },
            ],
            volume_index: 1,
            volume_cursor: 1,
            cwd: "/".into(),
            entries: vec![],
            cursor: 0,
            preview: None,
            error: None,
            message: None,
        });
        let text = draw(&mut app);
        assert!(text.contains("Recovery"), "{text}");
        assert!(
            !text.contains("Recovery Recovery"),
            "matching role must not double the name: {text}"
        );
        assert!(
            !text.contains("xART xART"),
            "matching role must not double the name: {text}"
        );
        assert!(text.contains("Macintosh HD"), "{text}");
        assert!(
            text.contains("System"),
            "a distinct role still shows: {text}"
        );
        assert!(text.contains("bootable"), "{text}");
        assert!(
            text.contains("iSCPreboot") && text.contains("Macintosh HD"),
            "multiple containers should be grouped: {text}"
        );
    }

    #[test]
    fn file_list_down_stops_on_the_last_entry() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, "/");
        let n = crate::explorer::file_row_count(app.explorer_view.as_ref().unwrap());
        assert!(n >= 1);
        for _ in 0..(n + 3) {
            press(&mut app, KeyCode::Down);
        }
        assert_eq!(app.explorer_view.as_ref().unwrap().cursor, n - 1);
        press(&mut app, KeyCode::PageUp);
        assert!(app.explorer_view.as_ref().unwrap().cursor < n - 1 || n == 1);
    }

    #[test]
    fn left_arrow_at_root_returns_to_the_volume_list() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, "/");
        assert_eq!(app.explorer_pane, ExplorerPane::Files);
        press(&mut app, KeyCode::Left);
        assert_eq!(app.explorer_pane, ExplorerPane::Volumes);
        press(&mut app, KeyCode::Right);
        assert_eq!(app.explorer_pane, ExplorerPane::Files);
        let text = draw(&mut app);
        assert!(text.contains(FIXTURE_DIR), "{text}");
    }

    #[test]
    fn left_arrow_leaves_an_empty_files_pane() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Browse;
        app.explorer_pane = ExplorerPane::Files;
        app.explorer_view = Some(ExplorerView {
            path: "disc.img".into(),
            backend: BackendKind::Qcow2,
            volumes: vec![VolumeInfo {
                name: "Recovery".into(),
                role: "Recovery".into(),
                sealed: false,
                encrypted: false,
                container_index: 0,
                partition_name: "APFS".into(),
                bootable: false,
                volume_group_id: [0u8; 16],
                system_version: None,
            }],
            volume_index: 0,
            volume_cursor: 0,
            cwd: "/".into(),
            entries: vec![],
            cursor: 0,
            preview: None,
            error: None,
            message: None,
        });
        press(&mut app, KeyCode::Left);
        assert_eq!(app.explorer_pane, ExplorerPane::Volumes);
    }

    #[test]
    fn export_key_writes_the_selected_file_to_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, &format!("/{FIXTURE_DIR}"));
        {
            let view = app.explorer_view.as_mut().expect("view");
            view.cursor = view
                .entries
                .iter()
                .position(|e| e.name == FIXTURE_FILE)
                .map(|i| i + 1)
                .expect("file row after parent");
        }
        press(&mut app, KeyCode::Char('e'));
        let dest = dir.path().join("apfs-export").join(FIXTURE_FILE);
        assert!(dest.exists(), "expected export at {}", dest.display());
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            apfs_fixture::FIXTURE_FILE_BYTES
        );
        let msg = app
            .explorer_view
            .as_ref()
            .unwrap()
            .message
            .clone()
            .unwrap_or_default();
        assert!(msg.contains("exported"), "{msg}");
    }

    #[test]
    fn paste_inserts_a_host_file_into_the_current_directory() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let host = dir.path().join("dropped.txt");
        std::fs::write(&host, b"from-paste").unwrap();
        let mut app = browse_app(&image, &format!("/{FIXTURE_DIR}"));
        app.handle_paste(&host.to_string_lossy());
        app.drain_explorer_load();
        let view = app.explorer_view.as_ref().expect("view");
        assert!(
            view.entries.iter().any(|e| e.name == "dropped.txt"),
            "{:?}",
            view.entries
        );
        let msg = view.message.clone().unwrap_or_default();
        assert!(msg.contains("inserted"), "{msg}");
    }

    #[test]
    fn opening_an_image_shows_a_waiting_screen_then_the_listing() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        app.open_explorer_image(image.to_str().unwrap());
        assert_eq!(app.explorer_phase, ExplorerPhase::Loading);
        let text = draw(&mut app);
        dump_ui("explorer-open.txt", &text);
        assert!(text.contains("opening"), "{text}");
        assert!(text.contains("disk.img"), "{text}");
        assert!(
            text.contains('━') || text.contains('─'),
            "loading screen needs a progress meter:\n{text}"
        );
        assert!(
            text.contains('%'),
            "loading screen needs a percent:\n{text}"
        );
        assert!(!text.contains("not implemented"), "{text}");
        app.drain_explorer_load();
        assert_eq!(app.explorer_phase, ExplorerPhase::Browse);
        let text = draw(&mut app);
        assert!(text.contains(FIXTURE_VOLUME), "{text}");
        assert!(text.contains(FIXTURE_DIR), "{text}");
    }

    #[test]
    fn escape_cancels_the_waiting_screen() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Loading;
        app.explorer_confirmed = "huge.qcow2".into();
        app.explorer_status = "opening huge.qcow2".into();
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.explorer_phase, ExplorerPhase::Path);
    }

    #[test]
    fn activating_a_directory_keeps_browse_and_shows_in_place_wait() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, "/");
        {
            let view = app.explorer_view.as_mut().expect("view");
            view.cursor = view
                .entries
                .iter()
                .position(|entry| entry.name == FIXTURE_DIR)
                .expect("docs directory");
        }
        send_key(&mut app, KeyCode::Enter);
        assert_eq!(app.explorer_phase, ExplorerPhase::Browse);
        assert!(app.explorer_busy());
        assert!(
            app.explorer_status.contains("reading"),
            "in-browse reload must set a reading status, got {:?}",
            app.explorer_status
        );
        let text = draw(&mut app);
        dump_ui("explorer-folder-load.txt", &text);
        assert!(text.contains("volumes"), "{text}");
        assert!(text.contains("files"), "{text}");
        assert!(
            text.contains("reading") || shows_in_place_wait(&text),
            "in-browse reload must keep an in-place wait, got:\n{text}"
        );
        assert!(
            text.contains(FIXTURE_VOLUME) || text.contains(FIXTURE_DIR),
            "listing panes must remain while reading:\n{text}"
        );
        assert!(
            !text.contains(" opening ") || text.contains("volumes"),
            "full-page opening plate must not replace the browse body:\n{text}"
        );
        app.drain_explorer_load();
        assert_eq!(app.explorer_phase, ExplorerPhase::Browse);
        let view = app.explorer_view.as_ref().expect("view after drain");
        assert_eq!(view.cwd, format!("/{FIXTURE_DIR}"));
    }

    #[test]
    fn export_shows_in_place_wait_while_writing() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = browse_app(&image, &format!("/{FIXTURE_DIR}"));
        {
            let view = app.explorer_view.as_mut().expect("view");
            view.cursor = view
                .entries
                .iter()
                .position(|e| e.name == FIXTURE_FILE)
                .map(|i| i + 1)
                .expect("file row after parent");
        }
        send_key(&mut app, KeyCode::Char('e'));
        assert_eq!(app.explorer_phase, ExplorerPhase::Browse);
        assert!(
            app.explorer_status.contains("exporting"),
            "export must set an exporting status, got {:?}",
            app.explorer_status
        );
        let text = draw(&mut app);
        dump_ui("sync-wait.txt", &text);
        assert!(text.contains("volumes"), "{text}");
        assert!(text.contains("files"), "{text}");
        assert!(
            text.contains("exporting") || shows_in_place_wait(&text),
            "export must show in-place wait, got:\n{text}"
        );
        assert!(
            !text.trim().is_empty(),
            "in-flight export must not blank the body:\n{text}"
        );
        for _ in 0..3 {
            app.prepare();
            let frame = draw(&mut app);
            assert!(frame.contains("volumes"), "{frame}");
            assert!(frame.contains("files"), "{frame}");
            assert!(
                !frame.trim().is_empty(),
                "prepare+draw during export must keep the listing:\n{frame}"
            );
        }
        app.drain_explorer_load();
        let dest = dir.path().join("apfs-export").join(FIXTURE_FILE);
        assert!(dest.exists(), "expected export at {}", dest.display());
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            apfs_fixture::FIXTURE_FILE_BYTES
        );
    }
}
