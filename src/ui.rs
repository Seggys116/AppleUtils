use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::app::{App, Screen};
use crate::clip::{FileInfo, FileKind, format_size};
use crate::theme;
pub use apple_tui::{
    ASCII, BarPalette, GLYPHS, GlyphPack, Glyphs, INSTRUMENT, PASS_BAR, PlateClass, WAIT_BAR,
    WORK_BAR, WaitPlate, busy_message, busy_status, center, choice_block, current_pack, cycle_pack,
    detect_pack, dots_frame, glow_bar, glow_bar_with, glyphs, inset, pane, parse_pack_name, plate,
    plate_class, prefers_ascii_from, progress_label, render_choice_card, render_cluster,
    render_empty_well, render_glow_bar, render_scrollbar, render_status_wait, render_wait_plate,
    rounded, set_pack, spinner_frame, truncate_middle, truncate_middle_with,
};

pub const MIN_WIDTH: u16 = 48;
pub const MIN_HEIGHT: u16 = 12;

pub fn render(frame: &mut Frame, app: &mut App) {
    set_pack(app.glyph_pack);
    let area = frame.area();
    frame.render_widget(Block::default().style(theme::bg()), area);
    app.hits.clear();

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }

    let (body, footer) = if app.screen == Screen::Picker {
        let [body, footer] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);
        (body, footer)
    } else {
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);
        render_header(frame, header, app);
        (body, footer)
    };

    crate::picker::render(frame, body, app);
    crate::recovery::render(frame, body, app);
    crate::explorer::render(frame, body, app);
    crate::repair::render(frame, body, app);
    crate::asahi::render(frame, body, app);
    render_footer(frame, footer, app);
}

fn render_too_small(frame: &mut Frame, area: Rect) {
    let text = vec![
        Line::from("terminal too small").style(theme::mute()),
        Line::from(format!("{MIN_WIDTH} × {MIN_HEIGHT} required")).style(theme::dim()),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .style(theme::bg()),
        area,
    );
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let [row, rule] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    let screen = match app.screen {
        Screen::Picker => "PICKER",
        Screen::Recovery => "RECOVERY",
        Screen::Explorer => "EXPLORER",
        Screen::Repair => "REPAIR",
        Screen::Asahi => "ASAHI",
    };

    let [left, right] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(screen.len() as u16 + 1),
    ])
    .areas(row);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" A P P L E", theme::title()),
            Span::styled("   ", theme::dim()),
            Span::styled("U T I L S", theme::title()),
        ])),
        left,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(screen, theme::mute()))).alignment(Alignment::Right),
        right,
    );
    frame.render_widget(
        Paragraph::new(glyphs().rule_line(rule.width)).style(theme::dim()),
        rule,
    );
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let hints = footer_hints(app, area.width);
    frame.render_widget(
        Paragraph::new(hints)
            .alignment(Alignment::Center)
            .style(Style::new().fg(theme::MUTE)),
        area,
    );
}

fn path_picker_hints(app: &App, width: u16) -> &'static [&'static str] {
    match (app.path_editing, width) {
        (true, w) if w >= 56 => &["type a path", "esc cancel", "enter"],
        (true, _) => &["type", "esc", "enter"],
        (false, w) if w >= 72 => &[
            "copy a file or folder",
            "tab path",
            "enter",
            "esc back",
            "q quit",
        ],
        (false, w) if w >= 48 => &["tab path", "enter", "esc", "q"],
        (false, _) => &["esc", "q"],
    }
}

fn footer_hints(app: &App, width: u16) -> Line<'static> {
    let parts: &[&str] = match (app.screen, width) {
        (Screen::Picker, w) if w >= 78 => &[
            "click open",
            "↑↓ move",
            "enter open",
            "1–4 jump",
            "g glyphs",
            "q quit",
        ],
        (Screen::Picker, w) if w >= 56 => &["click", "↑↓", "enter", "g", "q"],
        (Screen::Picker, _) => &["click", "g", "q"],
        (Screen::Recovery, w)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickFile =>
        {
            path_picker_hints(app, w)
        }
        (Screen::Recovery, w)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickSystem
                && w >= 56 =>
        {
            &["↑↓ scroll", "pgup/pgdn", "enter select", "esc back"]
        }
        (Screen::Recovery, _)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickSystem =>
        {
            &["enter", "esc"]
        }
        (Screen::Recovery, w)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickMode
                && w >= 56 =>
        {
            &["↑↓ move", "enter select", "esc back"]
        }
        (Screen::Recovery, _)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickMode =>
        {
            &["enter", "esc"]
        }
        (Screen::Recovery, w)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickDevice
                && w >= 56 =>
        {
            &["↑↓ scroll", "pgup/pgdn", "enter claim", "esc back"]
        }
        (Screen::Recovery, _)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::PickDevice =>
        {
            &["enter", "esc"]
        }
        (Screen::Recovery, w)
            if app.recovery.model.step() == crate::recovery_model::RecoveryStep::Working
                && w >= 40 =>
        {
            &["restoring", "x cancel"]
        }
        (Screen::Recovery, w) if w >= 40 => &["esc back", "q quit"],
        (Screen::Recovery, _) => &["esc"],
        (Screen::Explorer, w) if app.explorer_phase == crate::app::ExplorerPhase::Path => {
            path_picker_hints(app, w)
        }
        (Screen::Explorer, w)
            if app.explorer_phase == crate::app::ExplorerPhase::Loading && w >= 40 =>
        {
            &["opening disc", "esc cancel"]
        }
        (Screen::Explorer, _) if app.explorer_phase == crate::app::ExplorerPhase::Loading => {
            &["esc"]
        }
        (Screen::Explorer, w)
            if app.explorer_phase == crate::app::ExplorerPhase::Browse && w >= 72 =>
        {
            &[
                "tab pane",
                "↑↓ move",
                "pgup/pgdn",
                "enter open",
                "e export",
                "← back",
                "esc",
            ]
        }
        (Screen::Explorer, w)
            if app.explorer_phase == crate::app::ExplorerPhase::Browse && w >= 40 =>
        {
            &["tab", "↑↓", "enter", "backspace", "esc"]
        }
        (Screen::Explorer, _) => &["esc"],
        (Screen::Repair, w) if app.repair_step == crate::app::RepairStep::Path => {
            path_picker_hints(app, w)
        }
        (Screen::Repair, w) if app.repair_step == crate::app::RepairStep::Detection && w >= 56 => {
            &[
                "← findings",
                "→ detail",
                "↑↓ scroll",
                "enter repairs",
                "esc back",
            ]
        }
        (Screen::Repair, _) if app.repair_step == crate::app::RepairStep::Detection => {
            &["← →", "↑↓", "enter", "esc"]
        }
        (Screen::Repair, w)
            if app.repair_step == crate::app::RepairStep::Suggestions && w >= 72 =>
        {
            &[
                "← findings",
                "→ repairs",
                "↑↓ move",
                "space toggle",
                "enter apply",
                "esc back",
            ]
        }
        (Screen::Repair, _) if app.repair_step == crate::app::RepairStep::Suggestions => {
            &["tab", "↑↓", "space", "enter", "esc"]
        }
        (Screen::Repair, w) if app.repair_step == crate::app::RepairStep::Apply && w >= 56 => &[
            "← findings",
            "→ apply",
            "↑↓ scroll",
            "enter rescan",
            "esc back",
        ],
        (Screen::Repair, _) => &["← →", "↑↓", "enter", "esc"],
        (Screen::Asahi, w) if app.asahi_step == crate::app::AsahiStep::Menu && w >= 64 => {
            &["click open", "↑↓ move", "enter open", "esc back"]
        }
        (Screen::Asahi, _) if app.asahi_step == crate::app::AsahiStep::Menu => {
            &["click", "↑↓", "enter", "esc"]
        }
        (Screen::Asahi, w) if app.asahi_step == crate::app::AsahiStep::Size && w >= 64 => {
            &["←→ size", "enter next", "esc back"]
        }
        (Screen::Asahi, _) if app.asahi_step == crate::app::AsahiStep::Size => {
            &["←→", "enter", "esc"]
        }
        (Screen::Asahi, w)
            if matches!(
                app.asahi_step,
                crate::app::AsahiStep::WaitFile
                    | crate::app::AsahiStep::WaitKernel
                    | crate::app::AsahiStep::WaitM1n1
                    | crate::app::AsahiStep::WaitIpsw
            ) =>
        {
            path_picker_hints(app, w)
        }
        (Screen::Asahi, _) if app.asahi_step == crate::app::AsahiStep::RestoreTarget => {
            &["up/down target", "enter select", "esc IPSW"]
        }
        (Screen::Asahi, w) if app.asahi_step == crate::app::AsahiStep::Source && w >= 56 => {
            &["↑↓ move", "enter select", "esc back"]
        }
        (Screen::Asahi, _) if app.asahi_step == crate::app::AsahiStep::Source => {
            &["↑↓", "enter", "esc"]
        }
        (Screen::Asahi, w) if app.asahi_step == crate::app::AsahiStep::Flavor && w >= 56 => {
            &["↑↓ flavour", "enter select", "esc back"]
        }
        (Screen::Asahi, _) if app.asahi_step == crate::app::AsahiStep::Flavor => {
            &["↑↓", "enter", "esc"]
        }
        (Screen::Asahi, w) if w >= 40 => &["esc back", "q quit"],
        (Screen::Asahi, _) => &["esc"],
    };

    let mut spans = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(
                glyphs().footer_sep.to_string(),
                Style::new().fg(theme::DIM),
            ));
        }
        spans.push(Span::styled(
            (*part).to_string(),
            Style::new().fg(theme::MUTE),
        ));
    }
    Line::from(spans)
}

pub fn render_file_picker(frame: &mut Frame, area: Rect, app: &mut App, title: &str) {
    render_file_picker_with(frame, area, app, title, false, false);
}

pub fn render_file_picker_with(
    frame: &mut Frame,
    area: Rect,
    app: &mut App,
    title: &str,
    clipboard_invalid: bool,
    typed_invalid: bool,
) {
    let file = app.clip.file.as_ref();
    let typed = crate::clip::inspect(app.path_input.trim());
    let typing = app.path_editing || !app.path_input.is_empty();
    let (copy, path) = file_picker_stack(area, file.is_some(), typed.is_some());
    app.hits.path_box = path;

    render_copy_card(frame, copy, file, title, typing, clipboard_invalid);
    render_path_dialog(frame, path, app, typed.as_ref(), typed_invalid);
}

fn file_picker_stack(area: Rect, has_file: bool, has_typed: bool) -> (Rect, Rect) {
    let copy_want: u16 = if has_file { 13 } else { 11 };
    let path_want: u16 = if has_typed { 4 } else { 3 };
    let path_h = path_want.min(area.height.saturating_sub(5)).max(3);
    let gap = u16::from(area.height >= copy_want.saturating_add(path_h).saturating_add(2));
    let copy_h = copy_want
        .min(area.height.saturating_sub(path_h.saturating_add(gap)))
        .max(5);
    let width = {
        let inner = area.width.saturating_sub(4);
        inner.clamp(40.min(inner), 56.min(inner).max(40.min(inner)))
    };
    let group_h = copy_h
        .saturating_add(gap)
        .saturating_add(path_h)
        .min(area.height);
    let group = center(area, width, group_h);
    let copy = Rect {
        x: group.x,
        y: group.y,
        width: group.width,
        height: copy_h.min(
            group
                .height
                .saturating_sub(path_h.saturating_add(gap))
                .max(3),
        ),
    };
    let path_y = copy
        .y
        .saturating_add(copy.height)
        .saturating_add(gap)
        .min(group.y.saturating_add(group.height.saturating_sub(3)));
    let path_w = group.width.saturating_sub(4).max(32.min(group.width));
    let path = Rect {
        x: group.x + group.width.saturating_sub(path_w) / 2,
        y: path_y,
        width: path_w,
        height: group
            .y
            .saturating_add(group.height)
            .saturating_sub(path_y)
            .min(path_h)
            .max(3),
    };
    (copy, path)
}

fn render_copy_card(
    frame: &mut Frame,
    area: Rect,
    file: Option<&FileInfo>,
    title: &str,
    typing: bool,
    invalid: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let border = if file.is_some() && invalid {
        theme::FAIL
    } else if typing {
        theme::HAIRLINE
    } else {
        theme::ICE
    };
    let block = rounded(title, border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let max = inner.width.saturating_sub(4);
    let lines = match file {
        Some(info) => {
            let meta = file_meta(info);
            let modified = info
                .modified
                .as_deref()
                .map(|when| format!("modified  {when}"))
                .unwrap_or_else(|| "modified  unknown".into());
            vec![
                Line::from(Span::styled(
                    if info.kind == FileKind::Directory {
                        "from clipboard  ·  folder  ·  press Enter"
                    } else {
                        "from clipboard"
                    },
                    theme::dim(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    truncate_middle(&info.name, max),
                    theme::title(),
                )),
                Line::from(Span::styled(
                    truncate_middle(&info.path.to_string_lossy(), max),
                    theme::mute(),
                )),
                Line::from(""),
                Line::from(Span::styled(meta, theme::ice())),
                Line::from(Span::styled(modified, theme::dim())),
            ]
        }
        None => vec![
            Line::from(Span::styled("COPY A FILE OR FOLDER", theme::dim())),
            Line::from(Span::styled(
                "press Enter to search a folder for every remaining file",
                theme::mute(),
            )),
            Line::from(""),
            Line::from(Span::styled("waiting", theme::wait())),
            Line::from(Span::styled("no file on the clipboard", theme::dim())),
        ],
    };
    render_cluster(frame, inner, lines);
}

fn render_path_dialog(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    typed: Option<&FileInfo>,
    invalid: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let border = if typed.is_some() && invalid {
        theme::FAIL
    } else if app.path_editing || typed.is_some() {
        theme::ICE
    } else {
        theme::HAIRLINE
    };
    let block = rounded("file or folder path", border);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let field_w = inner.width.saturating_sub(2).max(1);
    let input = if app.path_input.is_empty() {
        if app.path_editing {
            Line::from(vec![
                Span::styled(" ", theme::focus_row()),
                Span::styled("paste or type", theme::dim()),
            ])
        } else {
            Line::from(Span::styled("paste a file or folder path", theme::dim()))
        }
    } else {
        path_field_line(&app.path_input, app.path_cursor, field_w, app.path_editing)
    };
    let well = pad_x(center(inner, inner.width, 1.min(inner.height)), 1);

    if inner.height >= 2
        && let Some(info) = typed
    {
        let [input_row, meta_row] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(center(
                inner,
                inner.width,
                2,
            ));
        frame.render_widget(Paragraph::new(input), pad_x(input_row, 1));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(file_meta(info), theme::ice()))),
            pad_x(meta_row, 1),
        );
        return;
    }

    frame.render_widget(Paragraph::new(input), well);
}

fn pad_x(area: Rect, pad: u16) -> Rect {
    let pad = pad.min(area.width / 2);
    Rect {
        x: area.x.saturating_add(pad),
        y: area.y,
        width: area.width.saturating_sub(pad.saturating_mul(2)),
        height: area.height,
    }
}

fn file_meta(info: &FileInfo) -> String {
    match (info.kind, info.size) {
        (FileKind::Directory, _) => info.kind.label().to_string(),
        (_, Some(bytes)) => format!("{} · {}", info.kind.label(), format_size(bytes)),
        _ => info.kind.label().to_string(),
    }
}

pub fn path_field_line(text: &str, cursor: usize, width: u16, show_cursor: bool) -> Line<'static> {
    let width = width.max(1) as usize;
    let chars: Vec<char> = text.chars().collect();
    let cursor_i = text
        .get(..cursor.min(text.len()))
        .map(|prefix| prefix.chars().count())
        .unwrap_or(chars.len())
        .min(chars.len());
    let total = chars.len() + usize::from(show_cursor);
    let start = if total <= width {
        0
    } else {
        (cursor_i + 1)
            .saturating_sub(width)
            .min(total.saturating_sub(width))
    };
    let end = (start + width).min(total);

    let mut spans = Vec::with_capacity(end.saturating_sub(start));
    for i in start..end {
        if i == chars.len() {
            let style = if show_cursor && i == cursor_i {
                theme::focus_row()
            } else {
                theme::title()
            };
            spans.push(Span::styled(" ", style));
            continue;
        }
        let style = if show_cursor && i == cursor_i {
            theme::focus_row()
        } else {
            theme::title()
        };
        spans.push(Span::styled(chars[i].to_string(), style));
    }
    Line::from(spans)
}
