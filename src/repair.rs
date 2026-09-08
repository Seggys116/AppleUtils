use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, RepairPane, RepairStep, Screen};
use crate::theme;
use crate::ui;

const STEPS: [RepairStep; 4] = [
    RepairStep::Path,
    RepairStep::Detection,
    RepairStep::Suggestions,
    RepairStep::Apply,
];

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.screen != Screen::Repair {
        return;
    }

    let chain_h = if area.width < 68 { 7 } else { 2 };
    let [chain, body] =
        Layout::vertical([Constraint::Length(chain_h), Constraint::Fill(1)]).areas(area);

    render_chain(frame, chain, app);

    match app.repair_step {
        RepairStep::Path => render_path(frame, body, app),
        RepairStep::Detection => render_detection(frame, body, app),
        RepairStep::Suggestions => render_suggestions(frame, body, app),
        RepairStep::Apply => render_apply(frame, body, app),
    }
}

fn render_chain(frame: &mut Frame, area: Rect, app: &App) {
    if area.width < 68 {
        render_chain_vertical(frame, area, app);
        return;
    }

    let current = app.repair_step.index();
    let mut spans = Vec::new();

    for (i, step) in STEPS.iter().enumerate() {
        let reached = i <= current;
        let active = i == current;
        let mark = if active {
            ui::glyphs().step_active
        } else if reached {
            ui::glyphs().step_reached
        } else {
            ui::glyphs().step_todo
        };
        let mark_style = if active {
            theme::ice_bold()
        } else if reached {
            theme::ice()
        } else {
            theme::dim()
        };
        let label_style = if active {
            Style::new().fg(theme::SILVER).add_modifier(Modifier::BOLD)
        } else if reached {
            theme::mute()
        } else {
            theme::dim()
        };

        spans.push(Span::styled(format!("{mark} "), mark_style));
        spans.push(Span::styled(step.label(), label_style));

        if i + 1 < STEPS.len() {
            let connector = if i < current {
                ui::glyphs().chain_done
            } else {
                ui::glyphs().chain_todo
            };
            spans.push(Span::styled(
                connector,
                Style::new().fg(if i < current { theme::ICE } else { theme::DIM }),
            ));
        }
    }

    let [row, rule] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    frame.render_widget(
        Paragraph::new(Line::from(spans)).alignment(Alignment::Center),
        row,
    );
    frame.render_widget(
        Paragraph::new(ui::glyphs().rule_line(rule.width)).style(theme::dim()),
        rule,
    );
}

fn render_chain_vertical(frame: &mut Frame, area: Rect, app: &App) {
    let current = app.repair_step.index();
    let mut lines = Vec::new();
    for (i, step) in STEPS.iter().enumerate() {
        let active = i == current;
        let reached = i <= current;
        let mark = if active {
            ui::glyphs().step_active
        } else if reached {
            ui::glyphs().step_reached
        } else {
            ui::glyphs().step_todo
        };
        let style = if active {
            theme::ice_bold()
        } else if reached {
            theme::mute()
        } else {
            theme::dim()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{mark}  "), style),
            Span::styled(step.label(), style),
        ]));
        if i + 1 < STEPS.len() {
            lines.push(Line::from(Span::styled(
                ui::glyphs().chain_vert,
                theme::dim(),
            )));
        }
    }
    let well = ui::center(area, area.width, (lines.len() as u16).min(area.height));
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), well);
}

fn render_path(frame: &mut Frame, area: Rect, app: &mut App) {
    ui::render_file_picker(frame, area, app, "path");
}

fn render_workspace(frame: &mut Frame, area: Rect, app: &mut App) {
    app.hits.repair_finding_rows.clear();

    let [chrome, panes] =
        Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]).areas(area);
    let [path_row, status_row, bar_row, _] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(chrome);

    render_chrome(frame, path_row, status_row, bar_row, app);

    let side_w = (area.width / 3).clamp(22, 38);
    let [sidebar, main] = Layout::horizontal([Constraint::Length(side_w), Constraint::Fill(1)])
        .spacing(1)
        .areas(panes);

    let findings_focus = app.repair_pane == RepairPane::Findings;
    render_findings_sidebar(frame, sidebar, app, findings_focus);
    render_main(frame, main, app, !findings_focus);
}

fn render_detection(frame: &mut Frame, area: Rect, app: &mut App) {
    render_workspace(frame, area, app);
}

fn render_suggestions(frame: &mut Frame, area: Rect, app: &mut App) {
    render_workspace(frame, area, app);
}

fn render_apply(frame: &mut Frame, area: Rect, app: &mut App) {
    render_workspace(frame, area, app);
}

fn render_chrome(frame: &mut Frame, path_row: Rect, status_row: Rect, bar_row: Rect, app: &App) {
    let path = if app.repair_confirmed.is_empty() {
        "Not selected"
    } else {
        &app.repair_confirmed
    };
    let backend = if app.repair_backend.is_empty() {
        "—"
    } else {
        app.repair_backend.as_str()
    };
    let path_budget = path_row.width.saturating_sub(18);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" image ", Style::new().fg(theme::DIM)),
            Span::styled(ui::truncate_middle(path, path_budget), theme::list_text()),
            Span::styled(format!("  {backend}"), theme::ice()),
        ])),
        path_row,
    );

    let (passed, failed) = finding_counts(&app.repair_findings);
    let mut spans = vec![Span::styled(" ", theme::dim())];
    if app.repair_scanning() {
        spans.push(Span::styled(
            format!("scanning{}", ui::dots_frame(app.tick)),
            theme::wait(),
        ));
    } else if let Some(err) = app.repair_error.as_ref() {
        spans.push(Span::styled("sweep failed", theme::fail()));
        spans.push(Span::styled("  ", theme::dim()));
        spans.push(Span::styled(
            ui::truncate_middle(err, status_row.width.saturating_sub(18)),
            theme::mute(),
        ));
    } else {
        spans.push(Span::styled(format!("{failed} failed"), theme::fail()));
        spans.push(Span::styled("  ·  ", theme::dim()));
        spans.push(Span::styled(format!("{passed} passed"), theme::pass()));
        let skipped = skipped_count(&app.repair_findings);
        if skipped > 0 {
            spans.push(Span::styled("  ·  ", theme::dim()));
            spans.push(Span::styled(format!("{skipped} n/a"), theme::mute()));
        }
        if !app.repair_findings.is_empty() {
            spans.push(Span::styled(
                format!("    {} checks", app.repair_findings.len()),
                theme::mute(),
            ));
        }
    }
    if let Some(label) = ui::progress_label(progress_for(app).0) {
        spans.push(Span::styled("    ", theme::dim()));
        spans.push(Span::styled(label, theme::ice()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), status_row);

    let (fill, palette) = progress_for(app);
    let bar = ui::glow_bar(app.tick, bar_row.width, fill, palette);
    frame.render_widget(Paragraph::new(bar), bar_row);
}

fn progress_for(app: &App) -> (Option<f64>, ui::BarPalette) {
    if app.repair_scanning() {
        return (app.detection_progress.or(Some(0.0)), ui::WORK_BAR);
    }
    if app.repair_applying() {
        return (app.apply_progress.or(Some(0.0)), ui::WORK_BAR);
    }
    if app.repair_step == RepairStep::Apply
        && let Some(progress) = app.apply_progress
    {
        return (Some(progress), ui::WORK_BAR);
    }
    if let Some(progress) = app.detection_progress {
        return (Some(progress), ui::PASS_BAR);
    }
    (Some(0.0), ui::WORK_BAR)
}

fn render_findings_sidebar(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    let (passed, failed) = finding_counts(&app.repair_findings);
    let title = if app.repair_scanning() {
        "findings  scanning".into()
    } else {
        let skipped = skipped_count(&app.repair_findings);
        if skipped > 0 {
            format!("findings  {failed} fail  {passed} pass  {skipped} n/a")
        } else {
            format!("findings  {failed} fail  {passed} pass")
        }
    };
    let block = ui::pane(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if app.repair_scanning() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    format!(" {} scanning", ui::spinner_frame(app.tick)),
                    theme::wait(),
                )),
                Line::from(Span::styled(" waiting for sweep", theme::dim())),
            ]),
            inner,
        );
        return;
    }

    if let Some(err) = app.repair_error.as_ref() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                ui::truncate_middle(err, inner.width.saturating_sub(1)),
                theme::fail(),
            ))),
            inner,
        );
        return;
    }

    if app.repair_findings.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(" no findings", theme::dim()))),
            inner,
        );
        return;
    }

    let order = display_order(&app.repair_findings);
    let height = inner.height as usize;
    app.repair_page_rows = height;
    let visual = order
        .iter()
        .position(|index| *index == app.repair_finding_cursor)
        .unwrap_or(0);
    let start = scroll_start(order.len(), visual, height);
    app.hits.repair_finding_rows = vec![Rect::default(); app.repair_findings.len()];

    let mut lines = Vec::new();
    for (offset, &index) in order.iter().skip(start).take(height).enumerate() {
        let finding = &app.repair_findings[index];
        let hovered = index == app.repair_finding_cursor;
        let marker = if hovered {
            ui::glyphs().focus
        } else {
            ui::glyphs().idle
        };
        let tag = finding.status.tag();
        let tag_style = match finding.status {
            crate::repair_ops::CheckStatus::Pass => theme::pass(),
            crate::repair_ops::CheckStatus::Fail => theme::fail(),
            crate::repair_ops::CheckStatus::NotApplicable => theme::mute(),
        };
        let id_budget = inner.width.saturating_sub(2 + 4 + 2).max(4);
        let id = ui::truncate_middle(&finding.id, id_budget);
        let row_style = if focused && hovered {
            theme::focus_row()
        } else if hovered {
            theme::selected_row()
        } else {
            theme::list_text()
        };
        let mut spans = vec![Span::styled(marker.to_string(), row_style)];
        if focused && hovered {
            spans.push(Span::styled(format!("{tag}  {id}"), theme::focus_row()));
        } else {
            spans.push(Span::styled(format!("{tag}  "), tag_style));
            spans.push(Span::styled(id, row_style));
        }
        lines.push(Line::from(spans));
        app.hits.repair_finding_rows[index] = Rect {
            x: inner.x,
            y: inner.y + offset as u16,
            width: inner.width,
            height: 1,
        };
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_main(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    match app.repair_step {
        RepairStep::Path => {}
        RepairStep::Detection => render_analysis_main(frame, area, app, focused),
        RepairStep::Suggestions => render_repairs_main(frame, area, app, focused),
        RepairStep::Apply => render_apply_main(frame, area, app, focused),
    }
}

fn render_analysis_main(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let block = ui::pane("analysis", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if app.repair_scanning() {
        let bar_w = inner.width.saturating_sub(4).clamp(16, 48);
        let lines = vec![
            Line::from(Span::styled(
                format!("{}  scanning container", ui::spinner_frame(app.tick)),
                theme::wait(),
            )),
            Line::from(""),
            ui::glow_bar(app.tick, bar_w, None, ui::WORK_BAR),
            Line::from(""),
            Line::from(Span::styled(
                ui::truncate_middle(&app.repair_confirmed, inner.width.saturating_sub(2)),
                theme::dim(),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
        return;
    }

    let Some(finding) = app.repair_findings.get(app.repair_finding_cursor) else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("select a finding", theme::dim()))),
            inner,
        );
        return;
    };

    let (tag, style) = match finding.status {
        crate::repair_ops::CheckStatus::Pass => ("PASS", theme::pass()),
        crate::repair_ops::CheckStatus::Fail => ("FAIL", theme::fail()),
        crate::repair_ops::CheckStatus::NotApplicable => ("N/A", theme::mute()),
    };
    let marked = app
        .suggestions
        .iter()
        .find(|item| item.id == finding.id)
        .map(|item| item.enabled);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(tag, style),
            Span::raw("  "),
            Span::styled(finding.id.clone(), theme::title()),
        ]),
        Line::from(""),
        Line::from(Span::styled(finding.summary.clone(), theme::list_text())),
        Line::from(Span::styled(finding.detail.clone(), theme::mute())),
    ];
    if finding.repairable {
        let mark = match marked {
            Some(true) => "queued for repair",
            _ => "repairable  ·  space to queue",
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(mark, theme::ice())));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_repairs_main(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let selected = app.suggestions.iter().filter(|item| item.enabled).count();
    let title = format!("repairs  {selected} queued");
    let block = ui::pane(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if app.suggestions.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no repairable findings",
                theme::mute(),
            ))),
            inner,
        );
        return;
    }

    let height = (inner.height as usize / 2).max(1);
    let start = scroll_start(app.suggestions.len(), app.suggestion_cursor, height);
    let mut lines = Vec::new();
    for (i, item) in app.suggestions.iter().enumerate().skip(start).take(height) {
        let selected = i == app.suggestion_cursor;
        let mark = if item.enabled {
            ui::glyphs().check_on
        } else {
            ui::glyphs().check_off
        };
        let mark_style = if item.enabled {
            theme::ice_bold()
        } else if selected && focused {
            theme::ice()
        } else {
            theme::mute()
        };
        let prefix = if selected {
            ui::glyphs().focus
        } else {
            ui::glyphs().idle
        };
        let label_style = if selected && focused {
            theme::focus_row()
        } else if selected {
            theme::selected_title()
        } else {
            theme::list_text()
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, theme::ice()),
            Span::styled(format!("{mark}  "), mark_style),
            Span::styled(item.label.clone(), label_style),
        ]));
        lines.push(Line::from(vec![
            Span::raw("       "),
            Span::styled(
                ui::truncate_middle(&item.detail, inner.width.saturating_sub(8)),
                theme::dim(),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_apply_main(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let block = ui::pane("apply", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines = Vec::new();
    if app.repair_applying() {
        lines.push(ui::busy_status("applying", app.tick));
        lines.push(Line::from(""));
        lines.push(ui::glow_bar(
            app.tick,
            inner.width.saturating_sub(4).clamp(16, 48),
            app.apply_progress,
            ui::WORK_BAR,
        ));
        if let Some(label) = ui::progress_label(app.apply_progress) {
            lines.push(Line::from(Span::styled(label, theme::ice())));
        }
        for entry in &app.repair_apply_log {
            if entry == "applying" {
                continue;
            }
            let style = if entry.starts_with("failed") {
                theme::fail()
            } else if entry.starts_with("applied") {
                theme::pass()
            } else {
                theme::mute()
            };
            lines.push(Line::from(Span::styled(
                ui::truncate_middle(entry, inner.width.saturating_sub(2)),
                style,
            )));
        }
    } else if app.repair_scanning() {
        lines.push(Line::from(Span::styled(
            format!("{}  rescanning", ui::spinner_frame(app.tick)),
            theme::wait(),
        )));
        lines.push(Line::from(""));
        lines.push(ui::glow_bar(
            app.tick,
            inner.width.saturating_sub(4).clamp(16, 48),
            None,
            ui::WORK_BAR,
        ));
    } else if app.repair_apply_log.is_empty()
        || app
            .repair_apply_log
            .iter()
            .all(|line| line == "no repairs selected")
    {
        lines.push(Line::from(Span::styled(
            "no repairs selected",
            theme::mute(),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "left  findings    esc  repairs",
            theme::dim(),
        )));
    } else {
        for entry in &app.repair_apply_log {
            let style = if entry.starts_with("failed") {
                theme::fail()
            } else if entry.starts_with("applied") {
                theme::pass()
            } else {
                theme::mute()
            };
            lines.push(Line::from(Span::styled(
                ui::truncate_middle(entry, inner.width.saturating_sub(2)),
                style,
            )));
        }
        if let Some(progress) = app.apply_progress {
            lines.push(Line::from(""));
            lines.push(ui::glow_bar(
                app.tick,
                inner.width.saturating_sub(4).clamp(16, 48),
                Some(progress),
                ui::WORK_BAR,
            ));
            if let Some(label) = ui::progress_label(Some(progress)) {
                lines.push(Line::from(Span::styled(label, theme::ice())));
            }
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn finding_counts(findings: &[crate::repair_ops::Finding]) -> (usize, usize) {
    let passed = findings.iter().filter(|finding| finding.passed()).count();
    let failed = findings.iter().filter(|finding| finding.failed()).count();
    (passed, failed)
}

fn skipped_count(findings: &[crate::repair_ops::Finding]) -> usize {
    findings
        .iter()
        .filter(|finding| finding.status == crate::repair_ops::CheckStatus::NotApplicable)
        .count()
}

fn display_order(findings: &[crate::repair_ops::Finding]) -> Vec<usize> {
    let mut fails = Vec::new();
    let mut skipped = Vec::new();
    let mut passes = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        match finding.status {
            crate::repair_ops::CheckStatus::Fail => fails.push(index),
            crate::repair_ops::CheckStatus::NotApplicable => skipped.push(index),
            crate::repair_ops::CheckStatus::Pass => passes.push(index),
        }
    }
    fails.extend(skipped);
    fails.extend(passes);
    fails
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
    use ratatui::style::Color;

    use super::*;
    use crate::apfs_fixture::{self, FIXTURE_VOL_APSB_PADDR, ImageWrap};
    use crate::app::{App, Suggestion};
    use crate::clip::{FileInfo, FileKind};
    use crate::repair_ops::{self, CheckStatus, Finding};

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

    fn draw(app: &mut App) -> (TestBackend, String) {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, app))
            .unwrap();
        let backend = terminal.backend().clone();
        let text = buffer_text(&backend);
        (backend, text)
    }

    fn press(app: &mut App, code: KeyCode) {
        let mut event = KeyEvent::new(code, KeyModifiers::NONE);
        event.kind = KeyEventKind::Press;
        app.handle_event(Event::Key(event));
    }

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                id: "checksum:0".into(),
                status: CheckStatus::Fail,
                summary: "fletcher64 mismatch at nxsb".into(),
                detail: "block 0".into(),
                repairable: true,
            },
            Finding {
                id: "container-magic".into(),
                status: CheckStatus::Pass,
                summary: "NXSB magic present".into(),
                detail: "offset 0".into(),
                repairable: false,
            },
            Finding {
                id: "volume-magic:21".into(),
                status: CheckStatus::Fail,
                summary: "volume superblock magic missing".into(),
                detail: "block 21".into(),
                repairable: true,
            },
        ]
    }

    fn analysis_app() -> App {
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Detection;
        app.repair_confirmed = "/dev/disk3s1".into();
        app.detection_progress = Some(1.0);
        app.repair_backend = "gpt".into();
        app.repair_findings = sample_findings();
        app
    }

    fn suggestions_app(enabled: [bool; 3]) -> App {
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Suggestions;
        app.repair_confirmed = "/dev/disk3s1".into();
        app.repair_findings = sample_findings();
        app.suggestions = vec![
            Suggestion {
                id: "checksum:0".into(),
                label: "rewrite container checksum".into(),
                detail: "seal nxsb fletcher64".into(),
                enabled: enabled[0],
            },
            Suggestion {
                id: "volume-magic:21".into(),
                label: "restore volume magic".into(),
                detail: "write APSB at block 21".into(),
                enabled: enabled[1],
            },
            Suggestion {
                id: "omap-root".into(),
                label: "rebuild object map".into(),
                detail: "rewrite omap root".into(),
                enabled: enabled[2],
            },
        ];
        app
    }

    fn apply_app() -> App {
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Apply;
        app.repair_confirmed = "/dev/disk3s1".into();
        app.repair_apply_log = vec![
            "applied checksum:0".into(),
            "failed volume-magic:21: still invalid".into(),
        ];
        app.repair_findings = sample_findings();
        app
    }

    fn label_cell_has_fg(backend: &TestBackend, label: &str, color: Color) -> bool {
        let buffer = backend.buffer();
        let area = buffer.area();
        let needle: Vec<char> = label.chars().collect();
        if needle.is_empty() || area.width < needle.len() as u16 {
            return false;
        }
        for y in 0..area.height {
            for x in 0..=area.width - needle.len() as u16 {
                let matched = needle.iter().enumerate().all(|(i, ch)| {
                    buffer[Position::new(x + i as u16, y)].symbol() == ch.to_string()
                });
                if !matched {
                    continue;
                }
                if needle
                    .iter()
                    .enumerate()
                    .any(|(i, _)| buffer[Position::new(x + i as u16, y)].fg == color)
                {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn analysis_pass_fail_labels_use_theme_colors() {
        let mut app = analysis_app();
        let (backend, text) = draw(&mut app);
        assert!(text.contains("PASS"), "{text}");
        assert!(text.contains("FAIL"), "{text}");
        assert!(
            label_cell_has_fg(&backend, "PASS", theme::PASS),
            "PASS label must use theme::PASS\n{text}"
        );
        assert!(
            label_cell_has_fg(&backend, "FAIL", theme::FAIL),
            "FAIL label must use theme::FAIL\n{text}"
        );
    }

    #[test]
    fn multiple_repair_paths_toggle_then_enter_applies() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        repair_ops::inject_checksum_fault(&image, 0).unwrap();
        repair_ops::inject_volume_magic_fault(&image, FIXTURE_VOL_APSB_PADDR).unwrap();

        let report = repair_ops::sweep(&image).expect("sweep mutated image");
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_confirmed = image.to_string_lossy().into_owned();
        app.ingest_repair_report(report);
        app.repair_step = RepairStep::Suggestions;
        app.repair_pane = RepairPane::Main;
        assert!(
            app.suggestions.len() >= 2,
            "mutated image must expose at least two repair paths: {:?}",
            app.suggestions
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
        );

        press(&mut app, KeyCode::Char(' '));
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char(' '));
        let enabled: Vec<String> = app
            .suggestions
            .iter()
            .filter(|item| item.enabled)
            .map(|item| item.id.clone())
            .collect();
        assert_eq!(enabled.len(), 2, "{enabled:?}");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.repair_step, RepairStep::Apply);
        app.drain_repair_job();

        let after = repair_ops::format_dump(&repair_ops::sweep(&image).expect("sweep after apply"));
        for id in &enabled {
            let still_fail = after.lines().any(|line| {
                let toks: Vec<&str> = line.split_whitespace().collect();
                toks.contains(&"FAIL") && toks.iter().any(|tok| *tok == id)
            });
            assert!(
                !still_fail,
                "selected {id} should be gone after apply:\n{after}"
            );
        }
        let volume_magic = format!("volume-magic:{FIXTURE_VOL_APSB_PADDR}");
        if !enabled.iter().any(|id| id == "checksum:0") {
            assert!(
                after.lines().any(|line| {
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    toks.contains(&"FAIL") && toks.contains(&"checksum:0")
                }),
                "unselected checksum:0 should remain:\n{after}"
            );
        }
        if !enabled.iter().any(|id| id == &volume_magic) {
            assert!(
                after.lines().any(|line| {
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    toks.contains(&"FAIL") && toks.contains(&volume_magic.as_str())
                }),
                "unselected {volume_magic} should remain:\n{after}"
            );
        }
    }

    #[test]
    fn analysis_puts_pass_fail_in_a_sidebar_with_a_progress_bar() {
        let mut app = analysis_app();
        let (backend, text) = draw(&mut app);
        assert!(text.contains("findings"), "{text}");
        assert!(text.contains("FAIL"), "{text}");
        assert!(text.contains("PASS"), "{text}");
        assert!(
            text.contains('━') || text.contains('─'),
            "progress bar missing:\n{text}"
        );
        let fail_col = first_col(&backend, "FAIL").expect("FAIL column");
        assert!(
            fail_col < 40,
            "FAIL should sit in the left sidebar, col={fail_col}\n{text}"
        );
    }

    #[test]
    fn findings_sidebar_scrolls_with_keys() {
        let mut app = analysis_app();
        app.repair_findings = (0..24)
            .map(|i| Finding {
                id: format!("check:{i:02}"),
                status: if i % 3 == 0 {
                    CheckStatus::Fail
                } else {
                    CheckStatus::Pass
                },
                summary: format!("summary {i}"),
                detail: format!("detail {i}"),
                repairable: i % 3 == 0,
            })
            .collect();
        app.repair_finding_cursor = 0;
        let (_backend, before) = draw(&mut app);
        assert!(before.contains("check:00"), "{before}");
        for _ in 0..20 {
            press(&mut app, KeyCode::Down);
        }
        let (_backend, after) = draw(&mut app);
        assert!(
            after.contains("check:19") || after.contains("check:18"),
            "scrolled list should show later findings:\n{after}"
        );
        assert!(
            !after.contains("check:00"),
            "first finding should scroll off:\n{after}"
        );
    }

    fn first_col(backend: &TestBackend, needle: &str) -> Option<u16> {
        let buffer = backend.buffer();
        let area = buffer.area();
        let chars: Vec<char> = needle.chars().collect();
        for y in 0..area.height {
            for x in 0..=area.width.saturating_sub(chars.len() as u16) {
                let matched = chars.iter().enumerate().all(|(i, ch)| {
                    buffer[Position::new(x + i as u16, y)].symbol() == ch.to_string()
                });
                if matched {
                    return Some(x);
                }
            }
        }
        None
    }

    #[test]
    fn left_arrow_returns_focus_to_findings() {
        let mut app = suggestions_app([false, false, false]);
        app.repair_pane = RepairPane::Main;
        press(&mut app, KeyCode::Left);
        assert_eq!(app.repair_pane, RepairPane::Findings);
        press(&mut app, KeyCode::Right);
        assert_eq!(app.repair_pane, RepairPane::Main);
        press(&mut app, KeyCode::Char('h'));
        assert_eq!(app.repair_pane, RepairPane::Findings);
    }

    #[test]
    fn enter_without_a_queued_repair_stays_on_repairs() {
        let mut app = suggestions_app([false, false, false]);
        app.repair_pane = RepairPane::Main;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.repair_step, RepairStep::Suggestions);
        assert!(app.repair_apply_log.is_empty() || !app.apply_progress.is_some_and(|p| p >= 1.0));
    }

    #[test]
    fn scanning_keeps_findings_sidebar_and_a_progress_bar() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Path;
        app.clip.set_file(FileInfo {
            path: image.clone(),
            name: "disk.img".into(),
            kind: FileKind::File,
            size: Some(1),
            modified: None,
        });
        press(&mut app, KeyCode::Enter);
        assert!(app.repair_scanning());
        assert_eq!(app.repair_step, RepairStep::Detection);
        let (_backend, text) = draw(&mut app);
        if let Ok(dir) = std::env::var("APPLE_UTILS_UI_DUMP") {
            std::fs::write(std::path::Path::new(&dir).join("repair-scan.txt"), &text)
                .expect("repair scan dump");
        }
        assert!(text.contains("findings"), "{text}");
        assert!(text.contains("scanning"), "{text}");
        assert!(
            text.contains(ui::glyphs().bar_fill) || text.contains(ui::glyphs().bar_track),
            "scan must keep a progress bar:\n{text}"
        );
        assert!(
            !text.contains("not implemented"),
            "scanning must not take over with a stub:\n{text}"
        );
        app.drain_repair_job();
        assert!(!app.repair_scanning());
    }

    #[test]
    fn applying_keeps_ticking_wait_chrome() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        apfs_fixture::write_fixture(&image, ImageWrap::RawGpt).unwrap();
        repair_ops::inject_checksum_fault(&image, 0).unwrap();
        let report = repair_ops::sweep(&image).expect("sweep");
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_confirmed = image.to_string_lossy().into_owned();
        app.ingest_repair_report(report);
        app.repair_step = RepairStep::Suggestions;
        app.repair_pane = RepairPane::Main;
        if let Some(item) = app.suggestions.first_mut() {
            item.enabled = true;
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.repair_step, RepairStep::Apply);
        let (_backend, text) = draw(&mut app);
        assert!(text.contains("apply"), "{text}");
        assert!(
            text.contains("applying")
                || text.contains(ui::glyphs().bar_fill)
                || text.contains(ui::glyphs().bar_track)
                || ui::glyphs().spinner.iter().any(|ch| text.contains(*ch)),
            "apply must show wait/progress:\n{text}"
        );
        for _ in 0..3 {
            app.prepare();
            let (_backend, frame) = draw(&mut app);
            assert!(!frame.trim().is_empty(), "{frame}");
            assert!(
                frame.contains("apply") || frame.contains("findings"),
                "{frame}"
            );
        }
        app.drain_repair_job();
    }

    #[test]
    fn repair_screens_omit_not_implemented() {
        let mut empty_repairs = suggestions_app([false, false, false]);
        empty_repairs.suggestions.clear();
        for mut app in [
            analysis_app(),
            suggestions_app([true, false, false]),
            empty_repairs,
            apply_app(),
        ] {
            let (_backend, text) = draw(&mut app);
            assert!(
                !text.contains("not implemented"),
                "repair screen {:?} still shows the stub\n{text}",
                app.repair_step
            );
        }
    }
}
