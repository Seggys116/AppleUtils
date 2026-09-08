use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use crate::geom::{PlateClass, center, plate_class};
use crate::glyphs::{Glyphs, dots_frame, glyphs, spinner_frame};
use crate::theme;

#[derive(Debug, Clone, Copy)]
pub struct BarPalette {
    pub hot: Color,
    pub soft: Color,
    pub rest: Color,
}

pub const WAIT_BAR: BarPalette = BarPalette {
    hot: theme::WAIT,
    soft: theme::WAIT_SOFT,
    rest: theme::DIM,
};

pub const WORK_BAR: BarPalette = BarPalette {
    hot: theme::ICE,
    soft: theme::ICE_SOFT,
    rest: theme::DIM,
};

pub const PASS_BAR: BarPalette = BarPalette {
    hot: theme::PASS,
    soft: theme::ICE,
    rest: theme::DIM,
};

fn chrome(border: Color, bg: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_set(glyphs().border_set())
        .border_style(Style::new().fg(border))
        .style(Style::new().bg(bg).fg(theme::SILVER))
}

pub fn rounded(title: &str, border: Color) -> Block<'static> {
    let mut block = chrome(border, theme::SURFACE);

    if !title.is_empty() {
        block = block.title(
            Line::from(format!(" {title} "))
                .style(Style::new().fg(theme::MUTE))
                .centered(),
        );
    }
    block
}

pub fn pane(title: &str, focused: bool) -> Block<'static> {
    let border = if focused { theme::ICE } else { theme::HAIRLINE };
    let title_style = if focused {
        Style::new().fg(theme::SILVER).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(theme::MUTE)
    };
    chrome(border, theme::SURFACE).title(
        Line::from(format!(" {title} "))
            .style(title_style)
            .centered(),
    )
}

pub fn choice_block(selected: bool) -> Block<'static> {
    let border = if selected {
        theme::ICE
    } else {
        theme::HAIRLINE
    };
    let bg = if selected {
        theme::RAISED
    } else {
        theme::SURFACE
    };
    chrome(border, bg)
}

pub fn render_scrollbar(
    frame: &mut Frame,
    area: Rect,
    content_len: usize,
    viewport_len: usize,
    position: usize,
) {
    if area.width == 0 || area.height == 0 || content_len <= viewport_len.max(1) {
        return;
    }
    let pack = glyphs();
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(Some(pack.scroll_track))
        .thumb_symbol(pack.scroll_thumb)
        .track_style(theme::dim())
        .thumb_style(theme::ice());
    let mut state = ScrollbarState::new(content_len)
        .position(position)
        .viewport_content_length(viewport_len.max(1));
    frame.render_stateful_widget(scrollbar, area, &mut state);
}

pub fn render_choice_card(frame: &mut Frame, area: Rect, name: &str, blurb: &str, selected: bool) {
    let block = choice_block(selected);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let pack = glyphs();
    let marker = if selected { pack.select } else { pack.idle };
    let name_style = if selected {
        theme::selected_title()
    } else {
        theme::mute()
    };

    let mut lines = vec![Line::from(vec![
        Span::styled(marker.to_string(), theme::ice()),
        Span::styled(name.to_string(), name_style),
    ])];

    if inner.height >= 2 {
        lines.push(Line::from(vec![
            Span::raw(pack.idle),
            Span::styled(blurb.to_string(), theme::dim()),
        ]));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn render_empty_well(frame: &mut Frame, area: Rect, title: &str, note: &str) {
    let block = rounded(title, theme::HAIRLINE);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(Span::styled("not implemented", theme::mute())).centered(),
        Line::from(""),
        Line::from(Span::styled(note, theme::dim())).centered(),
    ];
    let well = center(inner, inner.width.saturating_sub(2), 3);
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), well);
}

pub fn render_cluster(frame: &mut Frame, area: Rect, lines: Vec<Line>) {
    if area.width == 0 || area.height == 0 || lines.is_empty() {
        return;
    }
    let height = (lines.len() as u16).min(area.height);
    let well = center(area, area.width.saturating_sub(2).max(1), height);
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), well);
}

pub fn glow_bar(tick: u64, width: u16, fill: Option<f64>, palette: BarPalette) -> Line<'static> {
    glow_bar_with(glyphs(), tick, width, fill, palette)
}

pub fn glow_bar_with(
    glyphs: Glyphs,
    tick: u64,
    width: u16,
    fill: Option<f64>,
    palette: BarPalette,
) -> Line<'static> {
    let w = width as usize;
    if w < 4 {
        return Line::from("");
    }

    let filled = match fill {
        None => w,
        Some(progress) => ((progress.clamp(0.0, 1.0) * w as f64).round() as usize).min(w),
    };
    let travel = if fill.is_none() { w } else { filled.max(1) };
    let pos = (tick as usize / 2) % travel;

    let mut spans = Vec::with_capacity(w);
    for i in 0..w {
        let in_fill = fill.is_none() || i < filled;
        let dist = if in_fill { i.abs_diff(pos) } else { usize::MAX };
        let (ch, color) = if fill.is_none() {
            if dist == 0 {
                (glyphs.bar_fill, palette.hot)
            } else if dist == 1 {
                (glyphs.bar_track, palette.soft)
            } else {
                (glyphs.bar_track, palette.rest)
            }
        } else if i < filled {
            if dist <= 1 {
                (glyphs.bar_fill, palette.hot)
            } else {
                (glyphs.bar_fill, palette.soft)
            }
        } else {
            (glyphs.bar_track, palette.rest)
        };
        spans.push(Span::styled(ch.to_string(), Style::new().fg(color)));
    }
    Line::from(spans)
}

pub fn render_glow_bar(
    frame: &mut Frame,
    area: Rect,
    tick: u64,
    fill: Option<f64>,
    palette: BarPalette,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let bar_w = area.width.saturating_sub(6).clamp(16, 36).min(area.width);
    let bar_area = center(area, bar_w, 1);
    frame.render_widget(
        Paragraph::new(glow_bar(tick, bar_w, fill, palette)),
        bar_area,
    );
}

pub fn progress_label(fill: Option<f64>) -> Option<String> {
    fill.map(|progress| format!("{}%", (progress.clamp(0.0, 1.0) * 100.0).round() as u16))
}

pub fn busy_message(stage: &str, tick: u64) -> Line<'static> {
    Line::from(vec![
        Span::styled(stage.to_string(), theme::wait()),
        Span::styled(dots_frame(tick), theme::wait()),
    ])
}

pub fn busy_status(stage: &str, tick: u64) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}  {stage}", spinner_frame(tick)), theme::wait()),
        Span::styled(dots_frame(tick), theme::wait()),
    ])
}

pub struct WaitPlate<'a> {
    pub title: &'a str,
    pub message: &'a str,
    pub detail: Option<&'a str>,
    pub tick: u64,
    pub fill: Option<f64>,
    pub palette: BarPalette,
    pub border: Color,
    pub class: PlateClass,
    pub height: u16,
}

impl<'a> WaitPlate<'a> {
    pub fn opening(message: &'a str, detail: Option<&'a str>, tick: u64) -> Self {
        Self {
            title: "opening",
            message,
            detail,
            tick,
            fill: None,
            palette: WAIT_BAR,
            border: theme::WAIT,
            class: PlateClass::Card,
            height: 11,
        }
    }

    pub fn work(message: &'a str, tick: u64, fill: Option<f64>) -> Self {
        Self {
            title: "work",
            message,
            detail: None,
            tick,
            fill,
            palette: WORK_BAR,
            border: theme::WAIT,
            class: PlateClass::Wait,
            height: 11,
        }
    }

    pub fn recovery(tick: u64) -> Self {
        Self {
            title: "recovery",
            message: "Waiting for devices",
            detail: Some("watching for supported devices"),
            tick,
            fill: None,
            palette: WAIT_BAR,
            border: theme::WAIT,
            class: PlateClass::Wait,
            height: 9,
        }
    }
}

pub fn render_wait_plate(frame: &mut Frame, area: Rect, spec: WaitPlate<'_>) {
    let dialog = plate_class(area, spec.class, spec.height);
    let block = rounded(spec.title, spec.border);
    let inner = block.inner(dialog);
    frame.render_widget(block, dialog);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let [_, spin, msg, bar, detail, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(inner);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            spinner_frame(spec.tick),
            theme::wait(),
        )))
        .alignment(Alignment::Center),
        spin,
    );
    let mut msg_spans = vec![
        Span::styled(spec.message.to_string(), theme::wait()),
        Span::styled(dots_frame(spec.tick), theme::wait()),
    ];
    if spec.detail.is_some()
        && let Some(label) = progress_label(spec.fill)
    {
        msg_spans.push(Span::styled(format!("  {label}"), theme::dim()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(msg_spans)).alignment(Alignment::Center),
        msg,
    );
    render_glow_bar(frame, bar, spec.tick, spec.fill, spec.palette);

    let detail_text = spec
        .detail
        .map(|text| truncate_middle(text, inner.width.saturating_sub(4)))
        .or_else(|| progress_label(spec.fill))
        .unwrap_or_default();
    if !detail_text.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(detail_text, theme::dim())))
                .alignment(Alignment::Center),
            detail,
        );
    }
}

pub fn render_status_wait(
    frame: &mut Frame,
    status: Rect,
    bar: Option<Rect>,
    tick: u64,
    stage: &str,
    fill: Option<f64>,
    palette: BarPalette,
) {
    if status.width > 0 && status.height > 0 {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ", theme::dim()),
                Span::styled(format!("{}  {stage}", spinner_frame(tick)), theme::wait()),
                Span::styled(dots_frame(tick), theme::wait()),
            ])),
            status,
        );
    }
    if let Some(bar) = bar
        && bar.width > 0
        && bar.height > 0
    {
        let line = glow_bar(tick, bar.width, fill, palette);
        frame.render_widget(Paragraph::new(line), bar);
    }
}

pub fn truncate_middle(s: &str, max: u16) -> String {
    truncate_middle_with(glyphs(), s, max)
}

pub fn truncate_middle_with(glyphs: Glyphs, s: &str, max: u16) -> String {
    let max = max as usize;
    if max < 4 {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let head = keep / 2;
    let tail = keep - head;
    let mut out: String = chars[..head].iter().collect();
    out.push(glyphs.ellipsis);
    out.extend(chars[chars.len() - tail..].iter());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::{PlateClass, contains_rect, inset, plate_class};
    use crate::glyphs::GLYPHS;
    use ratatui::layout::Rect;

    #[test]
    fn glow_bar_matches_width() {
        assert_eq!(glow_bar(0, 20, None, WAIT_BAR).spans.len(), 20);
        assert_eq!(glow_bar(4, 20, Some(0.5), WORK_BAR).spans.len(), 20);
    }

    #[test]
    fn progress_fill_uses_glyph_tokens() {
        let line = glow_bar(0, 20, Some(0.5), WORK_BAR);
        let fill = GLYPHS.bar_fill.to_string();
        let track = GLYPHS.bar_track.to_string();
        let filled = line
            .spans
            .iter()
            .filter(|span| span.content.as_ref() == fill)
            .count();
        let rest = line
            .spans
            .iter()
            .filter(|span| span.content.as_ref() == track)
            .count();
        assert_eq!(filled, 10);
        assert_eq!(rest, 10);
    }

    #[test]
    fn ascii_bar_tokens_render() {
        let line = glow_bar_with(crate::glyphs::ASCII, 0, 20, Some(0.5), WORK_BAR);
        let filled = line
            .spans
            .iter()
            .filter(|span| span.content.as_ref() == "=")
            .count();
        let rest = line
            .spans
            .iter()
            .filter(|span| span.content.as_ref() == "-")
            .count();
        assert_eq!(filled, 10);
        assert_eq!(rest, 10);
    }

    #[test]
    fn changing_bar_tokens_changes_the_rendered_line() {
        let custom = Glyphs {
            bar_fill: '#',
            bar_track: '.',
            ..GLYPHS
        };
        let line = glow_bar_with(custom, 0, 20, Some(0.5), WORK_BAR);
        let filled = line
            .spans
            .iter()
            .filter(|span| span.content.as_ref() == "#")
            .count();
        let rest = line
            .spans
            .iter()
            .filter(|span| span.content.as_ref() == ".")
            .count();
        assert_eq!(filled, 10);
        assert_eq!(rest, 10);
        assert!(
            line.spans
                .iter()
                .all(|span| span.content.as_ref() != GLYPHS.bar_fill.to_string())
        );
    }

    #[test]
    fn spinner_and_dots_come_from_the_token_table() {
        assert_eq!(spinner_frame(0), GLYPHS.spinner[0]);
        assert_eq!(spinner_frame(2), GLYPHS.spinner[1]);
        assert_eq!(dots_frame(0), GLYPHS.dots[0]);
        assert_eq!(dots_frame(6), GLYPHS.dots[1]);
        let custom = Glyphs {
            spinner: ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
            dots: ["x", "xx", "xxx", "xxxx"],
            ..GLYPHS
        };
        assert_eq!(custom.spinner_at(0), "a");
        assert_eq!(custom.spinner_at(2), "b");
        assert_eq!(custom.dots_at(0), "x");
        assert_eq!(custom.dots_at(6), "xx");
        let line = busy_message("reading", 0);
        assert!(
            line.spans
                .iter()
                .any(|span| span.content.as_ref() == GLYPHS.dots[0])
        );
    }

    #[test]
    fn scrollbar_uses_glyph_tokens_and_hides_when_the_list_fits() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut terminal = Terminal::new(TestBackend::new(2, 8)).unwrap();
        terminal
            .draw(|frame| render_scrollbar(frame, frame.area(), 20, 4, 0))
            .unwrap();
        let overflow = column_text(terminal.backend().buffer(), 2, 8);
        assert!(
            overflow.contains(GLYPHS.scroll_thumb),
            "thumb missing: {overflow:?}"
        );
        assert!(
            overflow.contains(GLYPHS.scroll_track),
            "track missing: {overflow:?}"
        );

        terminal
            .draw(|frame| render_scrollbar(frame, frame.area(), 3, 8, 0))
            .unwrap();
        let fits = column_text(terminal.backend().buffer(), 2, 8);
        assert!(
            !fits.contains(GLYPHS.scroll_thumb) && !fits.contains(GLYPHS.scroll_track),
            "fitting list must not draw a rail: {fits:?}"
        );
    }

    #[test]
    fn scrollbar_thumb_moves_with_position() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut terminal = Terminal::new(TestBackend::new(1, 10)).unwrap();
        terminal
            .draw(|frame| render_scrollbar(frame, frame.area(), 40, 5, 0))
            .unwrap();
        let top = thumb_rows(terminal.backend().buffer(), 1, 10);
        terminal
            .draw(|frame| render_scrollbar(frame, frame.area(), 40, 5, 39))
            .unwrap();
        let bottom = thumb_rows(terminal.backend().buffer(), 1, 10);
        assert!(!top.is_empty() && !bottom.is_empty(), "{top:?} {bottom:?}");
        assert!(
            bottom.iter().copied().max() > top.iter().copied().max(),
            "thumb should travel down the rail: top={top:?} bottom={bottom:?}"
        );
    }

    fn column_text(buffer: &ratatui::buffer::Buffer, width: u16, height: u16) -> String {
        use ratatui::layout::Position;
        let mut out = String::new();
        for y in 0..height {
            out.push_str(buffer[Position::new(width.saturating_sub(1), y)].symbol());
        }
        out
    }

    fn thumb_rows(buffer: &ratatui::buffer::Buffer, width: u16, height: u16) -> Vec<u16> {
        use ratatui::layout::Position;
        let mut rows = Vec::new();
        for y in 0..height {
            for x in 0..width {
                if buffer[Position::new(x, y)].symbol() == GLYPHS.scroll_thumb {
                    rows.push(y);
                }
            }
        }
        rows
    }

    #[test]
    fn progress_label_rounds() {
        assert_eq!(progress_label(Some(0.624)).as_deref(), Some("62%"));
        assert_eq!(progress_label(None), None);
    }

    #[test]
    fn positioning_helpers_return_in_bounds_rects() {
        let area = Rect::new(2, 3, 72, 22);
        let inner = inset(area, 3, 1);
        let card = plate_class(area, PlateClass::Card, 11);
        let wait = plate_class(area, PlateClass::Wait, 9);
        assert!(contains_rect(area, inner));
        assert!(contains_rect(area, card));
        assert!(contains_rect(area, wait));
        assert_eq!(center(area, 20, 4).width, 20);
        assert_eq!(center(area, 20, 4).height, 4);
    }
}
