use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, AsahiAction, AsahiSource, AsahiStep, Screen};
use crate::asahi_ops::{SLIDER_MAX_GB, SLIDER_MIN_GB};
use crate::theme;
use crate::ui;

const SOURCES: [AsahiSource; 2] = [AsahiSource::Latest, AsahiSource::Custom];

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.screen != Screen::Asahi {
        return;
    }

    match app.asahi_step {
        AsahiStep::Menu => render_menu(frame, area, app),
        AsahiStep::Size => render_size(frame, area, app),
        AsahiStep::WaitFile => {
            let title = match app.asahi_action {
                AsahiAction::Update => "existing disc",
                AsahiAction::Install => "output folder",
            };
            ui::render_file_picker(frame, area, app, title);
        }
        AsahiStep::WaitKernel => {
            ui::render_file_picker(frame, area, app, "kernel");
        }
        AsahiStep::WaitM1n1 => {
            ui::render_file_picker(frame, area, app, "m1n1");
        }
        AsahiStep::WaitIpsw => {
            let rows = Layout::vertical([Constraint::Length(5), Constraint::Min(0)]).split(area);
            let hint = app.asahi_ipsw_hint();
            let message = app.asahi_error.as_deref().unwrap_or(&hint);
            frame.render_widget(Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: false }), rows[0]);
            ui::render_file_picker(frame, rows[1], app, "local restore IPSW");
        }
        AsahiStep::RestoreTarget => {
            if let Some(info) = &app.asahi_restore_info {
                let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);
                frame.render_widget(Paragraph::new(format!("Restore {} ({})\nSelect the target from this IPSW", info.product_version, info.product_build)), rows[0]);
                let items = info.identities.iter().map(|target| ratatui::widgets::ListItem::new(
                    format!("{}  ({}, chip {:#x})", crate::ramrod::boards::describe_board(&target.board, None).title, target.board, target.chip_id)));
                let list = ratatui::widgets::List::new(items).highlight_symbol("> ");
                let mut state = ratatui::widgets::ListState::default().with_selected(Some(app.asahi_restore_cursor));
                frame.render_stateful_widget(list, rows[1], &mut state);
            }
        }
        AsahiStep::Source => render_source(frame, area, app),
        AsahiStep::Flavor => render_flavors(frame, area, app),
        AsahiStep::Work | AsahiStep::InspectIpsw => render_work(frame, area, app),
        AsahiStep::Done => render_done(frame, area, app),
    }
}

fn render_menu(frame: &mut Frame, area: Rect, app: &mut App) {
    let rects = stacked_cards::<2>(area);
    app.hits.asahi_actions = rects;
    for (i, (action, rect)) in AsahiAction::ALL.iter().zip(rects).enumerate() {
        if rect.width > 0 && rect.height > 0 {
            ui::render_choice_card(
                frame,
                rect,
                action.name(),
                action.blurb(),
                i == app.asahi_action_cursor,
            );
        }
    }
}

fn render_source(frame: &mut Frame, area: Rect, app: &mut App) {
    let rects = stacked_cards::<2>(area);
    app.hits.asahi_sources = rects;
    for (i, (source, rect)) in SOURCES.iter().zip(rects).enumerate() {
        if rect.width > 0 && rect.height > 0 {
            ui::render_choice_card(
                frame,
                rect,
                source.name(),
                source.blurb(app.asahi_action),
                i == app.asahi_source_cursor,
            );
        }
    }
}

fn render_flavors(frame: &mut Frame, area: Rect, app: &mut App) {
    let n = app.asahi_flavors.len().clamp(1, 8);
    let rects = stacked_cards_n(area, n);
    app.hits.asahi_flavors = [Rect::default(); 8];
    for (i, rect) in rects.into_iter().enumerate() {
        app.hits.asahi_flavors[i] = rect;
        if let Some(flavor) = app.asahi_flavors.get(i)
            && rect.width > 0
            && rect.height > 0
        {
            ui::render_choice_card(
                frame,
                rect,
                &format!("{}  {}", flavor.slug, flavor.name),
                flavor.default_os_name.as_str(),
                i == app.asahi_flavor_cursor,
            );
        }
    }
}

fn render_size(frame: &mut Frame, area: Rect, app: &mut App) {
    let dialog = ui::plate_class(
        area,
        ui::PlateClass::Card,
        11.min(area.height.saturating_sub(1)).max(8),
    );
    let block = ui::rounded("DISC SIZE", theme::ICE);
    let inner = block.inner(dialog);
    frame.render_widget(block, dialog);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let [_, size_row, _, bar_row, labels_row, _] = Layout::vertical([
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
            format!("{} GB", app.asahi_size_gb),
            theme::ice_bold(),
        )))
        .alignment(Alignment::Center),
        size_row,
    );

    let bar_w = bar_row
        .width
        .saturating_sub(4)
        .clamp(16, 40)
        .min(bar_row.width);
    let bar_area = ui::center(bar_row, bar_w, 1);
    app.hits.asahi_slider = bar_area;
    frame.render_widget(
        Paragraph::new(slider_bar(bar_w, app.asahi_size_gb, app.asahi_slider_hover)),
        bar_area,
    );

    let labels_area = ui::center(labels_row, bar_w, 1);
    let [left, right] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(labels_area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{SLIDER_MIN_GB} GB"),
            theme::dim(),
        ))),
        left,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{SLIDER_MAX_GB} GB"),
            theme::dim(),
        )))
        .alignment(Alignment::Right),
        right,
    );
}

fn render_work(frame: &mut Frame, area: Rect, app: &App) {
    let stage = if app.asahi_status.is_empty() {
        "preparing"
    } else {
        app.asahi_status.as_str()
    };
    ui::render_wait_plate(
        frame,
        area,
        ui::WaitPlate::work(stage, app.tick, app.asahi_progress),
    );
}

fn render_done(frame: &mut Frame, area: Rect, app: &App) {
    let failed = app.asahi_error.is_some();
    let dialog = ui::plate_class(
        area,
        ui::PlateClass::Card,
        11.min(area.height.saturating_sub(1)).max(8),
    );
    let block = ui::rounded(
        if failed { "error" } else { "done" },
        if failed { theme::WAIT } else { theme::ICE },
    );
    let inner = block.inner(dialog);
    frame.render_widget(block, dialog);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let message = app
        .asahi_error
        .as_deref()
        .unwrap_or(app.asahi_status.as_str());
    let style = if failed { theme::wait() } else { theme::ice() };
    let rows = Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).split(inner);
    frame.render_widget(Paragraph::new(if failed { "failed" } else { "finished" }).style(style).alignment(Alignment::Center), rows[0]);
    frame.render_widget(Paragraph::new(message).style(style).wrap(ratatui::widgets::Wrap { trim: false }), rows[1]);
}

fn stacked_cards<const N: usize>(area: Rect) -> [Rect; N] {
    let v = stacked_cards_n(area, N);
    let mut cards = [Rect::default(); N];
    for (i, rect) in v.into_iter().take(N).enumerate() {
        cards[i] = rect;
    }
    cards
}

fn stacked_cards_n(area: Rect, n: usize) -> Vec<Rect> {
    let n = n.max(1) as u16;
    let inner = ui::inset(area, 2, 1);
    let card_gap = u16::from(inner.height >= n * 6);
    let card_h = if inner.height >= n * 5 { 4 } else { 3 };
    let cards_h = card_h * n + card_gap * n.saturating_sub(1);
    let card_w = inner
        .width
        .saturating_sub(2)
        .min(66)
        .max(36.min(inner.width));
    let group = ui::center(inner, inner.width, cards_h.min(inner.height));
    let card_x = group.x + group.width.saturating_sub(card_w) / 2;
    let mut cards = Vec::with_capacity(n as usize);
    let mut cy = group.y;
    let remain = group.height.max(1);
    for _ in 0..n {
        let height = card_h.min(remain.saturating_sub(cy.saturating_sub(group.y)).max(1));
        cards.push(Rect {
            x: card_x,
            y: cy,
            width: card_w.min(group.width),
            height,
        });
        cy = cy.saturating_add(card_h + card_gap);
    }
    cards
}

fn slider_bar(width: u16, gb: u32, hover: bool) -> Line<'static> {
    let w = width as usize;
    if w == 0 {
        return Line::from("");
    }
    let span = SLIDER_MAX_GB - SLIDER_MIN_GB;
    let t = f64::from(gb.saturating_sub(SLIDER_MIN_GB)) / f64::from(span.max(1));
    let filled = ((t.clamp(0.0, 1.0) * w as f64).round() as usize).min(w);
    let hot = if hover { theme::ICE } else { theme::ICE_SOFT };
    let mut spans = Vec::with_capacity(w);
    for i in 0..w {
        if i + 1 == filled {
            spans.push(Span::styled(ui::glyphs().knob, Style::new().fg(theme::ICE)));
        } else if i < filled {
            spans.push(Span::styled(
                ui::glyphs().bar_fill.to_string(),
                Style::new().fg(hot),
            ));
        } else {
            spans.push(Span::styled(
                ui::glyphs().bar_track.to_string(),
                Style::new().fg(theme::DIM),
            ));
        }
    }
    Line::from(spans)
}
