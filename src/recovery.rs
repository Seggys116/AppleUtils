use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, Screen};
use crate::clip::{FileInfo, FileKind};
use crate::recovery_model::{RecoveryStep, SessionPhase};
use crate::theme;
use crate::ui;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.screen != Screen::Recovery {
        return;
    }

    app.recovery.model.clear_hits();
    app.recovery.model.focus_open_request();

    match app.recovery.model.step() {
        RecoveryStep::WaitDevices => render_wait_devices(frame, area, app),
        RecoveryStep::PickSystem => render_pick_system(frame, area, app),
        RecoveryStep::PickMode => render_pick_mode(frame, area, app),
        RecoveryStep::PickDevice => render_pick_device(frame, area, app),
        RecoveryStep::Claiming => {
            render_wait(frame, area, app, claiming_message(app), None, ui::WAIT_BAR)
        }
        RecoveryStep::WaitRequest => render_wait(
            frame,
            area,
            app,
            wait_request_message(app),
            None,
            ui::WAIT_BAR,
        ),
        RecoveryStep::PickFile => render_pick_file(frame, area, app),
        RecoveryStep::Working => render_wait(
            frame,
            area,
            app,
            work_message(app),
            app.recovery
                .model
                .wait_progress()
                .and_then(|progress| progress.fraction)
                .or(Some(0.0)),
            ui::WORK_BAR,
        ),
        RecoveryStep::Done => render_done(frame, area, app),
    }
}

fn render_wait_devices(frame: &mut Frame, area: Rect, app: &App) {
    if app.recovery.model.next_open_request().is_none()
        && (app.recovery.model.all_required_files_supplied()
            && !app.recovery.model.requests.is_empty()
            || !app.recovery.model.compatible_systems.is_empty())
    {
        let message = if let Some(system) = app.recovery.model.selected_system_label() {
            format!("waiting for {}", system.title)
        } else if app.recovery.model.compatible_systems.is_empty() {
            "waiting for a device".to_string()
        } else {
            format!(
                "waiting for {}",
                app.recovery
                    .model
                    .compatible_systems
                    .iter()
                    .map(|system| system.title.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        render_wait(frame, area, app, message, None, ui::WAIT_BAR);
        return;
    }
    ui::render_wait_plate(frame, area, ui::WaitPlate::recovery(app.tick));
}

fn render_wait(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    message: String,
    fill: Option<f64>,
    palette: ui::BarPalette,
) {
    let mut spec = ui::WaitPlate::work(&message, app.tick, fill);
    spec.palette = palette;
    spec.border = if palette.hot == theme::WAIT {
        theme::WAIT
    } else {
        theme::ICE
    };
    ui::render_wait_plate(frame, area, spec);
}

fn render_pick_file(frame: &mut Frame, area: Rect, app: &mut App) {
    let error = app
        .recovery
        .model
        .selected_request()
        .and_then(|request| match &request.resolution {
            crate::recovery_model::RequestResolution::Rejected { reason, .. } => {
                Some(reason.as_str())
            }
            _ => app.recovery.model.last_error.as_deref(),
        })
        .or(app.recovery.model.last_error.as_deref());
    let title = app.recovery.model.picker_title();
    let clipboard_invalid = handoff_invalid(app, app.clip.file.as_ref());
    let typed = crate::clip::inspect(app.path_input.trim());
    let typed_invalid = handoff_invalid(app, typed.as_ref());

    if let Some(reason) = error.filter(|reason| !reason.is_empty()) {
        let [banner, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                ui::truncate_middle(reason, banner.width),
                theme::fail(),
            )))
            .alignment(Alignment::Center),
            banner,
        );
        ui::render_file_picker_with(frame, body, app, &title, clipboard_invalid, typed_invalid);
        return;
    }

    ui::render_file_picker_with(frame, area, app, &title, clipboard_invalid, typed_invalid);
}

fn handoff_invalid(app: &App, file: Option<&FileInfo>) -> bool {
    let Some(file) = file else {
        return false;
    };
    if file.kind == FileKind::Directory {
        return false;
    }
    if app.recovery.model.match_handoff(file).is_err() {
        return true;
    }
    let rejected_same =
        |request: &crate::recovery_model::FileRequestState| match &request.resolution {
            crate::recovery_model::RequestResolution::Rejected {
                file: Some(rejected),
                ..
            } => rejected.path == file.path,
            _ => false,
        };
    app.recovery
        .model
        .next_open_request()
        .and_then(|index| app.recovery.model.requests.get(index))
        .is_some_and(rejected_same)
        || app
            .recovery
            .model
            .selected_request()
            .is_some_and(rejected_same)
}

fn render_pick_system(frame: &mut Frame, area: Rect, app: &mut App) {
    if let Some(reason) = app
        .recovery
        .model
        .last_error
        .as_deref()
        .filter(|reason| !reason.is_empty())
    {
        let [banner, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                ui::truncate_middle(reason, banner.width),
                theme::fail(),
            )))
            .alignment(Alignment::Center),
            banner,
        );
        render_system_cards(frame, body, app);
        return;
    }
    render_system_cards(frame, area, app);
}

fn render_system_cards(frame: &mut Frame, area: Rect, app: &mut App) {
    let systems = &app.recovery.model.compatible_systems;
    if systems.is_empty() {
        render_wait_devices(frame, area, app);
        return;
    }
    if app.recovery.model.system_cursor >= systems.len() {
        app.recovery.model.system_cursor = 0;
    }
    let cursor = app.recovery.model.system_cursor;
    let [header, body] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    let visible = visible_card_count(body).min(systems.len()).max(1);
    app.recovery.model.device_page_rows = visible;
    let start = scroll_start(systems.len(), cursor, visible);
    let end = (start + visible).min(systems.len());
    let window = end.saturating_sub(start).max(1);

    let heading = match app.recovery.model.catalog_label() {
        Some(catalog) => format!(
            "{catalog}  ·  choose a system  ·  {} of {}",
            cursor + 1,
            systems.len()
        ),
        None => format!("choose a system  ·  {} of {}", cursor + 1, systems.len()),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(heading, theme::mute())))
            .alignment(Alignment::Center),
        header,
    );

    let overflow = systems.len() > visible;
    let rects = stacked_cards_n(body, window, if overflow { 2 } else { 0 });
    app.recovery.model.hits.device_rows = vec![Rect::default(); systems.len()];
    for (slot, rect) in rects.iter().copied().enumerate() {
        let index = start + slot;
        let Some(system) = systems.get(index) else {
            break;
        };
        app.recovery.model.hits.device_rows[index] = rect;
        if rect.width > 0 && rect.height > 0 {
            ui::render_choice_card(frame, rect, &system.title, &system.detail, index == cursor);
        }
    }
    render_list_scrollbar(frame, &rects, systems.len(), visible, cursor);
}

fn render_pick_mode(frame: &mut Frame, area: Rect, app: &mut App) {
    if let Some(reason) = app
        .recovery
        .model
        .last_error
        .as_deref()
        .filter(|reason| !reason.is_empty())
    {
        let [banner, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                ui::truncate_middle(reason, banner.width),
                theme::fail(),
            )))
            .alignment(Alignment::Center),
            banner,
        );
        render_mode_cards(frame, body, app);
        return;
    }
    render_mode_cards(frame, area, app);
}

fn render_mode_cards(frame: &mut Frame, area: Rect, app: &mut App) {
    let modes = app.recovery.model.compatible_modes.clone();
    if modes.is_empty() {
        render_wait_devices(frame, area, app);
        return;
    }
    if app.recovery.model.mode_cursor >= modes.len() {
        app.recovery.model.mode_cursor = 0;
    }
    let cursor = app.recovery.model.mode_cursor;
    let [header, body] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    let system = app
        .recovery
        .model
        .selected_system_label()
        .map(|system| system.title.as_str())
        .unwrap_or("this Mac");
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{system}  ·  choose restore mode"),
            theme::mute(),
        )))
        .alignment(Alignment::Center),
        header,
    );
    let rects = stacked_cards_n(body, modes.len().max(1), 0);
    app.recovery.model.hits.device_rows = vec![Rect::default(); modes.len()];
    for (index, rect) in rects.into_iter().enumerate() {
        let Some(mode) = modes.get(index) else {
            break;
        };
        app.recovery.model.hits.device_rows[index] = rect;
        if rect.width > 0 && rect.height > 0 {
            ui::render_choice_card(frame, rect, mode.title(), mode.detail(), index == cursor);
        }
    }
}

fn render_pick_device(frame: &mut Frame, area: Rect, app: &mut App) {
    let connected: Vec<usize> = app
        .recovery
        .model
        .devices
        .iter()
        .enumerate()
        .filter(|(_, device)| device.connected)
        .map(|(index, _)| index)
        .collect();
    if connected.is_empty() {
        render_wait_devices(frame, area, app);
        return;
    }
    if !connected.contains(&app.recovery.model.device_cursor) {
        app.recovery.model.device_cursor = connected[0];
    }

    let cursor = app.recovery.model.device_cursor;
    let visible = visible_card_count(area).min(connected.len()).max(1);
    app.recovery.model.device_page_rows = visible;
    let position = connected
        .iter()
        .position(|&index| index == cursor)
        .unwrap_or(0);
    let start = scroll_start(connected.len(), position, visible);
    let end = (start + visible).min(connected.len());
    let window = end.saturating_sub(start).max(1);
    let overflow = connected.len() > visible;
    let rects = stacked_cards_n(area, window, if overflow { 2 } else { 0 });
    app.recovery.model.hits.device_rows = vec![Rect::default(); app.recovery.model.devices.len()];
    for (slot, rect) in rects.iter().copied().enumerate() {
        let Some(&index) = connected.get(start + slot) else {
            break;
        };
        app.recovery.model.hits.device_rows[index] = rect;
        let device = &app.recovery.model.devices[index];
        if rect.width > 0 && rect.height > 0 {
            ui::render_choice_card(
                frame,
                rect,
                &device.title,
                &format!("{}  ·  {}", device.detail, device.connection),
                index == cursor,
            );
        }
    }
    render_list_scrollbar(frame, &rects, connected.len(), visible, position);
}

fn render_done(frame: &mut Frame, area: Rect, app: &App) {
    let failed = matches!(
        app.recovery.model.phase,
        SessionPhase::Failed | SessionPhase::Cancelled
    );
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
        .recovery
        .model
        .last_error
        .as_deref()
        .filter(|text| failed && !text.is_empty())
        .unwrap_or(app.recovery.model.status_message.as_str());
    let style = if failed {
        theme::wait()
    } else {
        theme::ice().add_modifier(Modifier::BOLD)
    };
    let max = inner.width.saturating_sub(4).max(1);
    let mut lines = vec![
        Line::from(Span::styled(
            if failed { "failed" } else { "finished" },
            if failed { theme::wait() } else { theme::mute() },
        )),
        Line::from(""),
    ];
    let wrap_rows = inner.height.saturating_sub(lines.len() as u16).max(1) as usize;
    for row in wrap_words(message, max).into_iter().take(wrap_rows) {
        lines.push(Line::from(Span::styled(row, style)));
    }
    ui::render_cluster(frame, inner, lines);
}

fn wrap_words(text: &str, max: u16) -> Vec<String> {
    let max = max.max(1) as usize;
    let mut rows = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current = take_width(word, max);
            let mut rest = skip_width(word, max);
            while !rest.is_empty() {
                rows.push(std::mem::take(&mut current));
                current = take_width(rest, max);
                rest = skip_width(rest, max);
            }
            continue;
        }
        let extra = 1 + word.chars().count();
        if current.chars().count() + extra <= max {
            current.push(' ');
            current.push_str(word);
            continue;
        }
        rows.push(std::mem::take(&mut current));
        current = take_width(word, max);
        let mut rest = skip_width(word, max);
        while !rest.is_empty() {
            rows.push(std::mem::take(&mut current));
            current = take_width(rest, max);
            rest = skip_width(rest, max);
        }
    }
    if !current.is_empty() {
        rows.push(current);
    }
    rows
}

fn take_width(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn skip_width(text: &str, max: usize) -> &str {
    let mut chars = text.chars();
    for _ in 0..max {
        if chars.next().is_none() {
            return "";
        }
    }
    chars.as_str()
}

fn claiming_message(app: &App) -> String {
    app.recovery
        .model
        .selected_device()
        .map(|device| format!("claiming {}", device.title))
        .unwrap_or_else(|| "claiming device".into())
}

fn wait_request_message(app: &App) -> String {
    if app.recovery.model.status_message.is_empty() {
        "waiting for the next file".into()
    } else {
        app.recovery.model.status_message.clone()
    }
}

fn work_message(app: &App) -> String {
    if let Some(progress) = app.recovery.model.wait_progress() {
        if progress.detail.is_empty() {
            progress.stage.clone()
        } else {
            format!("{}  {}", progress.stage, progress.detail)
        }
    } else if app.recovery.model.status_message.is_empty() {
        "restore".into()
    } else {
        app.recovery.model.status_message.clone()
    }
}

fn visible_card_count(area: Rect) -> usize {
    let inner = ui::inset(area, 2, 1);
    if inner.height < 3 {
        return 1;
    }
    let card_h: u16 = if inner.height >= 20 { 4 } else { 3 };
    let gap = u16::from(inner.height >= card_h.saturating_mul(3));
    let each = card_h.saturating_add(gap).max(1);
    usize::from((inner.height.saturating_add(gap)) / each).max(1)
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

fn stacked_cards_n(area: Rect, n: usize, rail: u16) -> Vec<Rect> {
    let n = n.max(1) as u16;
    let inner = ui::inset(area, 2, 1);
    let card_gap = u16::from(inner.height >= n * 6);
    let card_h = if inner.height >= n * 5 { 4 } else { 3 };
    let cards_h = card_h * n + card_gap * n.saturating_sub(1);
    let usable = inner.width.saturating_sub(rail);
    let card_w = usable.saturating_sub(2).min(66).max(36.min(usable));
    let cluster_w = card_w.saturating_add(rail).min(inner.width);
    let group = ui::center(inner, inner.width, cards_h.min(inner.height));
    let card_x = group.x + group.width.saturating_sub(cluster_w) / 2;
    let mut cards = Vec::with_capacity(n as usize);
    let mut cy = group.y;
    for _ in 0..n {
        cards.push(Rect {
            x: card_x,
            y: cy,
            width: card_w.min(group.width),
            height: card_h,
        });
        cy = cy.saturating_add(card_h + card_gap);
    }
    cards
}

fn render_list_scrollbar(
    frame: &mut Frame,
    cards: &[Rect],
    content_len: usize,
    viewport_len: usize,
    position: usize,
) {
    if content_len <= viewport_len {
        return;
    }
    let Some(&first) = cards.first() else {
        return;
    };
    let Some(&last) = cards.last() else {
        return;
    };
    if first.width == 0 || first.height == 0 {
        return;
    }
    let rail = Rect {
        x: first.x.saturating_add(first.width).saturating_add(1),
        y: first.y,
        width: 1,
        height: last
            .y
            .saturating_add(last.height)
            .saturating_sub(first.y)
            .max(1),
    };
    ui::render_scrollbar(frame, rail, content_len, viewport_len, position);
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Position;
    use ratatui::style::Color;

    use super::*;
    use crate::app::App;
    use crate::clip::{ClipWatch, FileInfo, FileKind};
    use crate::ramrod::describe_board;
    use crate::recovery_model::{
        CompatibleSystem, DeviceState, FileRequestSpec, RecoveryDevice, RecoveryEvent, RestoreMode,
        RestoreProgress, SizeRange,
    };

    fn boards(classes: &[&str]) -> Vec<CompatibleSystem> {
        classes
            .iter()
            .map(|class| {
                let label = describe_board(class, None);
                CompatibleSystem {
                    class: label.class,
                    title: label.title,
                    detail: label.detail,
                }
            })
            .collect()
    }

    #[test]
    fn recovery_starts_by_asking_for_the_manifest() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("BuildManifest.plist"), "{text}");
        assert!(
            text.contains("from clipboard") || text.contains("COPY A FILE"),
            "{text}"
        );
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
    }

    #[test]
    fn files_ready_waits_for_a_device() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: boards(&["J274AP"]),
                product_version: None,
                product_build: None,
            });
        app.recovery
            .model
            .apply_event(RecoveryEvent::SystemSelected {
                class: "J274AP".into(),
            });
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("waiting for Mac mini (M1, 2020)"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::WaitDevices);
    }

    #[test]
    fn manifest_leads_to_picking_a_system() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: boards(&["j274ap", "j293ap"]),
                product_version: None,
                product_build: None,
            });
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("Mac mini (M1, 2020)"), "{text}");
        assert!(text.contains("MacBook Pro 13-inch (M1, 2020)"), "{text}");
        assert!(text.contains("j274ap"), "{text}");
        assert!(text.contains("j293ap"), "{text}");
        assert!(!text.contains("waiting for"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickSystem);
    }

    #[test]
    fn remaining_files_keep_the_path_picker() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: boards(&["j274ap"]),
                product_version: None,
                product_build: None,
            });
        app.recovery
            .model
            .apply_event(RecoveryEvent::SystemSelected {
                class: "j274ap".into(),
            });
        app.recovery.model.apply_event(RecoveryEvent::FileRequested(
            crate::recovery_model::FileRequestSpec {
                request_id: "system-image".into(),
                role: "Restore image".into(),
                preferred_name: Some("OS.dmg".into()),
                accepted_names: vec!["OS.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: None,
                expected_hash: None,
                detail: None,
                required: true,
            },
        ));
        let text = render_text(&mut app, 100, 32);
        assert!(!text.contains("Autosearch"), "{text}");
        assert!(
            text.contains("file or folder path") || text.contains("COPY A FILE"),
            "{text}"
        );
        assert!(text.contains("press Enter to search a folder"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
    }

    #[test]
    fn catalog_version_is_shown_on_the_system_list() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: boards(&["j274ap"]),
                product_version: Some("26.5.1".into()),
                product_build: Some("25F80".into()),
            });
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("macOS 26.5.1 (25F80)"), "{text}");
        assert!(text.contains("Mac mini (M1, 2020)"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickSystem);
    }

    #[test]
    fn restore_mode_cards_offer_upgrade_then_erase() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: boards(&["j274ap"]),
                product_version: None,
                product_build: None,
            });
        app.recovery
            .model
            .apply_event(RecoveryEvent::SystemSelected {
                class: "j274ap".into(),
            });
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleModes {
                modes: vec![RestoreMode::Update, RestoreMode::Erase],
            });
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("Upgrade"), "{text}");
        assert!(text.contains("Keep files and settings"), "{text}");
        assert!(text.contains("Erase"), "{text}");
        assert!(text.contains("Wipe the Mac and install"), "{text}");
        assert!(text.contains("Mac mini (M1, 2020)"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickMode);
    }

    #[test]
    fn system_list_scrolls_to_keep_the_selection_visible() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        let classes = (0..40).map(|i| format!("j{i:03}ap")).collect::<Vec<_>>();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: classes
                    .iter()
                    .map(|class| {
                        let label = describe_board(class, None);
                        CompatibleSystem {
                            class: label.class,
                            title: label.title,
                            detail: label.detail,
                        }
                    })
                    .collect(),
                product_version: None,
                product_build: None,
            });
        app.recovery.model.system_cursor = 0;
        let first = render_text(&mut app, 80, 24);
        assert!(first.contains("j000ap"), "{first}");
        assert!(first.contains("choose a system"), "{first}");
        assert!(first.contains("1 of 40"), "{first}");
        assert!(!first.contains("j039ap"), "{first}");

        app.recovery.model.system_cursor = 39;
        let last = render_text(&mut app, 80, 24);
        assert!(last.contains("j039ap"), "{last}");
        assert!(last.contains("40 of 40"), "{last}");
        assert!(!last.contains("j000ap"), "{last}");
        assert!(
            first.contains(ui::GLYPHS.scroll_thumb) && first.contains(ui::GLYPHS.scroll_track),
            "overflowing system list must draw a scrollbar\n{first}"
        );
        assert!(
            last.contains(ui::GLYPHS.scroll_thumb),
            "scrolled system list must keep the scrollbar\n{last}"
        );
    }

    #[test]
    fn device_found_shows_a_choice_card_after_files_are_ready() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
                id: "dev-1".into(),
                title: "MacOS-Fresh".into(),
                detail: "DFU".into(),
                connection: "usb".into(),
                state: DeviceState::Available,
                connected: true,
            }));
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("MacOS-Fresh"), "{text}");
        assert!(text.contains("DFU"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickDevice);
        assert_eq!(app.recovery.model.hits.device_rows.len(), 1);
        assert!(
            !text.contains(ui::GLYPHS.scroll_thumb),
            "a single device must not draw a scrollbar\n{text}"
        );
    }

    #[test]
    fn overflowing_device_list_draws_a_scrollbar_that_tracks_the_selection() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        for i in 0..16 {
            app.recovery
                .model
                .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
                    id: format!("dev-{i}"),
                    title: format!("Device {i:02}"),
                    detail: "DFU".into(),
                    connection: "usb".into(),
                    state: DeviceState::Available,
                    connected: true,
                }));
        }
        app.recovery.model.device_cursor = 0;
        let (first_backend, first) = draw(&mut app, 80, 24);
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickDevice);
        assert!(first.contains("Device 00"), "{first}");
        assert!(!first.contains("Device 15"), "{first}");
        assert!(
            first.contains(ui::GLYPHS.scroll_thumb) && first.contains(ui::GLYPHS.scroll_track),
            "overflowing device list must draw a scrollbar\n{first}"
        );
        let top = symbol_rows(&first_backend, ui::GLYPHS.scroll_thumb);
        assert!(!top.is_empty(), "missing thumb\n{first}");

        app.recovery.model.device_cursor = 15;
        let (last_backend, last) = draw(&mut app, 80, 24);
        assert!(last.contains("Device 15"), "{last}");
        assert!(!last.contains("Device 00"), "{last}");
        let bottom = symbol_rows(&last_backend, ui::GLYPHS.scroll_thumb);
        assert!(!bottom.is_empty(), "missing thumb after scroll\n{last}");
        assert!(
            bottom.iter().copied().max() > top.iter().copied().max(),
            "thumb should travel down the rail: top={top:?} bottom={bottom:?}\n{last}"
        );
    }

    #[test]
    fn claimed_session_asks_for_one_file_at_a_time() {
        let mut app = sample_collecting();
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("BuildManifest.plist"), "{text}");
        assert!(
            text.contains("from clipboard") || text.contains("COPY A FILE"),
            "{text}"
        );
        assert!(
            text.contains("type a path") || text.contains("file or folder path"),
            "{text}"
        );
        assert!(!text.contains("activity"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
    }

    #[test]
    fn restore_progress_uses_the_wait_plate() {
        let mut app = sample_collecting();
        app.recovery
            .model
            .apply_event(RecoveryEvent::Progress(RestoreProgress {
                stage: "ramdisk".into(),
                detail: "Uploading".into(),
                fraction: Some(0.42),
            }));
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("ramdisk"), "{text}");
        assert!(text.contains("Uploading"), "{text}");
        assert!(text.contains("42%"), "{text}");
        assert!(!text.contains("clipboard"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::Working);
    }

    #[test]
    fn restore_progress_shows_the_full_checkpoint_name() {
        let mut app = sample_collecting();
        app.recovery
            .model
            .apply_event(RecoveryEvent::Progress(RestoreProgress {
                stage: "verify_storage_for_update".into(),
                detail: String::new(),
                fraction: Some(0.12),
            }));
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("verify_storage_for_update"), "{text}");
        assert!(!text.contains("operation"), "{text}");
        assert!(!text.contains("Restore running"), "{text}");
        assert_eq!(app.recovery.model.step(), RecoveryStep::Working);
    }

    #[test]
    fn queued_file_check_uses_the_wait_plate() {
        let mut app = sample_collecting();
        let file = app.clip.file.clone().expect("clipboard");
        app.recovery
            .model
            .note_clipboard_assignment(&file, "queued".into());
        assert_eq!(app.recovery.model.step(), RecoveryStep::Working);
        assert_eq!(app.recovery.model.phase, SessionPhase::Collecting);

        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("checking"), "{text}");
        assert!(!text.contains("clipboard"), "{text}");
        assert!(!text.contains("type a path"), "{text}");

        app.recovery
            .model
            .apply_event(RecoveryEvent::Progress(RestoreProgress {
                stage: "checking".into(),
                detail: String::new(),
                fraction: Some(0.42),
            }));
        assert_eq!(app.recovery.model.phase, SessionPhase::Collecting);
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("checking"), "{text}");
        assert!(text.contains("42%"), "{text}");

        app.recovery.model.apply_event(RecoveryEvent::FileRejected {
            request_id: "manifest".into(),
            reason: "hash mismatch".into(),
            keep_claim: true,
        });
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("hash mismatch"), "{text}");
        assert!(
            text.contains("from clipboard")
                || text.contains("COPY A FILE")
                || text.contains("type a path"),
            "{text}"
        );
    }

    #[test]
    fn hash_rejected_file_stays_on_the_picker_and_uses_fail_border() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.requests.clear();
        app.recovery
            .model
            .apply_event(RecoveryEvent::CompatibleBoards {
                systems: boards(&["J274AP"]),
                product_version: None,
                product_build: None,
            });
        app.recovery
            .model
            .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
                id: "dev-1".into(),
                title: "MacBook Pro 13-inch, 2020".into(),
                detail: "J274AP".into(),
                connection: "usb".into(),
                state: DeviceState::Available,
                connected: true,
            }));
        app.recovery
            .model
            .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
                request_id: "system-image".into(),
                role: "Restore image".into(),
                preferred_name: Some("OS.dmg".into()),
                accepted_names: vec!["OS.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: None,
                expected_hash: None,
                detail: Some("Select OS.dmg from the extracted restore tree.".into()),
                required: true,
            }));
        let file = sample_file("/tmp/OS.dmg", "OS.dmg");
        app.clip.set_file(file.clone());
        app.recovery
            .model
            .note_clipboard_assignment(&file, "queued".into());
        app.recovery.model.apply_event(RecoveryEvent::FileRejected {
            request_id: "system-image".into(),
            reason: "OS.dmg does not match OS.dmg. Select the correct file (sha2-384 a292bc492e84 vs 737b4342f6b9)".into(),
            keep_claim: true,
        });
        app.recovery
            .model
            .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
                request_id: "system-image".into(),
                role: "Restore image".into(),
                preferred_name: Some("OS.dmg".into()),
                accepted_names: vec!["OS.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: None,
                expected_hash: None,
                detail: Some("Select OS.dmg from the extracted restore tree.".into()),
                required: true,
            }));

        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
        assert!(
            app.recovery.model.match_handoff(&file).is_ok(),
            "the same path must still be retryable after the bytes are replaced"
        );
        let (backend, text) = draw(&mut app, 100, 32);
        assert!(text.contains("OS.dmg"), "{text}");
        assert!(text.contains("Select the correct file"), "{text}");
        assert!(
            !text.contains("waiting for J274AP"),
            "hash mismatch must not skip ahead to waiting for a device\n{text}"
        );
        assert!(
            row_has_fg(&backend, "(1/1)", theme::FAIL),
            "the rejected file must paint the copy card FAIL\n{text}"
        );
    }

    #[test]
    fn a_restore_failure_note_wraps_instead_of_hiding_the_middle() {
        let mut app = sample_collecting();
        app.recovery.model.apply_event(RecoveryEvent::Failed {
            note: "Possible blank device. Erase restore may be required.".into(),
        });
        let text = render_text(&mut app, 48, 24);
        assert!(text.contains("Possible blank device"), "{text}");
        assert!(text.contains("may be required."), "{text}");
    }

    #[test]
    fn recovery_screen_renders_failure_and_success() {
        let mut app = sample_collecting();
        app.recovery.model.apply_event(RecoveryEvent::Failed {
            note: "Digest mismatch".into(),
        });
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("Digest mismatch"));
        assert!(text.contains("failed") || text.contains("error"), "{text}");

        app.recovery.model.apply_event(RecoveryEvent::Succeeded {
            note: Some("Restore complete".into()),
        });
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("Restore complete"));
    }

    #[test]
    fn waiting_screen_clears_hidden_session_hit_targets() {
        let mut app = sample_collecting();
        render_text(&mut app, 100, 50);
        app.recovery.model.devices.clear();
        app.recovery.model.requests.clear();
        app.recovery.model.claimed_device_id = None;
        app.recovery.model.phase = SessionPhase::Waiting;
        let text = render_text(&mut app, 100, 32);
        assert!(text.contains("Waiting for devices"));
        assert!(app.recovery.model.hits.device_rows.is_empty());
        assert!(app.recovery.model.hits.request_rows.is_empty());
        assert!(app.recovery.model.hits.actions.is_empty());
    }

    #[test]
    fn invalid_clipboard_extension_uses_fail_border() {
        let mut app = sample_collecting();
        app.clip
            .set_file(sample_file("/tmp/kernelcache", "kernelcache"));
        let file = app.clip.file.clone().expect("clipboard");
        assert!(
            app.recovery.model.match_handoff(&file).is_err(),
            "wrong extension must miss the open request"
        );
        let (backend, text) = draw(&mut app, 100, 32);
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
        assert!(
            row_has_fg(&backend, "BuildManifest", theme::FAIL),
            "invalid extension must paint the copy card FAIL\n{text}"
        );
    }

    #[test]
    fn invalid_clipboard_name_uses_fail_border() {
        let mut app = sample_collecting();
        app.clip
            .set_file(sample_file("/tmp/Info.plist", "Info.plist"));
        let file = app.clip.file.clone().expect("clipboard");
        assert!(
            app.recovery.model.match_handoff(&file).is_err(),
            "wrong name must miss the open request"
        );
        let (backend, text) = draw(&mut app, 100, 32);
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
        assert!(
            row_has_fg(&backend, "BuildManifest", theme::FAIL),
            "invalid name must paint the copy card FAIL\n{text}"
        );
    }

    #[test]
    fn valid_clipboard_file_keeps_ice_border() {
        let mut app = sample_collecting();
        let file = app.clip.file.clone().expect("clipboard");
        assert!(
            app.recovery.model.match_handoff(&file).is_ok(),
            "BuildManifest.plist must match the open request"
        );
        let (backend, text) = draw(&mut app, 100, 32);
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
        assert!(
            row_has_fg(&backend, "BuildManifest", theme::ICE),
            "valid file must keep the ice border\n{text}"
        );
        assert!(
            !buffer_has_fg(&backend, theme::FAIL),
            "valid file must not use FAIL\n{text}"
        );
    }

    #[test]
    fn invalid_typed_path_uses_fail_border() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong.img");
        std::fs::write(&path, vec![0u8; 128]).unwrap();
        let mut app = sample_collecting();
        app.clip = ClipWatch::default();
        app.path_input = path.to_string_lossy().into_owned();
        app.path_cursor = app.path_input.len();
        let typed = crate::clip::inspect(app.path_input.trim()).expect("typed file");
        assert!(
            app.recovery.model.match_handoff(&typed).is_err(),
            "typed image must miss the plist request"
        );
        let (backend, text) = draw(&mut app, 100, 32);
        assert_eq!(app.recovery.model.step(), RecoveryStep::PickFile);
        assert!(
            row_has_fg(&backend, "file or folder path", theme::FAIL)
                || row_has_fg(&backend, "type a path", theme::FAIL),
            "invalid typed file must paint the path box FAIL\n{text}"
        );
    }

    fn sample_file(path: &str, name: &str) -> FileInfo {
        FileInfo {
            path: path.into(),
            name: name.into(),
            kind: FileKind::File,
            size: Some(128),
            modified: Some("just now".into()),
        }
    }

    fn sample_collecting() -> App {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.clip.set_file(sample_file(
            "/tmp/BuildManifest.plist",
            "BuildManifest.plist",
        ));
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
        app
    }

    fn render_text(app: &mut App, width: u16, height: u16) -> String {
        draw(app, width, height).1
    }

    fn draw(app: &mut App, width: u16, height: u16) -> (TestBackend, String) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| crate::ui::render(frame, app))
            .expect("draw");
        let backend = terminal.backend().clone();
        let text = buffer_to_text(backend.buffer(), width, height);
        (backend, text)
    }

    fn row_has_fg(backend: &TestBackend, needle: &str, color: Color) -> bool {
        let buffer = backend.buffer();
        let area = buffer.area();
        for y in 0..area.height {
            let mut row = String::new();
            for x in 0..area.width {
                row.push_str(buffer[Position::new(x, y)].symbol());
            }
            if !row.contains(needle) {
                continue;
            }
            for x in 0..area.width {
                if buffer[Position::new(x, y)].fg == color {
                    return true;
                }
            }
        }
        false
    }

    fn symbol_rows(backend: &TestBackend, symbol: &str) -> Vec<u16> {
        let buffer = backend.buffer();
        let area = buffer.area();
        let mut rows = Vec::new();
        for y in 0..area.height {
            for x in 0..area.width {
                if buffer[Position::new(x, y)].symbol() == symbol {
                    rows.push(y);
                }
            }
        }
        rows
    }

    fn buffer_has_fg(backend: &TestBackend, color: Color) -> bool {
        let buffer = backend.buffer();
        let area = buffer.area();
        for y in 0..area.height {
            for x in 0..area.width {
                if buffer[Position::new(x, y)].fg == color {
                    return true;
                }
            }
        }
        false
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
}
