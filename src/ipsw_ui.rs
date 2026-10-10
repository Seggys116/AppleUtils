//! Drawing for the IPSW Export tool. State and key handling live in `ipsw_app`.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, Screen};
use crate::clip::format_size;
use crate::ipsw_app::{
    FIRST_COMPONENT_OPTION, IpswPane, IpswPhase, IpswRow, IpswState, Mark, OptionItem, RunView,
    option_item,
};
use crate::ipsw_export::{ItemAction, Outcome};
use crate::theme;
use crate::ui::{self, GlyphPack};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.screen != Screen::Ipsw {
        return;
    }
    match app.ipsw.phase {
        IpswPhase::Path => render_path(frame, area, app),
        IpswPhase::Loading => render_loading(frame, area, app),
        IpswPhase::Browse => render_browse(frame, area, app),
        IpswPhase::Output => render_output(frame, area, app),
        IpswPhase::Exporting => render_exporting(frame, area, app),
        IpswPhase::Done => render_done(frame, area, app),
    }
}

pub fn footer_hints(app: &App, width: u16) -> &'static [&'static str] {
    match app.ipsw.phase {
        IpswPhase::Path => ui::path_picker_hints(app, width),
        IpswPhase::Loading if width >= 40 => &["opening archive", "esc cancel"],
        IpswPhase::Loading => &["esc"],
        IpswPhase::Browse if app.ipsw.filter_editing && width >= 40 => {
            &["type to filter", "enter done", "esc done"]
        }
        IpswPhase::Browse if app.ipsw.aea_editing && width >= 40 => {
            &["type the key", "enter done", "esc done"]
        }
        IpswPhase::Browse if app.ipsw.filter_editing || app.ipsw.aea_editing => &["enter", "esc"],
        IpswPhase::Browse if width >= 96 => &[
            "tab pane",
            "↑↓ move",
            "space select",
            "a all",
            "/ filter",
            "e export",
            "x clear",
            "esc back",
        ],
        IpswPhase::Browse if width >= 64 => {
            &["tab", "↑↓", "space", "a all", "/ filter", "e export", "esc"]
        }
        IpswPhase::Browse if width >= 40 => &["tab", "space", "e", "esc"],
        IpswPhase::Browse => &["esc"],
        IpswPhase::Output if app.path_editing && width >= 56 => {
            &["type a path", "esc cancel", "enter export"]
        }
        IpswPhase::Output if app.path_editing => &["type", "esc", "enter"],
        IpswPhase::Output if width >= 72 => &[
            "copy or type a folder",
            "tab path",
            "enter export",
            "esc back",
            "q quit",
        ],
        IpswPhase::Output if width >= 48 => &["tab path", "enter", "esc", "q"],
        IpswPhase::Output => &["esc", "q"],
        IpswPhase::Exporting if app.ipsw.run.cancelling => &["cancelling"],
        IpswPhase::Exporting if width >= 40 => &["esc/x cancel", "q quit"],
        IpswPhase::Exporting => &["x"],
        IpswPhase::Done if width >= 56 => &["↑↓ scroll", "enter back", "n new archive", "q quit"],
        IpswPhase::Done if width >= 40 => &["enter", "n", "q"],
        IpswPhase::Done => &["esc"],
    }
}

pub fn action_label(action: ItemAction) -> String {
    match action {
        ItemAction::Copy => "copying".into(),
        ItemAction::Link => "linking".into(),
        ItemAction::Decrypt => "decrypting".into(),
        ItemAction::Decompress => "decompressing".into(),
        ItemAction::Component(component) => {
            format!("running ipsw extract {}", component.flags().join(" "))
        }
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else if width < 4 {
        text.chars().take(width).collect()
    } else {
        ui::truncate_middle(text, width as u16)
    }
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

fn render_path(frame: &mut Frame, area: Rect, app: &mut App) {
    let message = app.ipsw.error.clone();
    let picker = match message.as_deref() {
        Some(_) if area.height > 6 => Rect {
            height: area.height - 2,
            ..area
        },
        _ => area,
    };
    ui::render_file_picker_hinted(
        frame,
        picker,
        app,
        "ipsw export",
        false,
        false,
        &ui::PickerHints {
            empty: "copy an .ipsw file, or type its path below",
            folder: "from clipboard  ·  folder  ·  choose an .ipsw file",
        },
    );
    if let Some(message) = message
        && area.height > 6
    {
        let row = Rect {
            y: area.y + area.height - 1,
            height: 1,
            ..area
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                fit(&message, row.width.saturating_sub(2) as usize),
                theme::fail(),
            )))
            .alignment(Alignment::Center),
            row,
        );
    }
}

fn render_loading(frame: &mut Frame, area: Rect, app: &App) {
    let state = &app.ipsw;
    let stage = if state.status.is_empty() {
        "reading the archive"
    } else {
        state.status.as_str()
    };
    let path = state
        .archive
        .as_ref()
        .map(|path| ui::truncate_middle(&path.to_string_lossy(), 48))
        .unwrap_or_default();
    let mut spec = ui::WaitPlate::opening(stage, Some(path.as_str()), app.tick);
    spec.fill = state.progress.or(Some(0.0));
    ui::render_wait_plate(frame, area, spec);
}

struct HeaderDevices {
    selected: String,
    names: Vec<String>,
    types: String,
    families: Vec<(String, usize)>,
    models: usize,
}

fn family_summary(families: &[(String, usize)], budget: usize) -> String {
    let len = |text: &str| text.chars().count();
    let total: usize = families.iter().map(|(_, count)| count).sum();
    let noun = if families.iter().all(|(family, _)| family.contains("Mac")) {
        "Macs"
    } else {
        "devices"
    };
    let prefix = format!("{total} {noun}: ");
    let mut used = len(&prefix);
    let mut shown = 0;
    for (index, (name, count)) in families.iter().enumerate() {
        let item = format!("{name} {count}");
        let rest = families.len() - index - 1;
        let suffix = if rest > 0 {
            len(&format!(" +{rest} more"))
        } else {
            0
        };
        let next = used + len(&item) + if index > 0 { 2 } else { 0 };
        if next + suffix > budget {
            break;
        }
        used = next;
        shown = index + 1;
    }
    if shown == 0 {
        return clip_end(&format!("{total} {noun}"), budget);
    }
    let items: Vec<String> = families[..shown]
        .iter()
        .map(|(name, count)| format!("{name} {count}"))
        .collect();
    let mut out = format!("{prefix}{}", items.join(", "));
    if shown < families.len() {
        out.push_str(&format!(" +{} more", families.len() - shown));
    }
    out
}

impl HeaderDevices {
    fn spans(&self, budget: usize) -> Vec<Span<'static>> {
        const SEP: &str = "  ·  ";
        let len = |text: &str| text.chars().count();
        let avail = budget.saturating_sub(len(&self.selected));
        let types_w = if self.types.is_empty() {
            0
        } else {
            len(SEP) + len(&self.types)
        };
        let mut spans = Vec::new();
        if !self.selected.is_empty() {
            spans.push(Span::styled(self.selected.clone(), theme::ice()));
        }
        let everything = len(&self.names.join(", ")) + types_w <= avail;
        if everything || self.families.is_empty() {
            let types = if types_w > avail / 2 && self.models > 0 {
                format!("{} models", self.models)
            } else {
                self.types.clone()
            };
            let types_w = if types.is_empty() {
                0
            } else {
                len(SEP) + len(&types)
            };
            spans.push(Span::styled(
                devices_phrase(&self.names, avail.saturating_sub(types_w)),
                theme::mute(),
            ));
            if !types.is_empty() {
                spans.push(Span::styled(format!("{SEP}{types}"), theme::dim()));
            }
            return spans;
        }
        let models = if self.models > 0 {
            format!("{SEP}{} models", self.models)
        } else {
            String::new()
        };
        spans.push(Span::styled(
            family_summary(&self.families, avail.saturating_sub(len(&models))),
            theme::mute(),
        ));
        if !models.is_empty() {
            spans.push(Span::styled(models, theme::dim()));
        }
        spans
    }
}

fn header_lines(state: &IpswState, width: u16, height: u16) -> Vec<Line<'static>> {
    let name = state
        .archive
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into());
    let (version, devices) = match state.info.as_ref() {
        Some(info) => {
            let version = match (info.product_version.as_deref(), info.build.as_deref()) {
                (Some(version), Some(build)) => format!("{version} ({build})"),
                (Some(version), None) => version.to_string(),
                (None, Some(build)) => format!("({build})"),
                (None, None) => "version unknown".into(),
            };
            let mut names = state.device_names();
            if names.is_empty() {
                names.push("devices unknown".into());
            }
            let types = if names == info.product_types {
                String::new()
            } else {
                info.product_types.join(", ")
            };
            let selected = state
                .device
                .as_deref()
                .map(|product_type| match state.device_name(product_type) {
                    Some(name) => format!("{product_type} selected ({name})  ·  "),
                    None => format!("{product_type} selected  ·  "),
                })
                .unwrap_or_default();
            (
                version,
                HeaderDevices {
                    selected,
                    names,
                    types,
                    families: state.device_families(),
                    models: info.product_types.len(),
                },
            )
        }
        None => (
            "no BuildManifest.plist".into(),
            HeaderDevices {
                selected: String::new(),
                names: vec!["devices unknown".into()],
                types: String::new(),
                families: Vec::new(),
                models: 0,
            },
        ),
    };

    let summary = state.summary();
    let mut summary_spans = vec![
        Span::styled(" ", theme::dim()),
        Span::styled(
            format!(
                "{} · {} selected, {}",
                plural(summary.files, "file", "files"),
                format_size(summary.bytes),
                plural(summary.components, "component", "components"),
            ),
            if summary.files + summary.components > 0 {
                theme::ice()
            } else {
                theme::mute()
            },
        ),
    ];
    if let Some(error) = state.error.as_deref() {
        summary_spans.push(Span::styled("    ", theme::dim()));
        summary_spans.push(Span::styled(
            fit(error, (width as usize).saturating_sub(40).max(16)),
            theme::fail(),
        ));
    }

    let budget = width.saturating_sub(2) as usize;
    if height >= 4 {
        vec![
            Line::from(vec![
                Span::styled(" archive  ", theme::dim()),
                Span::styled(fit(&name, budget.saturating_sub(9)), theme::title()),
            ]),
            Line::from(vec![
                Span::styled(" version  ", theme::dim()),
                Span::styled(fit(&version, budget.saturating_sub(9)), theme::list_text()),
            ]),
            Line::from(
                std::iter::once(Span::styled(" devices  ", theme::dim()))
                    .chain(devices.spans(budget.saturating_sub(9)))
                    .collect::<Vec<_>>(),
            ),
            Line::from(summary_spans),
        ]
    } else {
        let name = fit(&name, budget / 3);
        let version_len = version.chars().count();
        let rest = budget.saturating_sub(name.chars().count() + version_len + 4);
        let mut first = vec![
            Span::styled(" ", theme::dim()),
            Span::styled(name, theme::title()),
            Span::styled("  ", theme::dim()),
            Span::styled(version, theme::list_text()),
            Span::styled("  ", theme::dim()),
        ];
        first.extend(devices.spans(rest));
        vec![Line::from(first), Line::from(summary_spans)]
    }
}

fn render_browse(frame: &mut Frame, area: Rect, app: &mut App) {
    app.hits.ipsw_tree_rows.clear();
    app.hits.ipsw_tree_start = 0;
    app.hits.ipsw_option_rows.clear();
    app.hits.ipsw_option_start = 0;

    let header_h = if area.height >= 18 { 4 } else { 2 };
    let [header, panes] =
        Layout::vertical([Constraint::Length(header_h), Constraint::Fill(1)]).areas(area);
    frame.render_widget(
        Paragraph::new(header_lines(&app.ipsw, header.width, header_h)),
        header,
    );

    let tree_focus = app.ipsw.pane == IpswPane::Tree;
    if panes.width < 64 {
        if tree_focus {
            render_tree(frame, panes, app, true);
        } else {
            render_options(frame, panes, app, true);
        }
        return;
    }
    let options_w = (panes.width * 3 / 10).clamp(30, 42);
    let [tree, options] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(options_w)])
        .spacing(1)
        .areas(panes);
    render_tree(frame, tree, app, tree_focus);
    render_options(frame, options, app, !tree_focus);
}

fn mark_text(mark: Mark) -> String {
    let glyphs = ui::glyphs();
    match mark {
        Mark::None => glyphs.check_off.to_string(),
        Mark::Full => glyphs.check_on.to_string(),
        Mark::Partial => {
            if ui::current_pack() == GlyphPack::Ascii {
                "[-]".into()
            } else {
                "◐".into()
            }
        }
    }
}

fn mark_style(mark: Mark) -> Style {
    match mark {
        Mark::None => theme::dim(),
        Mark::Partial => theme::wait(),
        Mark::Full => theme::ice(),
    }
}

fn fold_text(expanded: bool) -> &'static str {
    match (ui::current_pack(), expanded) {
        (GlyphPack::Ascii, true) => "v ",
        (GlyphPack::Ascii, false) => "> ",
        (_, true) => "▾ ",
        (_, false) => "▸ ",
    }
}

fn row_parts(row: &IpswRow, filtering: bool) -> (String, String) {
    if filtering {
        return (String::new(), row.name.clone());
    }
    let indent = "  ".repeat(row.depth.min(12));
    let fold = if row.is_dir {
        fold_text(row.expanded)
    } else {
        "  "
    };
    let name = if row.is_dir {
        format!("{}/", row.label)
    } else {
        row.label.clone()
    };
    (format!("{indent}{fold}"), name)
}

fn natural_name_len(row: &IpswRow, filtering: bool) -> usize {
    let (lead, name) = row_parts(row, filtering);
    lead.chars().count() + name.chars().count()
}

fn clip_end(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    if width > 0 {
        out.push(ui::glyphs().ellipsis);
    }
    out
}

fn fit_segments(text: &str, width: usize, chips: &[String], count: usize) -> String {
    const SEP: &str = " · ";
    let fits = |candidate: &str| candidate.chars().count() <= width;
    if fits(text) {
        return text.to_string();
    }
    let mut segments = text.split(SEP);
    let title = segments.next().unwrap_or("");
    let rest: Vec<&str> = segments.collect();
    let install = rest
        .iter()
        .copied()
        .find(|segment| matches!(*segment, "erase" | "update"));
    let devices = rest
        .iter()
        .copied()
        .find(|segment| !matches!(*segment, "erase" | "update"))
        .map(short_devices);
    let short = short_title(title);
    let short = short.as_str();

    let join = |title: &str, install: Option<&str>, devices: Option<&str>| {
        [Some(title), install, devices]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(SEP)
    };
    let fallbacks = devices
        .as_deref()
        .map(|devices| device_fallbacks(devices, chips, count))
        .unwrap_or_default();
    let mut attempts = vec![join(title, install, fallbacks.first().map(String::as_str))];
    for fallback in &fallbacks {
        attempts.push(join(short, install, Some(fallback)));
    }
    if install.is_some() {
        attempts.push(join(short, install, None));
    }
    attempts.push(short.to_string());
    for candidate in attempts {
        if fits(&candidate) {
            return candidate;
        }
    }
    clip_end(short, width)
}

fn device_fallbacks(short: &str, chips: &[String], count: usize) -> Vec<String> {
    let mut options = vec![short.to_string()];
    if short == "all" {
        return options;
    }
    let (names, more) = match short.rsplit_once(" +") {
        Some((names, more)) if more.chars().all(|c| c.is_ascii_digit()) => {
            (names, more.parse::<usize>().unwrap_or(0))
        }
        _ => (short, 0),
    };
    let listed = names.split(", ").count();
    let total = listed + more;
    if total <= 1 {
        return options;
    }
    let first = names.split(", ").next().unwrap_or(names);
    options.push(format!("{first} +{}", total - 1));
    let noun = if short.contains("Mac") {
        "Macs"
    } else {
        "devices"
    };
    let count = if count > 0 { count } else { total };
    if (1..=3).contains(&chips.len()) {
        options.push(format!("{} · {count} {noun}", chips.join(", ")));
    }
    options.push(format!("{count} {noun}"));
    options
}

fn short_devices(phrase: &str) -> String {
    if phrase.starts_with("all ") && phrase.ends_with(" devices") {
        return "all".into();
    }
    let (names, more) = match phrase.rfind(" +") {
        Some(at) if phrase.ends_with(" more") => {
            let count = &phrase[at + 2..phrase.len() - " more".len()];
            (&phrase[..at], format!(" +{count}"))
        }
        _ => (phrase, String::new()),
    };
    let mut devices = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (index, c) in names.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                devices.push(&names[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    devices.push(&names[start..]);
    let short: Vec<&str> = devices
        .iter()
        .map(|device| {
            let device = device.trim();
            device.split(" (").next().unwrap_or(device)
        })
        .collect();
    format!("{}{more}", short.join(", "))
}

fn short_title(title: &str) -> String {
    // "(x86)" is kept because it tells two otherwise identical entries apart.
    let (base, arch) = match title
        .strip_suffix(')')
        .and_then(|rest| rest.rsplit_once(" ("))
    {
        Some((base, "x86")) => (base, " (x86)"),
        Some((base, _)) => (base, ""),
        None => (title, ""),
    };
    let short = match base.strip_prefix("Trust cache for ") {
        Some(of) if mapped_title(base).is_none() => {
            let mut chars = of.chars();
            let capitalised: String = chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect())
                .unwrap_or_default();
            format!("{} trust cache", short_title(&capitalised))
        }
        _ => mapped_title(base).unwrap_or(base).to_string(),
    };
    format!("{short}{arch}")
}

fn mapped_title(title: &str) -> Option<&'static str> {
    Some(match title {
        "Restore ramdisk" => "Ramdisk",
        "macOS system volume" | "iOS system volume" | "iPadOS system volume" => "System volume",
        "Restore trust cache" => "Trust cache",
        "Trust cache for restore ramdisk" => "Ramdisk trust cache",
        "Restore kernelcache" => "Restore kernel",
        "Encrypted disk image" => "Encrypted image",
        "Secure Enclave firmware" => "SEP firmware",
        "Restore information" => "Restore info",
        "Recovery base system" => "Recovery base",
        _ => return None,
    })
}

const MIN_DESCRIPTION_W: usize = 14;

struct TreeCols {
    name: usize,
    tag_w: usize,
    size_w: usize,
}

fn tree_cols<'a>(
    rows: impl Iterator<Item = &'a IpswRow> + Clone,
    width: usize,
    filtering: bool,
) -> TreeCols {
    let natural = rows
        .clone()
        .map(|row| natural_name_len(row, filtering))
        .max()
        .unwrap_or(1);
    let longest_description = rows
        .clone()
        .filter_map(|row| row.description.as_deref())
        .map(|text| text.chars().count())
        .max()
        .unwrap_or(0);
    let tag_w = if width >= 36 {
        rows.clone()
            .filter_map(|row| row.tag)
            .map(|tag| 1 + tag.len())
            .max()
            .unwrap_or(0)
    } else {
        0
    };
    let size_w = if width >= 28 {
        rows.filter(|row| !row.is_dir || row.size > 0)
            .map(|row| 1 + format_size(row.size).chars().count())
            .max()
            .unwrap_or(0)
    } else {
        0
    };
    TreeCols {
        name: capped_name_col(natural, width, tag_w, size_w, longest_description),
        tag_w,
        size_w,
    }
}

const DESCRIPTION_FLOOR: usize = 22;

const WHOLE_NAME_COLS: usize = 44;

/// Long paths in a flat filter view must not push every description out of the row.
fn capped_name_col(
    natural: usize,
    width: usize,
    tag_w: usize,
    size_w: usize,
    longest_description: usize,
) -> usize {
    let room = width.saturating_sub(4 + tag_w + size_w);
    let need = if longest_description == 0 {
        0
    } else {
        2 + longest_description.min(DESCRIPTION_FLOOR)
    };
    let cap = room
        .saturating_sub(need)
        .max(natural.min(WHOLE_NAME_COLS))
        .max(16);
    natural.min(cap)
}

fn tree_line(
    row: &IpswRow,
    width: u16,
    cursor: bool,
    focused: bool,
    filtering: bool,
    cols: &TreeCols,
) -> Line<'static> {
    let glyphs = ui::glyphs();
    let width = width as usize;
    let focus = if cursor { glyphs.focus } else { glyphs.idle };
    let mark = mark_text(row.mark);
    let (lead, name) = row_parts(row, filtering);
    let tag = if cols.tag_w > 0 {
        format!(
            " {:<w$}",
            row.tag.unwrap_or(""),
            w = cols.tag_w.saturating_sub(1)
        )
    } else {
        String::new()
    };
    let size = if cols.size_w > 0 && (!row.is_dir || row.size > 0) {
        format!(
            " {:>w$}",
            format_size(row.size),
            w = cols.size_w.saturating_sub(1)
        )
    } else {
        " ".repeat(cols.size_w)
    };
    let lead_w = lead.chars().count();
    let head_w = focus.chars().count() + mark.chars().count() + 1 + lead_w;
    let avail = width
        .saturating_sub(head_w + tag.chars().count() + size.chars().count())
        .max(1);
    let mut name_w = cols.name.saturating_sub(lead_w).clamp(1, avail);
    let room = avail - name_w;
    let desc_w = if room >= MIN_DESCRIPTION_W {
        room
    } else {
        name_w = avail;
        0
    };
    let name = format!("{:<name_w$}", fit(&name, name_w));
    let desc = if desc_w == 0 {
        String::new()
    } else {
        let text = row.description.as_deref().unwrap_or("");
        format!(
            "  {:<w$}",
            fit_segments(text, desc_w - 2, &row.chips, row.device_count),
            w = desc_w - 2
        )
    };

    if cursor {
        let mut text = format!("{focus}{mark} {lead}{name}{desc}{tag}{size}");
        pad_to_width(&mut text, width);
        let style = if focused {
            theme::focus_row()
        } else {
            theme::selected_row()
        };
        return Line::from(Span::styled(text, style));
    }
    let name_style = if row.is_dir {
        theme::ice()
    } else {
        theme::list_text()
    };
    let mut spans = vec![
        Span::styled(focus.to_string(), theme::ice()),
        Span::styled(format!("{mark} "), mark_style(row.mark)),
        Span::styled(lead, theme::dim()),
        Span::styled(name, name_style),
        Span::styled(desc, theme::dim()),
        Span::styled(tag, theme::dim()),
        Span::styled(size, theme::dim()),
    ];
    let used: usize = spans.iter().map(|span| span.content.chars().count()).sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
    Line::from(spans)
}

fn render_tree(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    let total = app.ipsw.tree.as_ref().map(|tree| tree.len()).unwrap_or(0);
    let filtering = !app.ipsw.filter.is_empty();
    let title = if filtering {
        format!("matches  {}", app.ipsw.row_count())
    } else {
        format!("archive  {total}")
    };
    let block = ui::pane(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let show_filter = filtering || app.ipsw.filter_editing;
    let list = if show_filter && inner.height >= 2 {
        let [bar, list] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
        let field_w = bar.width.saturating_sub(10).max(1);
        let editing = app.ipsw.filter_editing;
        let mut line = vec![Span::styled(" filter  ", theme::dim())];
        line.extend(
            ui::path_field_line(&app.ipsw.filter, app.ipsw.filter.len(), field_w, editing).spans,
        );
        frame.render_widget(Paragraph::new(Line::from(line)), bar);
        list
    } else {
        inner
    };
    let strip_lines: u16 = if list.height >= 15 {
        3
    } else if list.height >= 11 {
        2
    } else {
        0
    };
    let (list, strip) = if strip_lines > 0 {
        let [list, strip] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(strip_lines + 1)])
                .areas(list);
        (list, Some(strip))
    } else {
        (list, None)
    };

    app.ipsw.page_rows = list.height as usize;
    app.ipsw.clamp_cursor();
    let count = app.ipsw.row_count();
    if count == 0 {
        let text = if filtering {
            "no entries match the filter"
        } else {
            "the archive has no files"
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text, theme::dim()))),
            list,
        );
        return;
    }

    let height = list.height as usize;
    let cursor = app.ipsw.cursor;
    let start = scroll_start(count, cursor, height);
    let text_w = list.width.saturating_sub(u16::from(count > height));
    let lines: Vec<Line<'static>> = app.ipsw.with_rows(|rows| {
        let shown = rows.iter().enumerate().skip(start).take(height);
        let cols = tree_cols(
            shown.clone().map(|(_, row)| row),
            text_w as usize,
            filtering,
        );
        shown
            .map(|(index, row)| tree_line(row, text_w, index == cursor, focused, filtering, &cols))
            .collect()
    });
    app.hits.ipsw_tree_start = start;
    app.hits.ipsw_tree_rows = (0..lines.len())
        .map(|offset| Rect {
            x: list.x,
            y: list.y + offset as u16,
            width: text_w,
            height: 1,
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            width: text_w,
            ..list
        },
    );
    ui::render_scrollbar(frame, list, count, height, start);
    if let Some(strip) = strip {
        render_detail(frame, strip, &app.ipsw);
    }
}

fn devices_phrase(devices: &[String], budget: usize) -> String {
    let len = |text: &str| text.chars().count();
    let mut shown = 0;
    let mut used = 0;
    for (index, device) in devices.iter().enumerate() {
        let hidden_after = devices.len() - index - 1;
        let suffix = if hidden_after > 0 {
            len(&format!(" +{hidden_after} more"))
        } else {
            0
        };
        let next = used + len(device) + if index > 0 { 2 } else { 0 };
        if next + suffix > budget {
            break;
        }
        used = next;
        shown = index + 1;
    }
    if shown == 0 {
        return match devices.first() {
            Some(first) => clip_end(first, budget),
            None => String::new(),
        };
    }
    let mut out = devices[..shown].join(", ");
    if shown < devices.len() {
        out.push_str(&format!(" +{} more", devices.len() - shown));
    }
    out
}

fn detail_lines(state: &IpswState, row: &IpswRow, width: usize) -> Vec<Line<'static>> {
    let sep = "  ·  ";
    if row.is_dir {
        let (files, bytes) = state.folder_totals(&row.name);
        let title = match row.description.as_deref() {
            Some(about) => {
                let path = fit(
                    &format!("{}/", row.name),
                    width.saturating_sub(about.chars().count() + 2),
                );
                vec![
                    Span::styled(" ", theme::dim()),
                    Span::styled(clip_end(about, width), theme::title()),
                    Span::styled(format!("  {path}"), theme::dim()),
                ]
            }
            None => vec![
                Span::styled(" ", theme::dim()),
                Span::styled(fit(&format!("{}/", row.name), width), theme::title()),
            ],
        };
        return vec![
            Line::from(title),
            Line::from(Span::styled(
                format!(
                    " {} · {}",
                    plural(files, "file", "files"),
                    format_size(bytes)
                ),
                theme::mute(),
            )),
            Line::from(Span::styled(
                " space selects every file below it",
                theme::dim(),
            )),
        ];
    }

    let note = state.export_note(row);
    let found = state.describe(&row.name);
    let Some(found) = found else {
        return vec![
            Line::from(vec![
                Span::styled(" ", theme::dim()),
                Span::styled(fit(&row.label, width), theme::title()),
            ]),
            Line::from(Span::styled(" no description for this entry", theme::dim())),
            Line::from(Span::styled(format!(" {note}"), theme::ice())),
        ];
    };

    let mut title = vec![
        Span::styled(" ", theme::dim()),
        Span::styled(found.title.clone(), theme::title()),
    ];
    if !found.from_manifest {
        title.push(Span::styled("  from the name", theme::dim()));
    }
    let mut about = Vec::new();
    let install = found
        .install
        .as_deref()
        .map(|install| format!("{install} restore"));
    let chips = (found.devices.len() > 2 && !found.chips.is_empty())
        .then(|| format!("chips: {}", found.chips.join(", ")));
    let extras: usize = [install.as_ref(), chips.as_ref()]
        .into_iter()
        .flatten()
        .map(|text| text.chars().count() + sep.chars().count())
        .sum();
    let devices_budget = width.saturating_sub(1).saturating_sub(extras);
    let devices = devices_phrase(&found.devices, devices_budget);
    if !devices.is_empty() {
        about.push(devices);
    }
    about.extend(chips);
    about.extend(install);
    let components = if found.components.is_empty() {
        String::new()
    } else {
        format!("manifest: {}", found.components.join(", "))
    };
    vec![
        Line::from(title),
        Line::from(Span::styled(
            format!(" {}", clip_end(&about.join(sep), width.saturating_sub(1))),
            theme::mute(),
        )),
        Line::from(Span::styled(
            format!(
                " {}",
                fit(
                    &if components.is_empty() {
                        note.to_string()
                    } else {
                        format!("{components}{sep}{note}")
                    },
                    width.saturating_sub(1)
                )
            ),
            theme::dim(),
        )),
    ]
}

fn render_detail(frame: &mut Frame, area: Rect, state: &IpswState) {
    if area.height < 2 {
        return;
    }
    let [rule, body] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
    frame.render_widget(
        Paragraph::new(ui::glyphs().rule_line(rule.width)).style(theme::dim()),
        rule,
    );
    let Some(row) = state.row_at(state.cursor) else {
        return;
    };
    let mut lines = detail_lines(state, &row, body.width.saturating_sub(2) as usize);
    if lines.len() > body.height as usize {
        let last = lines.pop();
        lines.truncate(body.height as usize);
        if !row.is_dir
            && body.height >= 2
            && let Some(last) = last
        {
            lines[body.height as usize - 1] = last;
        }
    }
    frame.render_widget(Paragraph::new(lines), body);
}

fn mask_key(key: &str) -> String {
    let dot = if ui::current_pack() == GlyphPack::Ascii {
        '*'
    } else {
        '•'
    };
    let chars: Vec<char> = key.chars().collect();
    let hidden = chars.len().saturating_sub(4);
    let mut out: String = std::iter::repeat_n(dot, hidden).collect();
    out.extend(chars[hidden..].iter());
    out
}

fn option_parts(state: &IpswState, item: OptionItem) -> (String, String, bool) {
    let glyphs = ui::glyphs();
    let check = |on: bool| {
        if on {
            glyphs.check_on
        } else {
            glyphs.check_off
        }
    };
    match item {
        OptionItem::Toggle(toggle) => (
            format!("{} {}", check(toggle.get(&state.options)), toggle.label()),
            String::new(),
            false,
        ),
        OptionItem::AeaKey => {
            let mut value = match state.options.aea_key.as_deref() {
                Some(key) => mask_key(key),
                None if state.aea_editing => String::new(),
                None => "fetch from Apple".into(),
            };
            let placeholder = state.options.aea_key.is_none() && !state.aea_editing;
            if state.aea_editing {
                value.push('_');
            }
            ("AEA key".into(), value, placeholder)
        }
        OptionItem::Device => (
            "Device".into(),
            format!(
                "< {} >",
                state
                    .device
                    .as_deref()
                    .map(|device| {
                        state
                            .device_name(device)
                            .unwrap_or_else(|| device.to_string())
                    })
                    .unwrap_or_else(|| "all".into())
            ),
            state.device.is_none(),
        ),
        OptionItem::Component(component) => (
            format!(
                "{} {}",
                check(state.components.contains(&component)),
                component.label()
            ),
            String::new(),
            false,
        ),
    }
}

fn option_line(
    state: &IpswState,
    item: OptionItem,
    width: u16,
    cursor: bool,
    focused: bool,
) -> Line<'static> {
    let glyphs = ui::glyphs();
    let width = width as usize;
    let focus = if cursor { glyphs.focus } else { glyphs.idle };
    let (left, right, placeholder) = option_parts(state, item);
    let left_w = focus.chars().count() + left.chars().count();
    let budget = width.saturating_sub(left_w + 1).max(1);
    let right = if item == OptionItem::Device {
        let name = right
            .strip_prefix("< ")
            .and_then(|rest| rest.strip_suffix(" >"))
            .unwrap_or(&right);
        format!("< {} >", clip_end(name, budget.saturating_sub(4).max(1)))
    } else {
        clip_end(&right, budget)
    };
    let gap = width.saturating_sub(left_w + right.chars().count());
    if cursor {
        let mut text = format!("{focus}{left}{}{right}", " ".repeat(gap));
        pad_to_width(&mut text, width);
        let style = if focused {
            theme::focus_row()
        } else {
            theme::selected_row()
        };
        return Line::from(Span::styled(text, style));
    }
    Line::from(vec![
        Span::styled(focus.to_string(), theme::ice()),
        Span::styled(left, theme::list_text()),
        Span::raw(" ".repeat(gap)),
        Span::styled(
            right,
            if placeholder {
                theme::dim()
            } else {
                theme::ice()
            },
        ),
    ])
}

fn render_options(frame: &mut Frame, area: Rect, app: &mut App, focused: bool) {
    let block = ui::pane("export options", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let state = &app.ipsw;
    let count = crate::ipsw_app::OPTION_COUNT;
    let cursor = state.option_cursor.min(count - 1);
    let mut lines: Vec<(Option<usize>, Line<'static>)> = Vec::with_capacity(count + 1);
    for index in 0..count {
        if index == FIRST_COMPONENT_OPTION {
            lines.push((
                None,
                Line::from(Span::styled(
                    " Components (ipsw extract)",
                    theme::dim().add_modifier(Modifier::BOLD),
                )),
            ));
        }
        let Some(item) = option_item(index) else {
            continue;
        };
        let text_w = inner.width.saturating_sub(1);
        lines.push((
            Some(index),
            option_line(state, item, text_w, index == cursor, focused),
        ));
    }

    let height = inner.height as usize;
    let cursor_line = lines
        .iter()
        .position(|(index, _)| *index == Some(cursor))
        .unwrap_or(0);
    let start = scroll_start(lines.len(), cursor_line, height);
    let overflow = lines.len() > height;
    let text_w = inner.width.saturating_sub(u16::from(overflow));

    let mut rects = Vec::new();
    let mut first_item = None;
    let mut shown = Vec::new();
    for (offset, (index, line)) in lines.iter().skip(start).take(height).enumerate() {
        if let Some(index) = index {
            first_item.get_or_insert(*index);
            rects.push(Rect {
                x: inner.x,
                y: inner.y + offset as u16,
                width: text_w,
                height: 1,
            });
        }
        shown.push(line.clone());
    }
    app.hits.ipsw_option_start = first_item.unwrap_or(0);
    app.hits.ipsw_option_rows = rects;
    frame.render_widget(
        Paragraph::new(shown),
        Rect {
            width: text_w,
            ..inner
        },
    );
    ui::render_scrollbar(frame, inner, lines.len(), height, start);
}

fn render_output(frame: &mut Frame, area: Rect, app: &mut App) {
    let width = {
        let inner = area.width.saturating_sub(4);
        inner.clamp(40.min(inner), 56.min(inner).max(40.min(inner)))
    };
    let text_w = width.saturating_sub(4) as usize;
    let default = app.ipsw.default_output();
    let mut notes: Vec<Line<'static>> = Vec::new();
    if let Some(error) = app.ipsw.error.as_deref() {
        notes.push(Line::from(Span::styled(fit(error, text_w), theme::fail())));
    }
    if let Some(default) = default.as_ref() {
        notes.push(Line::from(vec![
            Span::styled("default  ", theme::dim()),
            Span::styled(
                fit(&default.to_string_lossy(), text_w.saturating_sub(9)),
                theme::ice(),
            ),
        ]));
    }
    notes.push(Line::from(Span::styled(
        "enter with nothing typed or copied uses the default",
        theme::dim(),
    )));
    notes.push(Line::from(Span::styled(
        "a folder that does not exist yet is created",
        theme::dim(),
    )));

    let want = if area.height >= 22 {
        (notes.len() as u16 + 2).min(6)
    } else if area.height >= 16 {
        4
    } else {
        3
    };
    let note_h = want.min(area.height.saturating_sub(5));
    let [top, bottom] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(note_h)]).areas(area);
    ui::render_file_picker_hinted(
        frame,
        top,
        app,
        "export folder",
        false,
        false,
        &ui::PickerHints {
            empty: "press Enter to use a copied folder, or the default",
            folder: "from clipboard  ·  folder  ·  Enter exports here",
        },
    );

    if note_h < 3 {
        return;
    }
    let card = ui::center(bottom, width, note_h);
    let block = ui::rounded("destination", theme::HAIRLINE);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let lines: Vec<Line<'static>> = notes.into_iter().take(inner.height as usize).collect();
    frame.render_widget(Paragraph::new(lines), ui::inset(inner, 1, 0));
}

fn render_exporting(frame: &mut Frame, area: Rect, app: &App) {
    let run: &RunView = &app.ipsw.run;
    let width = area.width.saturating_sub(4).clamp(40.min(area.width), 76);
    let height = area.height.min(17);
    let card = ui::center(area, width, height);
    let block = ui::rounded("exporting", theme::WAIT);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let text_w = inner.width.saturating_sub(2) as usize;

    let spinner = ui::spinner_frame(app.tick);
    let action = if run.cancelling {
        "cancelling".to_string()
    } else {
        run.action
            .map(action_label)
            .unwrap_or_else(|| "starting".into())
    };
    let position = if run.total_items > 0 {
        format!(
            "item {} of {}",
            (run.index + 1).min(run.total_items),
            run.total_items
        )
    } else {
        "preparing".into()
    };
    let fraction = run.fraction();
    let bar_w = inner.width.saturating_sub(10).clamp(10, 48);
    let mut bar = vec![Span::styled(" ", theme::dim())];
    bar.extend(ui::glow_bar(app.tick, bar_w, fraction, ui::WORK_BAR).spans);
    bar.push(Span::styled(
        format!(" {}", ui::progress_label(fraction).unwrap_or_default()),
        theme::mute(),
    ));
    let bytes = if run.total_bytes > 0 {
        format!(
            "{} of {}",
            format_size(run.done_bytes),
            format_size(run.total_bytes)
        )
    } else {
        String::new()
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {spinner}  {action}"), theme::wait()),
            Span::styled(ui::dots_frame(app.tick), theme::wait()),
        ]),
        Line::from(Span::styled(
            format!(" {}", fit(&run.current, text_w)),
            theme::title(),
        )),
        Line::from(Span::styled(format!(" {position}"), theme::dim())),
        Line::from(bar),
        Line::from(Span::styled(format!(" {bytes}"), theme::dim())),
    ];
    if let Some(found) = app.ipsw.describe(&run.current) {
        lines.insert(
            2,
            Line::from(Span::styled(
                format!(" {}", fit(&found.summary, text_w)),
                theme::mute(),
            )),
        );
    }
    if let Some(output) = app.ipsw.output.as_ref() {
        lines.push(Line::from(vec![
            Span::styled(" to ", theme::dim()),
            Span::styled(
                fit(&output.to_string_lossy(), text_w.saturating_sub(4)),
                theme::mute(),
            ),
        ]));
    }
    if run.cancelling {
        lines.push(Line::from(Span::styled(
            " stopping the running command and removing partial files",
            theme::wait(),
        )));
    } else {
        lines.push(Line::from(""));
    }
    let room = (inner.height as usize).saturating_sub(lines.len());
    let skip = run.log.len().saturating_sub(room);
    for entry in run.log.iter().skip(skip) {
        lines.push(Line::from(Span::styled(
            format!(" {}", fit(entry, text_w)),
            theme::dim(),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

const STATUS_W: usize = 14;

fn relative_to(path: &std::path::Path, output: &std::path::Path) -> String {
    path.strip_prefix(output)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn outcome_row(
    item: &crate::ipsw_export::ItemReport,
    output: &std::path::Path,
) -> (&'static str, String, Style) {
    let dest = |path: &std::path::Path| relative_to(path, output);
    match &item.outcome {
        Outcome::Written { path } => ("written", dest(path), theme::list_text()),
        Outcome::Linked { path } => ("linked", dest(path), theme::list_text()),
        Outcome::Decrypted { path, .. } => ("decrypted", dest(path), theme::list_text()),
        Outcome::Decompressed { path, .. } => ("decompressed", dest(path), theme::list_text()),
        Outcome::Kept { warning, .. } => ("kept", warning.clone(), theme::wait()),
        // "<path> already exists" repeats the name column; the reason is all that is new.
        Outcome::Skipped { reason } if reason.trim_end().ends_with("already exists") => {
            ("skipped", "already exists".to_string(), theme::mute())
        }
        Outcome::Skipped { reason } => ("skipped", reason.clone(), theme::mute()),
        Outcome::Produced { paths } => (
            "produced",
            plural(paths.len(), "file", "files"),
            theme::list_text(),
        ),
        Outcome::Failed { reason } => ("failed", reason.clone(), theme::fail()),
    }
}

fn render_done(frame: &mut Frame, area: Rect, app: &mut App) {
    let Some((counts, cancelled, output)) = app
        .ipsw
        .report
        .as_ref()
        .map(|report| (report.counts(), report.cancelled, report.output.clone()))
    else {
        return;
    };
    let border = if counts.failed > 0 {
        theme::FAIL
    } else if cancelled || counts.kept > 0 {
        theme::WAIT
    } else {
        theme::ICE
    };
    let width = area.width.saturating_sub(4).clamp(40.min(area.width), 100);
    let card = ui::center(area, width, area.height);
    let block = ui::rounded(if cancelled { "cancelled" } else { "done" }, border);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    if inner.width < 4 || inner.height == 0 {
        return;
    }
    let text_w = inner.width.saturating_sub(2) as usize;

    let mut summary = vec![
        Line::from(Span::styled(
            if cancelled {
                " Export cancelled"
            } else {
                " Export finished"
            },
            if cancelled {
                theme::wait()
            } else {
                theme::pass()
            },
        )),
        Line::from(vec![
            Span::styled(" output  ", theme::dim()),
            Span::styled(
                fit(&output.to_string_lossy(), text_w.saturating_sub(8)),
                theme::list_text(),
            ),
        ]),
    ];
    if cancelled {
        summary.push(Line::from(Span::styled(
            " cancelled - partial files were removed",
            theme::wait(),
        )));
    }
    let count = |label: &str, n: usize, style: Style| {
        vec![
            Span::styled(format!("{label} "), theme::dim()),
            Span::styled(format!("{n}"), if n > 0 { style } else { theme::dim() }),
            Span::styled("   ", theme::dim()),
        ]
    };
    let mut first = vec![Span::styled(" ", theme::dim())];
    first.extend(count("written", counts.written, theme::list_text()));
    first.extend(count("decrypted", counts.decrypted, theme::list_text()));
    first.extend(count(
        "decompressed",
        counts.decompressed,
        theme::list_text(),
    ));
    first.extend(count("linked", counts.linked, theme::list_text()));
    let mut second = vec![Span::styled(" ", theme::dim())];
    second.extend(count("produced", counts.produced, theme::list_text()));
    second.extend(count("kept with warnings", counts.kept, theme::wait()));
    second.extend(count("skipped", counts.skipped, theme::mute()));
    second.extend(count("failed", counts.failed, theme::fail()));
    summary.push(Line::from(first));
    summary.push(Line::from(second));

    let summary_h = (summary.len() as u16).min(inner.height);
    let [top, rest] =
        Layout::vertical([Constraint::Length(summary_h), Constraint::Fill(1)]).areas(inner);
    frame.render_widget(Paragraph::new(summary), top);
    if rest.height < 2 {
        return;
    }
    let [rule, list] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(rest);
    frame.render_widget(
        Paragraph::new(ui::glyphs().rule_line(rule.width)).style(theme::dim()),
        rule,
    );

    app.ipsw.page_rows = list.height as usize;
    let items = app.ipsw.done_items();
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " nothing was exported",
                theme::dim(),
            ))),
            list,
        );
        return;
    }
    let height = list.height as usize;
    // Always reserve the scrollbar column: wrapped reasons make line count differ from item count.
    let text_w = list.width.saturating_sub(1) as usize;
    let all: Vec<Vec<Line<'static>>> = items
        .iter()
        .map(|item| {
            let title = if matches!(item.outcome, Outcome::Produced { .. }) {
                None
            } else {
                app.ipsw
                    .describe(&item.name)
                    .map(|found| found.title)
                    .filter(|title| !title.eq_ignore_ascii_case(&item.name))
            };
            done_lines(item, &output, text_w, title)
        })
        .collect();

    let mut start_max = items.len() - 1;
    let mut tail = 0;
    for (index, lines) in all.iter().enumerate().rev() {
        if tail + lines.len() > height {
            break;
        }
        tail += lines.len();
        start_max = index;
    }
    let start = app.ipsw.done_scroll.min(start_max);
    let mut shown = Vec::new();
    let mut shown_items = 0;
    for lines in &all[start..] {
        if shown.len() >= height {
            break;
        }
        shown.extend(lines.iter().cloned());
        shown_items += 1;
    }
    frame.render_widget(
        Paragraph::new(shown),
        Rect {
            width: text_w as u16,
            ..list
        },
    );
    ui::render_scrollbar(frame, list, items.len(), shown_items, start);
}

fn wrap_reason(text: &str, first_w: usize) -> (String, Option<String>) {
    if text.chars().count() <= first_w {
        return (text.to_string(), None);
    }
    for (sep, keep, skip) in [(": ", 1, 2), (", ", 1, 2), (" ", 0, 1)] {
        let found = text
            .match_indices(sep)
            .filter(|(at, _)| text[..at + keep].chars().count() <= first_w)
            .last();
        if let Some((at, _)) = found {
            let rest = text[at + skip..].trim_start();
            if !rest.is_empty() {
                return (text[..at + keep].to_string(), Some(rest.to_string()));
            }
        }
    }
    let first: String = text.chars().take(first_w).collect();
    let rest: String = text.chars().skip(first_w).collect();
    (first, Some(rest))
}

fn done_lines(
    item: &crate::ipsw_export::ItemReport,
    output: &std::path::Path,
    text_w: usize,
    title: Option<String>,
) -> Vec<Line<'static>> {
    const DETAIL_FLOOR: usize = 45;

    let (tag, detail, style) = outcome_row(item, output);
    let name_w = (text_w / 3).max(8);
    let name = fit(&item.name, name_w);
    let base = 1 + STATUS_W + name_w + 2;
    let title_text = title
        .map(|title| {
            let title_w = title.chars().count().min(24);
            (title_w, title)
        })
        .filter(|(title_w, _)| text_w.saturating_sub(base + title_w + 2) >= DETAIL_FLOOR)
        .map(|(title_w, title)| format!("{:<title_w$}  ", clip_end(&title, title_w)))
        .unwrap_or_default();
    let used = base + title_text.chars().count();
    let detail_w = text_w.saturating_sub(used).max(1);
    let wraps = matches!(
        item.outcome,
        Outcome::Failed { .. } | Outcome::Kept { .. } | Outcome::Skipped { .. }
    );
    let (first, second) = if wraps {
        wrap_reason(&detail, detail_w)
    } else {
        (fit(&detail, detail_w), None)
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" {tag:<STATUS_W$}"), style),
        Span::styled(format!("{name:<name_w$}  "), theme::list_text()),
        Span::styled(title_text, theme::mute()),
        Span::styled(first, theme::dim()),
    ])];
    if let Some(rest) = second {
        lines.push(Line::from(vec![
            Span::raw(" ".repeat(used)),
            Span::styled(clip_end(&rest, detail_w), theme::dim()),
        ]));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsw_fixture::{sample_entries, write_ipsw};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::path::PathBuf;

    fn draw(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| ui::render(frame, app)).unwrap();
        text(terminal.backend().buffer())
    }

    fn text(buffer: &Buffer) -> String {
        let area = buffer.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn browsing() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("Fixture_26.0.ipsw");
        write_ipsw(&archive, &sample_entries()).unwrap();
        let mut app = App::new();
        app.set_ipsw_cli(Some(PathBuf::from("/nonexistent/ipsw")));
        app.screen = Screen::Ipsw;
        app.open_ipsw(archive.to_str().unwrap());
        app.drain_ipsw_job();
        (dir, app)
    }

    #[test]
    fn browse_shows_header_tree_and_options() {
        let (_dir, mut app) = browsing();
        let screen = draw(&mut app, 110, 34);
        assert!(screen.contains("Fixture_26.0.ipsw"), "{screen}");
        assert!(screen.contains("26.0 (25A1)"), "{screen}");
        assert!(screen.contains("Mac14,2"), "{screen}");
        assert!(screen.contains("0 files"), "{screen}");
        assert!(screen.contains("Firmware/"), "{screen}");
        assert!(screen.contains("Decrypt .aea images"), "{screen}");
        assert!(screen.contains("fetch from Apple"), "{screen}");
        assert!(screen.contains("Components (ipsw extract)"), "{screen}");
        assert!(!app.hits.ipsw_tree_rows.is_empty());
        assert!(!app.hits.ipsw_option_rows.is_empty());
    }

    fn realistic_browsing() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("Realistic_26.0.ipsw");
        write_ipsw(&archive, &crate::ipsw_fixture::realistic_entries()).unwrap();
        let mut app = App::new();
        app.set_ipsw_cli(Some(PathBuf::from("/nonexistent/ipsw")));
        app.screen = Screen::Ipsw;
        app.open_ipsw(archive.to_str().unwrap());
        app.drain_ipsw_job();
        (dir, app)
    }

    fn move_to(app: &mut App, name: &str) {
        app.ipsw.cursor = app
            .ipsw
            .rows()
            .iter()
            .position(|row| row.name == name)
            .unwrap_or_else(|| panic!("no row {name}"));
    }

    #[test]
    fn rows_show_what_each_entry_is() {
        let (_dir, mut app) = realistic_browsing();
        let screen = draw(&mut app, 120, 34);
        assert!(screen.contains("Restore ramdisk"), "{screen}");
        assert!(screen.contains("System cryptex"), "{screen}");
        assert!(screen.contains("Kernelcache"), "{screen}");
    }

    #[test]
    fn descriptions_never_push_out_names_and_a_short_terminal_keeps_rows() {
        let (_dir, mut app) = realistic_browsing();
        let screen = draw(&mut app, 100, 24);
        assert!(screen.contains("090-12345-001.dmg.aea"), "{screen}");
        assert!(screen.contains("kernelcache.release.mac14j"), "{screen}");
        assert!(screen.contains("Restore.plist"), "{screen}");
    }

    #[test]
    fn detail_strip_describes_a_file_and_what_export_does() {
        let (_dir, mut app) = realistic_browsing();
        move_to(&mut app, "090-12345-001.dmg.aea");
        let screen = draw(&mut app, 120, 34);
        assert!(screen.contains("macOS system volume"), "{screen}");
        assert!(screen.contains("manifest: OS"), "{screen}");
        assert!(screen.contains("decrypted on export"), "{screen}");
        app.ipsw.options.decrypt_aea = false;
        let screen = draw(&mut app, 120, 34);
        assert!(screen.contains("copied still encrypted"), "{screen}");
    }

    #[test]
    fn detail_strip_describes_a_folder_by_its_contents() {
        let (_dir, mut app) = realistic_browsing();
        move_to(&mut app, "Firmware");
        let (files, _) = app.ipsw.folder_totals("Firmware");
        assert!(files > 1);
        let screen = draw(&mut app, 120, 34);
        assert!(screen.contains(&format!("{files} files")), "{screen}");
        assert!(
            screen.contains("space selects every file below it"),
            "{screen}"
        );
    }

    #[test]
    fn header_names_the_devices_when_the_manifest_has_boards() {
        let (_dir, mut app) = realistic_browsing();
        let screen = draw(&mut app, 120, 34);
        let mini = crate::ramrod::boards::describe_board("j473ap", None).title;
        let macbook = crate::ramrod::boards::describe_board("j414cap", None).title;
        assert!(screen.contains(&mini), "{mini}\n{screen}");
        assert!(screen.contains(&macbook), "{macbook}\n{screen}");
        assert!(screen.contains("Mac14,3, Mac14,5"), "{screen}");
        app.ipsw.device = Some("Mac14,3".into());
        let screen = draw(&mut app, 120, 34);
        assert!(screen.contains("Mac14,3 selected"), "{screen}");
    }

    #[test]
    fn device_option_shows_the_device_name_and_clips_it_at_the_end() {
        let (_dir, mut app) = realistic_browsing();
        let mini = crate::ramrod::boards::describe_board("j473ap", None).title;
        app.ipsw.device = Some("Mac14,3".into());
        let (_, value, _) = option_parts(&app.ipsw, OptionItem::Device);
        assert_eq!(value, format!("< {mini} >"));
        app.ipsw.device = None;
        assert_eq!(option_parts(&app.ipsw, OptionItem::Device).1, "< all >");

        app.ipsw.device = Some("Mac14,3".into());
        let line = option_line(&app.ipsw, OptionItem::Device, 24, false, false);
        let shown: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(shown.contains("< Mac mini"), "{shown}");
        assert!(shown.trim_end().ends_with(" >"), "{shown}");
        assert!(
            shown.contains('…') || ui::current_pack() == GlyphPack::Ascii,
            "{shown}"
        );
    }

    #[test]
    fn descriptions_fit_by_whole_segments() {
        let fit = |text: &str, width: usize| fit_segments(text, width, &[], 0);
        let full = "Restore ramdisk · erase · all 2 devices";
        assert_eq!(fit(full, 60), full);
        assert_eq!(fit(full, 34), "Restore ramdisk · erase · all");
        assert_eq!(fit(full, 24), "Ramdisk · erase · all");
        assert_eq!(fit(full, 17), "Ramdisk · erase");
        assert_eq!(fit(full, 9), "Ramdisk");
        assert_eq!(fit(full, 5), "Ramd…");

        let mac = "Kernelcache · Mac mini (M2, 2023)";
        assert_eq!(fit(mac, 40), mac);
        assert_eq!(fit(mac, 22), "Kernelcache · Mac mini");
        assert_eq!(fit(mac, 15), "Kernelcache");

        let many = "Restore ramdisk · update · Mac mini (M2, 2023), MacBook Pro (14-inch, 2023, M2 Max) +1 more";
        assert_eq!(fit(many, 50), "Ramdisk · update · Mac mini, MacBook Pro +1");
        assert_eq!(fit("Kernelcache", 20), "Kernelcache");
    }

    #[test]
    fn device_segment_shrinks_step_by_step_before_it_goes() {
        let text = "Kernelcache · MacBook Air (M2, 2022), Mac mini (M2, 2023) +2 more";
        let chips = ["M2".to_string()];
        let fit = |width| fit_segments(text, width, &chips, 4);
        assert_eq!(fit(40), "Kernelcache · MacBook Air, Mac mini +2");
        assert_eq!(fit(30), "Kernelcache · MacBook Air +3");
        assert_eq!(fit(26), "Kernelcache · M2 · 4 Macs");
        assert_eq!(fit(21), "Kernelcache · 4 Macs");
        assert_eq!(fit(12), "Kernelcache");

        assert_eq!(
            device_fallbacks("MacBook Neo", &chips, 1),
            vec!["MacBook Neo".to_string()]
        );
        assert_eq!(device_fallbacks("all", &chips, 9), vec!["all".to_string()]);
        let many_chips: Vec<String> = ["M1", "M2", "M3", "M4"].map(String::from).to_vec();
        let options = device_fallbacks("A, B +2", &many_chips, 4);
        assert!(
            options.iter().all(|option| !option.contains("M1")),
            "{options:?}"
        );
        assert_eq!(options.last().map(String::as_str), Some("4 devices"));
    }

    fn header_text(devices: &HeaderDevices, budget: usize) -> String {
        devices
            .spans(budget)
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn header_keeps_names_and_types_when_they_fit_and_summarises_when_they_do_not() {
        let small = HeaderDevices {
            selected: "Mac14,3 selected (Mac mini (M2, 2023))  ·  ".into(),
            names: vec!["Mac mini (M2, 2023)".into()],
            types: "Mac14,3".into(),
            families: vec![("Mac mini".into(), 1)],
            models: 1,
        };
        assert_eq!(
            header_text(&small, 100),
            "Mac14,3 selected (Mac mini (M2, 2023))  ·  Mac mini (M2, 2023)  ·  Mac14,3"
        );

        let families: Vec<(String, usize)> = vec![
            ("MacBook Pro".into(), 23),
            ("Mac Studio".into(), 6),
            ("Mac mini".into(), 5),
            ("iMac".into(), 4),
        ];
        let big = HeaderDevices {
            selected: String::new(),
            names: (0..38).map(|n| format!("Mac model number {n}")).collect(),
            types: (0..40)
                .map(|n| format!("Mac{n},1"))
                .collect::<Vec<_>>()
                .join(", "),
            families: families.clone(),
            models: 40,
        };
        let text = header_text(&big, 100);
        assert_eq!(
            text,
            "38 Macs: MacBook Pro 23, Mac Studio 6, Mac mini 5, iMac 4  ·  40 models"
        );
        let narrow = header_text(&big, 62);
        assert!(narrow.starts_with("38 Macs: MacBook Pro 23"), "{narrow}");
        assert!(narrow.contains(" more"), "{narrow}");
        assert!(narrow.ends_with("  ·  40 models"), "{narrow}");
        assert!(narrow.chars().count() <= 62, "{narrow}");
    }

    #[test]
    fn family_summary_fits_whole_families() {
        let families: Vec<(String, usize)> = vec![
            ("MacBook Pro".into(), 23),
            ("Mac Studio".into(), 6),
            ("Mac mini".into(), 5),
            ("iMac".into(), 4),
        ];
        assert_eq!(
            family_summary(&families, 80),
            "38 Macs: MacBook Pro 23, Mac Studio 6, Mac mini 5, iMac 4"
        );
        assert_eq!(
            family_summary(&families, 45),
            "38 Macs: MacBook Pro 23, Mac Studio 6 +2 more"
        );
        assert_eq!(family_summary(&families, 12), "38 Macs");
    }

    #[test]
    fn long_paths_leave_descriptions_their_room() {
        let cap = capped_name_col(120, 100, 5, 8, 39);
        assert!(100 - 4 - 5 - 8 - cap >= DESCRIPTION_FLOOR, "{cap}");
        assert_eq!(capped_name_col(20, 74, 5, 8, 39), 20);
        assert_eq!(capped_name_col(43, 67, 5, 5, 26), 43);
        assert_eq!(capped_name_col(90, 100, 5, 8, 0), 83);

        let path = "Firmware/Manifests/restore/Customer Erase Install (IPSW)/centauri/centauri.j714cap.dev.im4m";
        let row = IpswRow {
            name: path.into(),
            label: "centauri.j714cap.dev.im4m".into(),
            depth: 0,
            is_dir: false,
            expanded: false,
            size: 1024,
            mark: Mark::None,
            tag: None,
            description: Some("Restore ramdisk · erase · all 2 devices".into()),
            chips: Vec::new(),
            device_count: 2,
        };
        let cols = tree_cols([&row].into_iter(), 74, true);
        let line = tree_line(&row, 74, false, true, true, &cols);
        let shown: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(shown.contains("erase"), "{shown}");
        assert!(shown.contains("cap.dev.im4m"), "{shown}");
        assert!(shown.contains('…'), "{shown}");
    }

    #[test]
    fn a_41_to_43_char_path_and_a_short_description_both_fit_whole() {
        let path = "Firmware/all_flash/iBoot.j414c.RELEASE.im4p";
        assert_eq!(path.len(), 43);
        let row = IpswRow {
            name: path.into(),
            label: "iBoot.j414c.RELEASE.im4p".into(),
            depth: 0,
            is_dir: false,
            expanded: false,
            size: 23,
            mark: Mark::None,
            tag: Some("im4p"),
            description: Some("iBoot · Mac mini".into()),
            chips: Vec::new(),
            device_count: 1,
        };
        let cols = tree_cols([&row].into_iter(), 80, true);
        let line = tree_line(&row, 80, false, true, true, &cols);
        let shown: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(shown.contains(path), "{shown}");
        assert!(shown.contains("iBoot · Mac mini"), "{shown}");
        assert!(!shown.contains('…'), "{shown}");
    }

    #[test]
    fn short_devices_drop_the_parenthesised_detail() {
        assert_eq!(short_devices("all 2 devices"), "all");
        assert_eq!(short_devices("Mac mini (M2, 2023)"), "Mac mini");
        assert_eq!(
            short_devices("Mac mini (M2, 2023), MacBook Pro (14-inch, 2023, M2 Max)"),
            "Mac mini, MacBook Pro"
        );
        assert_eq!(short_devices("A (x), B +3 more"), "A, B +3");
        assert_eq!(short_title("macOS system volume"), "System volume");
        assert_eq!(short_title("Something else"), "Something else");
        assert_eq!(short_title("Signed manifest (IM4M)"), "Signed manifest");
        assert_eq!(
            short_title("Bootability bundle (restore preflight)"),
            "Bootability bundle"
        );
        assert_eq!(short_title("LLB (low-level bootloader)"), "LLB");
        assert_eq!(
            short_title("T2 bridge version (Intel Macs)"),
            "T2 bridge version"
        );
        assert_eq!(
            short_title("Trust cache for restore ramdisk (x86)"),
            "Ramdisk trust cache (x86)"
        );
        assert_eq!(
            short_title("System volume trust cache (x86)"),
            "System volume trust cache (x86)"
        );
        assert_eq!(
            short_title("Trust cache for recovery base system"),
            "Recovery base trust cache"
        );
        assert_eq!(
            short_title("Trust cache for restore ramdisk"),
            "Ramdisk trust cache"
        );
    }

    #[test]
    fn tree_rows_never_cut_a_description_mid_segment() {
        let (_dir, mut app) = realistic_browsing();
        let screen = draw(&mut app, 110, 34);
        assert!(!screen.contains("· er…"), "{screen}");
        assert!(!screen.contains("Mac mi…"), "{screen}");

        let row = |name: &str| -> String {
            screen
                .lines()
                .find(|line| line.contains(name))
                .unwrap_or_else(|| panic!("no row {name}\n{screen}"))
                .to_string()
        };
        assert!(row("090-12345-003.dmg").contains("erase"), "{screen}");
        assert!(row("090-12345-004.dmg").contains("update"), "{screen}");
        let short = |class: &str| -> String {
            let title = crate::ramrod::boards::describe_board(class, None).title;
            title.split(" (").next().unwrap_or(&title).to_string()
        };
        assert!(
            row("kernelcache.release.mac14j").contains(&short("j473ap")),
            "{screen}"
        );
        assert!(
            row("kernelcache.release.mac14g").contains(&short("j414cap")),
            "{screen}"
        );
    }

    #[test]
    fn device_phrase_keeps_whole_names_and_counts_the_rest() {
        let devices: Vec<String> = [
            "Mac mini (M2, 2023)",
            "MacBook Pro (14-inch, 2023, M2 Max)",
            "iMac",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(devices_phrase(&devices, 200), devices.join(", "));
        let tight = devices_phrase(&devices, 40);
        assert_eq!(tight, "Mac mini (M2, 2023) +2 more");
        assert!(!tight.contains("MacBook"));
        assert_eq!(devices_phrase(&devices[..1], 8), "Mac min…");
        assert_eq!(devices_phrase(&[], 10), "");
    }

    #[test]
    fn done_list_wraps_long_reasons_instead_of_truncating_them() {
        let reason = "failed to extract files matching pattern from ZIP: no files found";
        let (first, rest) = wrap_reason(reason, 47);
        assert_eq!(first, "failed to extract files matching pattern from");
        assert_eq!(rest.as_deref(), Some("ZIP: no files found"));
        let (first, rest) = wrap_reason("short", 47);
        assert_eq!((first.as_str(), rest), ("short", None));
        let (first, rest) = wrap_reason("could not decode image: header is damaged", 30);
        assert_eq!(first, "could not decode image:");
        assert_eq!(rest.as_deref(), Some("header is damaged"));
    }

    #[test]
    fn exporting_screen_describes_the_current_item() {
        let (_dir, mut app) = realistic_browsing();
        app.ipsw.phase = IpswPhase::Exporting;
        app.ipsw.run.total_items = 2;
        app.ipsw.run.current = "090-12345-003.dmg".into();
        app.ipsw.run.action = Some(ItemAction::Copy);
        let screen = draw(&mut app, 100, 32);
        assert!(screen.contains("090-12345-003.dmg"), "{screen}");
        assert!(screen.contains("Restore ramdisk · erase"), "{screen}");
    }

    #[test]
    fn selected_rows_show_a_full_mark_and_the_summary_counts_them() {
        let (_dir, mut app) = browsing();
        let row = app
            .ipsw
            .rows()
            .iter()
            .position(|row| row.name == "BuildManifest.plist")
            .unwrap();
        let before = draw(&mut app, 110, 34);
        app.ipsw.toggle_row(row);
        let screen = draw(&mut app, 110, 34);
        assert!(screen.contains("1 file ·"), "{screen}");
        let on = ui::glyphs().check_on;
        assert_eq!(screen.matches(on).count(), before.matches(on).count() + 1);
    }

    #[test]
    fn masked_key_keeps_only_the_last_four_characters() {
        assert_eq!(
            mask_key("abcdefgh")
                .chars()
                .rev()
                .take(4)
                .collect::<String>(),
            "hgfe"
        );
        assert_eq!(mask_key("abcdefgh").chars().count(), 8);
        assert_eq!(mask_key("abc"), "abc");
        assert!(!mask_key("abcdefgh").contains('a'));
    }

    #[test]
    fn narrow_terminal_shows_one_pane_at_a_time() {
        let (_dir, mut app) = browsing();
        let screen = draw(&mut app, 60, 20);
        assert!(screen.contains("archive"), "{screen}");
        assert!(!screen.contains("export options"), "{screen}");
        app.ipsw.pane = IpswPane::Options;
        let screen = draw(&mut app, 60, 20);
        assert!(screen.contains("export options"), "{screen}");
    }

    #[test]
    fn action_labels_name_the_ipsw_extract_flags() {
        use crate::ipsw_export::Component;
        assert_eq!(
            action_label(ItemAction::Component(Component::Kernel)),
            "running ipsw extract --kernel"
        );
        assert_eq!(action_label(ItemAction::Decrypt), "decrypting");
    }
}
