use std::cell::Cell;
use std::env;

use ratatui::symbols::border;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlyphPack {
    Instrument,
    Ascii,
}

impl GlyphPack {
    pub fn name(self) -> &'static str {
        match self {
            Self::Instrument => "instrument",
            Self::Ascii => "ascii",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::Instrument => Self::Ascii,
            Self::Ascii => Self::Instrument,
        }
    }

    pub fn glyphs(self) -> Glyphs {
        match self {
            Self::Instrument => INSTRUMENT,
            Self::Ascii => ASCII,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyphs {
    pub spinner: [&'static str; 10],
    pub dots: [&'static str; 4],
    pub bar_fill: char,
    pub bar_track: char,
    pub ellipsis: char,
    pub rule: char,
    pub focus: &'static str,
    pub loaded: &'static str,
    pub idle: &'static str,
    pub select: &'static str,
    pub step_active: &'static str,
    pub step_reached: &'static str,
    pub step_todo: &'static str,
    pub chain_done: &'static str,
    pub chain_todo: &'static str,
    pub chain_vert: &'static str,
    pub check_on: &'static str,
    pub check_off: &'static str,
    pub tab_open: &'static str,
    pub tab_close: &'static str,
    pub footer_sep: &'static str,
    pub knob: &'static str,
    pub border_tl: &'static str,
    pub border_tr: &'static str,
    pub border_bl: &'static str,
    pub border_br: &'static str,
    pub border_h: &'static str,
    pub border_v: &'static str,
    pub scroll_track: &'static str,
    pub scroll_thumb: &'static str,
}

pub const INSTRUMENT: Glyphs = Glyphs {
    spinner: ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    dots: ["·", "··", "···", "····"],
    bar_fill: '━',
    bar_track: '─',
    ellipsis: '…',
    rule: '─',
    focus: "› ",
    loaded: "· ",
    idle: "  ",
    select: "› ",
    step_active: "●",
    step_reached: "○",
    step_todo: "·",
    chain_done: " ─── ",
    chain_todo: " ─ ─ ",
    chain_vert: "│",
    check_on: "●",
    check_off: "○",
    tab_open: "",
    tab_close: "",
    footer_sep: "  ·  ",
    knob: "●",
    border_tl: "╭",
    border_tr: "╮",
    border_bl: "╰",
    border_br: "╯",
    border_h: "─",
    border_v: "│",
    scroll_track: "┊",
    scroll_thumb: "┃",
};

pub const ASCII: Glyphs = Glyphs {
    spinner: ["|", "/", "-", "\\", "|", "/", "-", "\\", "|", "/"],
    dots: [".", "..", "...", "...."],
    bar_fill: '=',
    bar_track: '-',
    ellipsis: '.',
    rule: '-',
    focus: "> ",
    loaded: "* ",
    idle: "  ",
    select: "> ",
    step_active: "*",
    step_reached: "o",
    step_todo: ".",
    chain_done: " --- ",
    chain_todo: " . . ",
    chain_vert: "|",
    check_on: "[x]",
    check_off: "[ ]",
    tab_open: "[",
    tab_close: "]",
    footer_sep: "  .  ",
    knob: "o",
    border_tl: "+",
    border_tr: "+",
    border_bl: "+",
    border_br: "+",
    border_h: "-",
    border_v: "|",
    scroll_track: ":",
    scroll_thumb: "#",
};

pub const GLYPHS: Glyphs = INSTRUMENT;

thread_local! {
    static PACK: Cell<GlyphPack> = const { Cell::new(GlyphPack::Instrument) };
}

pub fn current_pack() -> GlyphPack {
    PACK.with(Cell::get)
}

pub fn set_pack(pack: GlyphPack) {
    PACK.with(|cell| cell.set(pack));
}

pub fn cycle_pack() -> GlyphPack {
    let next = current_pack().cycle();
    set_pack(next);
    next
}

pub fn glyphs() -> Glyphs {
    current_pack().glyphs()
}

pub fn detect_pack() -> GlyphPack {
    if let Ok(value) = env::var("APPLE_UTILS_GLYPHS")
        && let Some(pack) = parse_pack_name(&value)
    {
        return pack;
    }
    if prefers_ascii_from(
        env::var("TERM").ok().as_deref(),
        locale_charset().as_deref(),
    ) {
        GlyphPack::Ascii
    } else {
        GlyphPack::Instrument
    }
}

pub fn parse_pack_name(name: &str) -> Option<GlyphPack> {
    match name.trim().to_ascii_lowercase().as_str() {
        "ascii" => Some(GlyphPack::Ascii),
        "instrument" | "unicode" => Some(GlyphPack::Instrument),
        _ => None,
    }
}

fn locale_charset() -> Option<String> {
    env::var("LC_ALL")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| env::var("LC_CTYPE").ok().filter(|value| !value.is_empty()))
        .or_else(|| env::var("LANG").ok().filter(|value| !value.is_empty()))
}

pub fn prefers_ascii_from(term: Option<&str>, locale: Option<&str>) -> bool {
    if let Some(term) = term {
        let term = term.to_ascii_lowercase();
        if term == "dumb" || term == "linux" || term == "cons25" {
            return true;
        }
    }
    if let Some(locale) = locale {
        let locale = locale.to_ascii_lowercase();
        if !locale.is_empty() && !locale.contains("utf-8") && !locale.contains("utf8") {
            return true;
        }
    }
    false
}

impl Glyphs {
    pub fn spinner_at(self, tick: u64) -> &'static str {
        self.spinner[(tick / 2) as usize % self.spinner.len()]
    }

    pub fn dots_at(self, tick: u64) -> &'static str {
        self.dots[(tick / 6) as usize % self.dots.len()]
    }

    pub fn rule_line(self, width: u16) -> String {
        self.rule.to_string().repeat(width as usize)
    }

    pub fn border_set(self) -> border::Set<'static> {
        border::Set {
            top_left: self.border_tl,
            top_right: self.border_tr,
            bottom_left: self.border_bl,
            bottom_right: self.border_br,
            vertical_left: self.border_v,
            vertical_right: self.border_v,
            horizontal_top: self.border_h,
            horizontal_bottom: self.border_h,
        }
    }
}

pub fn spinner_frame(tick: u64) -> &'static str {
    glyphs().spinner_at(tick)
}

pub fn dots_frame(tick: u64) -> &'static str {
    glyphs().dots_at(tick)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PackGuard(GlyphPack);

    impl Drop for PackGuard {
        fn drop(&mut self) {
            set_pack(self.0);
        }
    }

    fn hold(pack: GlyphPack) -> PackGuard {
        let previous = current_pack();
        set_pack(pack);
        PackGuard(previous)
    }

    #[test]
    fn instrument_is_the_default_snapshot() {
        assert_eq!(GLYPHS, INSTRUMENT);
        assert_eq!(glyphs(), INSTRUMENT);
        assert_eq!(INSTRUMENT.select, "› ");
        assert_eq!(INSTRUMENT.focus, INSTRUMENT.select);
        assert_eq!(INSTRUMENT.check_on, "●");
        assert_eq!(INSTRUMENT.tab_open, "");
        assert_eq!(INSTRUMENT.border_tl, "╭");
        assert_eq!(INSTRUMENT.scroll_track, "┊");
        assert_eq!(INSTRUMENT.scroll_thumb, "┃");
        assert_eq!(
            INSTRUMENT.chain_done.chars().count(),
            INSTRUMENT.chain_todo.chars().count()
        );
        assert_eq!(
            ASCII.chain_done.chars().count(),
            ASCII.chain_todo.chars().count()
        );
    }

    #[test]
    fn ascii_pack_uses_plain_cells() {
        assert_eq!(ASCII.select, "> ");
        assert_eq!(ASCII.focus, ASCII.select);
        assert_eq!(ASCII.check_on, "[x]");
        assert_eq!(ASCII.bar_fill, '=');
        assert_eq!(ASCII.border_tl, "+");
        assert_eq!(ASCII.scroll_track, ":");
        assert_eq!(ASCII.scroll_thumb, "#");
        assert_eq!(ASCII.spinner[0], "|");
        assert_ne!(ASCII, INSTRUMENT);
    }

    #[test]
    fn set_pack_switches_runtime_glyphs() {
        let _guard = hold(GlyphPack::Ascii);
        assert_eq!(current_pack(), GlyphPack::Ascii);
        assert_eq!(glyphs().select, "> ");
        assert_eq!(spinner_frame(0), "|");
        assert_eq!(dots_frame(0), ".");
    }

    #[test]
    fn cycle_walks_both_packs() {
        assert_eq!(GlyphPack::Instrument.cycle(), GlyphPack::Ascii);
        assert_eq!(GlyphPack::Ascii.cycle(), GlyphPack::Instrument);
    }

    #[test]
    fn parse_pack_name_accepts_aliases() {
        assert_eq!(parse_pack_name("ascii"), Some(GlyphPack::Ascii));
        assert_eq!(parse_pack_name("INSTRUMENT"), Some(GlyphPack::Instrument));
        assert_eq!(parse_pack_name("unicode"), Some(GlyphPack::Instrument));
        assert_eq!(parse_pack_name("auto"), None);
        assert_eq!(parse_pack_name("nope"), None);
    }

    #[test]
    fn prefers_ascii_from_term_and_locale() {
        assert!(prefers_ascii_from(Some("dumb"), None));
        assert!(prefers_ascii_from(Some("linux"), None));
        assert!(prefers_ascii_from(None, Some("C")));
        assert!(!prefers_ascii_from(
            Some("xterm-256color"),
            Some("en_US.UTF-8")
        ));
        assert!(!prefers_ascii_from(None, None));
    }
}
