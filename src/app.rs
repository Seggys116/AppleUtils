use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Position, Rect};

use crate::banner;
use crate::clip::ClipWatch;
use crate::explorer::FileRow;
use crate::explorer_image::{self, EntryKind, ExplorerView};
use crate::recovery_model::{RecoveryAction, RecoveryStep};
use crate::recovery_runtime::RecoveryRuntime;
use crate::ui::GlyphPack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Recovery,
    Explorer,
    Repair,
    Asahi,
}

impl Tool {
    pub const ALL: [Tool; 4] = [Tool::Recovery, Tool::Explorer, Tool::Repair, Tool::Asahi];

    pub fn name(self) -> &'static str {
        match self {
            Tool::Recovery => "Recovery",
            Tool::Explorer => "APFS Explorer",
            Tool::Repair => "APFS Repair",
            Tool::Asahi => "Asahi Linux tooling",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Tool::Recovery => "Wait for a device, then recover it.",
            Tool::Explorer => "Pick a file, then browse the volume.",
            Tool::Repair => "Pick a path, then analysis, then repairs.",
            Tool::Asahi => "Update kernel and m1n1, or install Asahi Linux.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Picker,
    Recovery,
    Explorer,
    Repair,
    Asahi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorerPhase {
    Path,
    Loading,
    Browse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorerPane {
    Volumes,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairStep {
    Path,
    Detection,
    Suggestions,
    Apply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairPane {
    Findings,
    Main,
}

impl RepairStep {
    pub fn label(self) -> &'static str {
        match self {
            RepairStep::Path => "PATH",
            RepairStep::Detection => "ANALYSIS",
            RepairStep::Suggestions => "REPAIRS",
            RepairStep::Apply => "APPLY",
        }
    }

    pub fn index(self) -> usize {
        match self {
            RepairStep::Path => 0,
            RepairStep::Detection => 1,
            RepairStep::Suggestions => 2,
            RepairStep::Apply => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsahiAction {
    Update,
    Install,
}

impl AsahiAction {
    pub const ALL: [AsahiAction; 2] = [AsahiAction::Update, AsahiAction::Install];

    pub fn name(self) -> &'static str {
        match self {
            AsahiAction::Update => "Update Asahi Linux",
            AsahiAction::Install => "Install Asahi",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            AsahiAction::Update => "Replace the kernel and m1n1 bootloader on an existing disc.",
            AsahiAction::Install => {
                "Choose a size and output folder, then build and install Asahi Linux."
            }
        }
    }

    pub fn index(self) -> usize {
        match self {
            AsahiAction::Update => 0,
            AsahiAction::Install => 1,
        }
    }
}

enum ExplorerJobEvent {
    Finished {
        view: Result<crate::explorer_image::ExplorerView, String>,
        cursor: usize,
    },
    Preview {
        cursor: usize,
        cwd: String,
        volume_index: usize,
        preview: Option<String>,
    },
    Exported {
        message: Result<String, String>,
    },
    Inserted {
        message: Result<String, String>,
        cwd: String,
        volume_index: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExplorerJobKind {
    Load,
    Preview,
    Export,
    Insert,
}

enum RepairJobEvent {
    Progress { status: String, fraction: f64 },
    SweepDone(Result<crate::repair_ops::SweepReport, String>),
    ApplyDone(Result<crate::repair_ops::ApplyReport, String>),
}

#[derive(Clone, Copy)]
enum RepairJobKind {
    Sweep,
    Apply,
}

enum AsahiJobEvent {
    Progress {
        status: String,
        fraction: Option<f64>,
    },
    Catalog(Result<(String, Vec<crate::asahi_ops::Flavor>), String>),
    RestoreInspected(std::path::PathBuf, Result<crate::asahi_firmware_archive::RestoreArchiveInfo, String>),
    Finished(Result<String, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsahiStep {
    Menu,
    Size,
    WaitFile,
    Source,
    Flavor,
    WaitKernel,
    WaitM1n1,
    WaitIpsw,
    InspectIpsw,
    RestoreTarget,
    Work,
    Done,
}

impl AsahiStep {
    pub fn label(self) -> &'static str {
        match self {
            AsahiStep::Menu => "MENU",
            AsahiStep::Size => "SIZE",
            AsahiStep::WaitFile => "FILE",
            AsahiStep::Source => "SOURCE",
            AsahiStep::Flavor => "OS",
            AsahiStep::WaitKernel => "KERNEL",
            AsahiStep::WaitM1n1 => "M1N1",
            AsahiStep::WaitIpsw => "IPSW",
            AsahiStep::InspectIpsw => "CHECKING IPSW",
            AsahiStep::RestoreTarget => "TARGET",
            AsahiStep::Work => "WORK",
            AsahiStep::Done => "DONE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsahiSource {
    Latest,
    Custom,
}

impl AsahiSource {
    pub fn name(self) -> &'static str {
        match self {
            AsahiSource::Latest => "Latest",
            AsahiSource::Custom => "Custom",
        }
    }

    pub fn blurb(self, action: AsahiAction) -> &'static str {
        match (self, action) {
            (AsahiSource::Latest, AsahiAction::Update) => {
                "Resolve kernel and m1n1 from installer metadata."
            }
            (AsahiSource::Custom, AsahiAction::Update) => {
                "Wait for a kernel and m1n1, then replace those on the disc."
            }
            (AsahiSource::Latest, AsahiAction::Install) => {
                "Resolve kernel, m1n1 and root FS from installer metadata."
            }
            (AsahiSource::Custom, AsahiAction::Install) => {
                "Wait for a kernel and m1n1, then fetch the latest root FS."
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Suggestion {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HitMap {
    pub cards: [Rect; 4],
    pub asahi_actions: [Rect; 2],
    pub asahi_sources: [Rect; 2],
    pub asahi_flavors: [Rect; 8],
    pub asahi_slider: Rect,
    pub explorer_volume_rows: Vec<Rect>,
    pub explorer_file_rows: Vec<Rect>,
    pub repair_finding_rows: Vec<Rect>,
    pub path_box: Rect,
}

impl HitMap {
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn card_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.cards
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn asahi_action_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.asahi_actions
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn asahi_source_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.asahi_sources
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn asahi_flavor_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.asahi_flavors
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn asahi_slider_contains(&self, col: u16, row: u16) -> bool {
        let pos = Position::new(col, row);
        self.asahi_slider.width > 0
            && self.asahi_slider.height > 0
            && self.asahi_slider.contains(pos)
    }

    pub fn explorer_volume_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.explorer_volume_rows
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn explorer_file_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.explorer_file_rows
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn repair_finding_at(&self, col: u16, row: u16) -> Option<usize> {
        let pos = Position::new(col, row);
        self.repair_finding_rows
            .iter()
            .position(|rect| rect.width > 0 && rect.height > 0 && rect.contains(pos))
    }

    pub fn path_box_at(&self, col: u16, row: u16) -> bool {
        let pos = Position::new(col, row);
        self.path_box.width > 0 && self.path_box.height > 0 && self.path_box.contains(pos)
    }
}

pub struct App {
    pub screen: Screen,
    pub selected: usize,
    pub tick: u64,
    pub explorer_phase: ExplorerPhase,
    pub explorer_confirmed: String,
    pub explorer_view: Option<ExplorerView>,
    pub explorer_pane: ExplorerPane,
    pub explorer_status: String,
    pub explorer_progress: Option<f64>,
    explorer_pending_message: Option<String>,
    explorer_job_rx: Option<Receiver<ExplorerJobEvent>>,
    explorer_job_kind: Option<ExplorerJobKind>,
    pub explorer_page_rows: usize,
    pub repair_step: RepairStep,
    pub repair_confirmed: String,
    pub suggestions: Vec<Suggestion>,
    pub suggestion_cursor: usize,
    pub repair_findings: Vec<crate::repair_ops::Finding>,
    pub repair_finding_cursor: usize,
    pub repair_pane: RepairPane,
    pub repair_page_rows: usize,
    pub repair_error: Option<String>,
    pub repair_apply_log: Vec<String>,
    pub repair_backend: String,
    pub repair_status: String,
    pub apply_progress: Option<f64>,
    repair_job_rx: Option<Receiver<RepairJobEvent>>,
    repair_job_kind: Option<RepairJobKind>,
    pub banner_order: banner::BannerOrder,
    pub glyph_pack: GlyphPack,
    pub hits: HitMap,
    pub clip: ClipWatch,
    pub path_input: String,
    pub path_cursor: usize,
    pub path_editing: bool,
    pub recovery: RecoveryRuntime,
    pub detection_progress: Option<f64>,
    pub asahi_step: AsahiStep,
    pub asahi_action: AsahiAction,
    pub asahi_action_cursor: usize,
    pub asahi_source: AsahiSource,
    pub asahi_source_cursor: usize,
    pub asahi_flavors: Vec<crate::asahi_ops::Flavor>,
    pub asahi_flavor_cursor: usize,
    pub asahi_os_query: String,
    pub asahi_size_gb: u32,
    pub asahi_confirmed: String,
    pub asahi_kernel: String,
    pub asahi_m1n1: String,
    pub asahi_ipsw: Option<std::path::PathBuf>,
    pub asahi_restore_info: Option<crate::asahi_firmware_archive::RestoreArchiveInfo>,
    pub asahi_restore_cursor: usize,
    asahi_selected_target: Option<crate::asahi_firmware_archive::RestoreTarget>,
    pub asahi_status: String,
    pub asahi_progress: Option<f64>,
    pub asahi_error: Option<String>,
    asahi_job_rx: Option<Receiver<AsahiJobEvent>>,
    asahi_catalog_pending: bool,
    asahi_keys_own_cursor: bool,
    asahi_hover_lock_index: Option<usize>,
    asahi_pointer: Option<(u16, u16)>,
    pub asahi_injected_artifacts: Option<crate::asahi_ops::Artifacts>,
    pub asahi_injected_metadata: Option<String>,
    pub asahi_output_path: Option<std::path::PathBuf>,
    pub asahi_slider_hover: bool,
    last_tick: Instant,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self::with_banner_order(banner::BannerOrder::shuffled())
    }

    pub fn with_banner_order(banner_order: banner::BannerOrder) -> Self {
        Self::with_banner_order_and_recovery(banner_order, RecoveryRuntime::default())
    }

    pub fn with_banner_order_and_recovery(
        banner_order: banner::BannerOrder,
        recovery: RecoveryRuntime,
    ) -> Self {
        Self {
            screen: Screen::Picker,
            selected: 0,
            tick: 0,
            explorer_phase: ExplorerPhase::Path,
            explorer_confirmed: String::new(),
            explorer_view: None,
            explorer_pane: ExplorerPane::Files,
            explorer_status: String::new(),
            explorer_progress: None,
            explorer_pending_message: None,
            explorer_job_rx: None,
            explorer_job_kind: None,
            explorer_page_rows: 8,
            repair_step: RepairStep::Path,
            repair_confirmed: String::new(),
            suggestions: Vec::new(),
            suggestion_cursor: 0,
            repair_findings: Vec::new(),
            repair_finding_cursor: 0,
            repair_pane: RepairPane::Findings,
            repair_page_rows: 8,
            repair_error: None,
            repair_apply_log: Vec::new(),
            repair_backend: String::new(),
            repair_status: String::new(),
            apply_progress: None,
            repair_job_rx: None,
            repair_job_kind: None,
            banner_order,
            glyph_pack: GlyphPack::Instrument,
            hits: HitMap::default(),
            clip: ClipWatch::default(),
            path_input: String::new(),
            path_cursor: 0,
            path_editing: false,
            recovery,
            detection_progress: None,
            asahi_step: AsahiStep::Menu,
            asahi_action: AsahiAction::Update,
            asahi_action_cursor: 0,
            asahi_source: AsahiSource::Latest,
            asahi_source_cursor: 0,
            asahi_flavors: Vec::new(),
            asahi_flavor_cursor: 0,
            asahi_os_query: String::new(),
            asahi_size_gb: crate::asahi_ops::SLIDER_DEFAULT_GB,
            asahi_confirmed: String::new(),
            asahi_kernel: String::new(),
            asahi_m1n1: String::new(),
            asahi_ipsw: None,
            asahi_restore_info: None,
            asahi_restore_cursor: 0,
            asahi_selected_target: None,
            asahi_status: String::new(),
            asahi_progress: None,
            asahi_error: None,
            asahi_job_rx: None,
            asahi_catalog_pending: false,
            asahi_keys_own_cursor: false,
            asahi_hover_lock_index: None,
            asahi_pointer: None,
            asahi_injected_artifacts: None,
            asahi_injected_metadata: None,
            asahi_output_path: None,
            asahi_slider_hover: false,
            last_tick: Instant::now(),
        }
    }

    pub fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    pub fn prepare(&mut self) {
        if self.last_tick.elapsed() >= Duration::from_millis(80) {
            self.tick();
            self.last_tick = Instant::now();
        }
        self.recovery.prepare();
        self.poll_asahi_job();
        self.poll_explorer_job();
        self.poll_repair_job();
        if self.explorer_job_rx.is_some() {
            Self::nudge_progress(&mut self.explorer_progress, 0.04, 0.92);
        }
        if self.watching_clipboard() {
            self.clip.refresh();
        }
    }

    fn watching_clipboard(&self) -> bool {
        match self.screen {
            Screen::Recovery => self.recovery.wants_clipboard(),
            Screen::Explorer => {
                self.explorer_phase == ExplorerPhase::Path
                    || self.explorer_phase == ExplorerPhase::Browse
            }
            Screen::Repair => self.repair_step == RepairStep::Path,
            Screen::Asahi => matches!(
                self.asahi_step,
                AsahiStep::WaitFile | AsahiStep::WaitKernel | AsahiStep::WaitM1n1 | AsahiStep::WaitIpsw
            ),
            _ => false,
        }
    }

    pub(crate) fn resolve_picker_file(&self) -> Option<crate::clip::FileInfo> {
        let typed = self.path_input.trim();
        if !typed.is_empty() {
            return crate::clip::inspect(typed);
        }
        self.clip.file.clone()
    }

    fn confirm_clip_path(&self) -> Option<String> {
        self.resolve_picker_file()
            .map(|file| file.path.to_string_lossy().into_owned())
    }

    fn confirm_clip_file(&self) -> Option<String> {
        let info = self.resolve_picker_file()?;
        if info.path.is_dir() {
            None
        } else {
            Some(info.path.to_string_lossy().into_owned())
        }
    }

    fn confirm_clip_dir(&self) -> Option<String> {
        let info = self.resolve_picker_file()?;
        if info.path.is_dir() {
            Some(info.path.to_string_lossy().into_owned())
        } else {
            None
        }
    }

    fn take_picker_path(&mut self) -> Option<String> {
        let path = self.confirm_clip_path()?;
        self.clear_path_input();
        Some(path)
    }

    fn take_picker_file(&mut self) -> Option<String> {
        let path = self.confirm_clip_file()?;
        self.clear_path_input();
        Some(path)
    }

    fn take_picker_dir(&mut self) -> Option<String> {
        let path = self.confirm_clip_dir()?;
        self.clear_path_input();
        Some(path)
    }

    fn on_file_picker_card(&self) -> bool {
        match self.screen {
            Screen::Explorer => self.explorer_phase == ExplorerPhase::Path,
            Screen::Repair => self.repair_step == RepairStep::Path,
            Screen::Asahi => matches!(
                self.asahi_step,
                AsahiStep::WaitFile | AsahiStep::WaitKernel | AsahiStep::WaitM1n1 | AsahiStep::WaitIpsw
            ),
            Screen::Recovery => self.recovery.model.step() == RecoveryStep::PickFile,
            _ => false,
        }
    }

    fn on_path_entry(&self) -> bool {
        self.on_file_picker_card()
    }

    fn focus_path_input(&mut self) {
        self.path_editing = true;
    }

    fn typing_char(key: KeyEvent) -> Option<char> {
        let KeyCode::Char(c) = key.code else {
            return None;
        };
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
        {
            return None;
        }
        Some(c)
    }

    fn path_insert(&mut self, c: char) {
        let i = self.path_cursor_byte();
        self.path_input.insert(i, c);
        self.path_cursor = i + c.len_utf8();
    }

    fn path_insert_str(&mut self, text: &str) {
        let i = self.path_cursor_byte();
        self.path_input.insert_str(i, text);
        self.path_cursor = i + text.len();
    }

    fn path_backspace(&mut self) {
        let i = self.path_cursor_byte();
        if i == 0 {
            return;
        }
        let start = self.path_input[..i]
            .char_indices()
            .next_back()
            .map(|(idx, _)| idx)
            .unwrap_or(0);
        self.path_input.replace_range(start..i, "");
        self.path_cursor = start;
    }

    fn path_delete(&mut self) {
        let i = self.path_cursor_byte();
        if i >= self.path_input.len() {
            return;
        }
        let ch_len = self.path_input[i..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(0);
        self.path_input.replace_range(i..i + ch_len, "");
    }

    fn path_left(&mut self) {
        let i = self.path_cursor_byte();
        if i == 0 {
            return;
        }
        self.path_cursor = self.path_input[..i]
            .char_indices()
            .next_back()
            .map(|(idx, _)| idx)
            .unwrap_or(0);
    }

    fn path_right(&mut self) {
        let i = self.path_cursor_byte();
        if i >= self.path_input.len() {
            self.path_cursor = self.path_input.len();
            return;
        }
        let ch_len = self.path_input[i..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(0);
        self.path_cursor = i + ch_len;
    }

    fn path_cursor_byte(&self) -> usize {
        let i = self.path_cursor.min(self.path_input.len());
        if self.path_input.is_char_boundary(i) {
            i
        } else {
            self.path_input.len()
        }
    }

    fn clear_path_input(&mut self) {
        self.path_input.clear();
        self.path_cursor = 0;
        self.path_editing = false;
    }

    fn enter_file_picker(&mut self) {
        self.clear_path_input();
        self.clip.force_refresh();
    }

    fn file_picker_edit_key(&mut self, key: KeyEvent) -> bool {
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            self.path_editing = !self.path_editing;
            return true;
        }
        if !self.path_editing {
            if let Some(c) = Self::typing_char(key)
                && (c == '/' || c == '~')
            {
                self.path_editing = true;
                self.path_insert(c);
                return true;
            }
            return false;
        }
        if let Some(c) = Self::typing_char(key) {
            self.path_insert(c);
            return true;
        }
        match key.code {
            KeyCode::Backspace => {
                self.path_backspace();
                true
            }
            KeyCode::Delete => {
                self.path_delete();
                true
            }
            KeyCode::Left => {
                self.path_left();
                true
            }
            KeyCode::Right => {
                self.path_right();
                true
            }
            KeyCode::Home => {
                self.path_cursor = 0;
                true
            }
            KeyCode::End => {
                self.path_cursor = self.path_input.len();
                true
            }
            KeyCode::Esc => {
                self.clear_path_input();
                true
            }
            _ => false,
        }
    }

    pub fn current_tool(&self) -> Tool {
        Tool::ALL[self.selected]
    }

    pub fn handle_event(&mut self, event: Event) -> bool {
        match event {
            Event::Key(key) => self.handle_key(key),
            Event::Paste(text) => {
                self.handle_paste(&text);
                false
            }
            Event::Mouse(mouse) => self.handle_mouse(mouse),
            _ => false,
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> bool {
        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(MouseButton::Left) => {
                if self.screen == Screen::Picker
                    && let Some(index) = self.hits.card_at(mouse.column, mouse.row)
                {
                    self.selected = index;
                }
                if self.screen == Screen::Recovery {
                    self.recovery_hover(mouse.column, mouse.row);
                }
                if self.screen == Screen::Asahi {
                    self.asahi_hover(
                        mouse.column,
                        mouse.row,
                        matches!(mouse.kind, MouseEventKind::Drag(MouseButton::Left)),
                    );
                }
                false
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.on_file_picker_card() {
                    self.path_editing = self.hits.path_box_at(mouse.column, mouse.row);
                }
                if self.screen == Screen::Picker
                    && let Some(index) = self.hits.card_at(mouse.column, mouse.row)
                {
                    self.selected = index;
                    self.open_selected();
                }
                if self.screen == Screen::Recovery {
                    self.recovery_click(mouse.column, mouse.row);
                }
                if self.screen == Screen::Asahi {
                    self.asahi_click(mouse.column, mouse.row);
                }
                if self.screen == Screen::Explorer && self.explorer_phase == ExplorerPhase::Browse {
                    self.explorer_click(mouse.column, mouse.row);
                }
                if self.screen == Screen::Repair
                    && self.repair_step != RepairStep::Path
                    && let Some(index) = self.hits.repair_finding_at(mouse.column, mouse.row)
                {
                    self.repair_finding_cursor = index;
                    self.repair_pane = RepairPane::Findings;
                }
                false
            }
            MouseEventKind::ScrollDown if self.screen == Screen::Picker => {
                self.selected = (self.selected + 1) % Tool::ALL.len();
                false
            }
            MouseEventKind::ScrollUp if self.screen == Screen::Picker => {
                self.selected = if self.selected == 0 {
                    Tool::ALL.len() - 1
                } else {
                    self.selected - 1
                };
                false
            }
            MouseEventKind::ScrollDown
                if self.screen == Screen::Explorer
                    && self.explorer_phase == ExplorerPhase::Browse =>
            {
                self.explorer_move(1);
                false
            }
            MouseEventKind::ScrollUp
                if self.screen == Screen::Explorer
                    && self.explorer_phase == ExplorerPhase::Browse =>
            {
                self.explorer_move(-1);
                false
            }
            MouseEventKind::ScrollDown
                if self.screen == Screen::Repair && self.repair_step != RepairStep::Path =>
            {
                self.repair_move_finding(1);
                false
            }
            MouseEventKind::ScrollUp
                if self.screen == Screen::Repair && self.repair_step != RepairStep::Path =>
            {
                self.repair_move_finding(-1);
                false
            }
            MouseEventKind::ScrollDown
                if self.screen == Screen::Recovery
                    && self.recovery.model.step() == RecoveryStep::PickSystem =>
            {
                self.recovery.model.move_system_cursor(1);
                false
            }
            MouseEventKind::ScrollUp
                if self.screen == Screen::Recovery
                    && self.recovery.model.step() == RecoveryStep::PickSystem =>
            {
                self.recovery.model.move_system_cursor(-1);
                false
            }
            MouseEventKind::ScrollDown
                if self.screen == Screen::Recovery
                    && self.recovery.model.step() == RecoveryStep::PickMode =>
            {
                self.recovery.model.move_mode_cursor(1);
                false
            }
            MouseEventKind::ScrollUp
                if self.screen == Screen::Recovery
                    && self.recovery.model.step() == RecoveryStep::PickMode =>
            {
                self.recovery.model.move_mode_cursor(-1);
                false
            }
            MouseEventKind::ScrollDown
                if self.screen == Screen::Recovery
                    && self.recovery.model.step() == RecoveryStep::PickDevice =>
            {
                self.recovery.model.move_down();
                false
            }
            MouseEventKind::ScrollUp
                if self.screen == Screen::Recovery
                    && self.recovery.model.step() == RecoveryStep::PickDevice =>
            {
                self.recovery.model.move_up();
                false
            }
            _ => false,
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        if self.on_path_entry() {
            self.focus_path_input();
            let line = text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .unwrap_or(text.trim());
            if !line.is_empty() {
                self.path_insert_str(line);
            }
        }

        let mut last = None;
        for line in text.lines() {
            if let Some(file) = crate::clip::inspect(line) {
                last = Some(file);
            }
        }
        if last.is_none()
            && let Some(file) = crate::clip::inspect(text)
        {
            last = Some(file);
        }
        let Some(file) = last else {
            return;
        };
        self.clip.set_file(file.clone());
        if self.screen == Screen::Explorer && self.explorer_phase == ExplorerPhase::Browse {
            self.explorer_insert_host(&file.path);
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return false;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return true;
        }

        match self.screen {
            Screen::Picker => self.picker_key(key),
            Screen::Recovery => self.recovery_key(key),
            Screen::Explorer => self.explorer_key(key),
            Screen::Repair => self.repair_key(key),
            Screen::Asahi => self.asahi_key(key),
        }
    }

    fn picker_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => true,
            KeyCode::Char('g') => {
                self.glyph_pack = self.glyph_pack.cycle();
                crate::ui::set_pack(self.glyph_pack);
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = if self.selected == 0 {
                    Tool::ALL.len() - 1
                } else {
                    self.selected - 1
                };
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1) % Tool::ALL.len();
                false
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.open_selected();
                false
            }
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let n = c.to_digit(10).unwrap() as usize;
                if (1..=Tool::ALL.len()).contains(&n) {
                    self.selected = n - 1;
                    self.open_selected();
                }
                false
            }
            _ => false,
        }
    }

    fn recovery_key(&mut self, key: KeyEvent) -> bool {
        match self.recovery.model.step() {
            RecoveryStep::WaitDevices => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Backspace => {
                    self.back_to_picker();
                    false
                }
                _ => false,
            },
            RecoveryStep::PickSystem => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Backspace => {
                    self.back_to_picker();
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.recovery.model.move_system_cursor(-1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.recovery.model.move_system_cursor(1);
                    false
                }
                KeyCode::PageUp => {
                    let step = self.recovery.model.device_page_rows.max(1) as i32;
                    self.recovery.model.move_system_cursor(-step);
                    false
                }
                KeyCode::PageDown => {
                    let step = self.recovery.model.device_page_rows.max(1) as i32;
                    self.recovery.model.move_system_cursor(step);
                    false
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.recovery.model.system_cursor = 0;
                    false
                }
                KeyCode::End | KeyCode::Char('G') => {
                    let last = self
                        .recovery
                        .model
                        .compatible_systems
                        .len()
                        .saturating_sub(1);
                    self.recovery.model.system_cursor = last;
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.recovery.select_system();
                    false
                }
                _ => false,
            },
            RecoveryStep::PickMode => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Backspace => {
                    self.recovery.model.clear_restore_mode_choice();
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.recovery.model.move_mode_cursor(-1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.recovery.model.move_mode_cursor(1);
                    false
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.recovery.model.mode_cursor = 0;
                    false
                }
                KeyCode::End | KeyCode::Char('G') => {
                    let last = self.recovery.model.compatible_modes.len().saturating_sub(1);
                    self.recovery.model.mode_cursor = last;
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.recovery.select_restore_mode();
                    false
                }
                _ => false,
            },
            RecoveryStep::PickDevice => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Backspace => {
                    self.back_to_picker();
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.recovery.model.move_up();
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.recovery.model.move_down();
                    false
                }
                KeyCode::PageUp => {
                    self.recovery.model.page(-1);
                    false
                }
                KeyCode::PageDown => {
                    self.recovery.model.page(1);
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.recovery.claim_selected();
                    false
                }
                _ => false,
            },
            RecoveryStep::Claiming | RecoveryStep::WaitRequest => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    if self.recovery.model.can_release() {
                        self.recovery.release_claim();
                    } else {
                        self.back_to_picker();
                    }
                    false
                }
                _ => false,
            },
            RecoveryStep::PickFile => {
                if self.file_picker_edit_key(key) {
                    return false;
                }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.clear_path_input();
                        if self.recovery.model.can_release() {
                            self.recovery.release_claim();
                        } else {
                            self.back_to_picker();
                        }
                        false
                    }
                    KeyCode::Enter => {
                        self.recovery.model.focus_open_request();
                        let file = self.resolve_picker_file();
                        if file
                            .as_ref()
                            .is_some_and(|file| file.kind == crate::clip::FileKind::Directory)
                        {
                            self.recovery.autosearch(file.as_ref());
                        } else {
                            self.recovery.trigger(RecoveryAction::Attach, file.as_ref());
                        }
                        if file.is_some() {
                            self.clear_path_input();
                            self.enter_file_picker();
                        }
                        false
                    }
                    _ => false,
                }
            }
            RecoveryStep::Working => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Char('x') => {
                    self.recovery.cancel_restore();
                    false
                }
                _ => false,
            },
            RecoveryStep::Done => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Backspace => {
                    if self.recovery.model.can_release() {
                        self.recovery.release_claim();
                    }
                    self.back_to_picker();
                    false
                }
                KeyCode::Enter | KeyCode::Char('r') => {
                    if self.recovery.model.can_retry() {
                        self.recovery.retry_restore();
                    }
                    false
                }
                _ => false,
            },
        }
    }

    fn explorer_key(&mut self, key: KeyEvent) -> bool {
        match self.explorer_phase {
            ExplorerPhase::Loading => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.cancel_explorer_load();
                    false
                }
                _ => false,
            },
            ExplorerPhase::Path => {
                if self.file_picker_edit_key(key) {
                    return false;
                }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.back_to_picker();
                        false
                    }
                    KeyCode::Enter => {
                        if let Some(path) = self.take_picker_path() {
                            self.open_explorer_image(&path);
                        }
                        false
                    }
                    _ => false,
                }
            }
            ExplorerPhase::Browse => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.cancel_explorer_load();
                    false
                }
                KeyCode::Tab => {
                    self.explorer_pane = match self.explorer_pane {
                        ExplorerPane::Volumes => ExplorerPane::Files,
                        ExplorerPane::Files => ExplorerPane::Volumes,
                    };
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.explorer_move(-1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.explorer_move(1);
                    false
                }
                KeyCode::PageUp => {
                    self.explorer_page(-1);
                    false
                }
                KeyCode::PageDown => {
                    self.explorer_page(1);
                    false
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.explorer_jump(0);
                    false
                }
                KeyCode::End | KeyCode::Char('G') => {
                    self.explorer_jump(usize::MAX);
                    false
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                    self.explorer_activate();
                    false
                }
                KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                    self.explorer_leave_files();
                    false
                }
                KeyCode::Char('e') => {
                    self.explorer_export_selected();
                    false
                }
                _ => false,
            },
        }
    }

    fn repair_key(&mut self, key: KeyEvent) -> bool {
        match self.repair_step {
            RepairStep::Path => {
                if self.file_picker_edit_key(key) {
                    return false;
                }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.back_to_picker();
                        false
                    }
                    KeyCode::Enter => {
                        if let Some(path) = self.take_picker_path() {
                            self.repair_confirmed = path;
                            self.repair_apply_log.clear();
                            self.repair_step = RepairStep::Detection;
                            self.repair_pane = RepairPane::Findings;
                            self.start_repair_sweep();
                        }
                        false
                    }
                    _ => false,
                }
            }
            RepairStep::Detection => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.cancel_repair_sweep();
                    self.repair_step = RepairStep::Path;
                    false
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    self.repair_pane = RepairPane::Findings;
                    false
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    self.repair_pane = RepairPane::Main;
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.repair_move_finding(-1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.repair_move_finding(1);
                    false
                }
                KeyCode::Char(' ') => {
                    self.repair_toggle_finding();
                    false
                }
                KeyCode::Enter => {
                    if !self.repair_scanning() {
                        self.repair_step = RepairStep::Suggestions;
                        self.repair_pane = RepairPane::Main;
                    }
                    false
                }
                _ => false,
            },
            RepairStep::Suggestions => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.repair_step = RepairStep::Detection;
                    self.repair_pane = RepairPane::Findings;
                    false
                }
                KeyCode::Tab => {
                    self.repair_toggle_pane();
                    false
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    self.repair_pane = RepairPane::Findings;
                    false
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    self.repair_pane = RepairPane::Main;
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.repair_pane == RepairPane::Findings {
                        self.repair_move_finding(-1);
                    } else if !self.suggestions.is_empty() {
                        self.suggestion_cursor = if self.suggestion_cursor == 0 {
                            self.suggestions.len() - 1
                        } else {
                            self.suggestion_cursor - 1
                        };
                    }
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.repair_pane == RepairPane::Findings {
                        self.repair_move_finding(1);
                    } else if !self.suggestions.is_empty() {
                        self.suggestion_cursor =
                            (self.suggestion_cursor + 1) % self.suggestions.len();
                    }
                    false
                }
                KeyCode::Char(' ') => {
                    if self.repair_pane == RepairPane::Findings {
                        self.repair_toggle_finding();
                    } else if let Some(item) = self.suggestions.get_mut(self.suggestion_cursor) {
                        item.enabled = !item.enabled;
                    }
                    false
                }
                KeyCode::Enter => {
                    if self.suggestions.iter().any(|item| item.enabled) {
                        self.repair_step = RepairStep::Apply;
                        self.repair_pane = RepairPane::Main;
                        self.start_repair_apply();
                    }
                    false
                }
                _ => false,
            },
            RepairStep::Apply => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.repair_step = RepairStep::Suggestions;
                    self.repair_pane = RepairPane::Main;
                    false
                }
                KeyCode::Tab => {
                    self.repair_toggle_pane();
                    false
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    self.repair_pane = RepairPane::Findings;
                    false
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    self.repair_pane = RepairPane::Main;
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.repair_move_finding(-1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.repair_move_finding(1);
                    false
                }
                KeyCode::Enter => {
                    self.repair_rescan();
                    false
                }
                _ => false,
            },
        }
    }

    pub fn explorer_busy(&self) -> bool {
        self.explorer_job_rx.is_some()
    }

    fn explorer_blocks_nav(&self) -> bool {
        matches!(
            self.explorer_job_kind,
            Some(ExplorerJobKind::Load | ExplorerJobKind::Export | ExplorerJobKind::Insert)
        )
    }

    pub fn repair_scanning(&self) -> bool {
        matches!(self.repair_job_kind, Some(RepairJobKind::Sweep))
    }

    pub fn repair_applying(&self) -> bool {
        matches!(self.repair_job_kind, Some(RepairJobKind::Apply))
    }

    fn repair_toggle_pane(&mut self) {
        self.repair_pane = match self.repair_pane {
            RepairPane::Findings => RepairPane::Main,
            RepairPane::Main => RepairPane::Findings,
        };
    }

    fn nudge_progress(slot: &mut Option<f64>, step: f64, cap: f64) {
        let next = slot.unwrap_or(0.06) + step;
        *slot = Some(next.min(cap));
    }

    fn repair_move_finding(&mut self, delta: i32) {
        let n = self.repair_findings.len();
        if n == 0 {
            return;
        }
        let mut order: Vec<usize> = (0..n)
            .filter(|index| self.repair_findings[*index].failed())
            .collect();
        order.extend((0..n).filter(|index| {
            !self.repair_findings[*index].failed() && !self.repair_findings[*index].passed()
        }));
        order.extend((0..n).filter(|index| self.repair_findings[*index].passed()));
        let pos = order
            .iter()
            .position(|index| *index == self.repair_finding_cursor)
            .unwrap_or(0);
        let next = (pos as i32 + delta).rem_euclid(order.len() as i32) as usize;
        self.repair_finding_cursor = order[next];
    }

    fn repair_toggle_finding(&mut self) {
        let Some(finding) = self.repair_findings.get(self.repair_finding_cursor) else {
            return;
        };
        let id = finding.id.clone();
        if let Some(item) = self.suggestions.iter_mut().find(|item| item.id == id) {
            item.enabled = !item.enabled;
        }
    }

    pub(crate) fn ingest_repair_report(&mut self, report: crate::repair_ops::SweepReport) {
        self.suggestions = crate::repair_ops::repair_paths(&report)
            .into_iter()
            .map(|path| Suggestion {
                id: path.id,
                label: path.label,
                detail: path.detail,
                enabled: false,
            })
            .collect();
        self.suggestion_cursor = 0;
        self.repair_backend = report.backend;
        self.repair_findings = report.findings;
        self.repair_finding_cursor = self
            .repair_findings
            .iter()
            .position(|finding| finding.failed())
            .unwrap_or(0);
        let applicable = self
            .repair_findings
            .iter()
            .filter(|finding| finding.status != crate::repair_ops::CheckStatus::NotApplicable)
            .count() as f64;
        let passed = self
            .repair_findings
            .iter()
            .filter(|finding| finding.passed())
            .count() as f64;
        self.detection_progress = if applicable == 0.0 {
            Some(1.0)
        } else {
            Some(passed / applicable)
        };
        self.repair_status.clear();
        self.repair_error = None;
        self.repair_job_rx = None;
        self.repair_job_kind = None;
    }

    fn start_repair_sweep(&mut self) {
        let path = self.repair_confirmed.clone();
        if path.is_empty() {
            return;
        }
        self.repair_findings.clear();
        self.suggestions.clear();
        self.repair_error = None;
        self.detection_progress = Some(0.06);
        self.apply_progress = None;
        self.repair_status = "scanning".into();
        self.repair_finding_cursor = 0;
        let (tx, rx) = mpsc::channel();
        self.repair_job_rx = Some(rx);
        self.repair_job_kind = Some(RepairJobKind::Sweep);
        std::thread::spawn(move || {
            let result = crate::repair_ops::sweep(Path::new(&path));
            let _ = tx.send(RepairJobEvent::SweepDone(result));
        });
    }

    fn start_repair_apply(&mut self) {
        let ids: Vec<String> = self
            .suggestions
            .iter()
            .filter(|item| item.enabled)
            .map(|item| item.id.clone())
            .collect();
        if ids.is_empty() {
            self.repair_apply_log = vec!["no repairs selected".into()];
            self.apply_progress = None;
            return;
        }
        let path = self.repair_confirmed.clone();
        self.apply_progress = Some(0.04);
        self.repair_status = "applying".into();
        self.repair_apply_log = vec!["applying".into()];
        let (tx, rx) = mpsc::channel();
        self.repair_job_rx = Some(rx);
        self.repair_job_kind = Some(RepairJobKind::Apply);
        std::thread::spawn(move || {
            let progress_tx = tx.clone();
            let result = crate::repair_ops::apply_with_progress(
                Path::new(&path),
                &ids,
                |status, fraction| {
                    let _ = progress_tx.send(RepairJobEvent::Progress {
                        status: status.to_string(),
                        fraction,
                    });
                },
            );
            let _ = tx.send(RepairJobEvent::ApplyDone(result));
        });
    }

    fn cancel_repair_sweep(&mut self) {
        self.repair_job_rx = None;
        self.repair_job_kind = None;
        self.repair_status.clear();
        self.detection_progress = None;
    }

    fn poll_repair_job(&mut self) {
        let recv = {
            let Some(rx) = self.repair_job_rx.as_mut() else {
                return;
            };
            rx.try_recv()
        };
        let event = match recv {
            Ok(event) => event,
            Err(TryRecvError::Empty) => {
                match self.repair_job_kind {
                    Some(RepairJobKind::Sweep) => {
                        Self::nudge_progress(&mut self.detection_progress, 0.05, 0.92)
                    }
                    Some(RepairJobKind::Apply) => {
                        Self::nudge_progress(&mut self.apply_progress, 0.03, 0.92)
                    }
                    None => {}
                }
                return;
            }
            Err(TryRecvError::Disconnected) => {
                self.repair_job_rx = None;
                self.repair_job_kind = None;
                if self.repair_status == "scanning" {
                    self.repair_error = Some("opening the image was interrupted".into());
                    self.repair_status.clear();
                }
                return;
            }
        };
        match event {
            RepairJobEvent::Progress { status, fraction } => {
                self.repair_status = status.clone();
                if matches!(self.repair_job_kind, Some(RepairJobKind::Apply)) {
                    self.apply_progress = Some(fraction);
                    if self.repair_apply_log.last() != Some(&status) {
                        self.repair_apply_log.push(status);
                    }
                } else {
                    self.detection_progress = Some(fraction);
                }
            }
            RepairJobEvent::SweepDone(Ok(report)) => self.ingest_repair_report(report),
            RepairJobEvent::SweepDone(Err(err)) => {
                self.repair_job_rx = None;
                self.repair_job_kind = None;
                self.repair_error = Some(err);
                self.repair_status.clear();
                self.detection_progress = None;
            }
            RepairJobEvent::ApplyDone(Ok(report)) => {
                let mut log = Vec::new();
                for id in &report.applied {
                    log.push(format!("applied {id}"));
                }
                for (id, err) in &report.failed {
                    log.push(format!("failed {id}: {err}"));
                }
                if log.is_empty() {
                    log.push("no repairs selected".into());
                }
                self.apply_progress = Some(1.0);
                self.repair_apply_log = log;
                self.ingest_repair_report(report.after);
            }
            RepairJobEvent::ApplyDone(Err(err)) => {
                self.repair_job_rx = None;
                self.repair_job_kind = None;
                self.repair_apply_log = vec![format!("failed: {err}")];
                self.apply_progress = None;
            }
        }
    }

    #[cfg(test)]
    pub fn drain_repair_job(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.repair_job_rx.is_some() {
            self.poll_repair_job();
            if self.repair_job_rx.is_some() {
                if Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    fn repair_rescan(&mut self) {
        self.repair_apply_log = vec!["rescanning".into()];
        self.start_repair_sweep();
    }

    fn open_selected(&mut self) {
        match self.current_tool() {
            Tool::Recovery => self.screen = Screen::Recovery,
            Tool::Explorer => {
                self.screen = Screen::Explorer;
                self.explorer_phase = ExplorerPhase::Path;
                self.enter_file_picker();
            }
            Tool::Repair => {
                self.screen = Screen::Repair;
                self.repair_step = RepairStep::Path;
                self.enter_file_picker();
            }
            Tool::Asahi => {
                self.screen = Screen::Asahi;
                self.asahi_step = AsahiStep::Menu;
                self.asahi_action_cursor = 0;
                self.asahi_error = None;
                self.asahi_status.clear();
            }
        }
    }

    pub(crate) fn open_explorer_image(&mut self, path: &str) {
        self.explorer_confirmed = path.to_string();
        self.explorer_job_rx = None;
        self.explorer_job_kind = None;
        self.explorer_view = None;
        self.start_explorer_load("/".into(), 0, 0);
    }

    fn reload_explorer(&mut self, cwd: String, volume_index: usize, cursor: usize) {
        self.start_explorer_load(cwd, volume_index, cursor);
    }

    fn start_explorer_load(&mut self, cwd: String, volume_index: usize, cursor: usize) {
        if self.explorer_blocks_nav() {
            return;
        }
        let path = self.explorer_confirmed.clone();
        if path.is_empty() {
            return;
        }
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        self.explorer_progress = Some(0.06);
        if self.explorer_view.is_none() {
            self.explorer_phase = ExplorerPhase::Loading;
            self.explorer_status = format!("opening {name}");
        } else {
            self.explorer_status = format!("reading {cwd}");
        }
        let (tx, rx) = mpsc::channel();
        self.explorer_job_rx = Some(rx);
        self.explorer_job_kind = Some(ExplorerJobKind::Load);
        std::thread::spawn(move || {
            let view = explorer_image::load_view(std::path::Path::new(&path), &cwd, volume_index)
                .map_err(|e| e.to_string());
            let _ = tx.send(ExplorerJobEvent::Finished { view, cursor });
        });
    }

    fn cancel_explorer_load(&mut self) {
        self.explorer_job_rx = None;
        self.explorer_job_kind = None;
        self.explorer_status.clear();
        self.explorer_progress = None;
        self.explorer_phase = ExplorerPhase::Path;
        self.explorer_view = None;
    }

    fn poll_explorer_job(&mut self) {
        let Some(rx) = self.explorer_job_rx.as_mut() else {
            return;
        };
        let event = match rx.try_recv() {
            Ok(event) => event,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.explorer_job_rx = None;
                let kind = self.explorer_job_kind.take();
                if kind == Some(ExplorerJobKind::Load)
                    && self.explorer_phase == ExplorerPhase::Loading
                {
                    self.explorer_phase = ExplorerPhase::Browse;
                    self.explorer_pane = ExplorerPane::Volumes;
                    self.explorer_view = Some(ExplorerView {
                        path: self.explorer_confirmed.clone(),
                        backend: explorer_image::BackendKind::Raw,
                        volumes: Vec::new(),
                        volume_index: 0,
                        volume_cursor: 0,
                        cwd: "/".into(),
                        entries: Vec::new(),
                        cursor: 0,
                        preview: None,
                        error: Some("opening the image was interrupted".into()),
                        message: None,
                    });
                } else {
                    self.explorer_status.clear();
                    self.explorer_progress = None;
                }
                return;
            }
        };
        self.explorer_job_rx = None;
        self.explorer_job_kind = None;
        match event {
            ExplorerJobEvent::Finished { view, cursor } => self.apply_explorer_load(view, cursor),
            ExplorerJobEvent::Preview {
                cursor,
                cwd,
                volume_index,
                preview,
            } => {
                if let Some(view) = self.explorer_view.as_mut()
                    && view.cursor == cursor
                    && view.cwd == cwd
                    && view.volume_index == volume_index
                {
                    view.preview = preview;
                }
                if self.explorer_status.is_empty() {
                    self.explorer_progress = None;
                }
            }
            ExplorerJobEvent::Exported { message } => {
                self.explorer_status.clear();
                self.explorer_progress = None;
                if let Some(view) = self.explorer_view.as_mut() {
                    view.message = Some(match message {
                        Ok(msg) => msg,
                        Err(err) => err,
                    });
                }
            }
            ExplorerJobEvent::Inserted {
                message,
                cwd,
                volume_index,
            } => {
                self.explorer_status.clear();
                self.explorer_progress = None;
                match message {
                    Ok(msg) => {
                        self.explorer_pending_message = Some(msg);
                        self.reload_explorer(cwd, volume_index, 0);
                    }
                    Err(err) => {
                        if let Some(view) = self.explorer_view.as_mut() {
                            view.message = Some(err);
                        }
                    }
                }
            }
        }
    }

    fn apply_explorer_load(
        &mut self,
        view: Result<crate::explorer_image::ExplorerView, String>,
        cursor: usize,
    ) {
        match view {
            Ok(mut view) => {
                let rows = crate::explorer::file_row_count(&view);
                if rows > 0 {
                    view.cursor = cursor.min(rows - 1);
                }
                self.explorer_pane = if view.entries.is_empty() {
                    ExplorerPane::Volumes
                } else {
                    ExplorerPane::Files
                };
                view.message = self.explorer_pending_message.take().or(view.message.take());
                self.explorer_view = Some(view);
                self.explorer_status.clear();
                self.explorer_progress = None;
                self.explorer_phase = ExplorerPhase::Browse;
                self.start_explorer_preview();
            }
            Err(err) => {
                self.explorer_pane = ExplorerPane::Volumes;
                self.explorer_view = Some(ExplorerView {
                    path: self.explorer_confirmed.clone(),
                    backend: explorer_image::BackendKind::Raw,
                    volumes: Vec::new(),
                    volume_index: 0,
                    volume_cursor: 0,
                    cwd: "/".into(),
                    entries: Vec::new(),
                    cursor: 0,
                    preview: None,
                    error: Some(err),
                    message: None,
                });
                self.explorer_status.clear();
                self.explorer_progress = None;
                self.explorer_phase = ExplorerPhase::Browse;
            }
        }
    }

    #[cfg(test)]
    pub fn drain_explorer_load(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.explorer_job_rx.is_some() {
            self.poll_explorer_job();
            if self.explorer_job_rx.is_some() {
                if Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    fn explorer_move(&mut self, delta: i32) {
        match self.explorer_pane {
            ExplorerPane::Volumes => {
                let Some(view) = self.explorer_view.as_mut() else {
                    return;
                };
                let n = view.volumes.len();
                if n == 0 {
                    return;
                }
                view.volume_cursor = if delta < 0 {
                    view.volume_cursor.saturating_sub(1)
                } else {
                    (view.volume_cursor + 1).min(n - 1)
                };
            }
            ExplorerPane::Files => {
                let Some(view) = self.explorer_view.as_mut() else {
                    return;
                };
                let n = crate::explorer::file_row_count(view);
                if n == 0 {
                    if delta < 0 {
                        self.explorer_pane = ExplorerPane::Volumes;
                    }
                    return;
                }
                view.cursor = if delta < 0 {
                    view.cursor.saturating_sub(1)
                } else {
                    (view.cursor + 1).min(n - 1)
                };
                self.refresh_explorer_preview();
            }
        }
    }

    fn explorer_page(&mut self, delta: i32) {
        let step = self.explorer_page_rows.max(1);
        match self.explorer_pane {
            ExplorerPane::Volumes => {
                let Some(view) = self.explorer_view.as_mut() else {
                    return;
                };
                let n = view.volumes.len();
                if n == 0 {
                    return;
                }
                view.volume_cursor = if delta < 0 {
                    view.volume_cursor.saturating_sub(step)
                } else {
                    (view.volume_cursor + step).min(n - 1)
                };
            }
            ExplorerPane::Files => {
                let Some(view) = self.explorer_view.as_ref() else {
                    return;
                };
                let n = crate::explorer::file_row_count(view);
                if n == 0 {
                    return;
                }
                let cur = view.cursor;
                let next = if delta < 0 {
                    cur.saturating_sub(step)
                } else {
                    (cur + step).min(n - 1)
                };
                self.explorer_jump(next);
            }
        }
    }

    fn explorer_jump(&mut self, to: usize) {
        match self.explorer_pane {
            ExplorerPane::Volumes => {
                let Some(view) = self.explorer_view.as_mut() else {
                    return;
                };
                if view.volumes.is_empty() {
                    return;
                }
                view.volume_cursor = to.min(view.volumes.len() - 1);
            }
            ExplorerPane::Files => {
                let Some(view) = self.explorer_view.as_mut() else {
                    return;
                };
                let n = crate::explorer::file_row_count(view);
                if n == 0 {
                    return;
                }
                view.cursor = to.min(n - 1);
                self.refresh_explorer_preview();
            }
        }
    }

    fn explorer_click(&mut self, col: u16, row: u16) {
        if let Some(index) = self.hits.explorer_volume_at(col, row) {
            let loaded = self.explorer_view.as_ref().map(|view| view.volume_index);
            if loaded == Some(index) {
                if let Some(view) = self.explorer_view.as_mut() {
                    view.volume_cursor = index;
                }
                self.explorer_pane = ExplorerPane::Files;
            } else {
                self.explorer_pane = ExplorerPane::Volumes;
                self.reload_explorer("/".into(), index, 0);
            }
            return;
        }
        if let Some(index) = self.hits.explorer_file_at(col, row) {
            self.explorer_pane = ExplorerPane::Files;
            let same = self
                .explorer_view
                .as_ref()
                .is_some_and(|view| view.cursor == index);
            if let Some(view) = self.explorer_view.as_mut() {
                view.cursor = index;
            }
            if same {
                self.explorer_activate();
            } else {
                self.refresh_explorer_preview();
            }
        }
    }

    fn explorer_activate(&mut self) {
        match self.explorer_pane {
            ExplorerPane::Volumes => {
                let (cursor, loaded) = self
                    .explorer_view
                    .as_ref()
                    .map(|view| (view.volume_cursor, view.volume_index))
                    .unwrap_or((0, 0));
                if cursor != loaded {
                    self.reload_explorer("/".into(), cursor, 0);
                }
                self.explorer_pane = ExplorerPane::Files;
            }
            ExplorerPane::Files => {
                let Some(view) = self.explorer_view.as_ref() else {
                    return;
                };
                match crate::explorer::file_row_at(view, view.cursor) {
                    FileRow::Parent => self.explorer_parent(),
                    FileRow::Entry(entry) => match entry.kind {
                        EntryKind::Directory => {
                            let cwd = if view.cwd == "/" {
                                format!("/{}", entry.name)
                            } else {
                                format!("{}/{}", view.cwd, entry.name)
                            };
                            let volume_index = view.volume_index;
                            self.reload_explorer(cwd, volume_index, 0);
                        }
                        _ => self.refresh_explorer_preview(),
                    },
                    FileRow::None => {}
                }
            }
        }
    }

    fn explorer_insert_host(&mut self, host: &Path) {
        if self.explorer_blocks_nav() {
            return;
        }
        let Some(view) = self.explorer_view.as_ref() else {
            return;
        };
        if host == Path::new(&self.explorer_confirmed) {
            return;
        }
        let volume = view.volume_name().to_string();
        let cwd = view.cwd.clone();
        let volume_index = view.volume_index;
        let image = PathBuf::from(&self.explorer_confirmed);
        let host = host.to_path_buf();
        self.explorer_status = "inserting".into();
        self.explorer_progress = Some(0.06);
        let (tx, rx) = mpsc::channel();
        self.explorer_job_rx = Some(rx);
        self.explorer_job_kind = Some(ExplorerJobKind::Insert);
        std::thread::spawn(move || {
            let message = explorer_image::insert_host_path(&image, &volume, &cwd, &host)
                .map_err(|err| err.to_string());
            let _ = tx.send(ExplorerJobEvent::Inserted {
                message,
                cwd,
                volume_index,
            });
        });
    }

    fn explorer_export_selected(&mut self) {
        if self.explorer_blocks_nav() {
            return;
        }
        let Some(view) = self.explorer_view.as_ref() else {
            return;
        };
        let FileRow::Entry(entry) = crate::explorer::file_row_at(view, view.cursor) else {
            return;
        };
        let apfs_path = if view.cwd == "/" {
            format!("/{}", entry.name)
        } else {
            format!("{}/{}", view.cwd, entry.name)
        };
        let dest = self.explorer_export_dir();
        let image = PathBuf::from(&self.explorer_confirmed);
        let volume = view.volume_name().to_string();
        self.explorer_status = "exporting".into();
        self.explorer_progress = Some(0.06);
        let (tx, rx) = mpsc::channel();
        self.explorer_job_rx = Some(rx);
        self.explorer_job_kind = Some(ExplorerJobKind::Export);
        std::thread::spawn(move || {
            let message = (|| {
                std::fs::create_dir_all(&dest).map_err(|err| err.to_string())?;
                let path = explorer_image::export_entry(&image, &volume, &apfs_path, &dest)
                    .map_err(|err| err.to_string())?;
                Ok(format!("exported {}", path.display()))
            })();
            let _ = tx.send(ExplorerJobEvent::Exported { message });
        });
    }

    fn explorer_export_dir(&self) -> PathBuf {
        if let Some(dir) = self.confirm_clip_dir() {
            return PathBuf::from(dir);
        }
        Path::new(&self.explorer_confirmed)
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("apfs-export")
    }

    fn explorer_leave_files(&mut self) {
        if self.explorer_pane != ExplorerPane::Files {
            return;
        }
        let at_root = self
            .explorer_view
            .as_ref()
            .is_none_or(|view| view.cwd == "/");
        let empty = self
            .explorer_view
            .as_ref()
            .is_some_and(|view| view.entries.is_empty());
        if at_root || empty {
            self.explorer_pane = ExplorerPane::Volumes;
            return;
        }
        self.explorer_parent();
    }

    fn explorer_parent(&mut self) {
        let Some(view) = self.explorer_view.as_ref() else {
            return;
        };
        if view.cwd == "/" {
            self.explorer_pane = ExplorerPane::Volumes;
            return;
        }
        let cwd = match view.cwd.rsplit_once('/') {
            Some(("", _)) | None => "/".to_string(),
            Some((parent, _)) => parent.to_string(),
        };
        let volume_index = view.volume_index;
        self.reload_explorer(cwd, volume_index, 0);
    }

    fn refresh_explorer_preview(&mut self) {
        self.start_explorer_preview();
    }

    fn start_explorer_preview(&mut self) {
        if self.explorer_blocks_nav() {
            return;
        }
        let Some(view) = self.explorer_view.as_ref() else {
            return;
        };
        match crate::explorer::file_row_at(view, view.cursor) {
            FileRow::Entry(entry) if matches!(entry.kind, EntryKind::File | EntryKind::Symlink) => {
                let path = PathBuf::from(&self.explorer_confirmed);
                let volume = view.volume_name().to_string();
                let cwd = view.cwd.clone();
                let cursor = view.cursor;
                let volume_index = view.volume_index;
                let (tx, rx) = mpsc::channel();
                self.explorer_job_rx = Some(rx);
                self.explorer_job_kind = Some(ExplorerJobKind::Preview);
                std::thread::spawn(move || {
                    let preview = explorer_image::preview_entry(&path, &volume, &cwd, &entry).ok();
                    let _ = tx.send(ExplorerJobEvent::Preview {
                        cursor,
                        cwd,
                        volume_index,
                        preview,
                    });
                });
            }
            _ => {
                if let Some(view) = self.explorer_view.as_mut() {
                    view.preview = None;
                }
            }
        }
    }

    fn back_to_picker(&mut self) {
        self.clear_path_input();
        self.screen = Screen::Picker;
    }

    fn asahi_key(&mut self, key: KeyEvent) -> bool {
        match self.asahi_step {
            AsahiStep::Menu => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.back_to_picker();
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.asahi_action_cursor = if self.asahi_action_cursor == 0 {
                        AsahiAction::ALL.len() - 1
                    } else {
                        self.asahi_action_cursor - 1
                    };
                    self.asahi_lock_cursor_from_keys();
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.asahi_action_cursor =
                        (self.asahi_action_cursor + 1) % AsahiAction::ALL.len();
                    self.asahi_lock_cursor_from_keys();
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.asahi_action = AsahiAction::ALL[self.asahi_action_cursor];
                    self.asahi_enter_action();
                    false
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let n = c.to_digit(10).unwrap() as usize;
                    if (1..=AsahiAction::ALL.len()).contains(&n) {
                        self.asahi_action_cursor = n - 1;
                        self.asahi_action = AsahiAction::ALL[self.asahi_action_cursor];
                        self.asahi_enter_action();
                    }
                    false
                }
                _ => false,
            },
            AsahiStep::Size => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.asahi_step = AsahiStep::Menu;
                    false
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    self.asahi_size_gb =
                        crate::asahi_ops::clamp_slider_gb(self.asahi_size_gb.saturating_sub(1));
                    false
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    self.asahi_size_gb =
                        crate::asahi_ops::clamp_slider_gb(self.asahi_size_gb.saturating_add(1));
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.enter_file_picker();
                    self.asahi_step = AsahiStep::WaitFile;
                    false
                }
                _ => false,
            },
            AsahiStep::WaitFile => {
                if self.file_picker_edit_key(key) {
                    return false;
                }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.clear_path_input();
                        self.asahi_step = match self.asahi_action {
                            AsahiAction::Install => AsahiStep::Size,
                            AsahiAction::Update => AsahiStep::Menu,
                        };
                        false
                    }
                    KeyCode::Enter => {
                        match self.asahi_action {
                            AsahiAction::Update => {
                                if let Some(path) = self.take_picker_file() {
                                    self.asahi_confirmed = path;
                                    self.asahi_step = AsahiStep::Source;
                                }
                            }
                            AsahiAction::Install => {
                                if let Some(path) = self.take_picker_dir() {
                                    self.asahi_confirmed = path;
                                    self.asahi_step = AsahiStep::Source;
                                } else if self.path_input.trim().is_empty()
                                    && self.asahi_output_path.is_some()
                                {
                                    self.asahi_step = AsahiStep::Source;
                                }
                            }
                        }
                        false
                    }
                    _ => false,
                }
            }
            AsahiStep::Source => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.asahi_step = match self.asahi_action {
                        AsahiAction::Install => AsahiStep::WaitFile,
                        AsahiAction::Update => AsahiStep::WaitFile,
                    };
                    false
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {
                    self.asahi_source_cursor = 1 - self.asahi_source_cursor;
                    self.asahi_lock_cursor_from_keys();
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.asahi_source = if self.asahi_source_cursor == 0 {
                        AsahiSource::Latest
                    } else {
                        AsahiSource::Custom
                    };
                    if self.asahi_source == AsahiSource::Custom {
                        self.enter_file_picker();
                        self.asahi_step = AsahiStep::WaitKernel;
                    } else {
                        self.enter_asahi_latest();
                    }
                    false
                }
                KeyCode::Char('1') => {
                    self.asahi_source_cursor = 0;
                    self.asahi_source = AsahiSource::Latest;
                    self.enter_asahi_latest();
                    false
                }
                KeyCode::Char('2') => {
                    self.asahi_source_cursor = 1;
                    self.asahi_source = AsahiSource::Custom;
                    self.enter_file_picker();
                    self.asahi_step = AsahiStep::WaitKernel;
                    false
                }
                _ => false,
            },
            AsahiStep::Flavor => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.asahi_step = AsahiStep::Source;
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.asahi_flavor_cursor > 0 {
                        self.asahi_flavor_cursor -= 1;
                    }
                    self.asahi_lock_cursor_from_keys();
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.asahi_flavor_cursor + 1 < self.asahi_flavors.len() {
                        self.asahi_flavor_cursor += 1;
                    }
                    self.asahi_lock_cursor_from_keys();
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.confirm_asahi_flavor();
                    false
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let n = c.to_digit(10).unwrap() as usize;
                    if (1..=self.asahi_flavors.len()).contains(&n) {
                        self.asahi_flavor_cursor = n - 1;
                        self.confirm_asahi_flavor();
                    }
                    false
                }
                _ => false,
            },
            AsahiStep::WaitKernel => {
                if self.file_picker_edit_key(key) {
                    return false;
                }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.clear_path_input();
                        self.asahi_step = AsahiStep::Source;
                        false
                    }
                    KeyCode::Enter => {
                        if let Some(path) = self.take_picker_path() {
                            self.asahi_kernel = path;
                            self.clip.file = None;
                            self.enter_file_picker();
                            self.asahi_step = AsahiStep::WaitM1n1;
                        }
                        false
                    }
                    _ => false,
                }
            }
            AsahiStep::WaitM1n1 => {
                if self.file_picker_edit_key(key) {
                    return false;
                }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.clear_path_input();
                        self.asahi_step = AsahiStep::WaitKernel;
                        false
                    }
                    KeyCode::Enter => {
                        if let Some(path) = self.take_picker_path() {
                            self.asahi_m1n1 = path;
                            self.run_asahi_work();
                        }
                        false
                    }
                    _ => false,
                }
            }
            AsahiStep::WaitIpsw => {
                if self.file_picker_edit_key(key) { return false; }
                match key.code {
                    KeyCode::Char('q') => true,
                    KeyCode::Esc => {
                        self.clear_path_input();
                        self.asahi_step = AsahiStep::Source;
                        false
                    }
                    KeyCode::Enter => {
                        if let Some(path) = self.take_picker_path() {
                            let path = std::path::PathBuf::from(path);
                            self.start_asahi_restore_inspection(path);
                        }
                        false
                    }
                    _ => false,
                }
            }
            AsahiStep::RestoreTarget => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.asahi_selected_target = None;
                    self.enter_file_picker();
                    self.asahi_step = AsahiStep::WaitIpsw;
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.asahi_restore_cursor = self.asahi_restore_cursor.saturating_sub(1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.asahi_restore_info.as_ref().is_some_and(|info|
                        self.asahi_restore_cursor + 1 < info.identities.len()) {
                        self.asahi_restore_cursor += 1;
                    }
                    false
                }
                KeyCode::Enter => {
                    self.asahi_selected_target = self.asahi_restore_info.as_ref()
                        .and_then(|info| info.identities.get(self.asahi_restore_cursor)).cloned();
                    if self.asahi_selected_target.is_some() { self.run_asahi_work(); }
                    false
                }
                _ => false,
            },
            AsahiStep::InspectIpsw => matches!(key.code, KeyCode::Char('q')),
            AsahiStep::Work => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc if self.asahi_catalog_pending => {
                    self.asahi_job_rx = None;
                    self.asahi_catalog_pending = false;
                    self.asahi_progress = None;
                    self.asahi_status.clear();
                    self.asahi_step = AsahiStep::Source;
                    false
                }
                _ => false,
            },
            AsahiStep::Done => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.asahi_step = AsahiStep::Menu;
                    self.asahi_job_rx = None;
                    false
                }
                _ => false,
            },
        }
    }

    fn asahi_enter_action(&mut self) {
        self.asahi_error = None;
        self.asahi_status.clear();
        match self.asahi_action {
            AsahiAction::Install => self.asahi_step = AsahiStep::Size,
            AsahiAction::Update => {
                self.enter_file_picker();
                self.asahi_step = AsahiStep::WaitFile;
            }
        }
    }

    fn asahi_card_index_at(&self, col: u16, row: u16) -> Option<usize> {
        match self.asahi_step {
            AsahiStep::Menu => self.hits.asahi_action_at(col, row),
            AsahiStep::Source => self.hits.asahi_source_at(col, row),
            AsahiStep::Flavor => self
                .hits
                .asahi_flavor_at(col, row)
                .filter(|&index| index < self.asahi_flavors.len()),
            _ => None,
        }
    }

    fn asahi_lock_cursor_from_keys(&mut self) {
        self.asahi_keys_own_cursor = true;
        self.asahi_hover_lock_index = self
            .asahi_pointer
            .and_then(|(col, row)| self.asahi_card_index_at(col, row));
    }

    fn asahi_apply_hover_index(&mut self, index: usize) {
        if self.asahi_keys_own_cursor {
            if self.asahi_hover_lock_index.is_none() {
                self.asahi_hover_lock_index = Some(index);
            }
            if self.asahi_hover_lock_index == Some(index) {
                return;
            }
            self.asahi_keys_own_cursor = false;
            self.asahi_hover_lock_index = None;
        }
        match self.asahi_step {
            AsahiStep::Menu => self.asahi_action_cursor = index,
            AsahiStep::Source => self.asahi_source_cursor = index,
            AsahiStep::Flavor => self.asahi_flavor_cursor = index,
            _ => {}
        }
    }

    fn asahi_hover(&mut self, col: u16, row: u16, dragging: bool) {
        self.asahi_pointer = Some((col, row));
        match self.asahi_step {
            AsahiStep::Menu | AsahiStep::Source | AsahiStep::Flavor => {
                if let Some(index) = self.asahi_card_index_at(col, row) {
                    self.asahi_apply_hover_index(index);
                }
            }
            AsahiStep::Size => {
                let over = self.hits.asahi_slider_contains(col, row);
                self.asahi_slider_hover = over;
                if over && dragging {
                    self.apply_asahi_slider(col);
                }
            }
            _ => {
                self.asahi_slider_hover = false;
            }
        }
    }

    fn apply_asahi_slider(&mut self, col: u16) {
        let rect = self.hits.asahi_slider;
        if rect.width <= 2 {
            return;
        }
        let x = col.saturating_sub(rect.x);
        let frac = f64::from(x) / f64::from(rect.width);
        let span = crate::asahi_ops::SLIDER_MAX_GB - crate::asahi_ops::SLIDER_MIN_GB;
        self.asahi_size_gb = crate::asahi_ops::clamp_slider_gb(
            crate::asahi_ops::SLIDER_MIN_GB + (frac * f64::from(span)).round() as u32,
        );
    }

    fn asahi_click(&mut self, col: u16, row: u16) {
        match self.asahi_step {
            AsahiStep::Menu => {
                if let Some(index) = self.hits.asahi_action_at(col, row) {
                    self.asahi_action_cursor = index;
                    self.asahi_action = AsahiAction::ALL[index];
                    self.asahi_enter_action();
                }
            }
            AsahiStep::Source => {
                if let Some(index) = self.hits.asahi_source_at(col, row) {
                    self.asahi_source_cursor = index;
                    self.asahi_source = if index == 0 {
                        AsahiSource::Latest
                    } else {
                        AsahiSource::Custom
                    };
                    if self.asahi_source == AsahiSource::Custom {
                        self.enter_file_picker();
                        self.asahi_step = AsahiStep::WaitKernel;
                    } else {
                        self.enter_asahi_latest();
                    }
                }
            }
            AsahiStep::Flavor => {
                if let Some(index) = self.hits.asahi_flavor_at(col, row)
                    && index < self.asahi_flavors.len()
                {
                    self.asahi_flavor_cursor = index;
                    self.confirm_asahi_flavor();
                }
            }
            AsahiStep::Size if self.hits.asahi_slider_contains(col, row) => {
                self.asahi_slider_hover = true;
                self.apply_asahi_slider(col);
            }
            _ => {}
        }
    }

    fn enter_asahi_latest(&mut self) {
        if self.asahi_injected_artifacts.is_some() {
            self.run_asahi_work();
            return;
        }
        if self.asahi_action == AsahiAction::Update {
            self.run_asahi_work();
            return;
        }
        if self.asahi_injected_metadata.is_some() {
            match self.load_asahi_flavors() {
                Ok(list) => self.apply_asahi_flavors(list),
                Err(err) => {
                    self.asahi_error = Some(err);
                    self.asahi_step = AsahiStep::Done;
                }
            }
            return;
        }
        self.start_catalog_fetch();
    }

    fn load_asahi_flavors(&mut self) -> Result<Vec<crate::asahi_ops::Flavor>, String> {
        use crate::asahi_ops::{list_installable_flavors, parse_installer_data};
        let json = self
            .asahi_injected_metadata
            .clone()
            .ok_or_else(|| "installer catalogue is not loaded".to_string())?;
        let data = parse_installer_data(&json).map_err(|e| e.to_string())?;
        Ok(list_installable_flavors(&data))
    }

    fn apply_asahi_flavors(&mut self, list: Vec<crate::asahi_ops::Flavor>) {
        self.asahi_flavors = list;
        self.asahi_flavor_cursor = 0;
        self.asahi_progress = None;
        self.asahi_lock_cursor_from_keys();
        if self.asahi_flavors.len() <= 1 {
            if let Some(flavor) = self.asahi_flavors.first() {
                self.asahi_os_query = flavor.slug.clone();
            }
            self.run_asahi_work();
        } else {
            self.asahi_status.clear();
            self.asahi_step = AsahiStep::Flavor;
        }
    }

    fn start_catalog_fetch(&mut self) {
        use crate::asahi_ops;
        self.asahi_step = AsahiStep::Work;
        self.asahi_error = None;
        self.asahi_progress = Some(0.0);
        self.asahi_status = "fetching catalogue".into();
        self.asahi_catalog_pending = true;
        let url = asahi_ops::DEFAULT_INSTALLER_DATA_URL.to_string();
        let (tx, rx) = mpsc::channel();
        self.asahi_job_rx = Some(rx);
        std::thread::spawn(move || {
            let fetched = (|| {
                let work = std::env::temp_dir().join(format!(
                    "apple-utils-asahi-catalogue-{}",
                    std::process::id()
                ));
                std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
                let dest = work.join("installer_data.json");
                asahi_ops::fetch_url_to_file_with_progress(&url, &dest, |fraction| {
                    let _ = tx.send(AsahiJobEvent::Progress {
                        status: "fetching catalogue".into(),
                        fraction: fraction.or(Some(0.0)),
                    });
                })
                .map_err(|e| e.to_string())?;
                let json = std::fs::read_to_string(&dest).map_err(|e| e.to_string())?;
                let data = asahi_ops::parse_installer_data(&json).map_err(|e| e.to_string())?;
                let flavors = asahi_ops::list_installable_flavors(&data);
                Ok((json, flavors))
            })();
            let _ = tx.send(AsahiJobEvent::Catalog(fetched));
        });
    }

    fn confirm_asahi_flavor(&mut self) {
        if let Some(flavor) = self.asahi_flavors.get(self.asahi_flavor_cursor) {
            self.asahi_os_query = flavor.slug.clone();
        }
        self.run_asahi_work();
    }

    pub fn asahi_ipsw_hint(&self) -> String {
        let versions = self.asahi_injected_metadata.as_deref()
            .and_then(|json| crate::asahi_ops::parse_installer_data(json).ok())
            .and_then(|data| crate::asahi_ops::resolve_os(&data, &self.asahi_os_query).ok())
            .and_then(|resolved| resolved.supported_fw);
        match versions {
            Some(versions) => format!("Select a local IPSW. Package-supported macOS firmware: {}. Target-specific compatibility is checked after selection.", if versions.is_empty() { "none".into() } else { versions.join(", ") }),
            None => "Select a local IPSW compatible with the selected Asahi release and target.".into(),
        }
    }

    fn start_asahi_restore_inspection(&mut self, path: std::path::PathBuf) {
        self.asahi_step = AsahiStep::InspectIpsw;
        self.asahi_status = "checking IPSW manifest and restore targets".into();
        self.asahi_progress = None;
        self.asahi_error = None;
        self.asahi_ipsw = None;
        self.asahi_restore_info = None;
        self.asahi_selected_target = None;
        let (tx, rx) = mpsc::channel();
        self.asahi_job_rx = Some(rx);
        std::thread::spawn(move || {
            let result = crate::asahi_firmware_archive::inspect_restore_archive(&path)
                .map_err(|error| error.to_string());
            let _ = tx.send(AsahiJobEvent::RestoreInspected(path, result));
        });
    }

    fn accept_asahi_restore_archive(
        &mut self,
        path: std::path::PathBuf,
        info: crate::asahi_firmware_archive::RestoreArchiveInfo,
    ) {
        if let Some(json) = self.asahi_injected_metadata.as_deref() {
            let result = crate::asahi_ops::parse_installer_data(json).map_err(|e| e.to_string())
                .and_then(|data| crate::asahi_ops::resolve_os(&data, &self.asahi_os_query).map_err(|e| e.to_string()))
                .and_then(|resolved| crate::asahi_firmware::validate_supported_version(&info.product_version, resolved.supported_fw.as_deref()));
            if let Err(error) = result {
                self.asahi_ipsw = None;
                self.asahi_restore_info = None;
                self.asahi_selected_target = None;
                self.asahi_error = Some(error);
                self.asahi_step = AsahiStep::WaitIpsw;
                return;
            }
        }
        if info.identities.is_empty() {
            self.asahi_error = Some("The IPSW contains no supported restore targets".into());
            return;
        }
        self.asahi_ipsw = Some(path);
        self.asahi_restore_info = Some(info);
        self.asahi_restore_cursor = 0;
        self.asahi_selected_target = None;
        self.asahi_error = None;
        self.asahi_step = AsahiStep::RestoreTarget;
    }

    fn run_asahi_work(&mut self) {
        if self.asahi_source == AsahiSource::Latest && self.asahi_injected_artifacts.is_none()
            && self.asahi_selected_target.is_none() {
            self.asahi_error = None;
            self.enter_file_picker();
            self.asahi_step = AsahiStep::WaitIpsw;
            return;
        }

        self.asahi_step = AsahiStep::Work;
        self.asahi_error = None;
        self.asahi_progress = Some(0.0);
        self.asahi_status = match self.asahi_action {
            AsahiAction::Update => "updating disc".into(),
            AsahiAction::Install => "installing".into(),
        };
        let plan = self.asahi_work_plan();
        let (tx, rx) = mpsc::channel();
        self.asahi_job_rx = Some(rx);
        std::thread::spawn(move || {
            let result = execute_asahi_work(plan, |status, fraction| {
                let _ = tx.send(AsahiJobEvent::Progress {
                    status: status.to_string(),
                    fraction,
                });
            });
            let _ = tx.send(AsahiJobEvent::Finished(result));
        });
    }

    fn poll_asahi_job(&mut self) {
        let Some(rx) = self.asahi_job_rx.as_mut() else {
            return;
        };
        let mut finished: Option<Result<String, String>> = None;
        let mut catalog: Option<Result<(String, Vec<crate::asahi_ops::Flavor>), String>> = None;
        let mut inspected = None;
        let mut disconnected = false;
        loop {
            match rx.try_recv() {
                Ok(AsahiJobEvent::Progress { status, fraction }) => {
                    self.asahi_status = status;
                    self.asahi_progress = fraction;
                }
                Ok(AsahiJobEvent::RestoreInspected(path, result)) => {
                    inspected = Some((path, result));
                    break;
                }
                Ok(AsahiJobEvent::Catalog(result)) => {
                    catalog = Some(result);
                    break;
                }
                Ok(AsahiJobEvent::Finished(result)) => {
                    finished = Some(result);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if inspected.is_some() || catalog.is_some() || finished.is_some() || disconnected {
            self.asahi_job_rx = None;
        }
        if let Some((path, result)) = inspected {
            self.asahi_step = AsahiStep::WaitIpsw;
            self.asahi_status.clear();
            match result {
                Ok(info) => self.accept_asahi_restore_archive(path, info),
                Err(error) => self.asahi_error = Some(error),
            }
            return;
        }
        if disconnected && self.asahi_step == AsahiStep::InspectIpsw {
            self.asahi_error = Some("IPSW inspection worker stopped".into());
            self.asahi_step = AsahiStep::WaitIpsw;
            return;
        }
        if let Some(result) = catalog {
            self.asahi_catalog_pending = false;
            match result {
                Ok((json, list)) => {
                    self.asahi_injected_metadata = Some(json);
                    self.apply_asahi_flavors(list);
                }
                Err(err) => {
                    self.asahi_error = Some(err);
                    self.asahi_step = AsahiStep::Done;
                }
            }
            return;
        }
        if let Some(result) = finished {
            self.asahi_catalog_pending = false;
            match result {
                Ok(msg) => {
                    self.asahi_status = msg;
                    self.asahi_progress = Some(1.0);
                    self.asahi_error = None;
                    self.asahi_step = AsahiStep::Done;
                }
                Err(err) => {
                    self.asahi_error = Some(err);
                    self.asahi_step = AsahiStep::Done;
                }
            }
        } else if disconnected && self.asahi_step == AsahiStep::Work {
            self.asahi_catalog_pending = false;
            self.asahi_error = Some("install worker stopped".into());
            self.asahi_step = AsahiStep::Done;
        }
    }

    #[cfg(test)]
    pub fn drain_asahi_job(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.asahi_job_rx.is_some() {
            self.poll_asahi_job();
            if self.asahi_job_rx.is_some() {
                assert!(
                    Instant::now() <= deadline,
                    "asahi worker thread did not finish within 30s (status={:?}, progress={:?}); \
                     it is hung or deadlocked rather than merely slow, since it should have sent \
                     Finished/Catalog by now",
                    self.asahi_status,
                    self.asahi_progress,
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    fn asahi_work_plan(&self) -> AsahiWorkPlan {
        use crate::asahi_ops::slider_gb_to_bytes;
        let os_name = self
            .asahi_flavors
            .get(self.asahi_flavor_cursor)
            .map(|f| f.default_os_name.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Asahi Linux".into());
        AsahiWorkPlan {
            ipsw: self.asahi_ipsw.clone(),
            restore_target: self.asahi_selected_target.clone(),
            action: self.asahi_action,
            source: self.asahi_source,
            kernel: self.asahi_kernel.clone(),
            m1n1: self.asahi_m1n1.clone(),
            confirmed: self.asahi_confirmed.clone(),
            dest: self.asahi_install_dest(),
            size_bytes: if self.asahi_injected_artifacts.is_some() {
                crate::asahi_ops::min_disc_bytes()
            } else {
                slider_gb_to_bytes(self.asahi_size_gb).max(crate::asahi_ops::min_disc_bytes())
            },
            os_query: self.asahi_os_query.clone(),
            os_name,
            injected_artifacts: self.asahi_injected_artifacts.clone(),
            injected_metadata: self.asahi_injected_metadata.clone(),
        }
    }

    fn asahi_install_dest(&self) -> std::path::PathBuf {
        const NAME: &str = "asahi-linux.qcow2";
        if let Some(path) = &self.asahi_output_path {
            if path.is_dir() {
                return path.join(NAME);
            }
            return path.clone();
        }
        if !self.asahi_confirmed.is_empty() {
            let path = std::path::PathBuf::from(&self.asahi_confirmed);
            if path.is_dir() {
                return path.join(NAME);
            }
            return path;
        }
        std::path::PathBuf::from(NAME)
    }

    fn recovery_hover(&mut self, col: u16, row: u16) {
        if self.recovery.model.step() == RecoveryStep::PickSystem
            && let Some(index) = self.recovery.model.hits.device_at(col, row)
        {
            self.recovery.model.system_cursor = index;
        }
        if self.recovery.model.step() == RecoveryStep::PickMode
            && let Some(index) = self.recovery.model.hits.device_at(col, row)
        {
            self.recovery.model.mode_cursor = index;
        }
        if self.recovery.model.step() == RecoveryStep::PickDevice
            && let Some(index) = self.recovery.model.hits.device_at(col, row)
        {
            self.recovery.model.select_device(index);
        }
    }

    fn recovery_click(&mut self, col: u16, row: u16) {
        if self.recovery.model.step() == RecoveryStep::PickSystem
            && let Some(index) = self.recovery.model.hits.device_at(col, row)
        {
            self.recovery.model.system_cursor = index;
            self.recovery.select_system();
        }
        if self.recovery.model.step() == RecoveryStep::PickMode
            && let Some(index) = self.recovery.model.hits.device_at(col, row)
        {
            self.recovery.model.mode_cursor = index;
            self.recovery.select_restore_mode();
        }
        if self.recovery.model.step() == RecoveryStep::PickDevice
            && let Some(index) = self.recovery.model.hits.device_at(col, row)
        {
            self.recovery.model.select_device(index);
            self.recovery.claim_selected();
        }
    }
}

struct AsahiWorkPlan {
    ipsw: Option<std::path::PathBuf>,
    restore_target: Option<crate::asahi_firmware_archive::RestoreTarget>,
    action: AsahiAction,
    source: AsahiSource,
    kernel: String,
    m1n1: String,
    confirmed: String,
    dest: std::path::PathBuf,
    size_bytes: u64,
    os_query: String,
    os_name: String,
    injected_artifacts: Option<crate::asahi_ops::Artifacts>,
    injected_metadata: Option<String>,
}

fn execute_asahi_work(
    plan: AsahiWorkPlan,
    mut progress: impl FnMut(&str, Option<f64>),
) -> Result<String, String> {
    use crate::asahi_ops::{self, parse_installer_data, resolve_os, update_disc};
    use std::path::PathBuf;

    progress("preparing", Some(0.0));
    let mut next_object = "m1n1/boot.bin".to_string();

    let mut preflight_archives = None;
    let mut artifacts = if let Some(arts) = plan.injected_artifacts.clone() {
        arts
    } else if plan.action == AsahiAction::Update && plan.source == AsahiSource::Custom {
        asahi_ops::Artifacts::memory(
            std::fs::read(&plan.kernel).map_err(|e| e.to_string())?,
            std::fs::read(&plan.m1n1).map_err(|e| e.to_string())?,
            Vec::new(),
        )
    } else {
        let json = if let Some(doc) = plan.injected_metadata.clone() {
            doc
        } else {
            progress("fetching catalogue", Some(0.0));
            let meta_dir = std::env::temp_dir().join(format!(
                "apple-utils-asahi-catalogue-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&meta_dir).map_err(|e| e.to_string())?;
            let meta_path = meta_dir.join("installer_data.json");
            asahi_ops::fetch_url_to_file_with_progress(
                asahi_ops::DEFAULT_INSTALLER_DATA_URL,
                &meta_path,
                |fraction| progress("fetching catalogue", fraction.or(Some(0.0))),
            )
            .map_err(|e| e.to_string())?;
            progress("fetching catalogue", Some(1.0));
            std::fs::read_to_string(&meta_path).map_err(|e| e.to_string())?
        };
        let data = parse_installer_data(&json).map_err(|e| e.to_string())?;
        let resolved = resolve_os(&data, &plan.os_query).map_err(|e| e.to_string())?;
        if resolved.supported_fw.is_some() || !resolved.firmware_partitions.is_empty()
            || !resolved.installer_data_partitions.is_empty() {
            let ipsw = plan.ipsw.as_deref().ok_or("select a local IPSW before setup")?;
            let target = plan.restore_target.as_ref().ok_or("select an IPSW target before setup")?;
            crate::asahi_firmware_archive::validate_archive_for_package(
                ipsw, resolved.supported_fw.as_deref(), Some((&target.board, target.chip_id)),
            )?;
            let requirements = asahi_ops::FirmwareRequirements::from(&resolved);
            let work = tempfile::tempdir().map_err(|e| e.to_string())?;
            let archives = crate::asahi_firmware_download::resolve_firmware_archives(
                &crate::asahi_firmware_download::FirmwareArchiveInputs {
                    board: &target.board, chip_id: target.chip_id, expert: false,
                    workdir: work.path(), requirements: &requirements,
                    installer_archive: None, installer_source_uri: None,
                    ipsw: Some(ipsw), repair_identity: None,
                },
                |url, fraction| progress(&format!("fetching installer {url}"), fraction),
            )?;
            preflight_archives = Some((archives, work));
        }
        next_object = resolved.next_object.clone();
        let work = std::env::temp_dir().join(format!(
            "apple-utils-asahi-{}-{}",
            std::process::id(),
            resolved.os_name.replace(' ', "-")
        ));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        let package = work.join("package.zip");
        progress("downloading package", Some(0.0));
        asahi_ops::fetch_url_to_file_with_progress(&resolved.package_url, &package, |fraction| {
            progress(if fraction.is_none() { "checking package cache" } else { "downloading package" }, fraction);
        })
        .map_err(|e| e.to_string())?;
        progress("extracting package", Some(0.0));
        let include_root = plan.action == AsahiAction::Install;
        let mut arts = asahi_ops::load_artifacts_from_package_file_reporting(
            &data,
            &plan.os_query,
            &package,
            &work,
            include_root,
            |fraction| progress("extracting package", Some(fraction)),
        )
        .map_err(|e| e.to_string())?;
        progress("extracting package", Some(1.0));
        if plan.source == AsahiSource::Custom {
            arts.kernel = std::fs::read(&plan.kernel).map_err(|e| e.to_string())?;
            arts.m1n1 = std::fs::read(&plan.m1n1).map_err(|e| e.to_string())?;
        }
        arts
    };

    if plan.source == AsahiSource::Custom {
        if !plan.kernel.is_empty() {
            artifacts.kernel = std::fs::read(&plan.kernel).map_err(|e| e.to_string())?;
        }
        if !plan.m1n1.is_empty() {
            artifacts.m1n1 = std::fs::read(&plan.m1n1).map_err(|e| e.to_string())?;
        }
    }
    let mut provisioned_firmware = None;
    if let Some(requirements) = artifacts.firmware_requirements.clone() {
        let required = requirements.supported_fw.is_some()
            || !requirements.firmware_partitions.is_empty()
            || !requirements.installer_data_partitions.is_empty();
        if required {
            let target = plan.restore_target.as_ref().ok_or("select an IPSW target before setup")?;
            let (archives, work) = preflight_archives.take().ok_or("firmware compatibility was not checked before package download")?;
            progress("checking selected IPSW and extracting firmware", None);
            let prepared = crate::asahi_provisioning::prepare_firmware(
                &crate::asahi_provisioning::ProvisioningInputs {
                    board: &target.board, chip_id: target.chip_id, expert: false,
                    installer_archive: &archives.installer_archive,
                    installer_source_uri: &archives.installer_source_uri,
                    ipsw: &archives.ipsw, workdir: work.path(), repair_identity: None,
                }, &requirements,
            )?;
            progress("extracting recovery firmware", None);
            let recovery = crate::asahi_provisioning::RecoveryImageFiles::extract(prepared.recovery_image()?)?;
            progress("packaging firmware from selected IPSW", None);
            let provisioned = prepared.provision_artifacts(&mut artifacts, recovery.root(), None, false)?;
            provisioned_firmware = Some((provisioned, work));
        }
    }
    if artifacts.m1n1_stage1.is_empty() {
        progress("downloading installer stage one", Some(0.0));
        artifacts.m1n1_stage1 = asahi_ops::fetch_installer_stage1().map_err(|e| e.to_string())?;
        progress("downloading installer stage one", Some(1.0));
    }

    if plan.action == AsahiAction::Update {
        artifacts.root_fs.clear();
        artifacts.root_path = None;
    }

    let next_object = plan
        .injected_metadata
        .as_deref()
        .and_then(|json| parse_installer_data(json).ok())
        .and_then(|data| resolve_os(&data, &plan.os_query).ok())
        .map(|r| r.next_object)
        .unwrap_or(next_object);

    let result = (|| -> Result<String, String> { match plan.action {
        AsahiAction::Update => {
            progress("replacing kernel and m1n1", Some(0.0));
            let path = PathBuf::from(&plan.confirmed);
            let report = update_disc(&path, &artifacts).map_err(|e| e.to_string())?;
            progress("replacing kernel and m1n1", Some(1.0));
            Ok(format!("Updated {}", report.path))
        }
        AsahiAction::Install => {
            progress("writing disc", Some(0.0));
            let report = asahi_ops::create_qcow2_disc_with_progress(
                &plan.dest,
                &artifacts,
                plan.size_bytes,
                &next_object,
                &plan.os_name,
                |fraction| progress("writing disc", Some(fraction)),
            )
            .map_err(|e| e.to_string())?;
            progress("writing disc", Some(1.0));
            Ok(format!("Installed {}", report.path))
        }
    } })();
    drop(provisioned_firmware);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asahi_ops::{self, Artifacts, parse_installer_data};
    use crate::recovery_model::{
        DeviceState, FileRequestSpec, RecoveryDevice, RecoveryEvent, SessionPhase, SizeRange,
    };
    use std::path::Path;

    fn key(code: KeyCode) -> Event {
        let mut event = KeyEvent::new(code, KeyModifiers::NONE);
        event.kind = KeyEventKind::Press;
        Event::Key(event)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.handle_event(key(code));
    }

    fn screen_for(tool: Tool) -> Screen {
        match tool {
            Tool::Recovery => Screen::Recovery,
            Tool::Explorer => Screen::Explorer,
            Tool::Repair => Screen::Repair,
            Tool::Asahi => Screen::Asahi,
        }
    }

    fn tiny_artifacts(tag: &[u8]) -> Artifacts {
        let mut artifacts = Artifacts::memory(
            [b"KERN", tag].concat(),
            [b"M1N1", tag].concat(),
            [b"ROOT", tag, &[0u8; 64]].concat(),
        );
        let mut stage1 = vec![0u8; 2048];
        stage1[..12].copy_from_slice(b"##m1n1_ver##");
        artifacts.m1n1_stage1 = stage1;
        artifacts
    }

    fn set_clip_path(app: &mut App, path: &Path) {
        let info = crate::clip::inspect(&path.to_string_lossy())
            .unwrap_or_else(|| panic!("expected a clipboard file at {}", path.display()));
        app.clip.set_file(info);
    }

    fn picker_text(app: &mut App) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use ratatui::layout::Position;

        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, app))
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

    #[test]
    fn asahi_ipsw_inspection_waits_responsively_and_handles_completion() {
        use crate::asahi_firmware_archive::{RestoreArchiveInfo, RestoreTarget};
        let mut app = App::with_banner_order(crate::banner::BannerOrder::sequential());
        app.screen = Screen::Asahi;
        app.asahi_step = AsahiStep::InspectIpsw;
        app.asahi_status = "checking IPSW manifest and restore targets".into();
        app.asahi_progress = None;
        let (tx, rx) = mpsc::channel();
        app.asahi_job_rx = Some(rx);
        app.prepare();
        assert_eq!(app.asahi_step, AsahiStep::InspectIpsw);
        let first = picker_text(&mut app);
        assert!(first.contains("checking IPSW"));
        app.tick += 7;
        assert_ne!(first, picker_text(&mut app));
        tx.send(AsahiJobEvent::RestoreInspected("selected.ipsw".into(), Ok(RestoreArchiveInfo {
            product_version: "13.5".into(), product_build: "Test".into(),
            identities: vec![RestoreTarget { board: "j274ap".into(), chip_id: 0x8103 }],
        }))).unwrap();
        app.prepare();
        assert_eq!(app.asahi_step, AsahiStep::RestoreTarget);
        assert!(app.asahi_job_rx.is_none());
        assert_eq!(app.asahi_ipsw.as_deref(), Some(std::path::Path::new("selected.ipsw")));
    }

    #[test]
    fn asahi_ipsw_inspection_failure_returns_to_picker() {
        let mut app = App::new();
        let dir = tempfile::tempdir().unwrap();
        app.start_asahi_restore_inspection(dir.path().join("missing.ipsw"));
        assert_eq!(app.asahi_step, AsahiStep::InspectIpsw);
        assert!(app.asahi_progress.is_none());
        app.drain_asahi_job();
        assert_eq!(app.asahi_step, AsahiStep::WaitIpsw);
        assert!(app.asahi_error.is_some());
        assert!(app.asahi_job_rx.is_none());
        let (tx, rx) = mpsc::channel();
        app.asahi_step = AsahiStep::InspectIpsw;
        app.asahi_job_rx = Some(rx);
        drop(tx);
        app.prepare();
        assert_eq!(app.asahi_step, AsahiStep::WaitIpsw);
        assert_eq!(app.asahi_error.as_deref(), Some("IPSW inspection worker stopped"));
    }

    #[test]
    fn asahi_ipsw_preflight_shows_versions_and_keeps_invalid_file_in_picker() {
        let mut app = App::with_banner_order(crate::banner::BannerOrder::sequential());
        app.screen = Screen::Asahi;
        app.asahi_source = AsahiSource::Latest;
        app.asahi_step = AsahiStep::WaitIpsw;
        app.asahi_injected_metadata = Some(r#"{"os_list":[{"name":"Test OS","package":"https://example.test/os.zip","supported_fw":["12.3","13.5"]}]}"#.into());
        let hint = picker_text(&mut app);
        assert!(hint.contains("12.3") && hint.contains("13.5"));
        app.accept_asahi_restore_archive("selected.ipsw".into(), crate::asahi_firmware_archive::RestoreArchiveInfo {
            product_version: "26.5.1".into(), product_build: "Test".into(),
            identities: vec![crate::asahi_firmware_archive::RestoreTarget {board:"j274ap".into(),chip_id:0x8103}],
        });
        assert_eq!(app.asahi_step, AsahiStep::WaitIpsw);
        assert!(app.asahi_job_rx.is_none());
        assert!(app.asahi_ipsw.is_none());
        let error = picker_text(&mut app);
        assert!(error.contains("26.5.1") && error.contains("13.5"));
        assert!(!error.contains('…'));
        app.asahi_step = AsahiStep::Done;
        let done = picker_text(&mut app);
        assert!(done.contains("26.5.1") && done.contains("13.5"));
    }

    #[test]
    fn asahi_local_ipsw_selection_carries_only_explicit_manifest_target() {
        use crate::asahi_firmware_archive::{RestoreArchiveInfo, RestoreTarget};
        let mut app = App::with_banner_order(crate::banner::BannerOrder::sequential());
        app.screen = Screen::Asahi;
        app.asahi_source = AsahiSource::Latest;
        app.run_asahi_work();
        assert_eq!(app.asahi_step, AsahiStep::WaitIpsw);
        assert!(app.asahi_job_rx.is_none());
        app.accept_asahi_restore_archive(std::path::PathBuf::from("selected.ipsw"), RestoreArchiveInfo {
            product_version: "test-version".into(), product_build: "test-build".into(),
            identities: vec![RestoreTarget { board: "j274ap".into(), chip_id: 0x8103 },
                RestoreTarget { board: "j293ap".into(), chip_id: 0x8103 }],
        });
        assert_eq!(app.asahi_step, AsahiStep::RestoreTarget);
        assert!(app.asahi_selected_target.is_none());
        press(&mut app, KeyCode::Down);
        assert_eq!(app.asahi_restore_cursor, 1);
        let text = picker_text(&mut app);
        assert!(text.contains("j293ap"));
        app.asahi_selected_target = app.asahi_restore_info.as_ref().unwrap().identities.get(1).cloned();
        let plan = app.asahi_work_plan();
        assert_eq!(plan.ipsw.as_deref(), Some(std::path::Path::new("selected.ipsw")));
        assert_eq!(plan.restore_target.unwrap().board, "j293ap");
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.asahi_step, AsahiStep::WaitIpsw);
        assert!(app.asahi_selected_target.is_none());
    }

    #[test]
    fn asahi_empty_restore_manifest_does_not_advance_picker() {
        let mut app = App::with_banner_order(crate::banner::BannerOrder::sequential());
        app.asahi_step = AsahiStep::WaitIpsw;
        app.accept_asahi_restore_archive(std::path::PathBuf::from("empty.ipsw"),
            crate::asahi_firmware_archive::RestoreArchiveInfo {
                product_version: String::new(), product_build: String::new(), identities: Vec::new(),
            });
        assert_eq!(app.asahi_step, AsahiStep::WaitIpsw);
        assert!(app.asahi_ipsw.is_none());
        assert!(app.asahi_error.is_some());
    }

    #[test]
    fn picker_g_cycles_glyph_pack_without_leaving_the_menu() {
        let mut app = App::with_banner_order(crate::banner::BannerOrder::sequential());
        assert_eq!(app.glyph_pack, GlyphPack::Instrument);
        assert_eq!(app.screen, Screen::Picker);

        let instrument = picker_text(&mut app);
        assert!(
            instrument.contains(crate::ui::INSTRUMENT.select.trim()),
            "instrument select marker missing:\n{instrument}"
        );
        assert!(
            instrument.contains("g glyphs") || instrument.contains(" g "),
            "glyph toggle hint missing:\n{instrument}"
        );

        press(&mut app, KeyCode::Char('g'));
        assert_eq!(app.screen, Screen::Picker);
        assert_eq!(app.glyph_pack, GlyphPack::Ascii);

        let ascii = picker_text(&mut app);
        assert!(
            ascii.contains(crate::ui::ASCII.select.trim()),
            "ascii select marker missing:\n{ascii}"
        );
        assert!(
            !ascii.contains('›'),
            "instrument caret leaked into ascii pack:\n{ascii}"
        );
        assert!(ascii.contains('+'), "ascii borders missing:\n{ascii}");

        press(&mut app, KeyCode::Char('g'));
        assert_eq!(app.glyph_pack, GlyphPack::Instrument);
        assert_eq!(app.screen, Screen::Picker);
    }

    #[test]
    fn picker_jump_keys_cover_every_tool_and_asahi_actions_are_independent() {
        let mut app = App::new();
        assert_eq!(app.screen, Screen::Picker);
        assert_eq!(Tool::ALL.len(), 4);

        for (index, tool) in Tool::ALL.iter().enumerate() {
            let digit = char::from_digit((index + 1) as u32, 10).unwrap();
            press(&mut app, KeyCode::Char(digit));
            assert_eq!(app.selected, index, "jump key {}", digit);
            assert_eq!(app.screen, screen_for(*tool), "jump key {}", digit);
            if *tool == Tool::Asahi {
                assert_eq!(app.asahi_step, AsahiStep::Menu);
            }
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.screen, Screen::Picker);
        }

        press(&mut app, KeyCode::Char('4'));
        assert_eq!(app.screen, Screen::Asahi);
        assert_eq!(app.current_tool(), Tool::Asahi);
        assert_eq!(app.asahi_step, AsahiStep::Menu);

        for target in 0..AsahiAction::ALL.len() {
            while app.screen == Screen::Asahi && app.asahi_step != AsahiStep::Menu {
                press(&mut app, KeyCode::Esc);
            }
            assert_eq!(app.screen, Screen::Asahi);
            assert_eq!(app.asahi_step, AsahiStep::Menu);
            let mut hops = 0;
            while app.asahi_action_cursor != target {
                press(&mut app, KeyCode::Down);
                hops += 1;
                assert!(
                    hops <= AsahiAction::ALL.len(),
                    "cursor did not reach {target}"
                );
            }
            assert_eq!(app.asahi_action_cursor, target);
            press(&mut app, KeyCode::Enter);
            let action = AsahiAction::ALL[target];
            assert_eq!(app.asahi_action, action);
            let expected = match action {
                AsahiAction::Update => AsahiStep::WaitFile,
                AsahiAction::Install => AsahiStep::Size,
            };
            assert_eq!(app.asahi_step, expected);
        }

        press(&mut app, KeyCode::Esc);
        assert_eq!(app.asahi_step, AsahiStep::Menu);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Picker);
    }

    #[test]
    fn picker_mouse_click_on_a_drawn_card_opens_it() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();

        let asahi_index = Tool::ALL
            .iter()
            .position(|tool| *tool == Tool::Asahi)
            .expect("Asahi is a picker slot");
        let rect = app.hits.cards[asahi_index];
        assert!(
            rect.width > 0 && rect.height > 0,
            "Asahi picker card must be hittable after draw"
        );

        app.handle_event(Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x + rect.width / 2,
            row: rect.y + rect.height / 2,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(app.selected, asahi_index);
        assert_eq!(app.screen, Screen::Asahi);
    }

    #[test]
    fn clicking_the_path_box_focuses_it() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();
        let rect = app.hits.path_box;
        assert!(
            rect.width > 0 && rect.height > 0,
            "path box must be hittable after draw"
        );
        assert!(!app.path_editing);

        app.handle_event(Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: rect.x + rect.width / 2,
            row: rect.y + rect.height / 2,
            modifiers: KeyModifiers::NONE,
        }));
        assert!(app.path_editing);

        app.handle_event(Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }));
        assert!(!app.path_editing);
    }

    #[test]
    fn create_size_slider_moves_within_bounds_then_enter_goes_to_source() {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Char('2'));
        assert_eq!(app.asahi_action, AsahiAction::Install);
        assert_eq!(app.asahi_step, AsahiStep::Size);
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_DEFAULT_GB);

        press(&mut app, KeyCode::Left);
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_DEFAULT_GB - 1);
        press(&mut app, KeyCode::Right);
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_DEFAULT_GB);

        for _ in 0..(asahi_ops::SLIDER_MAX_GB + 8) {
            press(&mut app, KeyCode::Left);
        }
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_MIN_GB);
        press(&mut app, KeyCode::Left);
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_MIN_GB);

        for _ in 0..(asahi_ops::SLIDER_MAX_GB + 8) {
            press(&mut app, KeyCode::Right);
        }
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_MAX_GB);
        press(&mut app, KeyCode::Right);
        assert_eq!(app.asahi_size_gb, asahi_ops::SLIDER_MAX_GB);

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);
        app.clip.file = None;
        app.path_input.clear();
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            app.asahi_step,
            AsahiStep::WaitFile,
            "install waits for an output folder"
        );
    }

    #[test]
    fn update_waits_for_file_and_custom_overlays_user_kernel_m1n1() {
        let dir = tempfile::tempdir().unwrap();
        let disc = dir.path().join("asahi.qcow2");
        let original = tiny_artifacts(b"-old");
        asahi_ops::create_qcow2_disc(
            &disc,
            &original,
            asahi_ops::min_disc_bytes(),
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .expect("fixture disc");

        let latest = tiny_artifacts(b"-newL");
        let user_kernel = dir.path().join("user.kernel");
        let user_m1n1 = dir.path().join("user.m1n1");
        std::fs::write(&user_kernel, b"USERKERN").unwrap();
        std::fs::write(&user_m1n1, b"USERM1N1").unwrap();

        let mut app = App::new();
        app.asahi_injected_artifacts = Some(latest.clone());

        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_action, AsahiAction::Update);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);

        app.clip.file = None;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);
        assert!(app.asahi_confirmed.is_empty());

        set_clip_path(&mut app, &disc);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        assert_eq!(
            std::fs::canonicalize(&app.asahi_confirmed).unwrap(),
            std::fs::canonicalize(&disc).unwrap()
        );

        press(&mut app, KeyCode::Down);
        assert_eq!(app.asahi_source_cursor, 1);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_source, AsahiSource::Custom);
        assert_eq!(app.asahi_step, AsahiStep::WaitKernel);

        set_clip_path(&mut app, &user_kernel);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitM1n1);
        assert_eq!(
            std::fs::canonicalize(&app.asahi_kernel).unwrap(),
            std::fs::canonicalize(&user_kernel).unwrap()
        );

        set_clip_path(&mut app, &user_m1n1);
        press(&mut app, KeyCode::Enter);
        app.drain_asahi_job();
        assert_eq!(app.asahi_step, AsahiStep::Done, "{:?}", app.asahi_error);
        assert_eq!(app.asahi_error, None);
        assert_eq!(
            std::fs::canonicalize(&app.asahi_m1n1).unwrap(),
            std::fs::canonicalize(&user_m1n1).unwrap()
        );

        let info = asahi_ops::inspect_created(&disc).expect("updated disc");
        assert!(info.has_apfs && info.has_efi && info.has_linux);
        assert!(
            info.linux_prefix.starts_with(b"ROOT-old"),
            "update replaces kernel and m1n1 only, root must stay, got {:?}",
            String::from_utf8_lossy(&info.linux_prefix)
        );

        let current = asahi_ops::read_efi_files(&disc, &["asahi/kernel", "m1n1/boot.bin"])
            .expect("read updated EFI files");
        assert_eq!(current[0], b"USERKERN");
        assert_eq!(current[1], b"USERM1N1");
    }

    #[test]
    fn install_is_independently_selectable_and_writes_asahi_layout() {
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("images");
        std::fs::create_dir_all(&out_dir).unwrap();
        let dest = out_dir.join("asahi-linux.qcow2");

        let mut app = App::new();
        app.asahi_injected_artifacts = Some(tiny_artifacts(b"-inst"));

        press(&mut app, KeyCode::Char('4'));
        assert_eq!(app.asahi_step, AsahiStep::Menu);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.asahi_action_cursor, 1);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_action, AsahiAction::Install);
        assert_eq!(app.asahi_step, AsahiStep::Size);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);

        app.clip.file = None;
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile, "folder is required");

        set_clip_path(&mut app, &out_dir);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);

        press(&mut app, KeyCode::Enter);
        app.drain_asahi_job();
        assert_eq!(app.asahi_step, AsahiStep::Done, "{:?}", app.asahi_error);
        assert_eq!(app.asahi_error, None);
        assert!(dest.exists());
        assert!(asahi_ops::qcow2_magic_is_present(&dest));

        let info = asahi_ops::inspect_created(&dest).expect("installed layout");
        assert!(info.has_apfs && info.has_efi && info.has_linux);
        assert!(info.linux_prefix.starts_with(b"ROOT-inst"));
        assert!(info.kernel_on_efi);
        assert!(info.m1n1_on_efi);
        assert!(info.custom_boot_object);
    }

    fn type_chars(app: &mut App, text: &str) {
        app.focus_path_input();
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    #[test]
    fn clipboard_confirm_requires_a_file() {
        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Path;
        assert!(app.confirm_clip_path().is_none());
    }

    #[test]
    fn typed_path_confirms_on_every_file_picker() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payload.bin");
        std::fs::write(&file, b"data").unwrap();
        let file_s = file.to_string_lossy().into_owned();
        let folder_s = dir.path().to_string_lossy().into_owned();

        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        type_chars(&mut app, &file_s);
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            std::fs::canonicalize(&app.explorer_confirmed).unwrap(),
            std::fs::canonicalize(&file).unwrap()
        );
        assert_eq!(app.explorer_phase, ExplorerPhase::Loading);
        assert!(app.path_input.is_empty());

        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Path;
        type_chars(&mut app, &file_s);
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            std::fs::canonicalize(&app.repair_confirmed).unwrap(),
            std::fs::canonicalize(&file).unwrap()
        );
        assert_eq!(app.repair_step, RepairStep::Detection);
        assert!(app.path_input.is_empty());

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);
        type_chars(&mut app, &file_s);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        assert_eq!(
            std::fs::canonicalize(&app.asahi_confirmed).unwrap(),
            std::fs::canonicalize(&file).unwrap()
        );

        press(&mut app, KeyCode::Char('2'));
        assert_eq!(app.asahi_step, AsahiStep::WaitKernel);
        type_chars(&mut app, &file_s);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitM1n1);
        assert_eq!(
            std::fs::canonicalize(&app.asahi_kernel).unwrap(),
            std::fs::canonicalize(&file).unwrap()
        );
        type_chars(&mut app, &file_s);
        assert_eq!(app.path_input, file_s);

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Char('2'));
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);
        type_chars(&mut app, &folder_s);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        assert_eq!(
            std::fs::canonicalize(&app.asahi_confirmed).unwrap(),
            std::fs::canonicalize(dir.path()).unwrap()
        );
    }

    #[test]
    fn typed_path_wins_over_clipboard_and_invalid_typed_does_not_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        let clip_file = dir.path().join("clip.bin");
        let typed_file = dir.path().join("typed.bin");
        std::fs::write(&clip_file, b"clip").unwrap();
        std::fs::write(&typed_file, b"typed").unwrap();

        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Path;
        set_clip_path(&mut app, &clip_file);
        type_chars(&mut app, &typed_file.to_string_lossy());
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            std::fs::canonicalize(&app.repair_confirmed).unwrap(),
            std::fs::canonicalize(&typed_file).unwrap()
        );

        let mut app = App::new();
        app.screen = Screen::Repair;
        app.repair_step = RepairStep::Path;
        set_clip_path(&mut app, &clip_file);
        type_chars(&mut app, "/no/such/apple-utils-picker-path");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.repair_step, RepairStep::Path);
        assert!(app.repair_confirmed.is_empty());
        assert_eq!(app.path_input, "/no/such/apple-utils-picker-path");
    }

    #[test]
    fn paste_fills_path_input_on_file_picker() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pasted.bin");
        std::fs::write(&file, b"x").unwrap();
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        app.handle_paste(&file.to_string_lossy());
        assert!(app.path_editing, "paste must focus the path box");
        assert_eq!(app.path_input, file.to_string_lossy());
        assert_eq!(
            app.clip.file.as_ref().map(|info| info.path.clone()),
            Some(std::fs::canonicalize(&file).unwrap())
        );
    }

    #[test]
    fn escape_clears_typed_path_before_leaving_file_picker() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        type_chars(&mut app, "/tmp");
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Explorer);
        assert!(app.path_input.is_empty());
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Picker);
    }

    #[test]
    fn q_quits_idle_file_picker() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        let quit = app.handle_event(key(KeyCode::Char('q')));
        assert!(quit);
        assert!(app.path_input.is_empty());
        assert!(!app.path_editing);
    }

    #[test]
    fn slash_starts_path_entry_without_tab() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        press(&mut app, KeyCode::Char('/'));
        assert!(app.path_editing);
        assert_eq!(app.path_input, "/");
        press(&mut app, KeyCode::Char('t'));
        assert_eq!(app.path_input, "/t");
    }

    #[test]
    fn q_types_into_file_picker_when_path_is_focused() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        press(&mut app, KeyCode::Tab);
        assert!(app.path_editing);
        let quit = app.handle_event(key(KeyCode::Char('q')));
        assert!(!quit);
        assert_eq!(app.path_input, "q");
    }

    #[test]
    fn idle_escape_leaves_file_picker() {
        let mut app = App::new();
        app.screen = Screen::Explorer;
        app.explorer_phase = ExplorerPhase::Path;
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Picker);
        assert!(!app.path_editing);
    }

    #[test]
    fn recovery_file_picker_types_like_asahi() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery
            .model
            .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
                id: "dev-1".into(),
                title: "Recovery Device".into(),
                detail: "iPhone".into(),
                connection: "usb".into(),
                state: DeviceState::Available,
                connected: true,
            }));
        app.recovery
            .model
            .apply_event(RecoveryEvent::ClaimAccepted {
                device_id: "dev-1".into(),
                note: None,
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
                expected_size: None,
                expected_hash: None,
                detail: None,
                required: true,
            }));
        let quit = app.handle_event(key(KeyCode::Char('q')));
        assert!(quit, "q must quit while the path box is idle");
        assert!(app.path_input.is_empty());

        press(&mut app, KeyCode::Tab);
        let quit = app.handle_event(key(KeyCode::Char('q')));
        assert!(!quit);
        assert_eq!(app.path_input, "q");
        type_chars(&mut app, "/tmp/q");
        assert_eq!(app.path_input, "q/tmp/q");
        press(&mut app, KeyCode::Esc);
        assert!(app.path_input.is_empty());
        assert!(!app.path_editing);
        assert_eq!(app.screen, Screen::Recovery);
    }

    #[test]
    fn recovery_idle_escape_leaves_when_unclaimed() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        assert_eq!(
            app.recovery.model.step(),
            crate::recovery_model::RecoveryStep::PickFile
        );
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Picker);
        assert!(!app.path_editing);
    }

    #[test]
    fn recovery_watches_clipboard_for_requests() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery
            .model
            .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
                id: "dev-1".into(),
                title: "Recovery Device".into(),
                detail: "iPhone".into(),
                connection: "127.0.0.1:9123".into(),
                state: DeviceState::Available,
                connected: true,
            }));
        app.recovery
            .model
            .apply_event(RecoveryEvent::ClaimAccepted {
                device_id: "dev-1".into(),
                note: None,
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
                expected_size: Some(SizeRange { min: 12, max: 512 }),
                expected_hash: None,
                detail: None,
                required: true,
            }));
        assert!(app.watching_clipboard());
        assert_eq!(
            app.recovery.model.step(),
            crate::recovery_model::RecoveryStep::PickFile
        );
    }

    fn pickfile_app_with_bridge() -> (App, crate::recovery_runtime::RecoveryBridge) {
        let (service, bridge) = crate::recovery_runtime::ChannelRecoveryService::pair();
        let mut app = App::with_banner_order_and_recovery(
            crate::banner::BannerOrder::sequential(),
            RecoveryRuntime::from_service(service),
        );
        app.screen = Screen::Recovery;
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
                detail: None,
                required: true,
            }));
        (app, bridge)
    }

    #[test]
    fn pasting_a_folder_does_not_search_until_enter() {
        let dir = tempfile::tempdir().unwrap();
        let (mut app, bridge) = pickfile_app_with_bridge();
        app.handle_paste(&dir.path().to_string_lossy());
        app.prepare();
        assert!(
            matches!(bridge.recv_command(), Err(TryRecvError::Empty)),
            "copying or pasting a folder must not start a search"
        );
        assert_eq!(
            app.recovery.model.step(),
            crate::recovery_model::RecoveryStep::PickFile
        );
        assert!(
            app.clip
                .file
                .as_ref()
                .is_some_and(|file| file.kind == crate::clip::FileKind::Directory)
        );

        press(&mut app, KeyCode::Enter);
        let command = bridge
            .recv_command()
            .expect("enter starts the folder search");
        match command {
            crate::recovery_runtime::RecoveryCommand::Autosearch { path, .. } => {
                assert_eq!(
                    std::path::Path::new(&path),
                    dir.path().canonicalize().unwrap().as_path()
                );
            }
            other => panic!("expected Autosearch, got {other:?}"),
        }
    }

    #[test]
    fn recovery_enter_on_queued_file_shows_work_plate() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery
            .model
            .apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
                id: "dev-1".into(),
                title: "Recovery Device".into(),
                detail: "iPhone".into(),
                connection: "usb".into(),
                state: DeviceState::Available,
                connected: true,
            }));
        app.recovery
            .model
            .apply_event(RecoveryEvent::ClaimAccepted {
                device_id: "dev-1".into(),
                note: None,
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
                expected_size: None,
                expected_hash: None,
                detail: None,
                required: true,
            }));
        app.recovery
            .model
            .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
                request_id: "os".into(),
                role: "Restore image".into(),
                preferred_name: Some("OS.dmg".into()),
                accepted_names: vec!["OS.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: None,
                expected_hash: None,
                detail: None,
                required: true,
            }));
        app.clip.set_file(crate::clip::FileInfo {
            path: "/tmp/BuildManifest.plist".into(),
            name: "BuildManifest.plist".into(),
            kind: crate::clip::FileKind::File,
            size: Some(128),
            modified: None,
        });
        assert_eq!(
            app.recovery.model.step(),
            crate::recovery_model::RecoveryStep::PickFile
        );
        app.recovery_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.recovery.model.phase, SessionPhase::Collecting);
        assert_eq!(
            app.recovery.model.step(),
            crate::recovery_model::RecoveryStep::Working
        );
        assert!(app.recovery.model.verifying.is_some());
    }

    #[test]
    fn recovery_cancel_key_drives_runtime() {
        let mut app = App::new();
        app.screen = Screen::Recovery;
        app.recovery.model.claimed_device_id = Some("dev-1".into());
        app.recovery.model.phase = SessionPhase::Running;
        app.recovery_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert_eq!(app.recovery.model.phase, SessionPhase::Cancelling);
    }

    #[test]
    fn asahi_create_latest_writes_qcow2_from_injected_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("new.qcow2");
        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Char('2'));
        assert_eq!(app.asahi_step, AsahiStep::Size);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);
        app.asahi_injected_artifacts = Some(tiny_artifacts(b"-new"));
        app.asahi_output_path = Some(out.clone());
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        press(&mut app, KeyCode::Enter);
        app.drain_asahi_job();
        assert_eq!(app.asahi_step, AsahiStep::Done, "{:?}", app.asahi_error);
        assert_eq!(app.asahi_error, None);
        assert!(asahi_ops::qcow2_magic_is_present(&out));
        let info = asahi_ops::inspect_created(&out).expect("created disc");
        assert!(info.qcow2 && info.has_apfs && info.has_efi && info.has_linux);
        assert!(info.custom_boot_object);
        assert!(info.chainload);
        assert!(info.linux_prefix.starts_with(b"ROOT-new"));
    }

    #[test]
    fn asahi_latest_picks_among_published_rootfs_flavours() {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Char('2'));
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::WaitFile);
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("min.qcow2");
        app.asahi_output_path = Some(out.clone());
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        app.asahi_injected_metadata = Some(
            r#"{
                "os_list": [
                    {"name": "Fedora Asahi Remix 44 (KDE Plasma)", "default_os_name": "Fedora KDE", "package": "https://example.test/kde.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 (GNOME)", "default_os_name": "Fedora GNOME", "package": "https://example.test/gnome.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Server", "default_os_name": "Fedora Server", "package": "https://example.test/server.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Minimal", "default_os_name": "Fedora Minimal", "package": "https://example.test/min.zip", "partitions": []}
                ]
            }"#
            .into(),
        );
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Flavor);
        assert_eq!(app.asahi_flavors.len(), 4);
        assert_eq!(app.asahi_flavors[0].slug, "kde");
        assert_eq!(app.asahi_flavors[3].slug, "minimal");
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.asahi_flavor_cursor, 3);
        app.asahi_injected_artifacts = Some(tiny_artifacts(b"-min"));
        press(&mut app, KeyCode::Enter);
        app.drain_asahi_job();
        assert_eq!(app.asahi_os_query, "minimal");
        assert_eq!(app.asahi_step, AsahiStep::Done, "{:?}", app.asahi_error);
        assert_eq!(app.asahi_error, None);
        let info = asahi_ops::inspect_created(&out).expect("minimal disc");
        assert!(info.linux_prefix.starts_with(b"ROOT-min"));
    }

    fn flavored_installer_json() -> String {
        r#"{
                "os_list": [
                    {"name": "Fedora Asahi Remix 44 (KDE Plasma)", "default_os_name": "Fedora KDE", "package": "https://example.test/kde.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 (GNOME)", "default_os_name": "Fedora GNOME", "package": "https://example.test/gnome.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Server", "default_os_name": "Fedora Server", "package": "https://example.test/server.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Minimal", "default_os_name": "Fedora Minimal", "package": "https://example.test/min.zip", "partitions": []}
                ]
            }"#
        .into()
    }

    fn asahi_flavor_list(app: &mut App) {
        press(app, KeyCode::Char('4'));
        press(app, KeyCode::Char('2'));
        press(app, KeyCode::Enter);
        app.asahi_output_path = Some(tempfile::tempdir().unwrap().path().join("asahi.qcow2"));
        press(app, KeyCode::Enter);
        app.asahi_injected_metadata = Some(flavored_installer_json());
        press(app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Flavor);
    }

    fn move_asahi_pointer(app: &mut App, col: u16, row: u16) {
        app.handle_event(Event::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: col,
            row,
            modifiers: KeyModifiers::NONE,
        }));
    }

    #[test]
    fn down_to_gnome_is_not_stolen_by_a_parked_pointer_on_kde() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        asahi_flavor_list(&mut app);
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();

        let kde = app.hits.asahi_flavors[0];
        let gnome = app.hits.asahi_flavors[1];
        assert!(kde.width > 0 && gnome.width > 0);
        move_asahi_pointer(&mut app, kde.x + 1, kde.y + 1);
        assert_eq!(app.asahi_flavor_cursor, 0);

        press(&mut app, KeyCode::Down);
        assert_eq!(app.asahi_flavors[app.asahi_flavor_cursor].slug, "gnome");
        move_asahi_pointer(&mut app, kde.x + 1, kde.y + 1);
        assert_eq!(
            app.asahi_flavors[app.asahi_flavor_cursor].slug, "gnome",
            "a parked pointer on KDE must not snap the keyboard selection back"
        );
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.asahi_flavor_cursor, 3,
            "Down must stop on the last flavour"
        );
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.asahi_flavors[app.asahi_flavor_cursor].slug, "gnome");

        move_asahi_pointer(&mut app, gnome.x + 1, gnome.y + 1);
        assert_eq!(app.asahi_flavors[app.asahi_flavor_cursor].slug, "gnome");

        let dir = tempfile::tempdir().unwrap();
        app.asahi_output_path = Some(dir.path().join("gnome.qcow2"));
        app.asahi_injected_artifacts = Some(tiny_artifacts(b"-gnm"));
        press(&mut app, KeyCode::Enter);
        app.drain_asahi_job();
        assert_eq!(app.asahi_os_query, "gnome");
        assert_eq!(app.asahi_step, AsahiStep::Done, "{:?}", app.asahi_error);
    }

    #[test]
    fn moving_the_pointer_onto_another_flavour_takes_over_from_keys() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        asahi_flavor_list(&mut app);
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();
        let kde = app.hits.asahi_flavors[0];
        let server = app.hits.asahi_flavors[2];
        move_asahi_pointer(&mut app, kde.x + 1, kde.y + 1);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.asahi_flavors[app.asahi_flavor_cursor].slug, "gnome");
        move_asahi_pointer(&mut app, server.x + 1, server.y + 1);
        assert_eq!(app.asahi_flavors[app.asahi_flavor_cursor].slug, "server");
    }

    #[test]
    fn latest_catalogue_fetch_shows_progress_and_ignores_enter() {
        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Char('2'));
        press(&mut app, KeyCode::Enter);
        let dir = tempfile::tempdir().unwrap();
        app.asahi_output_path = Some(dir.path().join("asahi.qcow2"));
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.asahi_step, AsahiStep::Work);
        assert_eq!(app.asahi_status, "fetching catalogue");
        assert_eq!(app.asahi_progress, Some(0.0));
        assert!(app.asahi_catalog_pending);
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(
            app.asahi_step,
            AsahiStep::Work,
            "Enter during catalogue fetch must not confirm a flavour"
        );
        assert!(app.asahi_os_query.is_empty());
        assert!(app.asahi_flavors.is_empty());
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.asahi_step, AsahiStep::Source);
        assert!(!app.asahi_catalog_pending);
    }

    #[test]
    fn catalogue_result_opens_the_flavour_list_instead_of_the_first_os() {
        let json = r#"{
                "os_list": [
                    {"name": "Fedora Asahi Remix 44 (KDE Plasma)", "default_os_name": "Fedora KDE", "package": "https://example.test/kde.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 (GNOME)", "default_os_name": "Fedora GNOME", "package": "https://example.test/gnome.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Server", "default_os_name": "Fedora Server", "package": "https://example.test/server.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Minimal", "default_os_name": "Fedora Minimal", "package": "https://example.test/min.zip", "partitions": []}
                ]
            }"#;
        let data = parse_installer_data(json).unwrap();
        let flavors = asahi_ops::list_installable_flavors(&data);
        assert_eq!(flavors.len(), 4);

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        press(&mut app, KeyCode::Char('2'));
        app.asahi_action = AsahiAction::Install;
        app.asahi_step = AsahiStep::Work;
        app.asahi_status = "fetching catalogue".into();
        app.asahi_progress = Some(0.2);
        app.asahi_catalog_pending = true;
        let (tx, rx) = std::sync::mpsc::channel();
        app.asahi_job_rx = Some(rx);
        tx.send(AsahiJobEvent::Catalog(Ok((json.to_string(), flavors))))
            .unwrap();
        app.prepare();
        assert_eq!(app.asahi_step, AsahiStep::Flavor);
        assert_eq!(app.asahi_flavors.len(), 4);
        assert_eq!(app.asahi_flavor_cursor, 0);
        assert!(app.asahi_os_query.is_empty());
        assert!(!app.asahi_catalog_pending);
        let dir = tempfile::tempdir().unwrap();
        app.asahi_output_path = Some(dir.path().join("asahi.qcow2"));
        app.asahi_injected_artifacts = Some(tiny_artifacts(b"-cat"));
        press(&mut app, KeyCode::Enter);
        app.drain_asahi_job();
        assert_eq!(app.asahi_os_query, "kde");
        assert_eq!(app.asahi_step, AsahiStep::Done, "{:?}", app.asahi_error);
        assert_eq!(app.asahi_error, None);
    }

    #[test]
    fn catalogue_fetch_work_screen_shows_the_stage_and_fill() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        app.asahi_step = AsahiStep::Work;
        app.asahi_action = AsahiAction::Install;
        app.asahi_status = "fetching catalogue".into();
        app.asahi_progress = Some(0.37);
        app.asahi_catalog_pending = true;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[ratatui::layout::Position::new(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(
            text.contains("fetching catalogue"),
            "catalogue stage must be the headline, got:\n{text}"
        );
        assert!(
            text.contains("37%"),
            "catalogue percent must be visible, got:\n{text}"
        );
        assert!(!text.contains("Latest"));
        assert!(!text.contains("Fedora"));
    }

    #[test]
    fn asahi_menu_hovers_the_card_under_the_pointer() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();

        let rect = app.hits.asahi_actions[1];
        assert!(rect.width > 0 && rect.height > 0);
        app.handle_event(Event::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: rect.x + 1,
            row: rect.y + 1,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(app.asahi_action_cursor, 1);

        let update = app.hits.asahi_actions[0];
        app.handle_event(Event::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: update.x + 1,
            row: update.y + 1,
            modifiers: KeyModifiers::NONE,
        }));
        assert_eq!(app.asahi_action_cursor, 0);
    }

    #[test]
    fn asahi_work_screen_shows_waiting_progress_instead_of_the_menu() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        app.asahi_step = AsahiStep::Work;
        app.asahi_action = AsahiAction::Install;
        app.asahi_status = "downloading package".into();
        app.asahi_progress = Some(0.45);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[ratatui::layout::Position::new(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(
            text.contains("downloading package"),
            "work screen must show the stage name, got:\n{text}"
        );
        assert!(
            !text.contains("Waiting for download"),
            "waiting headline must not replace the stage, got:\n{text}"
        );
        assert!(
            text.contains("45%"),
            "download percent must be visible, got:\n{text}"
        );
        assert!(!text.contains("Update Asahi Linux"));
        assert!(!text.contains("Install Asahi"));
    }

    #[test]
    fn asahi_menu_shows_update_and_install_only() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = App::new();
        press(&mut app, KeyCode::Char('4'));
        let backend = TestBackend::new(100, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::ui::render(frame, &mut app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[ratatui::layout::Position::new(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("Update Asahi Linux"));
        assert!(text.contains("Install Asahi"));
        assert!(
            !text.contains("Create a new disc"),
            "install and create are the same TUI action, got:\n{text}"
        );
        assert_eq!(AsahiAction::ALL.len(), 2);
        assert_eq!(
            app.hits
                .asahi_actions
                .iter()
                .filter(|r| r.width > 0 && r.height > 0)
                .count(),
            2
        );
    }
}
