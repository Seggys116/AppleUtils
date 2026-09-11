use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use ratatui::layout::Rect;

use crate::clip::{FileInfo, FileKind, format_size, inspect};
use crate::ramrod::BUILD_MANIFEST_FILE_NAME;

const MAX_LOG_ENTRIES: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFocus {
    Devices,
    Requests,
    Events,
}

impl RecoveryFocus {
    pub const ALL: [RecoveryFocus; 3] = [
        RecoveryFocus::Devices,
        RecoveryFocus::Requests,
        RecoveryFocus::Events,
    ];

    pub fn next(self) -> Self {
        match self {
            RecoveryFocus::Devices => RecoveryFocus::Requests,
            RecoveryFocus::Requests => RecoveryFocus::Events,
            RecoveryFocus::Events => RecoveryFocus::Devices,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            RecoveryFocus::Devices => RecoveryFocus::Events,
            RecoveryFocus::Requests => RecoveryFocus::Devices,
            RecoveryFocus::Events => RecoveryFocus::Requests,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStep {
    WaitDevices,
    PickSystem,
    PickMode,
    PickDevice,
    Claiming,
    WaitRequest,
    PickFile,
    Working,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Claim,
    Attach,
    Autosearch,
    Start,
    Cancel,
    Retry,
    Release,
}

#[derive(Debug, Clone, Default)]
pub struct RecoveryHitMap {
    pub device_rows: Vec<Rect>,
    pub request_rows: Vec<Rect>,
    pub actions: Vec<(RecoveryAction, Rect)>,
    pub devices_pane: Rect,
    pub requests_pane: Rect,
    pub events_pane: Rect,
    pub handoff: Rect,
}

impl RecoveryHitMap {
    pub fn clear(&mut self) {
        self.device_rows.clear();
        self.request_rows.clear();
        self.actions.clear();
        self.devices_pane = Rect::default();
        self.requests_pane = Rect::default();
        self.events_pane = Rect::default();
        self.handoff = Rect::default();
    }

    pub fn device_at(&self, col: u16, row: u16) -> Option<usize> {
        hit_index(&self.device_rows, col, row)
    }

    pub fn request_at(&self, col: u16, row: u16) -> Option<usize> {
        hit_index(&self.request_rows, col, row)
    }

    pub fn action_at(&self, col: u16, row: u16) -> Option<RecoveryAction> {
        self.actions
            .iter()
            .find(|(_, rect)| contains(rect, col, row))
            .map(|(action, _)| *action)
    }

    pub fn handoff_at(&self, col: u16, row: u16) -> bool {
        contains(&self.handoff, col, row)
    }

    pub fn pane_at(&self, col: u16, row: u16) -> Option<RecoveryFocus> {
        if contains(&self.devices_pane, col, row) {
            Some(RecoveryFocus::Devices)
        } else if contains(&self.requests_pane, col, row) || contains(&self.handoff, col, row) {
            Some(RecoveryFocus::Requests)
        } else if contains(&self.events_pane, col, row) {
            Some(RecoveryFocus::Events)
        } else {
            None
        }
    }
}

fn hit_index(rows: &[Rect], col: u16, row: u16) -> Option<usize> {
    rows.iter().position(|rect| contains(rect, col, row))
}

fn contains(rect: &Rect, col: u16, row: u16) -> bool {
    rect.width > 0
        && rect.height > 0
        && col >= rect.x
        && col < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Available,
    Claiming,
    Claimed,
    Busy,
    Disconnected,
}

impl DeviceState {
    pub fn label(self) -> &'static str {
        match self {
            DeviceState::Available => "available",
            DeviceState::Claiming => "claiming",
            DeviceState::Claimed => "claimed",
            DeviceState::Busy => "running",
            DeviceState::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDevice {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub connection: String,
    pub state: DeviceState,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibleSystem {
    pub class: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMode {
    Update,
    Erase,
}

impl RestoreMode {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Update => "Update",
            Self::Erase => "Erase",
        }
    }

    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "Update" | "Upgrade" => Some(Self::Update),
            "Erase" => Some(Self::Erase),
            _ => None,
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Update => "Upgrade",
            Self::Erase => "Erase",
        }
    }

    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::Update => "Keep files and settings",
            Self::Erase => "Wipe the Mac and install",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeRange {
    pub min: u64,
    pub max: u64,
}

impl SizeRange {
    pub fn label(self) -> String {
        if self.min == self.max {
            format_size(self.min)
        } else {
            format!("{} to {}", format_size(self.min), format_size(self.max))
        }
    }

    pub fn contains(self, bytes: u64) -> bool {
        bytes >= self.min && bytes <= self.max
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashExpectation {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequestSpec {
    pub request_id: String,
    pub role: String,
    pub preferred_name: Option<String>,
    pub accepted_names: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub accept_directory: bool,
    pub expected_size: Option<SizeRange>,
    pub expected_hash: Option<HashExpectation>,
    pub detail: Option<String>,
    pub required: bool,
}

impl FileRequestSpec {
    pub fn title(&self) -> &str {
        self.preferred_name.as_deref().unwrap_or(self.role.as_str())
    }

    pub fn expectation_label(&self) -> String {
        if !self.accepted_names.is_empty() {
            self.accepted_names.join(", ")
        } else if let Some(name) = &self.preferred_name {
            name.clone()
        } else if !self.allowed_extensions.is_empty() {
            self.allowed_extensions
                .iter()
                .map(|ext| format!(".{ext}"))
                .collect::<Vec<_>>()
                .join(", ")
        } else if self.accept_directory {
            format!("{} folder", self.role)
        } else {
            self.role.clone()
        }
    }

    pub fn matches_name(&self, name: &str) -> bool {
        let eq = |expected: &str| {
            expected.eq_ignore_ascii_case(name) || payload_names_compatible(name, expected)
        };
        self.preferred_name.as_deref().is_some_and(eq)
            || self.accepted_names.iter().any(|item| eq(item))
    }

    pub fn matches_extension(&self, file: &FileInfo) -> bool {
        if self.allowed_extensions.is_empty() {
            return true;
        }
        let Some(ext) = file_extension(&file.path) else {
            return false;
        };
        if self
            .allowed_extensions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&ext))
        {
            return true;
        }
        let dmg = ext.eq_ignore_ascii_case("dmg");
        let aea = ext.eq_ignore_ascii_case("aea");
        (dmg && self.allows_extension("aea")) || (aea && self.allows_extension("dmg"))
    }

    fn allows_extension(&self, ext: &str) -> bool {
        self.allowed_extensions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(ext))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffPreview {
    pub headline: String,
    pub body: String,
    pub hint: String,
    pub ok: bool,
}

#[derive(Debug, Clone)]
pub enum RequestResolution {
    Missing,
    Submitted {
        file: FileInfo,
        note: String,
    },
    Accepted {
        file: FileInfo,
        note: String,
    },
    Rejected {
        file: Option<FileInfo>,
        reason: String,
    },
}

impl RequestResolution {
    pub fn label(&self) -> &'static str {
        match self {
            RequestResolution::Missing => "missing",
            RequestResolution::Submitted { .. } => "queued",
            RequestResolution::Accepted { .. } => "ready",
            RequestResolution::Rejected { .. } => "rejected",
        }
    }

    pub fn file(&self) -> Option<&FileInfo> {
        match self {
            RequestResolution::Submitted { file, .. } => Some(file),
            RequestResolution::Accepted { file, .. } => Some(file),
            RequestResolution::Rejected {
                file: Some(file), ..
            } => Some(file),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileRequestState {
    pub spec: FileRequestSpec,
    pub resolution: RequestResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryLogEntry {
    pub index: u64,
    pub level: LogLevel,
    pub message: String,
    pub repeats: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Waiting,
    Claiming,
    Collecting,
    Ready,
    Starting,
    Running,
    Cancelling,
    Cancelled,
    Succeeded,
    Failed,
}

impl SessionPhase {
    pub fn label(self) -> &'static str {
        match self {
            SessionPhase::Waiting => "waiting",
            SessionPhase::Claiming => "claiming",
            SessionPhase::Collecting => "collecting files",
            SessionPhase::Ready => "ready",
            SessionPhase::Starting => "starting",
            SessionPhase::Running => "running",
            SessionPhase::Cancelling => "cancelling",
            SessionPhase::Cancelled => "cancelled",
            SessionPhase::Succeeded => "completed",
            SessionPhase::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RestoreProgress {
    pub stage: String,
    pub detail: String,
    pub fraction: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct RecoveryModel {
    pub focus: RecoveryFocus,
    pub devices: Vec<RecoveryDevice>,
    pub device_cursor: usize,
    pub requests: Vec<FileRequestState>,
    pub request_cursor: usize,
    pub claimed_device_id: Option<String>,
    pub phase: SessionPhase,
    pub progress: Option<RestoreProgress>,
    pub status_message: String,
    pub logs: VecDeque<RecoveryLogEntry>,
    pub next_log_index: u64,
    pub last_error: Option<String>,
    pub verifying: Option<RestoreProgress>,
    pub compatible_systems: Vec<CompatibleSystem>,
    pub selected_system: Option<String>,
    pub system_cursor: usize,
    pub compatible_modes: Vec<RestoreMode>,
    pub selected_mode: Option<RestoreMode>,
    pub mode_cursor: usize,
    pub product_version: Option<String>,
    pub product_build: Option<String>,
    pub event_cursor: usize,
    pub device_page_rows: usize,
    pub request_page_rows: usize,
    pub event_page_rows: usize,
    pub hits: RecoveryHitMap,
}

impl Default for RecoveryModel {
    fn default() -> Self {
        let mut model = Self {
            focus: RecoveryFocus::Devices,
            devices: Vec::new(),
            device_cursor: 0,
            requests: Vec::new(),
            request_cursor: 0,
            claimed_device_id: None,
            phase: SessionPhase::Waiting,
            progress: None,
            status_message: "Watching for connected devices".into(),
            logs: VecDeque::new(),
            next_log_index: 1,
            last_error: None,
            verifying: None,
            compatible_systems: Vec::new(),
            selected_system: None,
            system_cursor: 0,
            compatible_modes: Vec::new(),
            selected_mode: None,
            mode_cursor: 0,
            product_version: None,
            product_build: None,
            event_cursor: 0,
            device_page_rows: 0,
            request_page_rows: 0,
            event_page_rows: 0,
            hits: RecoveryHitMap::default(),
        };
        model.push_log(LogLevel::Info, "Recovery monitor online");
        model
    }
}

pub fn initial_manifest_request() -> FileRequestSpec {
    FileRequestSpec {
        request_id: "build-manifest".into(),
        role: "BuildManifest".into(),
        preferred_name: Some("BuildManifest.plist".into()),
        accepted_names: vec!["BuildManifest.plist".into(), "Restore.plist".into()],
        allowed_extensions: vec!["plist".into()],
        accept_directory: false,
        expected_size: None,
        expected_hash: None,
        detail: Some(
            "Select BuildManifest.plist, Restore.plist, or the extracted restore folder.".into(),
        ),
        required: true,
    }
}

impl RecoveryModel {
    pub fn selected_device(&self) -> Option<&RecoveryDevice> {
        self.devices.get(self.device_cursor)
    }

    pub fn selected_request(&self) -> Option<&FileRequestState> {
        self.requests.get(self.request_cursor)
    }

    pub fn clear_hits(&mut self) {
        self.hits.clear();
    }

    pub fn device_count_label(&self) -> String {
        let connected = self
            .devices
            .iter()
            .filter(|device| device.connected)
            .count();
        format!(
            "{connected} device{}",
            if connected == 1 { "" } else { "s" }
        )
    }

    pub fn has_clipboard_target(&self) -> bool {
        self.step() == RecoveryStep::PickFile
    }

    pub fn wait_progress(&self) -> Option<&RestoreProgress> {
        self.verifying.as_ref().or(self.progress.as_ref())
    }

    pub fn step(&self) -> RecoveryStep {
        if self.verifying.is_some() {
            return RecoveryStep::Working;
        }
        match self.phase {
            SessionPhase::Claiming => RecoveryStep::Claiming,
            SessionPhase::Starting | SessionPhase::Running | SessionPhase::Cancelling => {
                RecoveryStep::Working
            }
            SessionPhase::Succeeded | SessionPhase::Failed | SessionPhase::Cancelled => {
                RecoveryStep::Done
            }
            SessionPhase::Waiting | SessionPhase::Collecting | SessionPhase::Ready => {
                if self.next_open_request().is_some() {
                    RecoveryStep::PickFile
                } else if self.selected_system.is_none() && !self.compatible_systems.is_empty() {
                    RecoveryStep::PickSystem
                } else if self.selected_mode.is_none() && !self.compatible_modes.is_empty() {
                    RecoveryStep::PickMode
                } else if self.claimed_device_id.is_some() {
                    RecoveryStep::WaitRequest
                } else if self.devices.iter().any(|device| device.connected) {
                    RecoveryStep::PickDevice
                } else {
                    RecoveryStep::WaitDevices
                }
            }
        }
    }

    pub fn next_open_request(&self) -> Option<usize> {
        let required_missing = self.requests.iter().position(|request| {
            request.spec.required && matches!(request.resolution, RequestResolution::Missing)
        });
        if required_missing.is_some() {
            return required_missing;
        }
        let required_rejected = self.requests.iter().position(|request| {
            request.spec.required
                && matches!(request.resolution, RequestResolution::Rejected { .. })
        });
        if required_rejected.is_some() {
            return required_rejected;
        }
        self.requests.iter().position(|request| {
            matches!(
                request.resolution,
                RequestResolution::Missing | RequestResolution::Rejected { .. }
            )
        })
    }

    pub fn focus_open_request(&mut self) {
        if let Some(index) = self.next_open_request() {
            self.select_request(index);
        }
    }

    pub fn picker_title(&self) -> String {
        let Some(request) = self
            .next_open_request()
            .and_then(|index| self.requests.get(index))
        else {
            return "file".into();
        };
        let total = self.requests.len().max(1);
        let index = self.next_open_request().unwrap_or(0) + 1;
        format!("{}  ({index}/{total})", request.spec.title())
    }

    pub fn files_ready_label(&self) -> String {
        let ready = self
            .requests
            .iter()
            .filter(|request| {
                matches!(
                    request.resolution,
                    RequestResolution::Submitted { .. } | RequestResolution::Accepted { .. }
                )
            })
            .count();
        let total = self.requests.len();
        if total == 0 {
            "no file requests".into()
        } else {
            format!("{ready} of {total} files ready")
        }
    }

    pub fn primary_action(&self) -> Option<RecoveryAction> {
        if self.can_start() {
            Some(RecoveryAction::Start)
        } else if self.can_attach() {
            Some(RecoveryAction::Attach)
        } else if self.can_claim() {
            Some(RecoveryAction::Claim)
        } else if self.can_retry() {
            Some(RecoveryAction::Retry)
        } else if self.can_cancel() {
            Some(RecoveryAction::Cancel)
        } else if self.can_release() {
            Some(RecoveryAction::Release)
        } else {
            None
        }
    }

    pub fn all_required_files_supplied(&self) -> bool {
        self.requests.iter().all(|request| {
            !request.spec.required
                || matches!(
                    request.resolution,
                    RequestResolution::Submitted { .. } | RequestResolution::Accepted { .. }
                )
        })
    }

    pub fn can_claim(&self) -> bool {
        self.claimed_device_id.is_none()
            && self
                .selected_device()
                .is_some_and(|device| device.connected && device.state == DeviceState::Available)
    }

    pub fn can_release(&self) -> bool {
        self.claimed_device_id.is_some()
            && !matches!(
                self.phase,
                SessionPhase::Starting | SessionPhase::Running | SessionPhase::Cancelling
            )
    }

    pub fn can_attach(&self) -> bool {
        self.selected_request().is_some()
            && !matches!(
                self.phase,
                SessionPhase::Running
                    | SessionPhase::Starting
                    | SessionPhase::Cancelling
                    | SessionPhase::Succeeded
            )
    }

    pub fn can_autosearch(&self) -> bool {
        self.can_attach() && (self.selected_system.is_some() || !self.compatible_systems.is_empty())
    }

    pub fn can_start(&self) -> bool {
        self.claimed_device_id.is_some()
            && self.all_required_files_supplied()
            && matches!(
                self.phase,
                SessionPhase::Collecting
                    | SessionPhase::Ready
                    | SessionPhase::Cancelled
                    | SessionPhase::Failed
            )
    }

    pub fn can_cancel(&self) -> bool {
        matches!(
            self.phase,
            SessionPhase::Claiming
                | SessionPhase::Starting
                | SessionPhase::Running
                | SessionPhase::Collecting
        ) && self.claimed_device_id.is_some()
    }

    pub fn can_retry(&self) -> bool {
        matches!(self.phase, SessionPhase::Cancelled | SessionPhase::Failed)
            && self.claimed_device_id.is_some()
    }

    pub fn action_enabled(&self, action: RecoveryAction) -> bool {
        match action {
            RecoveryAction::Claim => self.can_claim(),
            RecoveryAction::Attach => self.can_attach(),
            RecoveryAction::Autosearch => self.can_autosearch(),
            RecoveryAction::Start => self.can_start(),
            RecoveryAction::Cancel => self.can_cancel(),
            RecoveryAction::Retry => self.can_retry(),
            RecoveryAction::Release => self.can_release(),
        }
    }

    pub fn focus_next(&mut self) {
        self.focus = self.focus.next();
    }

    pub fn focus_prev(&mut self) {
        self.focus = self.focus.prev();
    }

    pub fn move_up(&mut self) {
        match self.focus {
            RecoveryFocus::Devices => {
                if !self.devices.is_empty() {
                    self.device_cursor = self.device_cursor.saturating_sub(1);
                }
            }
            RecoveryFocus::Requests => {
                if !self.requests.is_empty() {
                    self.request_cursor = self.request_cursor.saturating_sub(1);
                }
            }
            RecoveryFocus::Events => self.move_event(-1),
        }
    }

    pub fn move_down(&mut self) {
        match self.focus {
            RecoveryFocus::Devices => {
                if !self.devices.is_empty() {
                    self.device_cursor = (self.device_cursor + 1).min(self.devices.len() - 1);
                }
            }
            RecoveryFocus::Requests => {
                if !self.requests.is_empty() {
                    self.request_cursor = (self.request_cursor + 1).min(self.requests.len() - 1);
                }
            }
            RecoveryFocus::Events => self.move_event(1),
        }
    }

    pub fn page(&mut self, delta: i32) {
        let steps = match self.focus {
            RecoveryFocus::Devices => self.device_page_rows.max(1),
            RecoveryFocus::Requests => self.request_page_rows.max(1),
            RecoveryFocus::Events => self.event_page_rows.max(1),
        } as i32;
        for _ in 0..steps {
            if delta < 0 {
                self.move_up();
            } else {
                self.move_down();
            }
        }
    }

    fn move_event(&mut self, delta: i32) {
        if self.logs.is_empty() {
            self.event_cursor = 0;
            return;
        }
        let max = self.logs.len() - 1;
        self.event_cursor = if delta < 0 {
            self.event_cursor.saturating_sub(1)
        } else {
            (self.event_cursor + 1).min(max)
        };
    }

    pub fn select_device(&mut self, index: usize) {
        if self.devices.get(index).is_some() {
            self.focus = RecoveryFocus::Devices;
            self.device_cursor = index;
        }
    }

    pub fn move_system_cursor(&mut self, delta: i32) {
        let n = self.compatible_systems.len();
        if n == 0 {
            self.system_cursor = 0;
            return;
        }
        let last = n - 1;
        if delta < 0 {
            self.system_cursor = self
                .system_cursor
                .saturating_sub(delta.unsigned_abs() as usize);
        } else {
            self.system_cursor = self.system_cursor.saturating_add(delta as usize).min(last);
        }
    }

    pub fn selected_system_class(&self) -> Option<&str> {
        self.compatible_systems
            .get(self.system_cursor)
            .map(|system| system.class.as_str())
    }

    pub fn selected_system_label(&self) -> Option<&CompatibleSystem> {
        let class = self.selected_system.as_deref()?;
        self.compatible_systems
            .iter()
            .find(|system| system.class.eq_ignore_ascii_case(class))
            .or_else(|| self.compatible_systems.get(self.system_cursor))
    }

    pub fn move_mode_cursor(&mut self, delta: i32) {
        let n = self.compatible_modes.len();
        if n == 0 {
            self.mode_cursor = 0;
            return;
        }
        let last = n - 1;
        if delta < 0 {
            self.mode_cursor = self
                .mode_cursor
                .saturating_sub(delta.unsigned_abs() as usize);
        } else {
            self.mode_cursor = self.mode_cursor.saturating_add(delta as usize).min(last);
        }
    }

    pub fn selected_restore_mode(&self) -> Option<RestoreMode> {
        self.compatible_modes.get(self.mode_cursor).copied()
    }

    pub fn catalog_label(&self) -> Option<String> {
        match (&self.product_version, &self.product_build) {
            (Some(version), Some(build)) => Some(format!("macOS {version} ({build})")),
            (Some(version), None) => Some(format!("macOS {version}")),
            (None, Some(build)) => Some(build.clone()),
            (None, None) => None,
        }
    }

    pub fn clear_restore_mode_choice(&mut self) {
        self.selected_system = None;
        self.selected_mode = None;
        self.compatible_modes.clear();
        self.mode_cursor = 0;
        self.verifying = None;
        self.last_error = None;
        self.status_message = "Choose a system".into();
    }

    pub fn select_request(&mut self, index: usize) {
        if self.requests.get(index).is_some() {
            self.focus = RecoveryFocus::Requests;
            self.request_cursor = index;
        }
    }

    pub fn click_action(&mut self, action: RecoveryAction) {
        match action {
            RecoveryAction::Claim => self.focus = RecoveryFocus::Devices,
            RecoveryAction::Attach | RecoveryAction::Autosearch => {
                self.focus = RecoveryFocus::Requests
            }
            RecoveryAction::Start | RecoveryAction::Cancel | RecoveryAction::Retry => {
                self.focus = RecoveryFocus::Requests
            }
            RecoveryAction::Release => self.focus = RecoveryFocus::Devices,
        }
    }

    pub fn describe_focus(&self) -> &'static str {
        match self.focus {
            RecoveryFocus::Devices => "devices",
            RecoveryFocus::Requests => "requests",
            RecoveryFocus::Events => "events",
        }
    }

    pub fn note_clipboard_assignment(&mut self, file: &FileInfo, note: String) {
        if let Some(request) = self.requests.get_mut(self.request_cursor) {
            request.resolution = RequestResolution::Submitted {
                file: file.clone(),
                note,
            };
        }
        self.verifying = Some(RestoreProgress {
            stage: "checking".into(),
            detail: String::new(),
            fraction: Some(0.0),
        });
        self.status_message = "checking".into();
    }

    pub fn reject_clipboard_assignment(&mut self, file: FileInfo, reason: String) {
        self.verifying = None;
        if let Some(request) = self.requests.get_mut(self.request_cursor) {
            request.resolution = RequestResolution::Rejected {
                file: Some(file),
                reason: reason.clone(),
            };
            self.last_error = Some(reason.clone());
            self.push_log(LogLevel::Warn, reason);
        }
    }

    pub fn validate_request(&self, file: &FileInfo) -> Result<String, String> {
        self.match_handoff(file).map(|(_, _, note)| note)
    }

    pub fn match_handoff(&self, file: &FileInfo) -> Result<(usize, FileInfo, String), String> {
        if self.requests.is_empty() {
            return Err("No file has been requested yet".into());
        }

        let mut selected_error = None;
        if self.requests.get(self.request_cursor).is_some() {
            match self.try_handoff(self.request_cursor, file) {
                Ok(ok) => return Ok(ok),
                Err(error) => selected_error = Some(error),
            }
        }

        for index in 0..self.requests.len() {
            if index == self.request_cursor {
                continue;
            }
            let occupied = matches!(
                self.requests[index].resolution,
                RequestResolution::Submitted { .. } | RequestResolution::Accepted { .. }
            );
            if occupied {
                continue;
            }
            if let Ok(ok) = self.try_handoff(index, file) {
                return Ok(ok);
            }
        }

        Err(selected_error.unwrap_or_else(|| mismatch_summary(&self.requests, file)))
    }

    pub fn match_all_handoffs(
        &self,
        file: &FileInfo,
    ) -> Result<Vec<(usize, FileInfo, String)>, String> {
        let file = follow_if_link(file);
        if effective_kind(&file) != FileKind::Directory {
            return self.match_handoff(&file).map(|hit| vec![hit]);
        }

        let mut order = Vec::with_capacity(self.requests.len());
        if self.requests.get(self.request_cursor).is_some() {
            order.push(self.request_cursor);
        }
        for index in 0..self.requests.len() {
            if index != self.request_cursor {
                order.push(index);
            }
        }

        let mut hits = Vec::new();
        let mut used = HashSet::new();
        for index in order {
            let occupied = matches!(
                self.requests[index].resolution,
                RequestResolution::Submitted { .. } | RequestResolution::Accepted { .. }
            );
            if occupied {
                continue;
            }
            let Ok((_, resolved, note)) = self.try_handoff(index, &file) else {
                continue;
            };
            if !used.insert(resolved.path.clone()) {
                continue;
            }
            hits.push((index, resolved, note));
        }
        if hits.is_empty() {
            return Err(mismatch_summary(&self.requests, &file));
        }
        Ok(hits)
    }

    fn try_handoff(
        &self,
        index: usize,
        file: &FileInfo,
    ) -> Result<(usize, FileInfo, String), String> {
        let spec = &self.requests[index].spec;
        let resolved = resolve_handoff(file, spec)?;
        if let Some(size) = spec.expected_size {
            let bytes = resolved
                .size
                .ok_or_else(|| format!("{} size could not be read", resolved.name))?;
            if !size.contains(bytes) {
                return Err(format!(
                    "{} expects {} (got {})",
                    spec.role,
                    size.label(),
                    format_size(bytes)
                ));
            }
        }
        let hash_note = spec
            .expected_hash
            .as_ref()
            .map(|hash| format!("{} {}", hash.algorithm, abbreviate(&hash.value, 14)))
            .unwrap_or_else(|| "no hash gate".into());
        let note = if resolved.path == file.path {
            format!("queued {}, hash check: {hash_note}", resolved.name)
        } else {
            format!(
                "queued {} from {}, hash check: {hash_note}",
                resolved.name, file.name
            )
        };
        Ok((index, resolved, note))
    }

    pub fn describe_handoff(&self, file: Option<&FileInfo>) -> HandoffPreview {
        let Some(request) = self.selected_request() else {
            return HandoffPreview {
                headline: "No file requested".into(),
                body: "Claim a device and wait for the coordinator to ask for files.".into(),
                hint: String::new(),
                ok: false,
            };
        };
        let expected = request.spec.expectation_label();
        match file {
            None => HandoffPreview {
                headline: format!("Needs {expected}"),
                body: request.spec.detail.clone().unwrap_or_else(|| {
                    "Type the file path, or a folder that holds the remaining restore files.".into()
                }),
                hint: "enter attaches the clipboard or typed path".into(),
                ok: false,
            },
            Some(file) if follow_if_link(file).kind == FileKind::Directory => {
                match self.match_all_handoffs(file) {
                    Ok(hits) => {
                        let names = hits
                            .iter()
                            .map(|(_, resolved, _)| resolved.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        HandoffPreview {
                            headline: format!(
                                "Folder has {} remaining file{}",
                                hits.len(),
                                if hits.len() == 1 { "" } else { "s" }
                            ),
                            body: names,
                            hint: "enter scans this folder for every missing payload".into(),
                            ok: true,
                        }
                    }
                    Err(reason) => HandoffPreview {
                        headline: format!("Does not match {expected}"),
                        body: reason,
                        hint: "type the file path, or a folder that contains the remaining files"
                            .into(),
                        ok: false,
                    },
                }
            }
            Some(file) => match self.match_handoff(file) {
                Ok((index, resolved, _)) => {
                    let role = self.requests[index].spec.role.clone();
                    let body = if resolved.path == file.path {
                        format!("{} is ready to attach", resolved.name)
                    } else {
                        format!("Using {} from {}", resolved.name, file.name)
                    };
                    HandoffPreview {
                        headline: format!("Matches {role}"),
                        body,
                        hint: "enter or a attaches this file".into(),
                        ok: true,
                    }
                }
                Err(reason) => HandoffPreview {
                    headline: format!("Does not match {expected}"),
                    body: reason,
                    hint: "type the file path, or a folder that contains the remaining files"
                        .into(),
                    ok: false,
                },
            },
        }
    }

    pub fn apply_event(&mut self, event: RecoveryEvent) {
        match event {
            RecoveryEvent::DeviceDiscovered(device) => self.upsert_device(device),
            RecoveryEvent::DeviceDisconnected { device_id, note } => {
                self.mark_device_connected(&device_id, false, DeviceState::Disconnected);
                if self.claimed_device_id.as_deref() == Some(device_id.as_str()) {
                    self.phase = SessionPhase::Waiting;
                    self.claimed_device_id = None;
                    self.progress = None;
                    self.verifying = None;
                    self.status_message = note
                        .clone()
                        .unwrap_or_else(|| "Claimed device disconnected".into());
                    self.push_log(
                        LogLevel::Warn,
                        note.unwrap_or_else(|| "Claimed device disconnected".into()),
                    );
                }
            }
            RecoveryEvent::DeviceReconnected { device_id, note } => {
                self.mark_device_connected(&device_id, true, DeviceState::Available);
                self.push_log(
                    LogLevel::Info,
                    note.unwrap_or_else(|| "Device reconnected".into()),
                );
            }
            RecoveryEvent::ClaimAccepted { device_id, note } => {
                self.claimed_device_id = Some(device_id.clone());
                self.phase = SessionPhase::Collecting;
                self.progress = None;
                self.verifying = None;
                self.focus = RecoveryFocus::Requests;
                self.status_message = note
                    .clone()
                    .unwrap_or_else(|| "Device claimed, waiting for file requests".into());
                self.last_error = None;
                for device in &mut self.devices {
                    if device.id == device_id {
                        device.state = DeviceState::Claimed;
                    } else if device.connected {
                        device.state = DeviceState::Busy;
                    }
                }
                self.push_log(
                    LogLevel::Info,
                    note.unwrap_or_else(|| "Exclusive claim accepted".into()),
                );
            }
            RecoveryEvent::ClaimRejected { device_id, reason } => {
                self.phase = SessionPhase::Waiting;
                self.status_message = reason.clone();
                self.last_error = Some(reason.clone());
                self.mark_device_connected(&device_id, true, DeviceState::Available);
                self.push_log(LogLevel::Error, reason);
            }
            RecoveryEvent::Released { device_id, note } => {
                if self.claimed_device_id.as_deref() == Some(device_id.as_str()) {
                    self.claimed_device_id = None;
                    self.progress = None;
                    self.verifying = None;
                    self.phase = if self.next_open_request().is_some() {
                        SessionPhase::Collecting
                    } else if self.all_required_files_supplied() && !self.requests.is_empty() {
                        SessionPhase::Ready
                    } else {
                        SessionPhase::Waiting
                    };
                }
                for device in &mut self.devices {
                    if device.id == device_id {
                        device.state = if device.connected {
                            DeviceState::Available
                        } else {
                            DeviceState::Disconnected
                        };
                    } else if device.connected {
                        device.state = DeviceState::Available;
                    }
                }
                self.status_message = note.clone().unwrap_or_else(|| "Claim released".into());
                self.push_log(
                    LogLevel::Info,
                    note.unwrap_or_else(|| "Claim released".into()),
                );
            }
            RecoveryEvent::FileRequested(spec) => {
                self.phase = SessionPhase::Collecting;
                self.status_message = format!("Coordinator requested {}", spec.role);
                self.focus = RecoveryFocus::Requests;
                self.upsert_request(spec);
            }
            RecoveryEvent::FileRequestCleared { request_id, note } => {
                if let Some(request) = self
                    .requests
                    .iter_mut()
                    .find(|request| request.spec.request_id == request_id)
                {
                    request.resolution = RequestResolution::Missing;
                }
                self.status_message = note.clone().unwrap_or_else(|| "Request reopened".into());
                self.push_log(
                    LogLevel::Info,
                    note.unwrap_or_else(|| "File request reopened".into()),
                );
            }
            RecoveryEvent::FileAccepted { request_id, note } => {
                let known = self
                    .requests
                    .iter()
                    .any(|request| request.spec.request_id == request_id);
                if let Some(request) = self
                    .requests
                    .iter_mut()
                    .find(|request| request.spec.request_id == request_id)
                {
                    let title = request.spec.title().to_string();
                    let file = request
                        .resolution
                        .file()
                        .cloned()
                        .unwrap_or_else(|| FileInfo {
                            path: PathBuf::new(),
                            name: title,
                            kind: FileKind::File,
                            size: None,
                            modified: None,
                        });
                    request.resolution = RequestResolution::Accepted {
                        file,
                        note: note.clone().unwrap_or_else(|| "Accepted".into()),
                    };
                }
                if !known {
                    self.push_log(
                        LogLevel::Info,
                        note.unwrap_or_else(|| "Coordinator accepted file".into()),
                    );
                    return;
                }
                if !matches!(
                    self.phase,
                    SessionPhase::Starting
                        | SessionPhase::Running
                        | SessionPhase::Cancelling
                        | SessionPhase::Cancelled
                        | SessionPhase::Succeeded
                        | SessionPhase::Failed
                ) {
                    self.phase = if self.all_required_files_supplied() {
                        SessionPhase::Ready
                    } else {
                        SessionPhase::Collecting
                    };
                }
                self.verifying = None;
                self.status_message = note.clone().unwrap_or_else(|| "File accepted".into());
                self.push_log(
                    LogLevel::Info,
                    note.unwrap_or_else(|| "Coordinator accepted file".into()),
                );
            }
            RecoveryEvent::FileRejected {
                request_id,
                reason,
                keep_claim,
            } => {
                if let Some(request) = self
                    .requests
                    .iter_mut()
                    .find(|request| request.spec.request_id == request_id)
                {
                    let file = request.resolution.file().cloned();
                    request.resolution = RequestResolution::Rejected {
                        file,
                        reason: reason.clone(),
                    };
                }
                self.verifying = None;
                self.phase = if keep_claim {
                    SessionPhase::Collecting
                } else {
                    SessionPhase::Failed
                };
                self.status_message = reason.clone();
                self.last_error = Some(reason.clone());
                self.push_log(LogLevel::Error, reason);
                if keep_claim {
                    self.focus_open_request();
                }
            }
            RecoveryEvent::PhaseChanged { phase, note } => {
                self.phase = phase;
                if let Some(note) = note {
                    self.status_message = note.clone();
                    let level = if matches!(phase, SessionPhase::Failed) {
                        LogLevel::Error
                    } else {
                        LogLevel::Info
                    };
                    self.push_log(level, note);
                }
            }
            RecoveryEvent::Progress(progress) => {
                let checking = progress.stage.eq_ignore_ascii_case("checking")
                    || progress.stage.eq_ignore_ascii_case("hashing")
                    || progress.stage.eq_ignore_ascii_case("scanning")
                    || progress.stage.eq_ignore_ascii_case("reading");
                if checking {
                    self.verifying = Some(progress.clone());
                    self.status_message = if progress.detail.is_empty() {
                        progress.stage
                    } else {
                        format!("{} · {}", progress.stage, progress.detail)
                    };
                } else {
                    self.verifying = None;
                    self.phase = SessionPhase::Running;
                    self.status_message = if progress.detail.is_empty() {
                        progress.stage.clone()
                    } else {
                        format!("{} · {}", progress.stage, progress.detail)
                    };
                    self.progress = Some(progress.clone());
                    self.push_log(
                        LogLevel::Info,
                        if progress.detail.is_empty() {
                            progress.stage
                        } else {
                            progress.detail
                        },
                    );
                }
            }
            RecoveryEvent::CompatibleBoards {
                systems,
                product_version,
                product_build,
            } => {
                self.verifying = None;
                self.last_error = None;
                self.compatible_systems = systems;
                self.selected_system = None;
                self.system_cursor = 0;
                self.compatible_modes.clear();
                self.selected_mode = None;
                self.mode_cursor = 0;
                self.product_version = product_version;
                self.product_build = product_build;
            }
            RecoveryEvent::SystemSelected { class } => {
                self.selected_system = Some(class.clone());
                self.selected_mode = None;
                self.verifying = None;
                self.last_error = None;
                self.requests.retain(|request| {
                    request.spec.request_id == "build-manifest"
                        || request.spec.role.eq_ignore_ascii_case("BuildManifest")
                });
                self.request_cursor = 0;
                self.status_message = format!("Selected {class}");
                self.push_log(LogLevel::Info, format!("Selected system {class}"));
            }
            RecoveryEvent::CompatibleModes { modes } => {
                self.compatible_modes = modes;
                self.selected_mode = None;
                self.mode_cursor = 0;
                self.verifying = None;
                self.status_message = match self
                    .selected_system_label()
                    .map(|system| system.title.clone())
                {
                    Some(title) => format!("Choose restore mode for {title}"),
                    None => "Choose restore mode".into(),
                };
            }
            RecoveryEvent::ModeSelected { mode } => {
                self.selected_mode = Some(mode);
                self.compatible_modes.clear();
                self.verifying = None;
                self.last_error = None;
                self.phase = SessionPhase::Collecting;
                let system = self
                    .selected_system_label()
                    .map(|system| system.title.clone())
                    .or_else(|| self.selected_system.clone())
                    .unwrap_or_else(|| "system".into());
                self.status_message = format!("Collecting files for {system} ({})", mode.title());
                self.push_log(
                    LogLevel::Info,
                    format!("Selected {} for {system}", mode.title()),
                );
            }
            RecoveryEvent::Cancelled { note } => {
                self.phase = SessionPhase::Cancelled;
                self.progress = None;
                self.verifying = None;
                self.status_message = note.clone().unwrap_or_else(|| "Restore cancelled".into());
                self.push_log(
                    LogLevel::Warn,
                    note.unwrap_or_else(|| "Restore cancelled".into()),
                );
            }
            RecoveryEvent::Succeeded { note } => {
                self.phase = SessionPhase::Succeeded;
                self.progress = Some(RestoreProgress {
                    stage: "done".into(),
                    detail: note.clone().unwrap_or_else(|| "Restore completed".into()),
                    fraction: Some(1.0),
                });
                self.status_message = note.clone().unwrap_or_else(|| "Restore completed".into());
                self.push_log(
                    LogLevel::Info,
                    note.unwrap_or_else(|| "Restore completed".into()),
                );
            }
            RecoveryEvent::Failed { note } => {
                if note.contains("More files are still required") {
                    self.phase = SessionPhase::Collecting;
                    self.progress = None;
                    self.verifying = None;
                    self.last_error = None;
                    self.status_message = "Select the next restore file".into();
                    self.push_log(LogLevel::Info, note);
                    return;
                }
                self.phase = SessionPhase::Failed;
                self.progress = None;
                self.verifying = None;
                self.status_message = note.clone();
                self.last_error = Some(note.clone());
                self.push_log(LogLevel::Error, note);
            }
            RecoveryEvent::Log { level, message } => {
                self.push_log(level, message);
            }
        }
    }

    fn upsert_device(&mut self, device: RecoveryDevice) {
        let message = format!("{} on {}", device.title, device.connection);
        let existing = self
            .devices
            .iter()
            .position(|current| current.id == device.id);
        match existing {
            Some(index) => {
                let was_connected = self.devices[index].connected;
                self.devices[index] = device.clone();
                if device.connected && !was_connected {
                    self.push_log(LogLevel::Info, format!("Reconnected {message}"));
                } else if !device.connected && was_connected {
                    self.push_log(LogLevel::Warn, format!("{} disconnected", device.title));
                }
            }
            None => {
                self.devices.push(device);
                self.push_log(LogLevel::Info, format!("Discovered {message}"));
            }
        }
        self.devices
            .sort_by(|left, right| left.title.cmp(&right.title).then(left.id.cmp(&right.id)));
        if self.device_cursor >= self.devices.len() {
            self.device_cursor = self.devices.len().saturating_sub(1);
        }
        if self.claimed_device_id.is_none() {
            self.status_message = if self.devices.iter().any(|device| device.connected) {
                "Select a device to claim".into()
            } else if self.devices.is_empty() {
                "Watching for connected devices".into()
            } else {
                "Waiting for the device to come back".into()
            };
        }
    }

    fn mark_device_connected(&mut self, device_id: &str, connected: bool, state: DeviceState) {
        if let Some(device) = self
            .devices
            .iter_mut()
            .find(|device| device.id == device_id)
        {
            device.connected = connected;
            device.state = if connected {
                state
            } else {
                DeviceState::Disconnected
            };
        }
    }

    fn upsert_request(&mut self, spec: FileRequestSpec) {
        let title = spec.title().to_string();
        match self
            .requests
            .iter_mut()
            .find(|request| request.spec.request_id == spec.request_id)
        {
            Some(request) => request.spec = spec,
            None => self.requests.push(FileRequestState {
                spec,
                resolution: RequestResolution::Missing,
            }),
        }
        if self.request_cursor >= self.requests.len() {
            self.request_cursor = self.requests.len().saturating_sub(1);
        }
        self.push_log(LogLevel::Info, format!("Requested {title}"));
    }

    pub fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        let message = message.into();
        if let Some(front) = self.logs.front_mut()
            && front.level == level
            && front.message == message
        {
            front.repeats = front.repeats.saturating_add(1);
            return;
        }
        let entry = RecoveryLogEntry {
            index: self.next_log_index,
            level,
            message,
            repeats: 1,
        };
        self.next_log_index += 1;
        self.logs.push_front(entry);
        while self.logs.len() > MAX_LOG_ENTRIES {
            self.logs.pop_back();
        }
        if self.event_cursor >= self.logs.len() {
            self.event_cursor = self.logs.len().saturating_sub(1);
        }
    }
}

pub fn resolve_handoff(file: &FileInfo, spec: &FileRequestSpec) -> Result<FileInfo, String> {
    resolve_handoff_candidates(file, spec)?
        .into_iter()
        .next()
        .ok_or_else(|| mismatch_for_spec(spec, file))
}

pub fn resolve_handoff_candidates(
    file: &FileInfo,
    spec: &FileRequestSpec,
) -> Result<Vec<FileInfo>, String> {
    let file = follow_if_link(file);
    if is_archive_name(&file.name)
        && !spec.matches_name(&file.name)
        && !spec.matches_extension(&file)
    {
        return Err(format!(
            "{} needs {}. {} is an archive — extract it first, then copy {} from the extracted folder.",
            spec.role,
            spec.expectation_label(),
            file.name,
            spec.title()
        ));
    }

    if spec.accept_directory {
        if effective_kind(&file) != FileKind::Directory {
            return Err(format!(
                "{} must be a folder (got {})",
                spec.role, file.name
            ));
        }
        return Ok(vec![file]);
    }

    match effective_kind(&file) {
        FileKind::Directory => resolve_from_directory(&file, spec),
        FileKind::File => accept_regular_file(&file, spec).map(|file| vec![file]),
        FileKind::Symlink => Err(format!("{} cannot use the alias {}", spec.role, file.name)),
        other => Err(format!(
            "{} must be a regular file (got {} · {})",
            spec.role,
            file.name,
            other.label()
        )),
    }
}

fn accept_regular_file(file: &FileInfo, spec: &FileRequestSpec) -> Result<FileInfo, String> {
    if !spec.allowed_extensions.is_empty() && !spec.matches_extension(file) {
        let got = file_extension(&file.path).unwrap_or_else(|| "no extension".into());
        return Err(format!(
            "{} expects {} (got {})",
            spec.role,
            spec.allowed_extensions.join(", "),
            got
        ));
    }
    if payload_name_is_required(spec)
        && !spec.accepted_names.is_empty()
        && !spec.matches_name(&file.name)
    {
        return Err(format!(
            "{} expects {} (got {})",
            spec.role,
            spec.accepted_names.join(", "),
            file.name
        ));
    }
    Ok(file.clone())
}

fn payload_name_is_required(spec: &FileRequestSpec) -> bool {
    !spec.allowed_extensions.iter().any(|ext| {
        ext.eq_ignore_ascii_case("dmg")
            || ext.eq_ignore_ascii_case("aea")
            || ext.eq_ignore_ascii_case("im4p")
            || ext.eq_ignore_ascii_case("img4")
    })
}

fn resolve_from_directory(dir: &FileInfo, spec: &FileRequestSpec) -> Result<Vec<FileInfo>, String> {
    let mut wanted: Vec<String> = spec.accepted_names.clone();
    if let Some(name) = spec.preferred_name.as_ref()
        && !wanted.iter().any(|item| item.eq_ignore_ascii_case(name))
    {
        wanted.push(name.clone());
    }
    wanted = expand_accepted_names(&wanted);

    if let Some(named) = named_files_in_directory(&dir.path, spec, &wanted)
        && !named.is_empty()
    {
        return Ok(named);
    }

    let files = walk_payload_files(&dir.path)
        .map_err(|error| format!("Could not read folder {}: {error}", dir.path.display()))?;

    let mut named = Vec::new();
    let mut stemmed = Vec::new();
    let mut formatted = Vec::new();
    let mut seen_paths = HashSet::new();
    for file in files {
        let Ok(file) = accept_regular_file(&file, spec) else {
            continue;
        };
        if !seen_paths.insert(file.path.clone()) {
            continue;
        }
        if wanted
            .iter()
            .any(|item| item.eq_ignore_ascii_case(&file.name))
        {
            named.push(file);
        } else if wanted
            .iter()
            .any(|item| payload_names_compatible(&file.name, item))
        {
            stemmed.push(file);
        } else if wanted.is_empty() && formatted.is_empty() {
            formatted.push(file);
        }
    }

    let mut matches = named;
    matches.extend(stemmed);
    if matches.is_empty() {
        matches.extend(formatted);
    }
    if matches.is_empty() {
        let hint = if wanted.is_empty() {
            spec.expectation_label()
        } else {
            wanted.join(", ")
        };
        return Err(format!(
            "Folder {} does not contain a {} payload ({hint}). Copy the matching file, or the folder that contains it.",
            dir.name, spec.role
        ));
    }
    Ok(matches)
}

pub(crate) fn restore_set_manifest(root: &Path) -> Option<PathBuf> {
    let manifest = root.join(BUILD_MANIFEST_FILE_NAME);
    manifest.is_file().then_some(manifest)
}

pub(crate) fn declares_another_restore_set(dir: &Path, root_manifest: &Path) -> bool {
    let candidate = dir.join(BUILD_MANIFEST_FILE_NAME);
    candidate.is_file() && !files_have_identical_bytes(&candidate, root_manifest)
}

fn files_have_identical_bytes(left: &Path, right: &Path) -> bool {
    let (Ok(left_metadata), Ok(right_metadata)) =
        (std::fs::metadata(left), std::fs::metadata(right))
    else {
        return false;
    };
    if left_metadata.len() != right_metadata.len() {
        return false;
    }
    let (Ok(left_file), Ok(right_file)) = (File::open(left), File::open(right)) else {
        return false;
    };
    let mut left_reader = BufReader::new(left_file);
    let mut right_reader = BufReader::new(right_file);
    let mut left_chunk = vec![0u8; 64 * 1024];
    let mut right_chunk = vec![0u8; 64 * 1024];
    loop {
        let read = match left_reader.read(&mut left_chunk) {
            Ok(0) => return true,
            Ok(read) => read,
            Err(_) => return false,
        };
        if right_reader.read_exact(&mut right_chunk[..read]).is_err() {
            return false;
        }
        if left_chunk[..read] != right_chunk[..read] {
            return false;
        }
    }
}

fn named_files_in_directory(
    dir: &Path,
    spec: &FileRequestSpec,
    wanted: &[String],
) -> Option<Vec<FileInfo>> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut named = Vec::new();
    let mut seen_paths = HashSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !wanted.iter().any(|item| item.eq_ignore_ascii_case(name)) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Some(info) = inspect(&entry.path().to_string_lossy()) else {
            continue;
        };
        let Ok(file) = accept_regular_file(&info, spec) else {
            continue;
        };
        if seen_paths.insert(file.path.clone()) {
            named.push(file);
        }
    }
    named.sort_by_key(|file| {
        wanted
            .iter()
            .position(|item| item.eq_ignore_ascii_case(&file.name))
            .unwrap_or(usize::MAX)
    });
    Some(named)
}

fn walk_payload_files(dir: &Path) -> Result<Vec<FileInfo>, String> {
    let mut files = Vec::new();
    let root_manifest = restore_set_manifest(dir);
    let mut stack = vec![dir.to_path_buf()];
    let mut seen_dirs = HashSet::new();
    let mut visited = 0usize;
    while let Some(path) = stack.pop() {
        if visited >= 100_000 || files.len() >= 100_000 {
            break;
        }
        let canonical = std::fs::canonicalize(&path).unwrap_or(path);
        if !seen_dirs.insert(canonical.clone()) {
            continue;
        }
        let entries = match std::fs::read_dir(&canonical) {
            Ok(entries) => entries,
            Err(error) if seen_dirs.len() == 1 => {
                return Err(error.to_string());
            }
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with('.') || name == "__MACOSX" {
                continue;
            }
            let child = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                if root_manifest
                    .as_ref()
                    .is_some_and(|manifest| declares_another_restore_set(&child, manifest))
                {
                    continue;
                }
                stack.push(child);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let Some(info) = inspect(&child.to_string_lossy()) else {
                continue;
            };
            files.push(follow_if_link(&info));
        }
    }
    Ok(files)
}

fn mismatch_for_spec(spec: &FileRequestSpec, file: &FileInfo) -> String {
    format!(
        "Folder {} does not contain a {} payload ({}). Copy the matching file, or the folder that contains it.",
        file.name,
        spec.role,
        spec.expectation_label()
    )
}

pub(crate) fn expand_accepted_names(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if name.is_empty() {
            return;
        }
        if !out
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&name))
        {
            out.push(name);
        }
    };
    for name in names {
        push(name.clone());
        if let Some((_, rest)) = name.split_once("__")
            && rest.contains('.')
        {
            push(rest.to_string());
        }
        if name.contains(".dmg.aea.") {
            push(name.replace(".dmg.aea.", ".dmg."));
        }
        if let Some(stripped) = name.strip_suffix(".aea")
            && stripped.ends_with(".dmg")
        {
            push(stripped.to_string());
        }
    }
    out
}

pub(crate) fn payload_names_compatible(name: &str, wanted: &str) -> bool {
    let left = normalize_payload_name(name);
    let right = normalize_payload_name(wanted);
    if left.is_empty() || right.is_empty() {
        return false;
    }
    if left == right {
        return true;
    }
    match (asset_id(&left), asset_id(&right)) {
        (Some(left_id), Some(right_id)) if left_id == right_id => {
            payload_kind_suffix(&left) == payload_kind_suffix(&right)
        }
        _ => false,
    }
}

fn normalize_payload_name(name: &str) -> String {
    let mut value = name.to_ascii_lowercase();
    if let Some((prefix, rest)) = value.split_once("__")
        && !prefix.is_empty()
        && !prefix.contains('.')
        && rest.contains('.')
    {
        value = rest.to_string();
    }
    value = value.replace(".dmg.aea.", ".dmg.");
    if let Some(stripped) = value.strip_suffix(".dmg.aea") {
        format!("{stripped}.dmg")
    } else {
        value
    }
}

fn asset_id(name: &str) -> Option<&str> {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let first = i - start;
            if first >= 2 && i < bytes.len() && bytes[i] == b'-' {
                i += 1;
                let mid = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let middle = i - mid;
                if middle >= 3 && i < bytes.len() && bytes[i] == b'-' {
                    i += 1;
                    let last = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i - last >= 2 {
                        return Some(&name[start..i]);
                    }
                }
            }
            i = start + 1;
            continue;
        }
        i += 1;
    }
    None
}

fn payload_kind_suffix(name: &str) -> &str {
    for suffix in [
        "trustcache",
        "root_hash",
        "mtree",
        "im4p",
        "img4",
        "plist",
        "aea",
        "dmg",
    ] {
        if name == suffix || name.ends_with(&format!(".{suffix}")) {
            return suffix;
        }
    }
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or(name)
}

fn follow_if_link(file: &FileInfo) -> FileInfo {
    if file.kind != FileKind::Symlink {
        return file.clone();
    }
    inspect(&file.path.to_string_lossy()).unwrap_or_else(|| file.clone())
}

fn effective_kind(file: &FileInfo) -> FileKind {
    file.kind
}

fn is_archive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".ipsw") || lower.ends_with(".zip")
}

fn file_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
}

fn mismatch_summary(requests: &[FileRequestState], file: &FileInfo) -> String {
    let open = requests
        .iter()
        .filter(|request| {
            !matches!(
                request.resolution,
                RequestResolution::Submitted { .. } | RequestResolution::Accepted { .. }
            )
        })
        .map(|request| request.spec.expectation_label())
        .collect::<Vec<_>>();
    if open.is_empty() {
        format!("{} is not needed for any open request", file.name)
    } else {
        format!(
            "{} does not match {}. Copy the requested file, or the extracted folder that contains it.",
            file.name,
            open.join(" or ")
        )
    }
}

fn abbreviate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}…", &value[..max.saturating_sub(1)])
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryEvent {
    DeviceDiscovered(RecoveryDevice),
    DeviceDisconnected {
        device_id: String,
        note: Option<String>,
    },
    DeviceReconnected {
        device_id: String,
        note: Option<String>,
    },
    ClaimAccepted {
        device_id: String,
        note: Option<String>,
    },
    ClaimRejected {
        device_id: String,
        reason: String,
    },
    Released {
        device_id: String,
        note: Option<String>,
    },
    FileRequested(FileRequestSpec),
    FileRequestCleared {
        request_id: String,
        note: Option<String>,
    },
    FileAccepted {
        request_id: String,
        note: Option<String>,
    },
    FileRejected {
        request_id: String,
        reason: String,
        keep_claim: bool,
    },
    PhaseChanged {
        phase: SessionPhase,
        note: Option<String>,
    },
    Progress(RestoreProgress),
    CompatibleBoards {
        systems: Vec<CompatibleSystem>,
        product_version: Option<String>,
        product_build: Option<String>,
    },
    SystemSelected {
        class: String,
    },
    CompatibleModes {
        modes: Vec<RestoreMode>,
    },
    ModeSelected {
        mode: RestoreMode,
    },
    Cancelled {
        note: Option<String>,
    },
    Succeeded {
        note: Option<String>,
    },
    Failed {
        note: String,
    },
    Log {
        level: LogLevel,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_files_gate_start() {
        let mut model = RecoveryModel {
            claimed_device_id: Some("dev-1".into()),
            phase: SessionPhase::Collecting,
            ..Default::default()
        };
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
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
            },
            resolution: RequestResolution::Missing,
        });
        assert!(!model.can_start());

        model.requests[0].resolution = RequestResolution::Submitted {
            file: FileInfo {
                path: "/tmp/BuildManifest.plist".into(),
                name: "BuildManifest.plist".into(),
                kind: FileKind::File,
                size: Some(128),
                modified: None,
            },
            note: "queued".into(),
        };
        assert!(model.can_start());
    }

    #[test]
    fn local_validation_checks_extension_and_size() {
        let mut model = RecoveryModel::default();
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
                request_id: "ramdisk".into(),
                role: "RestoreRamDisk".into(),
                preferred_name: Some("restore.dmg".into()),
                accepted_names: vec!["restore.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: Some(SizeRange { min: 100, max: 200 }),
                expected_hash: None,
                detail: None,
                required: true,
            },
            resolution: RequestResolution::Missing,
        });
        model.focus = RecoveryFocus::Requests;

        let file = FileInfo {
            path: "/tmp/restore.ipsw".into(),
            name: "restore.ipsw".into(),
            kind: FileKind::File,
            size: Some(180),
            modified: None,
        };
        let error = model.validate_request(&file).unwrap_err();
        assert!(
            error.contains("expects dmg") || error.contains("archive"),
            "{error}"
        );

        let file = FileInfo {
            path: "/tmp/restore.dmg".into(),
            name: "restore.dmg".into(),
            kind: FileKind::File,
            size: Some(250),
            modified: None,
        };
        let error = model.validate_request(&file).unwrap_err();
        assert!(error.contains("100 B to 200 B"), "{error}");
    }

    #[test]
    fn handoff_resolves_manifest_from_extracted_folder() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("BuildManifest.plist");
        std::fs::write(&manifest, b"<?xml version=\"1.0\"?><plist></plist>").unwrap();

        let mut model = RecoveryModel::default();
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
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
            },
            resolution: RequestResolution::Missing,
        });
        model.focus = RecoveryFocus::Requests;

        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        let (index, resolved, _) = model.match_handoff(&folder).expect("resolved");
        assert_eq!(index, 0);
        assert_eq!(resolved.name, "BuildManifest.plist");
        assert_eq!(resolved.path, manifest.canonicalize().unwrap());
    }

    #[test]
    fn handoff_prefers_a_top_level_manifest_over_a_nested_restore_set() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("BuildManifest.plist");
        std::fs::write(&manifest, b"<?xml version=\"1.0\"?><plist></plist>").unwrap();
        let nested = dir.path().join("extract");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(
            nested.join("Restore.plist"),
            b"<?xml version=\"1.0\"?><plist></plist>",
        )
        .unwrap();

        let spec = FileRequestSpec {
            request_id: "build-manifest".into(),
            role: "BuildManifest".into(),
            preferred_name: Some("BuildManifest.plist".into()),
            accepted_names: vec!["BuildManifest.plist".into(), "Restore.plist".into()],
            allowed_extensions: vec!["plist".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        let resolved = resolve_handoff_candidates(&folder, &spec).expect("resolved");
        assert_eq!(resolved.len(), 1, "{resolved:?}");
        assert_eq!(resolved[0].name, "BuildManifest.plist");
        assert_eq!(resolved[0].path, manifest.canonicalize().unwrap());
    }

    #[test]
    fn a_folder_fills_every_open_request() {
        let dir = tempfile::tempdir().unwrap();
        let os = dir.path().join("OS.dmg");
        let ramdisk = dir.path().join("RestoreRamDisk.dmg");
        std::fs::write(&os, b"system").unwrap();
        std::fs::write(&ramdisk, b"ramdisk").unwrap();

        let mut model = RecoveryModel::default();
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
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
            resolution: RequestResolution::Missing,
        });
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
                request_id: "component:RestoreRamDisk".into(),
                role: "RestoreRamDisk".into(),
                preferred_name: Some("RestoreRamDisk.dmg".into()),
                accepted_names: vec!["RestoreRamDisk.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: None,
                expected_hash: None,
                detail: None,
                required: true,
            },
            resolution: RequestResolution::Missing,
        });
        model.request_cursor = 0;

        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        let hits = model.match_all_handoffs(&folder).expect("hits");
        assert_eq!(hits.len(), 2, "{hits:?}");
        let names = hits
            .iter()
            .map(|(_, file, _)| file.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"OS.dmg"), "{names:?}");
        assert!(names.contains(&"RestoreRamDisk.dmg"), "{names:?}");
    }

    #[test]
    fn handoff_finds_nested_payload_in_an_extracted_tree() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("Image");
        std::fs::create_dir_all(&nested).unwrap();
        let payload = nested.join("SystemOS.dmg");
        std::fs::write(&payload, b"cryptex").unwrap();

        let spec = FileRequestSpec {
            request_id: "component:Cryptex1,SystemOS".into(),
            role: "Cryptex1,SystemOS".into(),
            preferred_name: Some("SystemOS.dmg".into()),
            accepted_names: vec!["SystemOS.dmg".into()],
            allowed_extensions: vec!["dmg".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        let resolved = resolve_handoff(&folder, &spec).expect("nested");
        assert_eq!(resolved.name, "SystemOS.dmg");
    }

    #[test]
    fn firmware_names_match_without_the_component_prefix() {
        assert!(payload_names_compatible(
            "ipad13dcp.im4p",
            "Ap,DCP2__ipad13dcp.im4p"
        ));
        assert!(payload_names_compatible(
            "094-56453-088.dmg.trustcache",
            "094-56453-088.dmg.aea.trustcache"
        ));
        assert!(payload_names_compatible(
            "094-56453-088.dmg.aea.root_hash",
            "SystemVolume__094-56453-088.dmg.aea.root_hash"
        ));
        assert!(payload_names_compatible(
            "OS__094-56453-088.dmg",
            "094-56453-088.dmg.aea"
        ));
        assert!(!payload_names_compatible(
            "ipad13dcp_restore.im4p",
            "ipad13dcp.im4p"
        ));
        assert!(!payload_names_compatible(
            "094-56453-088.dmg.trustcache",
            "094-56453-088.dmg.aea.root_hash"
        ));
    }

    #[test]
    fn a_nested_firmware_tree_matches_the_manifest_basename() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir
            .path()
            .join("fw")
            .join("25F80__MacOS")
            .join("Firmware")
            .join("dcp");
        std::fs::create_dir_all(&nested).unwrap();
        let payload = nested.join("ipad13dcp.im4p");
        std::fs::write(&payload, b"IM4P-dcp").unwrap();
        std::fs::write(nested.join("ipad13dcp_restore.im4p"), b"IM4P-restore").unwrap();

        let spec = FileRequestSpec {
            request_id: "component:Ap,DCP2".into(),
            role: "Ap,DCP2".into(),
            preferred_name: Some("ipad13dcp.im4p".into()),
            accepted_names: vec!["Ap,DCP2__ipad13dcp.im4p".into(), "ipad13dcp.im4p".into()],
            allowed_extensions: vec!["im4p".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        let resolved = resolve_handoff(&folder, &spec).expect("nested firmware");
        assert_eq!(resolved.name, "ipad13dcp.im4p");
        assert_eq!(resolved.path, payload.canonicalize().unwrap());
    }

    #[test]
    fn a_folder_search_recurses_into_every_nested_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir
            .path()
            .join("random")
            .join("tree")
            .join("SE")
            .join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        let payload = nested.join("Stockholm7.RELEASE.sefw");
        std::fs::write(&payload, b"sefw-bytes").unwrap();
        let sidecar = dir.path().join("other").join("Firmware");
        std::fs::create_dir_all(&sidecar).unwrap();
        let mtree = sidecar.join("094-56453-088.dmg.aea.mtree");
        std::fs::write(&mtree, b"mtree-bytes").unwrap();

        let sefw = FileRequestSpec {
            request_id: "component:SE,UpdatePayload".into(),
            role: "SE,UpdatePayload".into(),
            preferred_name: Some("Stockholm7.RELEASE.sefw".into()),
            accepted_names: vec!["Stockholm7.RELEASE.sefw".into()],
            allowed_extensions: vec!["sefw".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let mtree_spec = FileRequestSpec {
            request_id: "component:Ap,SystemVolumeCanonicalMetadata".into(),
            role: "Ap,SystemVolumeCanonicalMetadata".into(),
            preferred_name: Some("094-56453-088.dmg.aea.mtree".into()),
            accepted_names: vec!["094-56453-088.dmg.aea.mtree".into()],
            allowed_extensions: vec!["mtree".into(), "im4p".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        let found_sefw = resolve_handoff(&folder, &sefw).expect("recursive sefw");
        assert_eq!(found_sefw.path, payload.canonicalize().unwrap());
        let found_mtree = resolve_handoff(&folder, &mtree_spec).expect("recursive mtree");
        assert_eq!(found_mtree.path, mtree.canonicalize().unwrap());
    }

    #[test]
    fn handoff_explains_ipsw_archives() {
        let spec = FileRequestSpec {
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
        };
        let file = FileInfo {
            path: "/tmp/iPhone.ipsw".into(),
            name: "iPhone.ipsw".into(),
            kind: FileKind::File,
            size: Some(2048),
            modified: None,
        };
        let error = resolve_handoff(&file, &spec).unwrap_err();
        assert!(error.contains("archive"), "{error}");
        assert!(error.contains("BuildManifest.plist"), "{error}");
    }

    #[test]
    fn handoff_routes_to_matching_open_request() {
        let mut model = RecoveryModel::default();
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
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
            },
            resolution: RequestResolution::Missing,
        });
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
                request_id: "ramdisk".into(),
                role: "RestoreRamDisk".into(),
                preferred_name: Some("restore.dmg".into()),
                accepted_names: vec!["restore.dmg".into()],
                allowed_extensions: vec!["dmg".into()],
                accept_directory: false,
                expected_size: None,
                expected_hash: None,
                detail: None,
                required: true,
            },
            resolution: RequestResolution::Missing,
        });
        model.request_cursor = 0;
        let file = FileInfo {
            path: "/tmp/restore.dmg".into(),
            name: "restore.dmg".into(),
            kind: FileKind::File,
            size: Some(180),
            modified: None,
        };
        let (index, resolved, _) = model.match_handoff(&file).expect("routed");
        assert_eq!(index, 1);
        assert_eq!(resolved.name, "restore.dmg");
    }

    #[test]
    fn restore_image_handoff_ignores_exact_file_name() {
        let spec = FileRequestSpec {
            request_id: "system-image".into(),
            role: "Restore image".into(),
            preferred_name: Some("OS.dmg".into()),
            accepted_names: vec!["OS.dmg".into(), "OS.dmg.aea".into()],
            allowed_extensions: vec!["dmg".into(), "aea".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let file = FileInfo {
            path: "/tmp/OS.dmg".into(),
            name: "OS.dmg".into(),
            kind: FileKind::File,
            size: Some(128),
            modified: None,
        };
        let renamed = FileInfo {
            path: "/tmp/restored-os.dmg".into(),
            name: "restored-os.dmg".into(),
            kind: FileKind::File,
            size: Some(128),
            modified: None,
        };
        assert!(resolve_handoff(&file, &spec).is_ok());
        assert!(
            resolve_handoff(&renamed, &spec).is_ok(),
            "decoded restore images must not require the manifest file name"
        );
    }

    #[test]
    fn handoff_matches_names_case_insensitively() {
        let spec = FileRequestSpec {
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
        };
        let file = FileInfo {
            path: "/tmp/buildmanifest.plist".into(),
            name: "buildmanifest.plist".into(),
            kind: FileKind::File,
            size: Some(64),
            modified: None,
        };
        let resolved = resolve_handoff(&file, &spec).expect("case");
        assert_eq!(resolved.name, "buildmanifest.plist");
    }

    #[test]
    fn disconnect_clears_claim() {
        let mut model = RecoveryModel::default();
        model.apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
            id: "dev-1".into(),
            title: "Recovery Device".into(),
            detail: "iPhone".into(),
            connection: "127.0.0.1:9123".into(),
            state: DeviceState::Available,
            connected: true,
        }));
        model.apply_event(RecoveryEvent::ClaimAccepted {
            device_id: "dev-1".into(),
            note: None,
        });
        model.apply_event(RecoveryEvent::DeviceDisconnected {
            device_id: "dev-1".into(),
            note: Some("Device link dropped".into()),
        });

        assert_eq!(model.phase, SessionPhase::Waiting);
        assert!(model.claimed_device_id.is_none());
        assert_eq!(model.devices[0].state, DeviceState::Disconnected);
    }

    #[test]
    fn more_files_required_stays_collecting_instead_of_failing() {
        let mut model = RecoveryModel {
            claimed_device_id: Some("dev-1".into()),
            phase: SessionPhase::Ready,
            ..Default::default()
        };
        model.apply_event(RecoveryEvent::Failed {
            note: "More files are still required before restore can start".into(),
        });
        assert_eq!(model.phase, SessionPhase::Collecting);
        assert!(model.last_error.is_none());
        assert_eq!(model.step(), RecoveryStep::WaitRequest);

        model.apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
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
        assert_eq!(model.step(), RecoveryStep::PickFile);
        assert!(model.picker_title().contains("OS.dmg"));
    }

    #[test]
    fn repeated_log_messages_collapse_instead_of_spamming() {
        let mut model = RecoveryModel::default();
        let message =
            "Recovery device discovery failed: Resource temporarily unavailable (os error 35)";
        for _ in 0..20 {
            model.apply_event(RecoveryEvent::Log {
                level: LogLevel::Warn,
                message: message.into(),
            });
        }
        let entry = model.logs.front().expect("log");
        assert_eq!(entry.message, message);
        assert_eq!(entry.repeats, 20);
        assert_eq!(
            model
                .logs
                .iter()
                .filter(|entry| entry.message == message)
                .count(),
            1
        );
    }

    #[test]
    fn delayed_file_accept_does_not_downgrade_starting_or_reenable_start() {
        let mut model = RecoveryModel {
            claimed_device_id: Some("dev-1".into()),
            phase: SessionPhase::Starting,
            ..Default::default()
        };
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
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
            },
            resolution: RequestResolution::Submitted {
                file: FileInfo {
                    path: "/tmp/BuildManifest.plist".into(),
                    name: "BuildManifest.plist".into(),
                    kind: FileKind::File,
                    size: Some(128),
                    modified: None,
                },
                note: "queued".into(),
            },
        });

        model.apply_event(RecoveryEvent::FileAccepted {
            request_id: "manifest".into(),
            note: Some("accepted".into()),
        });

        assert_eq!(model.phase, SessionPhase::Starting);
        assert!(!model.can_start());
        assert!(matches!(
            model.requests[0].resolution,
            RequestResolution::Accepted { .. }
        ));
        assert_eq!(model.status_message, "accepted");
    }

    #[test]
    fn submitted_file_uses_work_step_until_accept_or_reject() {
        let mut model = RecoveryModel {
            claimed_device_id: Some("dev-1".into()),
            phase: SessionPhase::Collecting,
            ..Default::default()
        };
        model.requests.push(FileRequestState {
            spec: FileRequestSpec {
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
            },
            resolution: RequestResolution::Missing,
        });
        assert_eq!(model.step(), RecoveryStep::PickFile);

        let file = FileInfo {
            path: "/tmp/BuildManifest.plist".into(),
            name: "BuildManifest.plist".into(),
            kind: FileKind::File,
            size: Some(128),
            modified: None,
        };
        model.note_clipboard_assignment(&file, "queued".into());
        assert_eq!(model.phase, SessionPhase::Collecting);
        assert_eq!(model.step(), RecoveryStep::Working);
        assert_eq!(
            model
                .verifying
                .as_ref()
                .and_then(|progress| progress.fraction),
            Some(0.0)
        );

        model.apply_event(RecoveryEvent::Progress(RestoreProgress {
            stage: "checking".into(),
            detail: String::new(),
            fraction: Some(0.5),
        }));
        assert_eq!(model.phase, SessionPhase::Collecting);
        assert_eq!(model.step(), RecoveryStep::Working);
        assert_eq!(
            model
                .verifying
                .as_ref()
                .and_then(|progress| progress.fraction),
            Some(0.5)
        );

        model.apply_event(RecoveryEvent::FileRejected {
            request_id: "manifest".into(),
            reason: "hash mismatch".into(),
            keep_claim: true,
        });
        assert!(model.verifying.is_none());
        assert_eq!(model.phase, SessionPhase::Collecting);
        assert_eq!(model.step(), RecoveryStep::PickFile);
    }

    #[test]
    fn listing_boards_leaves_the_catalog_read_wait() {
        let mut model = RecoveryModel::default();
        model.requests.clear();
        model.apply_event(RecoveryEvent::Progress(RestoreProgress {
            stage: "reading".into(),
            detail: "BuildManifest.plist".into(),
            fraction: None,
        }));
        assert_eq!(model.step(), RecoveryStep::Working);
        model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![CompatibleSystem {
                class: "j617ap".into(),
                title: "j617ap".into(),
                detail: "j617ap".into(),
            }],
            product_version: Some("27.0".into()),
            product_build: Some("24A5390f".into()),
        });
        assert!(model.verifying.is_none());
        assert_eq!(model.step(), RecoveryStep::PickSystem);
    }

    #[test]
    fn choosing_a_system_with_two_modes_opens_the_mode_picker() {
        let mut model = RecoveryModel::default();
        model.requests.clear();
        model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![CompatibleSystem {
                class: "j274ap".into(),
                title: "Mac mini (M1, 2020)".into(),
                detail: "j274ap  ·  M1".into(),
            }],
            product_version: Some("26.5.1".into()),
            product_build: Some("25F80".into()),
        });
        assert_eq!(model.step(), RecoveryStep::PickSystem);
        assert!(model.verifying.is_none());
        model.apply_event(RecoveryEvent::SystemSelected {
            class: "j274ap".into(),
        });
        model.apply_event(RecoveryEvent::CompatibleModes {
            modes: vec![RestoreMode::Update, RestoreMode::Erase],
        });
        assert_eq!(model.step(), RecoveryStep::PickMode);
        assert_eq!(
            model.catalog_label().as_deref(),
            Some("macOS 26.5.1 (25F80)")
        );
        assert_eq!(model.selected_restore_mode(), Some(RestoreMode::Update));
        model.apply_event(RecoveryEvent::ModeSelected {
            mode: RestoreMode::Update,
        });
        assert_eq!(model.selected_mode, Some(RestoreMode::Update));
        assert_eq!(model.step(), RecoveryStep::WaitDevices);
    }

    #[test]
    fn accepted_files_the_wizard_never_asked_for_do_not_take_over_the_screen() {
        let mut model = RecoveryModel {
            phase: SessionPhase::Collecting,
            ..Default::default()
        };
        model.apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
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
        assert_eq!(model.step(), RecoveryStep::PickFile);
        model.apply_event(RecoveryEvent::FileAccepted {
            request_id: "component:Cryptex1,SystemTrustCache".into(),
            note: Some("094-56679-090.dmg.aea.trustcache ready".into()),
        });
        assert_eq!(model.step(), RecoveryStep::PickFile);
        assert!(
            !model.status_message.contains("trustcache"),
            "{}",
            model.status_message
        );
        assert!(matches!(
            model.requests[0].resolution,
            RequestResolution::Missing
        ));
    }

    #[test]
    fn hash_rejected_payload_stays_open_when_a_compatible_device_is_waiting() {
        let mut model = RecoveryModel::default();
        model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![CompatibleSystem {
                class: "J274AP".into(),
                title: "Mac mini (M1, 2020)".into(),
                detail: "J274AP  ·  M1".into(),
            }],
            product_version: None,
            product_build: None,
        });
        model.apply_event(RecoveryEvent::DeviceDiscovered(RecoveryDevice {
            id: "dev-1".into(),
            title: "MacBook Pro 13-inch, 2020".into(),
            detail: "J274AP".into(),
            connection: "usb".into(),
            state: DeviceState::Available,
            connected: true,
        }));
        model.apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
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
        let file = FileInfo {
            path: "/tmp/OS.dmg".into(),
            name: "OS.dmg".into(),
            kind: FileKind::File,
            size: Some(128),
            modified: None,
        };
        model.note_clipboard_assignment(&file, "queued".into());
        model.apply_event(RecoveryEvent::FileRejected {
            request_id: "system-image".into(),
            reason: "OS.dmg does not match OS.dmg. Select the correct file".into(),
            keep_claim: true,
        });
        model.apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
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

        assert_eq!(model.phase, SessionPhase::Collecting);
        assert_eq!(model.step(), RecoveryStep::PickFile);
        assert_eq!(model.next_open_request(), Some(0));
        assert!(matches!(
            model.requests[0].resolution,
            RequestResolution::Rejected { .. }
        ));
        assert!(
            model.picker_title().contains("OS.dmg"),
            "{}",
            model.picker_title()
        );
    }

    #[test]
    fn payload_walk_skips_other_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root_bytes = b"root-manifest";
        std::fs::write(dir.path().join(BUILD_MANIFEST_FILE_NAME), root_bytes).unwrap();

        let foreign = dir.path().join("other").join("Firmware").join("dcp");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(
            dir.path().join("other").join(BUILD_MANIFEST_FILE_NAME),
            b"other-manifest",
        )
        .unwrap();
        std::fs::write(foreign.join("ipad13dcp.im4p"), b"other-payload").unwrap();

        let linked = dir.path().join("linked");
        std::fs::create_dir_all(linked.join("Firmware").join("dcp")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("other").join(BUILD_MANIFEST_FILE_NAME),
            linked.join(BUILD_MANIFEST_FILE_NAME),
        )
        .unwrap();
        std::fs::write(
            linked.join("Firmware").join("dcp").join("ipad13dcp.im4p"),
            b"linked-payload",
        )
        .unwrap();

        let spec = FileRequestSpec {
            request_id: "component:Ap,DCP2".into(),
            role: "Ap,DCP2".into(),
            preferred_name: Some("ipad13dcp.im4p".into()),
            accepted_names: vec!["Ap,DCP2__ipad13dcp.im4p".into(), "ipad13dcp.im4p".into()],
            allowed_extensions: vec!["im4p".into()],
            accept_directory: false,
            expected_size: None,
            expected_hash: None,
            detail: None,
            required: true,
        };
        let folder = inspect(&dir.path().to_string_lossy()).expect("folder");
        assert!(resolve_handoff(&folder, &spec).is_err());

        let owned = dir
            .path()
            .join("same")
            .join("restore-assets")
            .join("Firmware")
            .join("dcp");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::write(
            dir.path().join("same").join(BUILD_MANIFEST_FILE_NAME),
            root_bytes,
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("same")
                .join("restore-assets")
                .join(BUILD_MANIFEST_FILE_NAME),
            root_bytes,
        )
        .unwrap();
        let payload = owned.join("ipad13dcp.im4p");
        std::fs::write(&payload, b"payload").unwrap();

        let resolved = resolve_handoff(&folder, &spec).unwrap();
        assert_eq!(resolved.path, payload.canonicalize().unwrap());
    }
}
