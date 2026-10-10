//! State, key and mouse handling, and the background job for the IPSW Export tool.
//! Drawing lives in `ipsw_ui`; `app.rs` only routes events here.

use std::cell::{Ref, RefCell};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent};

use crate::app::App;
use crate::clip;
use crate::ipsw_catalog::{Description, IpswCatalog};
use crate::ipsw_export::{
    Component, ExportOptions, ExportProgress, ExportReport, ExportRequest, IpswInfo, ItemAction,
    ItemReport, Outcome, is_aea_name, looks_like_im4p_name, plan_destinations, read_info,
    run_export,
};
use crate::ipsw_tree::{EntryKind, IpswTree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpswPhase {
    Path,
    Loading,
    Browse,
    Output,
    Exporting,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpswPane {
    Tree,
    Options,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpswRow {
    pub name: String,
    pub label: String,
    pub depth: usize,
    pub is_dir: bool,
    pub expanded: bool,
    pub size: u64,
    pub mark: Mark,
    pub tag: Option<&'static str>,
    pub description: Option<String>,
    pub chips: Vec<String>,
    pub device_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionToggle {
    DecryptAea,
    DecompressIm4p,
    KeepOriginals,
    PreservePaths,
    Overwrite,
}

impl OptionToggle {
    pub const ALL: [OptionToggle; 5] = [
        OptionToggle::DecryptAea,
        OptionToggle::DecompressIm4p,
        OptionToggle::KeepOriginals,
        OptionToggle::PreservePaths,
        OptionToggle::Overwrite,
    ];

    pub fn label(self) -> &'static str {
        match self {
            OptionToggle::DecryptAea => "Decrypt .aea images",
            OptionToggle::DecompressIm4p => "Decompress IM4P payloads",
            OptionToggle::KeepOriginals => "Keep originals too",
            OptionToggle::PreservePaths => "Keep folder structure",
            OptionToggle::Overwrite => "Overwrite existing",
        }
    }

    pub fn get(self, options: &ExportOptions) -> bool {
        match self {
            OptionToggle::DecryptAea => options.decrypt_aea,
            OptionToggle::DecompressIm4p => options.decompress_im4p,
            OptionToggle::KeepOriginals => options.keep_originals,
            OptionToggle::PreservePaths => options.preserve_paths,
            OptionToggle::Overwrite => options.overwrite,
        }
    }

    fn flip(self, options: &mut ExportOptions) {
        let slot = match self {
            OptionToggle::DecryptAea => &mut options.decrypt_aea,
            OptionToggle::DecompressIm4p => &mut options.decompress_im4p,
            OptionToggle::KeepOriginals => &mut options.keep_originals,
            OptionToggle::PreservePaths => &mut options.preserve_paths,
            OptionToggle::Overwrite => &mut options.overwrite,
        };
        *slot = !*slot;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionItem {
    Toggle(OptionToggle),
    AeaKey,
    Device,
    Component(Component),
}

pub const OPTION_COUNT: usize = OptionToggle::ALL.len() + 2 + Component::ALL.len();

pub fn option_item(index: usize) -> Option<OptionItem> {
    let toggles = OptionToggle::ALL.len();
    if index < toggles {
        Some(OptionItem::Toggle(OptionToggle::ALL[index]))
    } else if index == toggles {
        Some(OptionItem::AeaKey)
    } else if index == toggles + 1 {
        Some(OptionItem::Device)
    } else {
        Component::ALL
            .get(index - toggles - 2)
            .copied()
            .map(OptionItem::Component)
    }
}

pub const FIRST_COMPONENT_OPTION: usize = OptionToggle::ALL.len() + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionSummary {
    pub files: usize,
    pub bytes: u64,
    pub components: usize,
}

#[derive(Debug, Clone, Default)]
pub struct RunView {
    pub total_items: usize,
    pub index: usize,
    pub current: String,
    pub action: Option<ItemAction>,
    pub done_bytes: u64,
    pub total_bytes: u64,
    pub log: VecDeque<String>,
    pub cancelling: bool,
}

impl RunView {
    pub fn fraction(&self) -> Option<f64> {
        (self.total_bytes > 0).then(|| self.done_bytes as f64 / self.total_bytes as f64)
    }
}

const LOG_LIMIT: usize = 64;

enum JobEvent {
    Loaded(Result<(Arc<IpswTree>, Option<IpswInfo>), String>),
    Progress(ExportProgress),
    Finished(Result<ExportReport, String>),
}

/// Dropping an export job joins its thread so the engine can kill `ipsw` and remove its work
/// folder; loads are detached because they cannot be interrupted.
struct IpswJob {
    cancel: Arc<AtomicBool>,
    rx: Receiver<JobEvent>,
    handle: Option<JoinHandle<()>>,
    join_on_drop: bool,
}

impl Drop for IpswJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if self.join_on_drop
            && let Some(handle) = self.handle.take()
        {
            let _ = handle.join();
        }
    }
}

struct TreeIndex {
    tree_id: usize,
    totals: HashMap<String, (usize, u64)>,
    children: HashMap<String, Vec<(String, bool)>>,
}

impl TreeIndex {
    fn build(tree: &IpswTree, tree_id: usize) -> Self {
        let mut totals: HashMap<String, (usize, u64)> = HashMap::new();
        for name in tree.names() {
            let size = tree.entry(name).map(|entry| entry.size).unwrap_or(0);
            for prefix in ancestors(name) {
                if let Some(total) = totals.get_mut(prefix) {
                    total.0 += 1;
                    total.1 += size;
                } else {
                    totals.insert(prefix.to_string(), (1, size));
                }
            }
        }
        Self {
            tree_id,
            totals,
            children: HashMap::new(),
        }
    }

    /// Cached because `IpswTree::children` is O(entries).
    fn children_of(&mut self, tree: &IpswTree, directory: &str) -> Vec<(String, bool)> {
        if let Some(kids) = self.children.get(directory) {
            return kids.clone();
        }
        let mut kids = tree.children(directory);
        kids.sort_by_cached_key(|(name, is_dir)| (!*is_dir, name.to_lowercase()));
        self.children.insert(directory.to_string(), kids.clone());
        kids
    }
}

fn ancestors(name: &str) -> impl Iterator<Item = &str> {
    name.match_indices('/').map(move |(i, _)| &name[..i])
}

fn join_path(directory: &str, child: &str) -> String {
    if directory.is_empty() {
        child.to_string()
    } else {
        format!("{directory}/{child}")
    }
}

fn base_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn mark_for(selected: usize, total: usize) -> Mark {
    if total == 0 || selected == 0 {
        Mark::None
    } else if selected >= total {
        Mark::Full
    } else {
        Mark::Partial
    }
}

#[derive(Default)]
struct RowCache {
    valid: bool,
    key: u64,
    rows: Vec<IpswRow>,
    selected_bytes: u64,
}

pub struct IpswState {
    pub cli: Option<PathBuf>,
    pub phase: IpswPhase,
    pub pane: IpswPane,
    pub archive: Option<PathBuf>,
    pub tree: Option<Arc<IpswTree>>,
    pub info: Option<IpswInfo>,
    pub expanded: BTreeSet<String>,
    pub selected: BTreeSet<String>,
    pub options: ExportOptions,
    pub components: BTreeSet<Component>,
    pub device: Option<String>,
    pub report: Option<ExportReport>,
    pub error: Option<String>,
    pub output: Option<PathBuf>,
    pub cursor: usize,
    pub filter: String,
    pub filter_editing: bool,
    pub option_cursor: usize,
    pub aea_editing: bool,
    pub page_rows: usize,
    pub status: String,
    pub progress: Option<f64>,
    pub run: RunView,
    pub done_scroll: usize,
    job: Option<IpswJob>,
    index: RefCell<Option<TreeIndex>>,
    cache: RefCell<RowCache>,
}

impl Default for IpswState {
    fn default() -> Self {
        Self {
            cli: None,
            phase: IpswPhase::Path,
            pane: IpswPane::Tree,
            archive: None,
            tree: None,
            info: None,
            expanded: BTreeSet::new(),
            selected: BTreeSet::new(),
            options: ExportOptions::default(),
            components: BTreeSet::new(),
            device: None,
            report: None,
            error: None,
            output: None,
            cursor: 0,
            filter: String::new(),
            filter_editing: false,
            option_cursor: 0,
            aea_editing: false,
            page_rows: 10,
            status: String::new(),
            progress: None,
            run: RunView::default(),
            done_scroll: 0,
            job: None,
            index: RefCell::new(None),
            cache: RefCell::new(RowCache::default()),
        }
    }
}

impl IpswState {
    pub fn wants_clipboard(&self) -> bool {
        matches!(self.phase, IpswPhase::Path | IpswPhase::Output)
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn reset_session(&mut self) {
        // The job holds a clone of the tree; join it before releasing ours.
        self.job = None;
        self.tree = None;
        self.info = None;
        self.archive = None;
        self.expanded.clear();
        self.selected.clear();
        self.components.clear();
        self.device = None;
        self.report = None;
        self.error = None;
        self.output = None;
        self.cursor = 0;
        self.filter.clear();
        self.filter_editing = false;
        self.option_cursor = 0;
        self.aea_editing = false;
        self.status.clear();
        self.progress = None;
        self.run = RunView::default();
        self.done_scroll = 0;
        self.pane = IpswPane::Tree;
        self.phase = IpswPhase::Path;
        *self.index.borrow_mut() = None;
        *self.cache.borrow_mut() = RowCache::default();
    }

    pub fn begin_load(&mut self, archive: PathBuf) {
        self.reset_session();
        let name = archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| archive.to_string_lossy().into_owned());
        self.status = format!("opening {name}");
        self.progress = Some(0.06);
        self.archive = Some(archive.clone());
        self.phase = IpswPhase::Loading;

        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("ipsw-open".into())
            .spawn(move || {
                let result = IpswTree::open(&archive)
                    .map(|tree| {
                        // An archive without a readable BuildManifest still opens.
                        let info = read_info(&tree).ok();
                        (Arc::new(tree), info)
                    })
                    .map_err(|error| error.to_string());
                let _ = tx.send(JobEvent::Loaded(result));
            });
        match spawned {
            Ok(handle) => {
                self.job = Some(IpswJob {
                    cancel,
                    rx,
                    handle: Some(handle),
                    join_on_drop: false,
                });
            }
            Err(error) => {
                self.phase = IpswPhase::Path;
                self.status.clear();
                self.progress = None;
                self.error = Some(format!("could not start reading the archive: {error}"));
            }
        }
    }

    pub fn cancel_load(&mut self) {
        self.job = None;
        self.archive = None;
        self.status.clear();
        self.progress = None;
        self.phase = IpswPhase::Path;
    }

    pub fn request_cancel(&mut self) {
        if let Some(job) = self.job.as_ref() {
            job.cancel.store(true, Ordering::SeqCst);
            self.run.cancelling = true;
        }
    }

    pub fn poll_job(&mut self) -> bool {
        let mut changed = false;
        loop {
            let Some(job) = self.job.as_ref() else {
                return changed;
            };
            match job.rx.try_recv() {
                Ok(event) => {
                    changed = true;
                    self.apply_event(event);
                }
                Err(TryRecvError::Empty) => return changed,
                Err(TryRecvError::Disconnected) => {
                    self.job = None;
                    self.worker_vanished();
                    return true;
                }
            }
        }
    }

    fn worker_vanished(&mut self) {
        match self.phase {
            IpswPhase::Loading => {
                self.phase = IpswPhase::Path;
                self.status.clear();
                self.progress = None;
                self.error = Some("opening the archive was interrupted".into());
            }
            IpswPhase::Exporting => {
                self.phase = IpswPhase::Browse;
                self.error = Some("the export stopped unexpectedly".into());
            }
            _ => {}
        }
    }

    fn apply_event(&mut self, event: JobEvent) {
        match event {
            JobEvent::Loaded(result) => {
                self.job = None;
                self.status.clear();
                self.progress = None;
                match result {
                    Ok((tree, info)) => {
                        self.tree = Some(tree);
                        self.info = info;
                        self.cursor = 0;
                        self.pane = IpswPane::Tree;
                        self.phase = IpswPhase::Browse;
                    }
                    Err(message) => {
                        self.archive = None;
                        self.error = Some(message);
                        self.phase = IpswPhase::Path;
                    }
                }
            }
            JobEvent::Progress(progress) => self.apply_progress(progress),
            JobEvent::Finished(result) => {
                self.job = None;
                match result {
                    Ok(report) => {
                        self.report = Some(report);
                        self.done_scroll = 0;
                        self.phase = IpswPhase::Done;
                    }
                    Err(message) => {
                        self.error = Some(message);
                        self.phase = IpswPhase::Browse;
                    }
                }
            }
        }
    }

    fn apply_progress(&mut self, progress: ExportProgress) {
        match progress {
            ExportProgress::Started {
                total_items,
                total_bytes,
            } => {
                self.run.total_items = total_items;
                self.run.total_bytes = total_bytes;
            }
            ExportProgress::Item {
                index,
                name,
                action,
            } => {
                self.run.index = index;
                self.run.current = name;
                self.run.action = Some(action);
            }
            ExportProgress::Bytes { done, total } => {
                self.run.done_bytes = done;
                if total > 0 {
                    self.run.total_bytes = total;
                }
            }
            ExportProgress::Log(line) => {
                if self.run.log.len() >= LOG_LIMIT {
                    self.run.log.pop_front();
                }
                self.run.log.push_back(line);
            }
        }
    }

    fn cache_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.tree
            .as_ref()
            .map(|tree| Arc::as_ptr(tree) as usize)
            .hash(&mut hasher);
        self.filter.hash(&mut hasher);
        self.expanded.hash(&mut hasher);
        self.selected.hash(&mut hasher);
        hasher.finish()
    }

    /// `children` and `names_under` are O(entries), so rebuild only when the key changes.
    fn refresh(&self) {
        let key = self.cache_key();
        {
            let cache = self.cache.borrow();
            if cache.valid && cache.key == key {
                return;
            }
        }
        let mut fresh = match self.tree.as_ref() {
            Some(tree) => self.rebuild(tree),
            None => RowCache::default(),
        };
        fresh.valid = true;
        fresh.key = key;
        *self.cache.borrow_mut() = fresh;
    }

    fn rebuild(&self, tree: &IpswTree) -> RowCache {
        let tree_id = tree as *const IpswTree as usize;
        let mut index_slot = self.index.borrow_mut();
        if index_slot.as_ref().map(|index| index.tree_id) != Some(tree_id) {
            *index_slot = Some(TreeIndex::build(tree, tree_id));
        }
        let index = index_slot.as_mut().expect("index was just built");

        let selected_bytes = self
            .selected
            .iter()
            .filter_map(|name| tree.entry(name))
            .map(|entry| entry.size)
            .sum();

        let tag_for = |name: &str| -> Option<&'static str> {
            if tree
                .entry(name)
                .is_some_and(|entry| entry.kind == EntryKind::Symlink)
            {
                Some("link")
            } else if is_aea_name(name) {
                Some("aea")
            } else if looks_like_im4p_name(name) {
                Some("im4p")
            } else {
                None
            }
        };
        let empty_catalog = IpswCatalog::default();
        let catalog = self
            .info
            .as_ref()
            .map(|info| &info.catalog)
            .unwrap_or(&empty_catalog);
        let file_row = |name: &str, depth: usize| {
            let found = catalog.describe(name);
            IpswRow {
                name: name.to_string(),
                label: base_name(name).to_string(),
                depth,
                is_dir: false,
                expanded: false,
                size: tree.entry(name).map(|entry| entry.size).unwrap_or(0),
                mark: if self.selected.contains(name) {
                    Mark::Full
                } else {
                    Mark::None
                },
                tag: tag_for(name),
                device_count: found.as_ref().map_or(0, |found| found.devices.len()),
                chips: found
                    .as_ref()
                    .map(|found| found.chips.clone())
                    .unwrap_or_default(),
                description: found.map(|found| found.summary),
            }
        };

        let mut rows = Vec::new();
        if self.filter.is_empty() {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for name in &self.selected {
                for prefix in ancestors(name) {
                    *counts.entry(prefix).or_insert(0) += 1;
                }
            }
            let mut walk = Walk {
                tree,
                index,
                catalog,
                expanded: &self.expanded,
                counts: &counts,
                rows: &mut rows,
                file_row: &file_row,
            };
            walk.directory("", 0);
        } else {
            let needle = self.filter.to_lowercase();
            for name in tree.names() {
                if name.to_lowercase().contains(&needle)
                    || catalog.search_text(name).contains(&needle)
                {
                    rows.push(file_row(name, 0));
                }
            }
        }
        RowCache {
            valid: true,
            key: 0,
            rows,
            selected_bytes,
        }
    }

    fn cached(&self) -> Ref<'_, RowCache> {
        self.refresh();
        self.cache.borrow()
    }

    pub fn rows(&self) -> Vec<IpswRow> {
        self.cached().rows.clone()
    }

    pub fn row_count(&self) -> usize {
        self.cached().rows.len()
    }

    pub fn row_at(&self, index: usize) -> Option<IpswRow> {
        self.cached().rows.get(index).cloned()
    }

    pub fn with_rows<R>(&self, f: impl FnOnce(&[IpswRow]) -> R) -> R {
        f(&self.cached().rows)
    }

    pub fn describe(&self, name: &str) -> Option<Description> {
        match self.info.as_ref() {
            Some(info) => info.catalog.describe(name),
            None => IpswCatalog::default().describe(name),
        }
    }

    pub fn device_names(&self) -> Vec<String> {
        let Some(info) = self.info.as_ref() else {
            return Vec::new();
        };
        let mut names: Vec<String> = Vec::new();
        for (_, title) in info.catalog.boards() {
            if !names.contains(&title) {
                names.push(title);
            }
        }
        if names.is_empty() {
            names = info.product_types.clone();
        }
        names
    }

    pub fn device_name(&self, product_type: &str) -> Option<String> {
        self.info
            .as_ref()
            .and_then(|info| info.catalog.product_name(product_type))
    }

    pub fn device_label(&self, product_type: &str) -> String {
        match self
            .info
            .as_ref()
            .and_then(|info| info.catalog.product_name(product_type))
        {
            Some(name) => format!("{product_type}  {name}"),
            None => product_type.to_string(),
        }
    }

    pub fn device_families(&self) -> Vec<(String, usize)> {
        self.info
            .as_ref()
            .map(|info| info.catalog.device_families())
            .unwrap_or_default()
    }

    pub fn folder_totals(&self, directory: &str) -> (usize, u64) {
        self.refresh();
        self.index
            .borrow()
            .as_ref()
            .and_then(|index| index.totals.get(directory).copied())
            .unwrap_or((0, 0))
    }

    pub fn export_note(&self, row: &IpswRow) -> &'static str {
        match row.tag {
            Some("link") => "recreated as a link",
            Some("aea") if self.options.decrypt_aea => "decrypted on export",
            Some("aea") => "copied still encrypted",
            Some("im4p") if self.options.decompress_im4p => "decompressed on export",
            _ => "copied as is",
        }
    }

    pub fn summary(&self) -> SelectionSummary {
        SelectionSummary {
            files: self.selected.len(),
            bytes: self.cached().selected_bytes,
            components: self.components.len(),
        }
    }

    pub fn clamp_cursor(&mut self) {
        let last = self.row_count().saturating_sub(1);
        self.cursor = self.cursor.min(last);
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            self.cursor = 0;
            return;
        }
        let next = (self.cursor as isize).saturating_add(delta);
        self.cursor = next.clamp(0, count as isize - 1) as usize;
    }

    pub fn jump_cursor(&mut self, to_end: bool) {
        self.cursor = if to_end {
            self.row_count().saturating_sub(1)
        } else {
            0
        };
    }

    fn files_of(&self, row: &IpswRow) -> Vec<String> {
        if !row.is_dir {
            return vec![row.name.clone()];
        }
        match self.tree.as_ref() {
            Some(tree) => tree.names_under(&row.name).map(str::to_string).collect(),
            None => Vec::new(),
        }
    }

    fn set_selected(&mut self, files: &[String], on: bool) {
        for file in files {
            if on {
                self.selected.insert(file.clone());
            } else {
                self.selected.remove(file);
            }
        }
    }

    pub fn toggle_row(&mut self, index: usize) {
        let Some(row) = self.row_at(index) else {
            return;
        };
        let files = self.files_of(&row);
        if files.is_empty() {
            return;
        }
        let all = files.iter().all(|file| self.selected.contains(file));
        self.set_selected(&files, !all);
    }

    pub fn toggle_all(&mut self) {
        let scope: Vec<String> = if self.filter.is_empty() {
            match self.tree.as_ref() {
                Some(tree) => tree.names().map(str::to_string).collect(),
                None => return,
            }
        } else {
            self.with_rows(|rows| {
                rows.iter()
                    .filter(|row| !row.is_dir)
                    .map(|row| row.name.clone())
                    .collect()
            })
        };
        if scope.is_empty() {
            return;
        }
        let all = scope.iter().all(|file| self.selected.contains(file));
        self.set_selected(&scope, !all);
    }

    pub fn clear_selection(&mut self) {
        self.selected.clear();
        self.components.clear();
    }

    pub fn activate_row(&mut self) {
        let Some(row) = self.row_at(self.cursor) else {
            return;
        };
        if row.is_dir {
            if !self.expanded.remove(&row.name) {
                self.expanded.insert(row.name);
            }
        } else {
            self.toggle_row(self.cursor);
        }
    }

    pub fn expand_or_enter(&mut self) {
        if !self.filter.is_empty() {
            return;
        }
        let Some(row) = self.row_at(self.cursor) else {
            return;
        };
        if !row.is_dir {
            return;
        }
        if !row.expanded {
            self.expanded.insert(row.name);
            return;
        }
        if self
            .row_at(self.cursor + 1)
            .is_some_and(|next| next.depth > row.depth)
        {
            self.cursor += 1;
        }
    }

    pub fn collapse_or_parent(&mut self) {
        if !self.filter.is_empty() {
            return;
        }
        let Some(row) = self.row_at(self.cursor) else {
            return;
        };
        if row.is_dir && row.expanded {
            self.expanded.remove(&row.name);
            return;
        }
        if row.depth == 0 {
            return;
        }
        let parent = self.with_rows(|rows| {
            rows[..self.cursor.min(rows.len())]
                .iter()
                .rposition(|candidate| candidate.depth < row.depth)
        });
        if let Some(parent) = parent {
            self.cursor = parent;
        }
    }

    pub fn filter_push(&mut self, c: char) {
        self.filter.push(c);
        self.cursor = 0;
    }

    pub fn filter_pop(&mut self) {
        self.filter.pop();
        self.cursor = 0;
    }

    pub fn filter_clear(&mut self) {
        self.filter.clear();
        self.filter_editing = false;
        self.cursor = 0;
    }

    pub fn device_choices(&self) -> Vec<Option<String>> {
        let mut choices = vec![None];
        if let Some(info) = self.info.as_ref() {
            choices.extend(info.product_types.iter().cloned().map(Some));
        }
        choices
    }

    pub fn cycle_device(&mut self, delta: isize) {
        let choices = self.device_choices();
        let at = choices
            .iter()
            .position(|choice| *choice == self.device)
            .unwrap_or(0) as isize;
        let next = (at + delta).rem_euclid(choices.len() as isize) as usize;
        self.device = choices[next].clone();
    }

    pub fn move_option_cursor(&mut self, delta: isize) {
        let next = (self.option_cursor as isize).saturating_add(delta);
        self.option_cursor = next.clamp(0, OPTION_COUNT as isize - 1) as usize;
    }

    pub fn activate_option(&mut self) {
        match option_item(self.option_cursor) {
            Some(OptionItem::Toggle(toggle)) => toggle.flip(&mut self.options),
            Some(OptionItem::AeaKey) => self.aea_editing = true,
            Some(OptionItem::Device) => self.cycle_device(1),
            Some(OptionItem::Component(component)) => self.toggle_component(component),
            None => {}
        }
    }

    fn toggle_component(&mut self, component: Component) {
        if !self.components.remove(&component) {
            self.components.insert(component);
        }
    }

    pub fn aea_key_push(&mut self, c: char) {
        self.options.aea_key.get_or_insert_with(String::new).push(c);
    }

    pub fn aea_key_pop(&mut self) {
        if let Some(key) = self.options.aea_key.as_mut() {
            key.pop();
            if key.is_empty() {
                self.options.aea_key = None;
            }
        }
    }

    pub fn default_output(&self) -> Option<PathBuf> {
        let archive = self.archive.as_deref()?;
        let stem = archive.file_stem()?.to_string_lossy().into_owned();
        let parent = match archive.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        Some(parent.join(format!("{stem}-export")))
    }

    pub fn begin_output(&mut self) -> bool {
        if self.selected.is_empty() && self.components.is_empty() {
            self.error = Some("select files or components first".into());
            return false;
        }
        let files: Vec<String> = self.selected.iter().cloned().collect();
        if let Err(message) = plan_destinations(&files, &self.options) {
            self.error = Some(message);
            return false;
        }
        self.error = None;
        self.phase = IpswPhase::Output;
        true
    }

    pub fn build_request(&self, output: PathBuf) -> ExportRequest {
        let files = match self.tree.as_ref() {
            Some(tree) => self
                .selected
                .iter()
                .filter(|name| tree.contains_file(name))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        let mut options = self.options.clone();
        options.aea_key = options
            .aea_key
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty());
        ExportRequest {
            files,
            components: self.components.iter().copied().collect(),
            device: self.device.clone(),
            output,
            options,
        }
    }

    pub fn start_export(&mut self, output: PathBuf) {
        let Some(tree) = self.tree.clone() else {
            return;
        };
        self.job = None;
        let request = self.build_request(output.clone());
        let cli = self.cli.clone();
        self.run = RunView::default();
        self.report = None;
        self.error = None;
        self.output = Some(output);
        self.phase = IpswPhase::Exporting;

        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("ipsw-export".into())
            .spawn(move || {
                let mut last_bytes = Instant::now();
                let mut progress = |event: ExportProgress| {
                    if let ExportProgress::Bytes { done, total } = &event {
                        // Byte updates arrive per buffer; the screen needs a few per second.
                        if done < total && last_bytes.elapsed() < Duration::from_millis(40) {
                            return;
                        }
                        last_bytes = Instant::now();
                    }
                    let _ = tx.send(JobEvent::Progress(event));
                };
                let result = run_export(&tree, cli.as_deref(), &request, &flag, &mut progress)
                    .map_err(|error| error.to_string());
                let _ = tx.send(JobEvent::Finished(result));
            });
        match spawned {
            Ok(handle) => {
                self.job = Some(IpswJob {
                    cancel,
                    rx,
                    handle: Some(handle),
                    join_on_drop: true,
                });
            }
            Err(error) => {
                self.phase = IpswPhase::Browse;
                self.error = Some(format!("could not start the export: {error}"));
            }
        }
    }

    pub fn done_items(&self) -> Vec<&ItemReport> {
        let Some(report) = self.report.as_ref() else {
            return Vec::new();
        };
        let rank = |item: &ItemReport| match item.outcome {
            Outcome::Failed { .. } => 0,
            Outcome::Kept { .. } => 1,
            _ => 2,
        };
        let mut items: Vec<&ItemReport> = report.items.iter().collect();
        items.sort_by_key(|item| rank(item));
        items
    }

    pub fn scroll_done(&mut self, delta: isize) {
        let last = self.done_items().len().saturating_sub(1) as isize;
        self.done_scroll = (self.done_scroll as isize)
            .saturating_add(delta)
            .clamp(0, last) as usize;
    }
}

struct Walk<'a, F: Fn(&str, usize) -> IpswRow> {
    tree: &'a IpswTree,
    index: &'a mut TreeIndex,
    catalog: &'a IpswCatalog,
    expanded: &'a BTreeSet<String>,
    counts: &'a HashMap<&'a str, usize>,
    rows: &'a mut Vec<IpswRow>,
    file_row: &'a F,
}

impl<F: Fn(&str, usize) -> IpswRow> Walk<'_, F> {
    fn directory(&mut self, directory: &str, depth: usize) {
        for (child, is_dir) in self.index.children_of(self.tree, directory) {
            let full = join_path(directory, &child);
            if !is_dir {
                self.rows.push((self.file_row)(&full, depth));
                continue;
            }
            let (total, size) = self.index.totals.get(&full).copied().unwrap_or((0, 0));
            let selected = self.counts.get(full.as_str()).copied().unwrap_or(0);
            let expanded = self.expanded.contains(&full);
            self.rows.push(IpswRow {
                name: full.clone(),
                label: child,
                depth,
                is_dir: true,
                expanded,
                size,
                mark: mark_for(selected, total),
                tag: None,
                description: self.catalog.describe_folder(&full),
                chips: Vec::new(),
                device_count: 0,
            });
            if expanded {
                self.directory(&full, depth + 1);
            }
        }
    }
}

pub fn resolve_new_folder(text: &str) -> Result<PathBuf, String> {
    let trimmed = text.trim();
    let unquoted = match (trimmed.chars().next(), trimmed.chars().last()) {
        (Some('"'), Some('"')) | (Some('\''), Some('\'')) if trimmed.len() >= 2 => {
            &trimmed[1..trimmed.len() - 1]
        }
        _ => trimmed,
    };
    if unquoted.is_empty() {
        return Err("type a folder path".into());
    }
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    let mut path = if unquoted == "~" {
        home().ok_or_else(|| "HOME is not set".to_string())?
    } else if let Some(rest) = unquoted.strip_prefix("~/") {
        home()
            .ok_or_else(|| "HOME is not set".to_string())?
            .join(rest)
    } else {
        PathBuf::from(unquoted)
    };
    if path.is_relative() {
        let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
        path = cwd.join(path);
    }
    if path.is_file() {
        return Err(format!("{} is a file, not a folder", path.display()));
    }
    if let Some(existing) = path.ancestors().find(|ancestor| ancestor.exists())
        && !existing.is_dir()
    {
        return Err(format!("{} is not a folder", existing.display()));
    }
    Ok(path)
}

impl App {
    pub fn open_ipsw(&mut self, path: &str) {
        self.ipsw.begin_load(PathBuf::from(path));
    }

    pub(crate) fn poll_ipsw_job(&mut self) {
        self.ipsw.poll_job();
        if self.ipsw.phase == IpswPhase::Loading && self.ipsw.busy() {
            Self::nudge_progress(&mut self.ipsw.progress, 0.04, 0.92);
        }
    }

    pub fn drain_ipsw_job(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while self.ipsw.busy() {
            self.ipsw.poll_job();
            if self.ipsw.busy() {
                if Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    pub fn ipsw_busy(&self) -> bool {
        self.ipsw.busy()
    }

    pub(crate) fn ipsw_key(&mut self, key: KeyEvent) -> bool {
        match self.ipsw.phase {
            IpswPhase::Path => self.ipsw_path_key(key),
            IpswPhase::Loading => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc => {
                    self.ipsw.cancel_load();
                    false
                }
                _ => false,
            },
            IpswPhase::Browse => self.ipsw_browse_key(key),
            IpswPhase::Output => self.ipsw_output_key(key),
            IpswPhase::Exporting => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Char('x') => {
                    self.ipsw.request_cancel();
                    false
                }
                _ => false,
            },
            IpswPhase::Done => match key.code {
                KeyCode::Char('q') => true,
                KeyCode::Esc | KeyCode::Enter => {
                    self.ipsw.report = None;
                    self.ipsw.phase = IpswPhase::Browse;
                    false
                }
                KeyCode::Char('n') => {
                    self.ipsw_start_over();
                    false
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.ipsw.scroll_done(-1);
                    false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.ipsw.scroll_done(1);
                    false
                }
                KeyCode::PageUp => {
                    self.ipsw
                        .scroll_done(-(self.ipsw.page_rows.max(1) as isize));
                    false
                }
                KeyCode::PageDown => {
                    self.ipsw.scroll_done(self.ipsw.page_rows.max(1) as isize);
                    false
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.ipsw.done_scroll = 0;
                    false
                }
                KeyCode::End | KeyCode::Char('G') => {
                    self.ipsw.scroll_done(isize::MAX / 2);
                    false
                }
                _ => false,
            },
        }
    }

    fn ipsw_start_over(&mut self) {
        self.ipsw.reset_session();
        self.enter_file_picker();
    }

    fn ipsw_path_key(&mut self, key: KeyEvent) -> bool {
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
                if let Some(path) = self.take_picker_file() {
                    self.open_ipsw(&path);
                } else if self.resolve_picker_file().is_some() {
                    self.ipsw.error = Some("choose an IPSW file, not a folder".into());
                }
                false
            }
            _ => false,
        }
    }

    fn ipsw_output_key(&mut self, key: KeyEvent) -> bool {
        if self.file_picker_edit_key(key) {
            return false;
        }
        match key.code {
            KeyCode::Char('q') => true,
            KeyCode::Esc => {
                self.clear_path_input();
                self.ipsw.error = None;
                self.ipsw.phase = IpswPhase::Browse;
                false
            }
            KeyCode::Enter => {
                match self.resolve_ipsw_output() {
                    Ok(path) => {
                        self.clear_path_input();
                        self.ipsw.start_export(path);
                    }
                    Err(message) => self.ipsw.error = Some(message),
                }
                false
            }
            _ => false,
        }
    }

    /// `clip::inspect` only sees paths that exist, so a typed folder still to be created goes
    /// through `resolve_new_folder`.
    fn resolve_ipsw_output(&self) -> Result<PathBuf, String> {
        let typed = self.path_input.trim();
        if !typed.is_empty() {
            return match clip::inspect(typed) {
                Some(info) if info.path.is_dir() => Ok(info.path),
                Some(info) => Err(format!("{} is a file, not a folder", info.path.display())),
                None => resolve_new_folder(typed),
            };
        }
        if let Some(file) = self.clip.file.as_ref()
            && file.path.is_dir()
        {
            return Ok(file.path.clone());
        }
        self.ipsw
            .default_output()
            .ok_or_else(|| "no archive is open".to_string())
    }

    fn ipsw_browse_key(&mut self, key: KeyEvent) -> bool {
        self.ipsw.error = None;
        self.ipsw.clamp_cursor();

        if self.ipsw.filter_editing {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.ipsw.filter_editing = false,
                KeyCode::Backspace => self.ipsw.filter_pop(),
                KeyCode::Up => self.ipsw.move_cursor(-1),
                KeyCode::Down => self.ipsw.move_cursor(1),
                _ => {
                    if let Some(c) = Self::typing_char(key) {
                        self.ipsw.filter_push(c);
                    }
                }
            }
            return false;
        }
        if self.ipsw.aea_editing {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.ipsw.aea_editing = false,
                KeyCode::Backspace => self.ipsw.aea_key_pop(),
                _ => {
                    if let Some(c) = Self::typing_char(key)
                        && !c.is_whitespace()
                    {
                        self.ipsw.aea_key_push(c);
                    }
                }
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => {
                if self.ipsw.filter.is_empty() {
                    self.ipsw_start_over();
                } else {
                    self.ipsw.filter_clear();
                }
                return false;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.ipsw.pane = match self.ipsw.pane {
                    IpswPane::Tree => IpswPane::Options,
                    IpswPane::Options => IpswPane::Tree,
                };
                return false;
            }
            KeyCode::Char('e') => {
                if self.ipsw.begin_output() {
                    self.enter_file_picker();
                }
                return false;
            }
            KeyCode::Char('x') => {
                self.ipsw.clear_selection();
                return false;
            }
            KeyCode::Char('/') => {
                self.ipsw.pane = IpswPane::Tree;
                self.ipsw.filter_editing = true;
                return false;
            }
            _ => {}
        }

        match self.ipsw.pane {
            IpswPane::Tree => self.ipsw_tree_key(key),
            IpswPane::Options => self.ipsw_options_key(key),
        }
        false
    }

    fn ipsw_tree_key(&mut self, key: KeyEvent) {
        let page = self.ipsw.page_rows.max(1) as isize;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.ipsw.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.ipsw.move_cursor(1),
            KeyCode::PageUp => self.ipsw.move_cursor(-page),
            KeyCode::PageDown => self.ipsw.move_cursor(page),
            KeyCode::Home | KeyCode::Char('g') => self.ipsw.jump_cursor(false),
            KeyCode::End | KeyCode::Char('G') => self.ipsw.jump_cursor(true),
            KeyCode::Right | KeyCode::Char('l') => self.ipsw.expand_or_enter(),
            KeyCode::Left | KeyCode::Char('h') => self.ipsw.collapse_or_parent(),
            KeyCode::Enter => self.ipsw.activate_row(),
            KeyCode::Char(' ') => {
                let cursor = self.ipsw.cursor;
                self.ipsw.toggle_row(cursor);
            }
            KeyCode::Char('a') => self.ipsw.toggle_all(),
            _ => {}
        }
    }

    fn ipsw_options_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.ipsw.move_option_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.ipsw.move_option_cursor(1),
            KeyCode::PageUp => self.ipsw.move_option_cursor(-5),
            KeyCode::PageDown => self.ipsw.move_option_cursor(5),
            KeyCode::Home | KeyCode::Char('g') => self.ipsw.option_cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.ipsw.option_cursor = OPTION_COUNT - 1,
            KeyCode::Left | KeyCode::Char('h') => {
                if option_item(self.ipsw.option_cursor) == Some(OptionItem::Device) {
                    self.ipsw.cycle_device(-1);
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if option_item(self.ipsw.option_cursor) == Some(OptionItem::Device) {
                    self.ipsw.cycle_device(1);
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.ipsw.activate_option(),
            _ => {}
        }
    }

    pub(crate) fn ipsw_paste(&mut self, text: &str) -> bool {
        if self.ipsw.phase != IpswPhase::Browse {
            return false;
        }
        let line = text.lines().map(str::trim).find(|line| !line.is_empty());
        if self.ipsw.filter_editing {
            for c in line.unwrap_or("").chars() {
                self.ipsw.filter_push(c);
            }
            return true;
        }
        if self.ipsw.aea_editing {
            for c in line.unwrap_or("").chars().filter(|c| !c.is_whitespace()) {
                self.ipsw.aea_key_push(c);
            }
            return true;
        }
        false
    }

    pub(crate) fn ipsw_click(&mut self, col: u16, row: u16) {
        if self.ipsw.phase != IpswPhase::Browse {
            return;
        }
        self.ipsw.filter_editing = false;
        self.ipsw.aea_editing = false;
        if let Some(index) = self.hits.ipsw_option_at(col, row) {
            self.ipsw.pane = IpswPane::Options;
            self.ipsw.option_cursor = index;
            self.ipsw.activate_option();
            return;
        }
        if let Some(index) = self.hits.ipsw_tree_row_at(col, row) {
            self.ipsw.pane = IpswPane::Tree;
            if index == self.ipsw.cursor {
                self.ipsw.activate_row();
            } else {
                self.ipsw.cursor = index;
            }
        }
    }

    pub(crate) fn ipsw_scroll(&mut self, col: u16, row: u16, delta: isize) {
        match self.ipsw.phase {
            IpswPhase::Browse => {
                let over_options = self.hits.ipsw_option_at(col, row).is_some();
                let over_tree = self.hits.ipsw_tree_row_at(col, row).is_some();
                let pane = if over_options {
                    IpswPane::Options
                } else if over_tree {
                    IpswPane::Tree
                } else {
                    self.ipsw.pane
                };
                match pane {
                    IpswPane::Tree => self.ipsw.move_cursor(delta),
                    IpswPane::Options => self.ipsw.move_option_cursor(delta),
                }
            }
            IpswPhase::Done => self.ipsw.scroll_done(delta),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsw_fixture::{FIXTURE_DEVICES, sample_entries, write_ipsw};

    fn opened() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("Fixture_26.0.ipsw");
        write_ipsw(&archive, &sample_entries()).unwrap();
        let mut app = App::new();
        app.set_ipsw_cli(Some(PathBuf::from("/nonexistent/ipsw")));
        app.open_ipsw(archive.to_str().unwrap());
        assert_eq!(app.ipsw.phase, IpswPhase::Loading);
        app.drain_ipsw_job();
        (dir, app)
    }

    fn row_names(state: &IpswState) -> Vec<String> {
        state.rows().into_iter().map(|row| row.name).collect()
    }

    #[test]
    fn open_reads_the_tree_and_manifest() {
        let (_dir, app) = opened();
        assert_eq!(app.ipsw.phase, IpswPhase::Browse);
        let info = app.ipsw.info.as_ref().expect("manifest info");
        assert_eq!(
            info.product_types,
            FIXTURE_DEVICES.map(String::from).to_vec()
        );
        let names = row_names(&app.ipsw);
        assert!(names.contains(&"Firmware".to_string()));
        assert!(names.contains(&"BuildManifest.plist".to_string()));
        assert!(
            !names.iter().any(|name| name.starts_with("Firmware/")),
            "folders start collapsed"
        );
    }

    #[test]
    fn open_error_returns_to_path_with_the_message() {
        let mut app = App::new();
        app.set_ipsw_cli(Some(PathBuf::from("/nonexistent/ipsw")));
        app.open_ipsw("/nonexistent/missing.ipsw");
        app.drain_ipsw_job();
        assert_eq!(app.ipsw.phase, IpswPhase::Path);
        assert!(app.ipsw.error.is_some());
        assert!(app.ipsw.tree.is_none());
    }

    #[test]
    fn archive_without_a_manifest_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("plain.ipsw");
        write_ipsw(
            &archive,
            &[crate::ipsw_fixture::FixtureEntry::file(
                "a/b.txt",
                b"hi".to_vec(),
            )],
        )
        .unwrap();
        let mut app = App::new();
        app.open_ipsw(archive.to_str().unwrap());
        app.drain_ipsw_job();
        assert_eq!(app.ipsw.phase, IpswPhase::Browse);
        assert!(app.ipsw.info.is_none());
    }

    #[test]
    fn selecting_a_folder_selects_its_files_and_marks_partial_then_full() {
        let (_dir, mut app) = opened();
        let state = &mut app.ipsw;
        let folder = state
            .rows()
            .iter()
            .position(|row| row.name == "Firmware")
            .unwrap();
        state.cursor = folder;
        state.expand_or_enter();
        assert!(
            state
                .rows()
                .iter()
                .any(|row| row.name == "Firmware/notes.txt")
        );

        let leaf = state
            .rows()
            .iter()
            .position(|row| row.name == "Firmware/notes.txt")
            .unwrap();
        state.toggle_row(leaf);
        assert_eq!(state.rows()[folder].mark, Mark::Partial);

        state.toggle_row(folder);
        assert_eq!(state.rows()[folder].mark, Mark::Full);
        assert!(
            state
                .selected
                .contains("Firmware/dfu/iBEC.j414c.RELEASE.im4p")
        );

        state.toggle_row(folder);
        assert_eq!(state.rows()[folder].mark, Mark::None);
        assert!(state.selected.is_empty());
    }

    #[test]
    fn filter_lists_matches_flat_and_select_all_acts_on_them() {
        let (_dir, mut app) = opened();
        let state = &mut app.ipsw;
        state.filter = "IM4P".into();
        let names = row_names(state);
        assert!(!names.is_empty());
        assert!(
            names
                .iter()
                .all(|name| name.to_lowercase().contains("im4p"))
        );
        assert!(state.rows().iter().all(|row| row.depth == 0 && !row.is_dir));

        state.toggle_all();
        assert_eq!(state.selected.len(), names.len());
        state.toggle_all();
        assert!(state.selected.is_empty());
    }

    #[test]
    fn tags_mark_aea_im4p_and_links() {
        let (_dir, mut app) = opened();
        let tag_of = |state: &IpswState, name: &str| {
            state
                .rows()
                .into_iter()
                .find(|row| row.name == name)
                .and_then(|row| row.tag)
        };
        app.ipsw.filter = "a".into();
        assert_eq!(tag_of(&app.ipsw, "090-12345-001.dmg.aea"), Some("aea"));
        assert_eq!(tag_of(&app.ipsw, "Firmware/latest"), Some("link"));
        assert_eq!(
            tag_of(&app.ipsw, "kernelcache.release.mac14j"),
            Some("im4p")
        );
        assert_eq!(tag_of(&app.ipsw, "Firmware/notes.txt"), None);
    }

    #[test]
    fn export_needs_a_selection_and_cancels_cleanly_when_dropped() {
        let (_dir, mut app) = opened();
        assert!(!app.ipsw.begin_output());
        assert_eq!(
            app.ipsw.error.as_deref(),
            Some("select files or components first")
        );
        app.ipsw.selected.insert("Firmware/notes.txt".into());
        assert!(app.ipsw.begin_output());
        assert_eq!(app.ipsw.phase, IpswPhase::Output);

        let out = tempfile::tempdir().unwrap();
        app.ipsw.start_export(out.path().join("export"));
        assert_eq!(app.ipsw.phase, IpswPhase::Exporting);
        drop(app);
        // Dropping joined the worker, so the work folder is gone.
        let leftovers: Vec<_> = std::fs::read_dir(out.path().join("export"))
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".apple-utils-export-")
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn typed_folder_that_does_not_exist_yet_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fresh/export");
        let resolved = resolve_new_folder(target.to_str().unwrap()).unwrap();
        assert_eq!(resolved, target);

        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(resolve_new_folder(file.to_str().unwrap()).is_err());
        assert!(resolve_new_folder(file.join("below").to_str().unwrap()).is_err());
        assert!(resolve_new_folder("   ").is_err());
    }

    #[test]
    fn default_output_sits_next_to_the_archive() {
        let mut state = IpswState::default();
        assert_eq!(state.default_output(), None);
        state.archive = Some(PathBuf::from("/data/iPhone_26.0.ipsw"));
        assert_eq!(
            state.default_output(),
            Some(PathBuf::from("/data/iPhone_26.0-export"))
        );
    }

    #[test]
    fn device_cycles_through_all_and_the_manifest_devices() {
        let (_dir, mut app) = opened();
        let state = &mut app.ipsw;
        assert_eq!(state.device, None);
        state.cycle_device(1);
        assert_eq!(state.device.as_deref(), Some(FIXTURE_DEVICES[0]));
        state.cycle_device(1);
        assert_eq!(state.device.as_deref(), Some(FIXTURE_DEVICES[1]));
        state.cycle_device(1);
        assert_eq!(state.device, None);
        state.cycle_device(-1);
        assert_eq!(state.device.as_deref(), Some(FIXTURE_DEVICES[1]));
    }

    fn realistic() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("Realistic_26.0.ipsw");
        write_ipsw(&archive, &crate::ipsw_fixture::realistic_entries()).unwrap();
        let mut app = App::new();
        app.set_ipsw_cli(Some(PathBuf::from("/nonexistent/ipsw")));
        app.open_ipsw(archive.to_str().unwrap());
        app.drain_ipsw_job();
        assert_eq!(app.ipsw.phase, IpswPhase::Browse);
        (dir, app)
    }

    #[test]
    fn rows_carry_catalog_descriptions_and_folders_do_not() {
        let (_dir, app) = realistic();
        let rows = app.ipsw.rows();
        let ramdisk = rows
            .iter()
            .find(|row| row.name == "090-12345-003.dmg")
            .expect("erase ramdisk row");
        let text = ramdisk.description.as_deref().expect("description");
        assert!(text.starts_with("Restore ramdisk"), "{text}");
        assert!(text.contains("erase"), "{text}");
        let folder = rows.iter().find(|row| row.name == "Firmware").unwrap();
        assert_eq!(folder.description, None);
    }

    #[test]
    fn filter_matches_what_an_entry_is_not_just_its_path() {
        let (_dir, mut app) = realistic();
        let names_for = |app: &mut App, filter: &str| -> Vec<String> {
            app.ipsw.filter = filter.into();
            app.ipsw.rows().into_iter().map(|row| row.name).collect()
        };
        let mini = names_for(&mut app, "mac mini");
        assert!(
            mini.contains(&"kernelcache.release.mac14j".to_string()),
            "{mini:?}"
        );
        assert!(
            !mini.contains(&"kernelcache.release.mac14g".to_string()),
            "{mini:?}"
        );
        let erase = names_for(&mut app, "erase");
        assert!(
            erase.contains(&"090-12345-003.dmg".to_string()),
            "{erase:?}"
        );
        assert!(
            !erase.contains(&"090-12345-004.dmg".to_string()),
            "{erase:?}"
        );
        let cryptex = names_for(&mut app, "cryptex");
        assert!(
            cryptex.contains(&"090-12345-005.dmg.aea".to_string()),
            "{cryptex:?}"
        );
        assert!(
            !cryptex.contains(&"kernelcache.release.mac14j".to_string()),
            "{cryptex:?}"
        );
    }

    #[test]
    fn device_names_and_labels_use_the_manifest_boards() {
        let (_dir, app) = realistic();
        let names = app.ipsw.device_names();
        assert!(
            names.iter().any(|name| name.contains("Mac mini")),
            "{names:?}"
        );
        assert!(!names.iter().any(|name| name == "Mac14,3"), "{names:?}");
        let label = app.ipsw.device_label("Mac14,3");
        assert!(label.starts_with("Mac14,3"), "{label}");
        assert!(label.contains("Mac mini"), "{label}");
        assert_eq!(app.ipsw.device_label("Unknown9,9"), "Unknown9,9");
    }

    #[test]
    fn device_names_fall_back_to_product_types_without_boards() {
        let (_dir, app) = opened();
        assert_eq!(
            app.ipsw.device_names(),
            FIXTURE_DEVICES.map(String::from).to_vec()
        );
    }

    #[test]
    fn export_note_follows_the_options() {
        let (_dir, mut app) = realistic();
        let rows = app.ipsw.rows();
        let aea = rows
            .iter()
            .find(|row| row.name == "090-12345-001.dmg.aea")
            .unwrap();
        assert_eq!(app.ipsw.export_note(aea), "decrypted on export");
        app.ipsw.options.decrypt_aea = false;
        assert_eq!(app.ipsw.export_note(aea), "copied still encrypted");
        let plist = rows
            .iter()
            .find(|row| row.name == "BuildManifest.plist")
            .unwrap();
        assert_eq!(app.ipsw.export_note(plist), "copied as is");
    }

    #[test]
    fn aea_key_edits_collapse_to_none_when_empty() {
        let mut state = IpswState::default();
        state.aea_key_push('a');
        state.aea_key_push('b');
        assert_eq!(state.options.aea_key.as_deref(), Some("ab"));
        state.aea_key_pop();
        state.aea_key_pop();
        assert_eq!(state.options.aea_key, None);
    }
}
