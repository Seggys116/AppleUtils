use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use crate::clip::FileInfo;
use crate::recovery_model::{LogLevel, RecoveryAction, RecoveryEvent, RecoveryModel, SessionPhase};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCommand {
    ClaimDevice {
        device_id: String,
    },
    ReleaseDevice {
        device_id: String,
    },
    ProvideFile {
        device_id: String,
        request_id: String,
        path: String,
    },
    StartRestore {
        device_id: String,
    },
    CancelRestore {
        device_id: String,
    },
    RetryRestore {
        device_id: String,
    },
    SelectSystem {
        device_class: String,
    },
    SelectRestoreMode {
        mode: crate::recovery_model::RestoreMode,
    },
    Autosearch {
        device_id: String,
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryServiceError {
    pub message: String,
}

impl RecoveryServiceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait RecoveryService: Send {
    fn send(&mut self, command: RecoveryCommand) -> Result<(), RecoveryServiceError>;
    fn poll(&mut self) -> Vec<RecoveryEvent>;
}

#[derive(Debug, Default)]
pub struct NullRecoveryService;

impl RecoveryService for NullRecoveryService {
    fn send(&mut self, _command: RecoveryCommand) -> Result<(), RecoveryServiceError> {
        Ok(())
    }

    fn poll(&mut self) -> Vec<RecoveryEvent> {
        Vec::new()
    }
}

pub struct ChannelRecoveryService {
    command_tx: Sender<RecoveryCommand>,
    event_rx: Receiver<RecoveryEvent>,
}

pub struct RecoveryBridge {
    command_rx: Receiver<RecoveryCommand>,
    event_tx: Sender<RecoveryEvent>,
}

impl ChannelRecoveryService {
    pub fn pair() -> (Self, RecoveryBridge) {
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        (
            Self {
                command_tx,
                event_rx,
            },
            RecoveryBridge {
                command_rx,
                event_tx,
            },
        )
    }
}

impl RecoveryBridge {
    pub fn recv_command(&self) -> Result<RecoveryCommand, TryRecvError> {
        self.command_rx.try_recv()
    }

    pub fn emit(&self, event: RecoveryEvent) -> Result<(), RecoveryServiceError> {
        self.event_tx
            .send(event)
            .map_err(|_| RecoveryServiceError::new("Recovery event channel closed"))
    }
}

impl RecoveryService for ChannelRecoveryService {
    fn send(&mut self, command: RecoveryCommand) -> Result<(), RecoveryServiceError> {
        self.command_tx
            .send(command)
            .map_err(|_| RecoveryServiceError::new("Recovery command channel closed"))
    }

    fn poll(&mut self) -> Vec<RecoveryEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }
        events
    }
}

pub struct RecoveryRuntime {
    pub model: RecoveryModel,
    service: Box<dyn RecoveryService>,
}

impl Default for RecoveryRuntime {
    fn default() -> Self {
        Self::offline()
    }
}

impl RecoveryRuntime {
    pub fn offline() -> Self {
        let mut runtime = Self {
            model: RecoveryModel::default(),
            service: Box::new(NullRecoveryService),
        };
        runtime.seed_manifest_request();
        runtime
    }

    pub fn from_service(service: impl RecoveryService + 'static) -> Self {
        Self {
            model: RecoveryModel::default(),
            service: Box::new(service),
        }
    }

    fn seed_manifest_request(&mut self) {
        if self.model.requests.is_empty() {
            self.model.apply_event(RecoveryEvent::FileRequested(
                crate::recovery_model::initial_manifest_request(),
            ));
        }
    }

    pub fn prepare(&mut self) {
        for event in self.service.poll() {
            self.model.apply_event(event);
        }
        if self.model.claimed_device_id.is_none()
            && self.model.devices.is_empty()
            && self.model.requests.is_empty()
        {
            self.model.phase = SessionPhase::Waiting;
        }
        self.model.focus_open_request();
        if self.model.claimed_device_id.is_some()
            && self.model.can_start()
            && matches!(
                self.model.phase,
                SessionPhase::Collecting | SessionPhase::Ready
            )
        {
            self.start_restore();
        }
    }

    pub fn wants_clipboard(&self) -> bool {
        self.model.has_clipboard_target()
    }

    pub fn claim_selected(&mut self) {
        let Some(device) = self.model.selected_device().cloned() else {
            return;
        };
        if !self.model.can_claim() {
            return;
        }
        if self
            .service
            .send(RecoveryCommand::ClaimDevice {
                device_id: device.id.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not send claim request".into());
            self.model
                .push_log(LogLevel::Error, "Could not send claim request");
            return;
        }
        if let Some(entry) = self
            .model
            .devices
            .iter_mut()
            .find(|entry| entry.id == device.id)
        {
            entry.state = crate::recovery_model::DeviceState::Claiming;
        }
        self.model.phase = SessionPhase::Claiming;
        self.model.status_message = format!("Claiming {}", device.title);
        self.model.push_log(
            LogLevel::Info,
            format!("Claim request sent for {}", device.title),
        );
    }

    pub fn select_system(&mut self) {
        let Some(class) = self.model.selected_system_class().map(str::to_string) else {
            return;
        };
        if self
            .service
            .send(RecoveryCommand::SelectSystem {
                device_class: class.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not select the system".into());
            self.model
                .push_log(LogLevel::Error, "Could not select the system");
            return;
        }
        self.model.verifying = Some(crate::recovery_model::RestoreProgress {
            stage: "reading identity".into(),
            detail: class.clone(),
            fraction: None,
        });
        self.model.status_message = format!("Selecting {class}");
        self.model
            .push_log(LogLevel::Info, format!("System {class} requested"));
    }

    pub fn select_restore_mode(&mut self) {
        let Some(mode) = self.model.selected_restore_mode() else {
            return;
        };
        if self
            .service
            .send(RecoveryCommand::SelectRestoreMode { mode })
            .is_err()
        {
            self.model.last_error = Some("Could not select the restore mode".into());
            self.model
                .push_log(LogLevel::Error, "Could not select the restore mode");
            return;
        }
        self.model.verifying = Some(crate::recovery_model::RestoreProgress {
            stage: "reading identity".into(),
            detail: mode.title().to_string(),
            fraction: None,
        });
        self.model.status_message = format!("Selecting {}", mode.title());
        self.model
            .push_log(LogLevel::Info, format!("{} requested", mode.title()));
    }

    pub fn release_claim(&mut self) {
        let Some(device_id) = self.model.claimed_device_id.clone() else {
            return;
        };
        if self
            .service
            .send(RecoveryCommand::ReleaseDevice {
                device_id: device_id.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not release device".into());
            self.model
                .push_log(LogLevel::Error, "Could not release device");
            return;
        }
        self.model.status_message = "Release requested".into();
        self.model
            .push_log(LogLevel::Info, format!("Release requested for {device_id}"));
    }

    pub fn attach_clipboard(&mut self, file: &FileInfo) {
        if !self.model.can_attach() {
            return;
        }
        let device_id = self.model.claimed_device_id.clone().unwrap_or_default();
        if file.kind == crate::clip::FileKind::Directory {
            match self.model.match_all_handoffs(file) {
                Ok(hits) => {
                    let request_id = self
                        .model
                        .next_open_request()
                        .and_then(|index| self.model.requests.get(index))
                        .map(|request| request.spec.request_id.clone())
                        .or_else(|| {
                            self.model
                                .selected_request()
                                .map(|request| request.spec.request_id.clone())
                        })
                        .unwrap_or_default();
                    if self
                        .service
                        .send(RecoveryCommand::ProvideFile {
                            device_id,
                            request_id,
                            path: file.path.to_string_lossy().into_owned(),
                        })
                        .is_err()
                    {
                        self.model.reject_clipboard_assignment(
                            file.clone(),
                            "Could not send folder handoff".into(),
                        );
                        return;
                    }
                    self.model.verifying = Some(crate::recovery_model::RestoreProgress {
                        stage: "scanning".into(),
                        detail: file.name.clone(),
                        fraction: None,
                    });
                    self.model.status_message = format!(
                        "Scanning {} for {} file{}",
                        file.name,
                        hits.len(),
                        if hits.len() == 1 { "" } else { "s" }
                    );
                    self.model.push_log(
                        LogLevel::Info,
                        format!(
                            "Scanning {} for {} remaining file{}",
                            file.name,
                            hits.len(),
                            if hits.len() == 1 { "" } else { "s" }
                        ),
                    );
                }
                Err(reason) => self.model.reject_clipboard_assignment(file.clone(), reason),
            }
            return;
        }
        let was_ready = self.model.all_required_files_supplied();
        match self.model.match_handoff(file) {
            Ok((index, resolved, note)) => {
                self.model.select_request(index);
                let request_id = self
                    .model
                    .requests
                    .get(index)
                    .map(|request| request.spec.request_id.clone())
                    .expect("matched request");
                let path = resolved.path.to_string_lossy().into_owned();
                if self
                    .service
                    .send(RecoveryCommand::ProvideFile {
                        device_id,
                        request_id: request_id.clone(),
                        path,
                    })
                    .is_err()
                {
                    self.model.reject_clipboard_assignment(
                        resolved,
                        "Could not send file handoff".into(),
                    );
                    return;
                }
                self.model.note_clipboard_assignment(&resolved, note);
                self.model.push_log(
                    LogLevel::Info,
                    format!("Queued {} for {}", resolved.name, request_id),
                );
                if self.model.all_required_files_supplied() {
                    self.model.phase = SessionPhase::Ready;
                }
                self.auto_start_if_ready_transitioned(was_ready);
            }
            Err(reason) => self.model.reject_clipboard_assignment(file.clone(), reason),
        }
    }

    pub fn autosearch(&mut self, folder: Option<&FileInfo>) {
        if !self.model.can_attach() {
            return;
        }
        let Some(folder) = folder.filter(|file| file.kind == crate::clip::FileKind::Directory)
        else {
            self.model.last_error = Some("Copy or type a file or folder".into());
            self.model
                .push_log(LogLevel::Warn, "Copy or type a file or folder");
            return;
        };
        let device_id = self.model.claimed_device_id.clone().unwrap_or_default();
        let path = folder.path.to_string_lossy().into_owned();
        if self
            .service
            .send(RecoveryCommand::Autosearch {
                device_id,
                path: path.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not start autosearch".into());
            self.model
                .push_log(LogLevel::Error, "Could not start autosearch");
            return;
        }
        self.model.last_error = None;
        self.model.verifying = Some(crate::recovery_model::RestoreProgress {
            stage: "scanning".into(),
            detail: folder.name.clone(),
            fraction: None,
        });
        self.model.status_message = format!("Searching {}", folder.name);
        self.model
            .push_log(LogLevel::Info, format!("Searching {path}"));
    }

    pub fn start_restore(&mut self) {
        let Some(device_id) = self.model.claimed_device_id.clone() else {
            return;
        };
        if !self.model.can_start() {
            return;
        }
        if self
            .service
            .send(RecoveryCommand::StartRestore {
                device_id: device_id.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not start restore".into());
            self.model
                .push_log(LogLevel::Error, "Could not start restore");
            return;
        }
        self.model.phase = SessionPhase::Starting;
        self.model.status_message = "Start requested".into();
        self.model
            .push_log(LogLevel::Info, format!("Start requested for {device_id}"));
    }

    pub fn cancel_restore(&mut self) {
        let Some(device_id) = self.model.claimed_device_id.clone() else {
            return;
        };
        if !self.model.can_cancel() {
            return;
        }
        if self
            .service
            .send(RecoveryCommand::CancelRestore {
                device_id: device_id.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not cancel restore".into());
            self.model
                .push_log(LogLevel::Error, "Could not cancel restore");
            return;
        }
        self.model.phase = SessionPhase::Cancelling;
        self.model.status_message = "Cancel requested".into();
        self.model
            .push_log(LogLevel::Warn, format!("Cancel requested for {device_id}"));
    }

    pub fn retry_restore(&mut self) {
        let Some(device_id) = self.model.claimed_device_id.clone() else {
            return;
        };
        if !self.model.can_retry() {
            return;
        }
        if self
            .service
            .send(RecoveryCommand::RetryRestore {
                device_id: device_id.clone(),
            })
            .is_err()
        {
            self.model.last_error = Some("Could not retry restore".into());
            self.model
                .push_log(LogLevel::Error, "Could not retry restore");
            return;
        }
        self.model.phase = SessionPhase::Collecting;
        self.model.progress = None;
        self.model.status_message = "Retry requested".into();
        self.model
            .push_log(LogLevel::Info, format!("Retry requested for {device_id}"));
    }

    pub fn trigger(&mut self, action: RecoveryAction, clipboard: Option<&FileInfo>) {
        self.model.click_action(action);
        match action {
            RecoveryAction::Claim => self.claim_selected(),
            RecoveryAction::Attach => {
                if let Some(file) = clipboard {
                    self.attach_clipboard(file);
                } else {
                    self.model.last_error = Some("Copy or type a file or folder first".into());
                    self.model
                        .push_log(LogLevel::Warn, "Copy or type a file or folder first");
                }
            }
            RecoveryAction::Autosearch => self.autosearch(clipboard),
            RecoveryAction::Start => self.start_restore(),
            RecoveryAction::Cancel => self.cancel_restore(),
            RecoveryAction::Retry => self.retry_restore(),
            RecoveryAction::Release => self.release_claim(),
        }
    }

    fn auto_start_if_ready_transitioned(&mut self, was_ready: bool) {
        if !was_ready && self.model.all_required_files_supplied() && self.model.can_start() {
            self.start_restore();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clip::{FileInfo, FileKind};
    use crate::recovery_model::{
        DeviceState, FileRequestSpec, RecoveryDevice, RecoveryEvent, RecoveryFocus, RecoveryStep,
        SizeRange,
    };

    fn discovered_device() -> RecoveryDevice {
        RecoveryDevice {
            id: "dev-1".into(),
            title: "Recovery Device".into(),
            detail: "iPhone".into(),
            connection: "127.0.0.1:9123".into(),
            state: DeviceState::Available,
            connected: true,
        }
    }

    fn request_spec(request_id: &str, required: bool) -> FileRequestSpec {
        FileRequestSpec {
            request_id: request_id.into(),
            role: "BuildManifest".into(),
            preferred_name: Some("BuildManifest.plist".into()),
            accepted_names: vec!["BuildManifest.plist".into()],
            allowed_extensions: vec!["plist".into()],
            accept_directory: false,
            expected_size: Some(SizeRange {
                min: 12,
                max: 1_024,
            }),
            expected_hash: None,
            detail: None,
            required,
        }
    }

    fn manifest_file() -> FileInfo {
        FileInfo {
            path: "/tmp/BuildManifest.plist".into(),
            name: "BuildManifest.plist".into(),
            kind: FileKind::File,
            size: Some(128),
            modified: None,
        }
    }

    fn claimed_runtime() -> (RecoveryRuntime, RecoveryBridge) {
        let (service, bridge) = ChannelRecoveryService::pair();
        let mut runtime = RecoveryRuntime::from_service(service);
        runtime
            .model
            .apply_event(RecoveryEvent::DeviceDiscovered(discovered_device()));
        runtime.model.apply_event(RecoveryEvent::ClaimAccepted {
            device_id: "dev-1".into(),
            note: None,
        });
        runtime.model.focus = RecoveryFocus::Requests;
        (runtime, bridge)
    }

    #[test]
    fn selecting_a_system_sends_the_board_class() {
        let (service, bridge) = ChannelRecoveryService::pair();
        let mut runtime = RecoveryRuntime::from_service(service);
        runtime.model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![crate::recovery_model::CompatibleSystem {
                class: "j274ap".into(),
                title: "Mac mini (M1, 2020)".into(),
                detail: "j274ap  ·  M1".into(),
            }],
            product_version: None,
            product_build: None,
        });
        runtime.model.system_cursor = 0;
        runtime.select_system();
        let command = bridge.recv_command().expect("select");
        assert_eq!(
            command,
            RecoveryCommand::SelectSystem {
                device_class: "j274ap".into(),
            }
        );
        assert!(runtime.model.verifying.is_some());
    }

    #[test]
    fn selecting_a_restore_mode_sends_the_mode() {
        let (service, bridge) = ChannelRecoveryService::pair();
        let mut runtime = RecoveryRuntime::from_service(service);
        runtime.model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![crate::recovery_model::CompatibleSystem {
                class: "j274ap".into(),
                title: "Mac mini (M1, 2020)".into(),
                detail: "j274ap  ·  M1".into(),
            }],
            product_version: None,
            product_build: None,
        });
        runtime.model.apply_event(RecoveryEvent::SystemSelected {
            class: "j274ap".into(),
        });
        runtime.model.apply_event(RecoveryEvent::CompatibleModes {
            modes: vec![
                crate::recovery_model::RestoreMode::Update,
                crate::recovery_model::RestoreMode::Erase,
            ],
        });
        runtime.model.mode_cursor = 0;
        runtime.select_restore_mode();
        let command = bridge.recv_command().expect("select mode");
        assert_eq!(
            command,
            RecoveryCommand::SelectRestoreMode {
                mode: crate::recovery_model::RestoreMode::Update,
            }
        );
        assert!(runtime.model.verifying.is_some());
    }

    #[test]
    fn attach_clipboard_sends_a_folder_path_for_scanning() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("BuildManifest.plist"),
            b"BuildManifest.plist body",
        )
        .unwrap();
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));
        let folder = crate::clip::inspect(&dir.path().to_string_lossy()).expect("folder");
        runtime.attach_clipboard(&folder);
        let command = bridge.recv_command().expect("recv");
        match command {
            RecoveryCommand::ProvideFile {
                request_id, path, ..
            } => {
                assert_eq!(request_id, "manifest");
                assert_eq!(
                    std::path::Path::new(&path),
                    dir.path().canonicalize().unwrap().as_path()
                );
            }
            other => panic!("expected ProvideFile, got {other:?}"),
        }
        assert!(runtime.model.verifying.is_some());
        assert!(
            runtime
                .model
                .status_message
                .to_ascii_lowercase()
                .contains("scanning"),
            "{}",
            runtime.model.status_message
        );
    }

    #[test]
    fn autosearch_without_a_folder_asks_for_one() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime.model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![crate::recovery_model::CompatibleSystem {
                class: "j274ap".into(),
                title: "Mac mini (M1, 2020)".into(),
                detail: "j274ap  ·  M1".into(),
            }],
            product_version: None,
            product_build: None,
        });
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));
        runtime.autosearch(None);
        assert!(matches!(bridge.recv_command(), Err(TryRecvError::Empty)));
        assert!(
            runtime
                .model
                .last_error
                .as_deref()
                .is_some_and(|error| error.to_ascii_lowercase().contains("folder")
                    || error.to_ascii_lowercase().contains("file")),
            "{:?}",
            runtime.model.last_error
        );
    }

    #[test]
    fn autosearch_sends_the_handed_folder() {
        let dir = tempfile::tempdir().unwrap();
        let (mut runtime, bridge) = claimed_runtime();
        runtime.model.apply_event(RecoveryEvent::CompatibleBoards {
            systems: vec![crate::recovery_model::CompatibleSystem {
                class: "j274ap".into(),
                title: "Mac mini (M1, 2020)".into(),
                detail: "j274ap  ·  M1".into(),
            }],
            product_version: None,
            product_build: None,
        });
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec(
                "system-image",
                true,
            )));
        let folder = crate::clip::inspect(&dir.path().to_string_lossy()).expect("folder");
        runtime.autosearch(Some(&folder));
        let command = bridge.recv_command().expect("autosearch");
        match command {
            RecoveryCommand::Autosearch { path, .. } => {
                assert_eq!(
                    std::path::Path::new(&path),
                    dir.path().canonicalize().unwrap().as_path()
                );
            }
            other => panic!("expected Autosearch, got {other:?}"),
        }
    }

    #[test]
    fn channel_pair_moves_commands_and_events() {
        let (mut service, bridge) = ChannelRecoveryService::pair();
        service
            .send(RecoveryCommand::ClaimDevice {
                device_id: "dev-1".into(),
            })
            .expect("send");
        let command = bridge.recv_command().expect("recv");
        assert_eq!(
            command,
            RecoveryCommand::ClaimDevice {
                device_id: "dev-1".into()
            }
        );

        bridge
            .emit(RecoveryEvent::Succeeded {
                note: Some("done".into()),
            })
            .expect("emit");
        let events = service.poll();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn attach_clipboard_submits_file() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));

        runtime.attach_clipboard(&manifest_file());

        let command = bridge.recv_command().expect("recv");
        assert!(matches!(
            command,
            RecoveryCommand::ProvideFile { request_id, .. } if request_id == "manifest"
        ));
        assert!(matches!(
            runtime.model.requests[0].resolution,
            crate::recovery_model::RequestResolution::Submitted { .. }
        ));
        assert_eq!(runtime.model.phase, SessionPhase::Starting);
    }

    #[test]
    fn attach_clipboard_auto_starts_after_final_required_handoff() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));

        runtime.attach_clipboard(&manifest_file());

        let provide = bridge.recv_command().expect("provide");
        assert!(matches!(
            provide,
            RecoveryCommand::ProvideFile { request_id, .. } if request_id == "manifest"
        ));
        let start = bridge.recv_command().expect("start");
        assert_eq!(
            start,
            RecoveryCommand::StartRestore {
                device_id: "dev-1".into(),
            }
        );
        assert_eq!(runtime.model.phase, SessionPhase::Starting);
        assert_eq!(runtime.model.status_message, "Start requested");
    }

    #[test]
    fn attach_clipboard_does_not_start_before_all_required_files_are_supplied() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec(
                "manifest-1",
                true,
            )));
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
                request_id: "manifest-2".into(),
                role: "BuildManifest".into(),
                preferred_name: Some("BuildManifest.plist".into()),
                accepted_names: vec!["BuildManifest.plist".into()],
                allowed_extensions: vec!["plist".into()],
                accept_directory: false,
                expected_size: Some(SizeRange {
                    min: 12,
                    max: 1_024,
                }),
                expected_hash: None,
                detail: Some("second".into()),
                required: true,
            }));
        runtime.model.select_request(0);

        runtime.attach_clipboard(&manifest_file());

        let provide = bridge.recv_command().expect("provide");
        assert!(matches!(
            provide,
            RecoveryCommand::ProvideFile { request_id, .. } if request_id == "manifest-1"
        ));
        assert!(matches!(bridge.recv_command(), Err(TryRecvError::Empty)));
        assert_eq!(runtime.model.phase, SessionPhase::Collecting);
        assert_eq!(runtime.model.step(), RecoveryStep::Working);
        assert!(runtime.model.verifying.is_some());
    }

    #[test]
    fn attach_clipboard_does_not_double_start_when_only_optional_request_changes() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
                request_id: "notes".into(),
                role: "Notes".into(),
                preferred_name: Some("BuildManifest.plist".into()),
                accepted_names: vec!["BuildManifest.plist".into()],
                allowed_extensions: vec!["plist".into()],
                accept_directory: false,
                expected_size: Some(SizeRange {
                    min: 12,
                    max: 1_024,
                }),
                expected_hash: None,
                detail: None,
                required: false,
            }));

        runtime.model.select_request(0);
        runtime.attach_clipboard(&manifest_file());

        let first = bridge.recv_command().expect("first");
        assert!(matches!(
            first,
            RecoveryCommand::ProvideFile { request_id, .. } if request_id == "manifest"
        ));
        let second = bridge.recv_command().expect("second");
        assert_eq!(
            second,
            RecoveryCommand::StartRestore {
                device_id: "dev-1".into(),
            }
        );

        runtime.model.phase = SessionPhase::Ready;
        runtime.model.select_request(1);
        runtime.attach_clipboard(&manifest_file());

        let third = bridge.recv_command().expect("third");
        assert!(matches!(
            third,
            RecoveryCommand::ProvideFile { request_id, .. } if request_id == "notes"
        ));
        assert!(matches!(bridge.recv_command(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn attach_clipboard_routes_to_matching_open_request() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(FileRequestSpec {
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
            }));
        runtime.model.select_request(0);
        runtime.attach_clipboard(&FileInfo {
            path: "/tmp/restore.dmg".into(),
            name: "restore.dmg".into(),
            kind: FileKind::File,
            size: Some(180),
            modified: None,
        });

        let command = bridge.recv_command().expect("recv");
        assert!(
            matches!(
                command,
                RecoveryCommand::ProvideFile { ref request_id, .. } if request_id == "ramdisk"
            ),
            "{command:?}"
        );
        assert_eq!(runtime.model.request_cursor, 1);
    }

    #[test]
    fn delayed_acceptance_after_auto_start_does_not_enable_duplicate_start() {
        let (mut runtime, bridge) = claimed_runtime();
        runtime
            .model
            .apply_event(RecoveryEvent::FileRequested(request_spec("manifest", true)));

        runtime.attach_clipboard(&manifest_file());

        assert!(matches!(
            bridge.recv_command().expect("provide"),
            RecoveryCommand::ProvideFile { request_id, .. } if request_id == "manifest"
        ));
        assert_eq!(
            bridge.recv_command().expect("start"),
            RecoveryCommand::StartRestore {
                device_id: "dev-1".into(),
            }
        );
        assert_eq!(runtime.model.phase, SessionPhase::Starting);

        runtime.model.apply_event(RecoveryEvent::FileAccepted {
            request_id: "manifest".into(),
            note: Some("accepted".into()),
        });
        assert_eq!(runtime.model.phase, SessionPhase::Starting);
        assert!(!runtime.model.can_start());

        runtime.start_restore();

        assert!(matches!(bridge.recv_command(), Err(TryRecvError::Empty)));
    }
}
