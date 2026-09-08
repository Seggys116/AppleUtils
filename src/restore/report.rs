use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

pub const ASR_SERVE_PREFIX: &str = "[asr-serve]";

pub const MUX_PREFIX: &str = "[usbmux]";

pub const ASR_SERVE_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

pub struct RestoreEvent<'a> {
    pub result: &'a str,
    pub line: &'a str,
}

pub trait RestoreReporter: Send {
    fn event(&mut self, event: RestoreEvent<'_>);
    fn payload_block(
        &mut self,
        _sent_bytes: u64,
        _total_bytes: u64,
        _blocks: u64,
        _elapsed: Duration,
    ) {
    }
    fn guest_progress(&mut self, _operation: Option<i64>, _fraction: Option<f64>) {}
    fn guest_checkpoint(&mut self, _name: &str, _beginning: bool) {}
    fn guest_status(&mut self, _status: i64) {}
    fn data_request(&mut self, _data_type: &str, _answered: bool) {}
}

pub type SharedReporter = Arc<Mutex<dyn RestoreReporter>>;

pub(crate) fn lock(reporter: &SharedReporter) -> MutexGuard<'_, dyn RestoreReporter + 'static> {
    match reporter.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn report(reporter: &SharedReporter, result: &str, line: &str) {
    append_mux_log(line);
    lock(reporter).event(RestoreEvent { result, line });
}

pub fn mux_log_path() -> std::path::PathBuf {
    std::env::temp_dir().join("appleutils-restore-mux.log")
}

pub fn mux_log_prev_path() -> std::path::PathBuf {
    mux_log_path().with_extension("log.prev")
}

pub(crate) fn rotate_mux_log() {
    let path = mux_log_path();
    let prev = mux_log_prev_path();
    let _ = std::fs::rename(&path, &prev);
}

fn append_mux_log(line: &str) {
    let path = mux_log_path();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

pub struct StdoutReporter {
    last_report_elapsed: Duration,
}

impl StdoutReporter {
    pub fn new() -> Self {
        Self {
            last_report_elapsed: Duration::ZERO,
        }
    }

    pub fn shared() -> SharedReporter {
        Arc::new(Mutex::new(Self::new()))
    }
}

impl Default for StdoutReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl RestoreReporter for StdoutReporter {
    fn event(&mut self, event: RestoreEvent<'_>) {
        println!("{}", event.line);
        let _ = std::io::stdout().flush();
    }

    fn payload_block(&mut self, sent_bytes: u64, total_bytes: u64, blocks: u64, elapsed: Duration) {
        if elapsed.saturating_sub(self.last_report_elapsed) < ASR_SERVE_PROGRESS_INTERVAL {
            return;
        }
        self.last_report_elapsed = elapsed;
        let elapsed = elapsed.as_secs_f64();
        let rate = if elapsed > 0.0 {
            sent_bytes as f64 / elapsed / (1024.0 * 1024.0)
        } else {
            0.0
        };
        let percent = if total_bytes > 0 {
            sent_bytes as f64 * 100.0 / total_bytes as f64
        } else {
            0.0
        };
        println!(
            "{ASR_SERVE_PREFIX} result=streaming bytes={} of={} percent={percent:.2} blocks={} elapsed={elapsed:.3}s rate={rate:.2}MiB/s",
            sent_bytes, total_bytes, blocks
        );
        let _ = std::io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ASR_SERVE_PROGRESS_INTERVAL, RestoreEvent, RestoreReporter, SharedReporter, StdoutReporter,
        report,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct Recorder {
        events: Vec<(String, String)>,
    }

    impl RestoreReporter for Recorder {
        fn event(&mut self, event: RestoreEvent<'_>) {
            self.events
                .push((event.result.to_string(), event.line.to_string()));
        }
    }

    #[test]
    fn a_reported_line_carries_both_its_token_and_its_whole_text() {
        let recorder = Arc::new(Mutex::new(Recorder::default()));
        let reporter: SharedReporter = recorder.clone();
        report(&reporter, "link-up", "[usbmux] result=link-up port=62078");
        let recorder = recorder.lock().unwrap();
        assert_eq!(recorder.events.len(), 1);
        assert_eq!(recorder.events[0].0, "link-up");
        assert_eq!(recorder.events[0].1, "[usbmux] result=link-up port=62078");
    }

    #[test]
    fn a_poisoned_reporter_still_reports() {
        let recorder = Arc::new(Mutex::new(Recorder::default()));
        let reporter: SharedReporter = recorder.clone();
        let poisoner = Arc::clone(&recorder);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the lock");
        })
        .join();
        assert!(recorder.is_poisoned());
        report(&reporter, "restore-ended", "[usbmux] result=restore-ended");
        let recorded = match recorder.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert_eq!(recorded.events.len(), 1);
        assert_eq!(recorded.events[0].0, "restore-ended");
    }

    #[test]
    fn the_streaming_line_is_rate_limited_on_the_transfers_own_clock() {
        let mut reporter = StdoutReporter::new();
        assert_eq!(reporter.last_report_elapsed, Duration::ZERO);
        reporter.payload_block(1024, 4096, 1, Duration::from_millis(10));
        assert_eq!(reporter.last_report_elapsed, Duration::ZERO);
        reporter.payload_block(2048, 4096, 2, ASR_SERVE_PROGRESS_INTERVAL);
        assert_eq!(reporter.last_report_elapsed, ASR_SERVE_PROGRESS_INTERVAL);
        reporter.payload_block(3072, 4096, 3, ASR_SERVE_PROGRESS_INTERVAL);
        assert_eq!(reporter.last_report_elapsed, ASR_SERVE_PROGRESS_INTERVAL);
    }
}
