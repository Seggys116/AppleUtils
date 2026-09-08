use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::usbmux::{
    BulkTransport, LinkWatchdogHandle, MuxDialer, MuxReadPolicy, MuxVersion, MuxWritePolicy,
    WriteExpiry,
};

use super::plan::RestorePlan;
use super::report::{MUX_PREFIX, SharedReporter, report};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostDetachOutcome {
    pub was_connected: bool,
    pub was_configured: bool,
    pub disconnect_delivered: bool,
    pub reset_delivered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostDetachDisposition {
    Complete,
    Cancelled,
    Failed,
}

pub trait HostDetacher: Send + Sync {
    fn detach_host(&self, disposition: HostDetachDisposition) -> HostDetachOutcome;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedMuxTransportMetadata {
    pub transport_kind: &'static str,
    pub interface: u8,
    pub device_to_host_endpoint: u8,
    pub host_to_device_endpoint: u8,
    pub host_to_device_max_packet_size: u16,
    pub version: MuxVersion,
}

pub struct ClaimedMuxTransport<T: BulkTransport> {
    dialer: MuxDialer<T>,
    metadata: ClaimedMuxTransportMetadata,
    detacher: Option<Arc<dyn HostDetacher>>,
    watchdog: Option<Arc<LinkWatchdogHandle>>,
}

impl<T: BulkTransport> Clone for ClaimedMuxTransport<T> {
    fn clone(&self) -> Self {
        Self {
            dialer: self.dialer.clone(),
            metadata: self.metadata.clone(),
            detacher: self.detacher.clone(),
            watchdog: self.watchdog.clone(),
        }
    }
}

impl<T: BulkTransport> ClaimedMuxTransport<T> {
    #[must_use]
    pub fn new(dialer: MuxDialer<T>, metadata: ClaimedMuxTransportMetadata) -> Self {
        Self {
            dialer,
            metadata,
            detacher: None,
            watchdog: None,
        }
    }

    #[must_use]
    pub fn with_detacher(mut self, detacher: Arc<dyn HostDetacher>) -> Self {
        self.detacher = Some(detacher);
        self
    }

    // Kept alive for as long as this transport is; stops tracing when the last clone drops.
    #[must_use]
    pub fn with_watchdog(mut self, watchdog: Arc<LinkWatchdogHandle>) -> Self {
        self.watchdog = Some(watchdog);
        self
    }

    #[must_use]
    pub fn dialer(&self) -> &MuxDialer<T> {
        &self.dialer
    }

    #[must_use]
    pub fn metadata(&self) -> &ClaimedMuxTransportMetadata {
        &self.metadata
    }

    #[must_use]
    pub fn detach_host(&self, disposition: HostDetachDisposition) -> HostDetachOutcome {
        self.detacher
            .as_ref()
            .map_or_else(HostDetachOutcome::default, |detacher| {
                detacher.detach_host(disposition)
            })
    }

    fn with_dialer(mut self, dialer: MuxDialer<T>) -> Self {
        self.dialer = dialer;
        self
    }
}

pub fn bring_up_mux<T: BulkTransport>(
    claimed: ClaimedMuxTransport<T>,
    plan: &RestorePlan,
    armed_at_secs: f64,
    stop: &Arc<AtomicBool>,
    reporter: &SharedReporter,
) -> Result<ClaimedMuxTransport<T>, (&'static str, String)> {
    if stop.load(Ordering::Relaxed) {
        return Err((
            "interrupted",
            "the run stopped before the claimed mux link was used".to_string(),
        ));
    }

    let control = MuxReadPolicy::retrying(plan.read_poll);
    let data = match plan.asr_read_timeout {
        Some(bound) => MuxReadPolicy::failing_after(bound),
        None => control,
    };
    let write_policy = MuxWritePolicy::default();

    let configured = claimed.clone().with_dialer(
        claimed
            .dialer
            .clone()
            .on_control_port(plan.port)
            .with_read_policy(control)
            .with_data_read_policy(data)
            .with_cancel(Arc::clone(stop)),
    );

    let metadata = configured.metadata();
    let link_line = format!(
        "{MUX_PREFIX} result=link-up port={} at={armed_at_secs:.3}s interface={} in=phys{} out=phys{} out-maxpacket={} version={} transport={} meaning=\"the mux link was already claimed and verified before restore started, so restore is reusing that link rather than owning controller bring-up\" detail=\"\"",
        plan.port,
        metadata.interface,
        metadata.device_to_host_endpoint,
        metadata.host_to_device_endpoint,
        metadata.host_to_device_max_packet_size,
        metadata.version.wire_value(),
        metadata.transport_kind
    );
    report(reporter, "link-up", &link_line);

    let asr_rule = match plan.asr_read_timeout {
        Some(bound) => format!(
            "bounded at {:.3}s and an expiry is a failure",
            bound.as_secs_f64()
        ),
        None => "retrying, like the control session".to_string(),
    };
    let write_rule = match write_policy.on_expiry {
        WriteExpiry::Retry => format!(
            "retrying every {:.3}s with no total",
            write_policy.poll.as_secs_f64()
        ),
        WriteExpiry::Fail => format!(
            "bounded at {:.3}s and an expiry is a failure",
            write_policy.poll.as_secs_f64()
        ),
    };
    let policy_line = format!(
        "{MUX_PREFIX} result=read-policy-armed port={} at={armed_at_secs:.3}s control-poll={:.3}s asr-rule=\"{asr_rule}\" asr-write-rule=\"{write_rule}\" meaning=\"the claimed mux link is live and restore is arming the same control and bulk session policies the mux-owned path used\" detail=\"no controller polling or device-mode bring-up happens here; those stages belong to the claimer that supplied the link\"",
        plan.port,
        plan.read_poll.as_secs_f64()
    );
    report(reporter, "read-policy-armed", &policy_line);

    Ok(configured)
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimedMuxTransport, ClaimedMuxTransportMetadata, HostDetachDisposition, HostDetachOutcome,
        HostDetacher, bring_up_mux,
    };
    use crate::restore::RestorePlan;
    use crate::restore::report::{RestoreEvent, RestoreReporter, SharedReporter};
    use crate::usbmux::{BulkTransport, MuxDialer, MuxLink, MuxVersion, SharedLink};
    use std::io;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct NullTransport;

    impl BulkTransport for NullTransport {
        fn send(&mut self, _packet: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn recv(&mut self, _timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn out_max_packet_size(&self) -> u16 {
            512
        }
    }

    #[derive(Default)]
    struct Recorder {
        events: Vec<String>,
    }

    impl RestoreReporter for Recorder {
        fn event(&mut self, event: RestoreEvent<'_>) {
            self.events.push(event.line.to_string());
        }
    }

    struct Detacher {
        outcome: HostDetachOutcome,
    }

    impl HostDetacher for Detacher {
        fn detach_host(&self, _disposition: HostDetachDisposition) -> HostDetachOutcome {
            self.outcome
        }
    }

    fn plan() -> RestorePlan {
        RestorePlan {
            image: "restore.dmg".into(),
            system_image: None,
            recovery_image: None,
            image_root: None,
            manifest: None,
            behavior: None,
            port: 62078,
            timeout: Duration::from_secs(35),
            window: Duration::from_secs(600),
            retry: Duration::from_secs(5),
            read_poll: Duration::from_secs(30),
            asr_read_timeout: None,
            metadata: true,
            global_manifests: None,
            firmware_root: None,
            bootability_bundle: None,
            corrupt_manifest: false,
            staged_boot_manifest_sha384: None,
            fdr_trust_digest: None,
            fdr_material_dir: None,
        }
    }

    fn claimed() -> ClaimedMuxTransport<NullTransport> {
        let link = SharedLink::new(MuxLink::new(NullTransport));
        ClaimedMuxTransport::new(
            MuxDialer::new(link),
            ClaimedMuxTransportMetadata {
                transport_kind: "local-bridge",
                interface: 0,
                device_to_host_endpoint: 0x81,
                host_to_device_endpoint: 0x01,
                host_to_device_max_packet_size: 512,
                version: MuxVersion::V2,
            },
        )
    }

    #[test]
    fn bring_up_mux_reuses_the_claimed_link_and_reports_policy() {
        let recorder = Arc::new(Mutex::new(Recorder::default()));
        let reporter: SharedReporter = recorder.clone();
        let stop = Arc::new(AtomicBool::new(false));

        let configured =
            bring_up_mux(claimed(), &plan(), 0.0, &stop, &reporter).expect("claimed link accepted");

        assert_eq!(configured.metadata().transport_kind, "local-bridge");
        let recorded = recorder.lock().unwrap();
        assert_eq!(recorded.events.len(), 2);
        assert!(recorded.events[0].contains("result=link-up"));
        assert!(recorded.events[1].contains("result=read-policy-armed"));
    }

    #[test]
    fn detach_host_uses_the_supplied_detacher() {
        let outcome = HostDetachOutcome {
            was_connected: true,
            was_configured: true,
            disconnect_delivered: false,
            reset_delivered: true,
        };
        let claimed = claimed().with_detacher(Arc::new(Detacher { outcome }));
        assert_eq!(
            claimed.detach_host(HostDetachDisposition::Complete),
            outcome
        );
    }
}
