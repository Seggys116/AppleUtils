use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreadClass {
    /// Also places the thread in disk I/O tier 3.
    Background,
    Utility,
    Default,
    UserInitiated,
    UserInteractive,
    Unspecified(u32),
    Unsupported,
}

pub const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
const QOS_CLASS_USER_INITIATED: u32 = 0x19;
const QOS_CLASS_DEFAULT: u32 = 0x15;
const QOS_CLASS_UTILITY: u32 = 0x11;
const QOS_CLASS_BACKGROUND: u32 = 0x09;
const QOS_CLASS_UNSPECIFIED: u32 = 0x00;

impl ThreadClass {
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::Background => QOS_CLASS_BACKGROUND,
            Self::Utility => QOS_CLASS_UTILITY,
            Self::Default => QOS_CLASS_DEFAULT,
            Self::UserInitiated => QOS_CLASS_USER_INITIATED,
            Self::UserInteractive => QOS_CLASS_USER_INTERACTIVE,
            Self::Unspecified(value) => value,
            Self::Unsupported => QOS_CLASS_UNSPECIFIED,
        }
    }

    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        match value {
            QOS_CLASS_BACKGROUND => Self::Background,
            QOS_CLASS_UTILITY => Self::Utility,
            QOS_CLASS_DEFAULT => Self::Default,
            QOS_CLASS_USER_INITIATED => Self::UserInitiated,
            QOS_CLASS_USER_INTERACTIVE => Self::UserInteractive,
            other => Self::Unspecified(other),
        }
    }

    #[must_use]
    pub const fn competes_with_vcpu(self) -> bool {
        match self {
            Self::UserInteractive => true,
            Self::Unspecified(value) => value >= QOS_CLASS_USER_INTERACTIVE,
            _ => false,
        }
    }
}

impl fmt::Display for ThreadClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Background => formatter.write_str("background"),
            Self::Utility => formatter.write_str("utility"),
            Self::Default => formatter.write_str("default"),
            Self::UserInitiated => formatter.write_str("user-initiated"),
            Self::UserInteractive => formatter.write_str("user-interactive"),
            Self::Unspecified(value) => write!(formatter, "unspecified-0x{value:02x}"),
            Self::Unsupported => formatter.write_str("unsupported"),
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> libc::c_int;
    fn pthread_get_qos_class_np(
        thread: libc::pthread_t,
        qos_class: *mut u32,
        relative_priority: *mut i32,
    ) -> libc::c_int;
    fn setiopolicy_np(iotype: libc::c_int, scope: libc::c_int, policy: libc::c_int) -> libc::c_int;
    fn getiopolicy_np(iotype: libc::c_int, scope: libc::c_int) -> libc::c_int;
}

#[cfg(target_os = "macos")]
const IOPOL_TYPE_DISK: libc::c_int = 0;
#[cfg(target_os = "macos")]
const IOPOL_SCOPE_THREAD: libc::c_int = 1;
#[cfg(target_os = "macos")]
const IOPOL_IMPORTANT: libc::c_int = 0;

pub fn set_current_thread_disk_io_important() -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: both calls take three integers by value, own no pointers, and affect only the calling thread's I/O policy.
        unsafe {
            setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, IOPOL_IMPORTANT);
            Some(getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[must_use]
pub fn current_thread_disk_io_policy() -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: takes two integers by value and owns no pointers.
        Some(unsafe { getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD) })
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[must_use]
pub fn current_thread_class() -> ThreadClass {
    #[cfg(target_os = "macos")]
    {
        let mut class: u32 = QOS_CLASS_UNSPECIFIED;
        let mut relative: i32 = 0;
        // SAFETY: both out pointers address live locals of the exact widths the call writes, and pthread_self names the calling thread.
        let rc = unsafe {
            pthread_get_qos_class_np(
                libc::pthread_self(),
                std::ptr::addr_of_mut!(class),
                std::ptr::addr_of_mut!(relative),
            )
        };
        if rc != 0 {
            return ThreadClass::Unsupported;
        }
        ThreadClass::from_raw(class)
    }
    #[cfg(not(target_os = "macos"))]
    {
        ThreadClass::Unsupported
    }
}

pub fn set_current_thread_class(class: ThreadClass) -> ThreadClass {
    #[cfg(target_os = "macos")]
    {
        if matches!(class, ThreadClass::Unsupported) {
            return current_thread_class();
        }
        // SAFETY: the call takes a qos_class_t by value, owns no pointers, and affects only the calling thread's scheduling class.
        let rc = unsafe { pthread_set_qos_class_self_np(class.raw(), 0) };
        if rc != 0 {
            return current_thread_class();
        }
        current_thread_class()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = class;
        ThreadClass::Unsupported
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BulkWorkClass {
    pub class: ThreadClass,
    pub disk_io_policy: Option<i32>,
}

pub fn with_thread_class<T>(class: ThreadClass, work: impl FnOnce() -> T) -> (T, BulkWorkClass) {
    let previous_class = current_thread_class();
    let previous_policy = current_thread_disk_io_policy();
    let class = set_current_thread_class(class);
    let disk_io_policy = set_current_thread_disk_io_important();
    let value = work();
    if !matches!(previous_class, ThreadClass::Unsupported) {
        set_current_thread_class(previous_class);
    }
    if let Some(policy) = previous_policy {
        set_current_thread_disk_io_policy(policy);
    }
    (
        value,
        BulkWorkClass {
            class,
            disk_io_policy,
        },
    )
}

fn set_current_thread_disk_io_policy(policy: i32) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: takes three integers by value, owns no pointers, and affects only the calling thread.
        unsafe {
            setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, policy);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = policy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_survives_the_round_trip_through_its_raw_value() {
        for class in [
            ThreadClass::Background,
            ThreadClass::Utility,
            ThreadClass::Default,
            ThreadClass::UserInitiated,
            ThreadClass::UserInteractive,
        ] {
            assert_eq!(ThreadClass::from_raw(class.raw()), class);
        }
    }

    #[test]
    fn only_the_vcpu_class_and_above_competes_with_a_vcpu() {
        assert!(ThreadClass::UserInteractive.competes_with_vcpu());
        assert!(ThreadClass::Unspecified(0x30).competes_with_vcpu());
        assert!(!ThreadClass::UserInitiated.competes_with_vcpu());
        assert!(!ThreadClass::Default.competes_with_vcpu());
        assert!(!ThreadClass::Utility.competes_with_vcpu());
        assert!(!ThreadClass::Background.competes_with_vcpu());
        assert!(!ThreadClass::Unsupported.competes_with_vcpu());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn a_thread_lowered_to_a_bulk_class_reports_that_class_back() {
        let handle = std::thread::spawn(|| {
            let effective = set_current_thread_class(ThreadClass::Background);
            assert_eq!(effective, ThreadClass::Background);
            assert!(!effective.competes_with_vcpu());
            let (inner, during) = with_thread_class(ThreadClass::Utility, current_thread_class);
            assert_eq!(during.class, ThreadClass::Utility);
            assert_eq!(inner, ThreadClass::Utility);
            assert_eq!(during.disk_io_policy, Some(0));
            assert_eq!(current_thread_class(), ThreadClass::Background);
        });
        handle.join().expect("the class probe thread panicked");
    }
}
