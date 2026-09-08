pub mod apfs_fixture;
pub mod apfs_image;
pub mod apfs_mutate;
pub mod apfs_read;
pub mod apfs_update;
pub mod apfs_verify;
pub mod apfs_verify_corpus;
pub mod apfs_write;
pub mod app;
pub mod asahi;
pub mod asahi_cache;
pub mod asahi_cli;
pub mod asahi_firmware;
pub mod asahi_firmware_archive;
pub mod asahi_firmware_catalog;
pub mod asahi_firmware_download;
pub mod asahi_installer_bundle;
pub mod asahi_installer_data;
pub mod asahi_kernel;
pub mod asahi_ops;
pub mod asahi_provisioning;
mod asahi_recovery_cache;
pub mod asahi_vendor_firmware;
pub mod asr_server;
pub mod banner;
pub mod bridge_protocol;
pub mod clip;
pub mod crypto;
pub mod explorer;
pub mod explorer_cli;
pub mod explorer_image;
pub mod fat32;
pub mod lzvn;
pub mod picker;
pub mod preview;
pub mod ramrod;
pub mod recovery;
pub mod recovery_model;
pub mod recovery_runtime;
pub mod repair;
pub mod repair_cli;
pub mod repair_ops;
pub mod repair_volume;
pub mod restore;
pub mod restore_service;
pub mod ui;
pub mod usbmux;

pub use apple_tui::theme;

pub use crypto::embedded_panic_crc32;

pub mod topology {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HostTopology {
        pub logical_cpus: usize,
        pub performance_cpus: usize,
        pub efficiency_cpus: usize,
        pub measured: bool,
    }

    pub fn host_topology() -> HostTopology {
        let logical = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        HostTopology {
            logical_cpus: logical,
            performance_cpus: logical,
            efficiency_cpus: 0,
            measured: false,
        }
    }
}
