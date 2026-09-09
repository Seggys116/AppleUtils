use crate::asahi_firmware_download::{FirmwareArchiveInputs, resolve_firmware_archives};
use crate::asahi_provisioning::{
    ProvisionedFirmware, ProvisioningInputs, RecoveryImageFiles, prepare_firmware,
};
use std::path::{Path, PathBuf};
type LoadedArtifacts = (Artifacts, String, String, Option<ProvisionedFirmware>);

use crate::asahi_ops::{
    self, Artifacts, create_qcow2_disc, install_raw_disc, list_installable_flavors, min_disc_bytes,
    parse_installer_data, parse_size_arg, resolve_os, update_disc, validate_disc,
};

pub fn run(args: &[String]) -> Result<String, String> {
    if args.is_empty() {
        return Err(usage());
    }
    match args[0].as_str() {
        "flavors" | "flavours" => {
            let opts = CliOpts::parse(&args[1..])?;
            flavors_report(&opts)
        }
        "create" => {
            let opts = CliOpts::parse(&args[1..])?;
            let out = opts
                .output
                .clone()
                .ok_or_else(|| "create requires --output PATH".to_string())?;
            let (arts, next, os_name, _firmware) = opts.artifacts(true)?;
            let size = opts.size.unwrap_or_else(min_disc_bytes);
            let report =
                create_qcow2_disc(&out, &arts, size, &next, &os_name).map_err(|e| e.to_string())?;
            let info = validate_disc(&out).map_err(|e| e.to_string())?;
            Ok(format!(
                "created {}\nos={os_name}\n{}",
                report.path,
                info.report()
            ))
        }
        "install" => {
            let opts = CliOpts::parse(&args[1..])?;
            let dest = opts
                .output
                .clone()
                .ok_or_else(|| "install requires --output PATH".to_string())?;
            let (arts, next, os_name, _firmware) = opts.artifacts(true)?;
            let size = opts.size.unwrap_or_else(min_disc_bytes);
            let report =
                install_raw_disc(&dest, &arts, size, &next, &os_name).map_err(|e| e.to_string())?;
            let info = validate_disc(&dest).map_err(|e| e.to_string())?;
            Ok(format!(
                "installed {}\nos={os_name}\n{}",
                report.path,
                info.report()
            ))
        }
        "update" => {
            let opts = CliOpts::parse(&args[1..])?;
            let disc = opts
                .disc
                .clone()
                .or(opts.output.clone())
                .ok_or_else(|| "update requires PATH".to_string())?;
            let (arts, _, os_name, _firmware) = opts.update_artifacts()?;
            let report = update_disc(&disc, &arts).map_err(|e| e.to_string())?;
            let info = validate_disc(&disc).map_err(|e| e.to_string())?;
            Ok(format!(
                "updated {}\nos={os_name}\n{}",
                report.path,
                info.report()
            ))
        }
        "validate" => {
            let path = args
                .get(1)
                .ok_or_else(|| "validate requires PATH".to_string())?;
            let info = validate_disc(Path::new(path)).map_err(|e| e.to_string())?;
            Ok(info.report())
        }
        "-h" | "--help" | "help" => Ok(usage()),
        other => Err(format!("unknown asahi command {other}\n{}", usage())),
    }
}

fn usage() -> String {
    "apple-utils asahi flavors [--metadata FILE]\n\
     apple-utils asahi create --output DISC.qcow2 --latest [--os FLAVOR] [--size 32G] [--workdir DIR]\n\
     apple-utils asahi create --output DISC.qcow2 --package ZIP [--os FLAVOR] [--size 32G] [--workdir DIR]\n\
     apple-utils asahi create --output DISC.qcow2 --kernel FILE --m1n1 FILE --root FILE [--size 8G]\n\
     apple-utils asahi install --output DEST --latest [--os FLAVOR] [--size 32G]\n\
     apple-utils asahi install --output DEST --kernel FILE --m1n1 FILE --root FILE [--size 8G]\n\
     apple-utils asahi update DISC.qcow2 --kernel FILE --m1n1 FILE [--root FILE]\n\
     apple-utils asahi validate DISC.qcow2\n\
     Package firmware provisioning requires --target-board BOARD --target-chip ID --ipsw FILE; --target-calibration DIR supplies target calibration and --expert enables official expert catalog entries. The official installer is downloaded when no local installer archive is supplied; IPSW files must be supplied locally; --installer-archive FILE [--installer-source-uri URI] and --ipsw FILE supply local archives.\n\
     --m1n1 selects EFI stage two; --stage1 FILE supplies installer stage one offline (otherwise downloaded from the official installer)."
        .into()
}

#[derive(Default)]
struct CliOpts {
    output: Option<PathBuf>,
    disc: Option<PathBuf>,
    kernel: Option<PathBuf>,
    m1n1: Option<PathBuf>,
    stage1: Option<PathBuf>,
    root: Option<PathBuf>,
    size: Option<u64>,
    os: String,
    latest: bool,
    package: Option<PathBuf>,
    workdir: Option<PathBuf>,
    metadata: Option<PathBuf>,
    expert: bool,
    target_board: Option<String>,
    target_chip: Option<u32>,
    installer_archive: Option<PathBuf>,
    installer_source_uri: Option<String>,
    ipsw: Option<PathBuf>,
    target_calibration: Option<PathBuf>,
    requires_als_calibration: Option<bool>,
}

impl CliOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut opts = CliOpts::default();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--expert" => {
                    opts.expert = true;
                    i += 1;
                }
                "--target-board" => {
                    opts.target_board = Some(need(args, i + 1, "--target-board")?.into());
                    i += 2;
                }
                "--target-chip" => {
                    let value = need(args, i + 1, "--target-chip")?;
                    opts.target_chip = Some(
                        if let Some(value) = value
                            .strip_prefix("0x")
                            .or_else(|| value.strip_prefix("0X"))
                        {
                            u32::from_str_radix(value, 16)
                        } else {
                            value.parse()
                        }
                        .map_err(|_| "invalid --target-chip")?,
                    );
                    i += 2;
                }
                "--firmware-output" => {
                    return Err("--firmware-output is no longer supported; selected firmware is installed inside the disk".into());
                }
                "--installer-archive" => {
                    opts.installer_archive = Some(need(args, i + 1, "--installer-archive")?.into());
                    i += 2;
                }
                "--installer-source-uri" => {
                    opts.installer_source_uri =
                        Some(need(args, i + 1, "--installer-source-uri")?.into());
                    i += 2;
                }
                "--ipsw" => {
                    opts.ipsw = Some(need(args, i + 1, "--ipsw")?.into());
                    i += 2;
                }
                "--target-calibration" => {
                    opts.target_calibration =
                        Some(need(args, i + 1, "--target-calibration")?.into());
                    i += 2;
                }
                "--requires-als-calibration" => {
                    opts.requires_als_calibration =
                        Some(match need(args, i + 1, "--requires-als-calibration")? {
                            "true" => true,
                            "false" => false,
                            _ => {
                                return Err(
                                    "--requires-als-calibration requires true or false".into()
                                );
                            }
                        });
                    i += 2;
                }
                "--output" | "-o" => {
                    opts.output = Some(PathBuf::from(need(args, i + 1, "--output")?));
                    i += 2;
                }
                "--kernel" => {
                    opts.kernel = Some(PathBuf::from(need(args, i + 1, "--kernel")?));
                    i += 2;
                }
                "--m1n1" => {
                    opts.m1n1 = Some(PathBuf::from(need(args, i + 1, "--m1n1")?));
                    i += 2;
                }
                "--stage1" => {
                    opts.stage1 = Some(PathBuf::from(need(args, i + 1, "--stage1")?));
                    i += 2;
                }
                "--root" => {
                    opts.root = Some(PathBuf::from(need(args, i + 1, "--root")?));
                    i += 2;
                }
                "--size" => {
                    opts.size = Some(
                        parse_size_arg(need(args, i + 1, "--size")?).map_err(|e| e.to_string())?,
                    );
                    i += 2;
                }
                "--os" => {
                    opts.os = need(args, i + 1, "--os")?.to_string();
                    i += 2;
                }
                "--latest" => {
                    opts.latest = true;
                    i += 1;
                }
                "--package" => {
                    opts.package = Some(PathBuf::from(need(args, i + 1, "--package")?));
                    i += 2;
                }
                "--workdir" => {
                    opts.workdir = Some(PathBuf::from(need(args, i + 1, "--workdir")?));
                    i += 2;
                }
                "--metadata" => {
                    opts.metadata = Some(PathBuf::from(need(args, i + 1, "--metadata")?));
                    i += 2;
                }
                flag if flag.starts_with('-') => return Err(format!("unknown flag {flag}")),
                path => {
                    if opts.disc.is_none() {
                        opts.disc = Some(PathBuf::from(path));
                    }
                    i += 1;
                }
            }
        }
        Ok(opts)
    }

    fn provisioning_requested(&self) -> bool {
        self.target_board.is_some()
            || self.target_chip.is_some()
            || self.installer_archive.is_some()
            || self.installer_source_uri.is_some()
            || self.ipsw.is_some()
            || self.target_calibration.is_some()
            || self.requires_als_calibration.is_some()
    }

    fn provisioning_inputs(&self) -> Result<(&str, u32, bool), String> {
        if self.ipsw.is_none() {
            return Err("firmware provisioning requires --ipsw FILE".into());
        }
        if self.stage1.is_some() {
            return Err(
                "--stage1 cannot replace stage one from the selected installer archive".into(),
            );
        }
        Ok((
            self.target_board
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or("firmware provisioning requires --target-board")?,
            self.target_chip
                .ok_or("firmware provisioning requires --target-chip")?,
            self.requires_als_calibration.unwrap_or(false),
        ))
    }

    fn resolve_archives(
        &self,
        requirements: &asahi_ops::FirmwareRequirements,
    ) -> Result<crate::asahi_firmware_download::ResolvedFirmwareArchives, String> {
        let (board, chip_id, _) = self.provisioning_inputs()?;
        let workdir = self.workdir();
        let mut last_url = String::new();
        let mut last_percent = None;
        resolve_firmware_archives(
            &FirmwareArchiveInputs {
                board,
                chip_id,
                expert: self.expert,
                workdir: &workdir,
                requirements,
                installer_archive: self.installer_archive.as_deref(),
                installer_source_uri: self.installer_source_uri.as_deref(),
                ipsw: self.ipsw.as_deref(),
                repair_identity: None,
            },
            |url, percent| {
                let rounded = percent.map(|p| (p * 100.0) as u64);
                if url != last_url || rounded != last_percent {
                    eprintln!(
                        "firmware download: {url}{}",
                        percent
                            .map(|p| format!(" {:.0}%", p * 100.0))
                            .unwrap_or_default()
                    );
                    last_url = url.to_owned();
                    last_percent = rounded;
                }
            },
        )
    }

    fn provision(
        &self,
        artifacts: &mut Artifacts,
        preflight: Option<crate::asahi_firmware_download::ResolvedFirmwareArchives>,
    ) -> Result<Option<ProvisionedFirmware>, String> {
        let required = artifacts.firmware_requirements.as_ref().is_some_and(|r| {
            r.supported_fw.is_some()
                || !r.firmware_partitions.is_empty()
                || !r.installer_data_partitions.is_empty()
        });
        if !required && !self.provisioning_requested() {
            return Ok(None);
        }
        let (board, chip_id, requires_als) = self.provisioning_inputs()?;
        let requirements = artifacts
            .firmware_requirements
            .as_ref()
            .ok_or("firmware provisioning requires package metadata")?;
        let workdir = self.workdir();
        let archives = match preflight {
            Some(archives) => archives,
            None => self.resolve_archives(requirements)?,
        };
        let prepared = prepare_firmware(
            &ProvisioningInputs {
                board,
                chip_id,
                expert: self.expert,
                installer_archive: &archives.installer_archive,
                installer_source_uri: &archives.installer_source_uri,
                ipsw: &archives.ipsw,
                workdir: &workdir,
                repair_identity: None,
            },
            requirements,
        )?;
        let recovery = RecoveryImageFiles::extract(prepared.recovery_image()?)?;
        let result = prepared.provision_artifacts(
            artifacts,
            recovery.root(),
            self.target_calibration.as_deref(),
            requires_als,
        );
        result.map(Some)
    }

    fn stage1_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = match &self.stage1 {
            Some(path) => std::fs::read(path).map_err(|e| e.to_string())?,
            None => asahi_ops::fetch_installer_stage1().map_err(|e| e.to_string())?,
        };
        asahi_ops::validate_stage1(&bytes).map_err(|e| e.to_string())?;
        Ok(bytes)
    }

    fn workdir(&self) -> PathBuf {
        self.workdir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("apple-utils-asahi-{}", std::process::id()))
        })
    }

    fn installer_json(&self) -> Result<String, String> {
        if let Some(path) = &self.metadata {
            return std::fs::read_to_string(path).map_err(|e| e.to_string());
        }
        let bytes = asahi_ops::fetch_url(asahi_ops::DEFAULT_INSTALLER_DATA_URL)
            .map_err(|e| e.to_string())?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    fn artifacts(&self, include_root: bool) -> Result<LoadedArtifacts, String> {
        if self.latest || self.package.is_some() {
            let json = self.installer_json()?;
            let data = parse_installer_data(&json).map_err(|e| e.to_string())?;
            let resolved = resolve_os(&data, &self.os).map_err(|e| e.to_string())?;
            let mut preflight = None;
            if resolved.supported_fw.is_some()
                || !resolved.firmware_partitions.is_empty()
                || !resolved.installer_data_partitions.is_empty()
                || self.provisioning_requested()
            {
                let (board, chip, _) = self.provisioning_inputs()?;
                crate::asahi_firmware_archive::validate_archive_for_package(
                    self.ipsw
                        .as_deref()
                        .ok_or("select a local IPSW with --ipsw FILE")?,
                    resolved.supported_fw.as_deref(),
                    Some((board, chip)),
                )?;
                preflight =
                    Some(self.resolve_archives(&asahi_ops::FirmwareRequirements::from(&resolved))?);
            }
            let work = self.workdir();
            std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
            let package = if let Some(path) = &self.package {
                path.clone()
            } else {
                let dest = work.join("package.zip");
                asahi_ops::fetch_url_to_file(&resolved.package_url, &dest)
                    .map_err(|e| e.to_string())?;
                dest
            };
            let mut arts = asahi_ops::load_artifacts_from_package_file_parts(
                &data,
                &self.os,
                &package,
                &work,
                include_root,
            )
            .map_err(|e| e.to_string())?;
            if let Some(kernel) = &self.kernel {
                arts.kernel = std::fs::read(kernel).map_err(|e| e.to_string())?;
            }
            if let Some(m1n1) = &self.m1n1 {
                arts.m1n1 = std::fs::read(m1n1).map_err(|e| e.to_string())?;
            }
            if let Some(root) = &self.root {
                arts.root_fs.clear();
                arts.root_path = Some(root.clone());
            }
            let firmware = self.provision(&mut arts, preflight)?;
            if firmware.is_none() {
                arts.m1n1_stage1 = self.stage1_bytes()?;
            }
            return Ok((arts, resolved.next_object, resolved.os_name, firmware));
        }
        if self.provisioning_requested() {
            return Err(
                "firmware provisioning requires --latest or --package with installer metadata"
                    .into(),
            );
        }
        let kernel = std::fs::read(self.kernel.as_ref().ok_or("--kernel FILE")?)
            .map_err(|e| e.to_string())?;
        let m1n1 =
            std::fs::read(self.m1n1.as_ref().ok_or("--m1n1 FILE")?).map_err(|e| e.to_string())?;
        let root_path = self.root.clone().ok_or("--root FILE")?;
        let arts = Artifacts {
            kernel,
            m1n1,
            efi_files: Vec::new(),
            efi_volume_id: None,
            firmware_requirements: None,
            firmware: None,
            installer_data: None,
            m1n1_stage1: self.stage1_bytes()?,
            root_fs: Vec::new(),
            root_path: Some(root_path),
            boot_fs: Vec::new(),
            boot_path: None,
        };
        Ok((arts, "m1n1/boot.bin".into(), "Asahi Linux".into(), None))
    }

    fn update_artifacts(&self) -> Result<LoadedArtifacts, String> {
        if self.latest || self.package.is_some() {
            let (mut arts, next, os_name, firmware) = self.artifacts(false)?;
            if self.root.is_none() {
                arts.root_fs.clear();
                arts.root_path = None;
            }
            return Ok((arts, next, os_name, firmware));
        }
        if self.provisioning_requested() {
            return Err(
                "firmware provisioning requires --latest or --package with installer metadata"
                    .into(),
            );
        }
        let kernel = std::fs::read(self.kernel.as_ref().ok_or("--kernel FILE")?)
            .map_err(|e| e.to_string())?;
        let m1n1 =
            std::fs::read(self.m1n1.as_ref().ok_or("--m1n1 FILE")?).map_err(|e| e.to_string())?;
        let (root_fs, root_path) = if let Some(path) = &self.root {
            (Vec::new(), Some(path.clone()))
        } else {
            (Vec::new(), None)
        };
        Ok((
            Artifacts {
                kernel,
                m1n1,
                efi_files: Vec::new(),
                efi_volume_id: None,
                firmware_requirements: None,
                firmware: None,
                installer_data: None,
                m1n1_stage1: self.stage1_bytes()?,
                root_fs,
                root_path,
                boot_fs: Vec::new(),
                boot_path: None,
            },
            "m1n1/boot.bin".into(),
            "Asahi Linux".into(),
            None,
        ))
    }
}

fn flavors_report(opts: &CliOpts) -> Result<String, String> {
    let json = opts.installer_json()?;
    let data = parse_installer_data(&json).map_err(|e| e.to_string())?;
    let flavors = list_installable_flavors(&data);
    if flavors.is_empty() {
        return Err("installer metadata names no installable OS flavour".into());
    }
    let mut lines = Vec::new();
    for flavor in flavors {
        lines.push(format!(
            "{}\t{}\t{}",
            flavor.slug, flavor.name, flavor.package_url
        ));
    }
    Ok(lines.join("\n") + "\n")
}

fn need<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    args.get(i)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_options_require_explicit_target_and_ipsw() {
        let args = [
            "--target-board",
            "testap",
            "--target-chip",
            "0x8103",
            "--installer-archive",
            "installer.tar.gz",
            "--installer-source-uri",
            "https://example.test/installer",
            "--ipsw",
            "restore.ipsw",
        ]
        .map(str::to_owned);
        let mut opts = CliOpts::parse(&args).unwrap();
        assert!(
            CliOpts::parse(&["--firmware-output".into(), "output".into()])
                .err()
                .unwrap()
                .contains("inside the disk")
        );
        assert_eq!(opts.target_chip, Some(0x8103));
        opts.requires_als_calibration = Some(false);
        assert!(opts.provisioning_inputs().is_ok());
        opts.stage1 = Some("unrelated.bin".into());
        assert!(opts.provisioning_inputs().is_err());
        assert!(CliOpts::parse(&["--requires-als-calibration".into(), "unknown".into()]).is_err());
        assert!(CliOpts::parse(&["--target-chip".into(), "0x100000000".into()]).is_err());
        assert!(!CliOpts::default().provisioning_requested());
    }
    #[test]
    fn headless_create_then_validate_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("kernel");
        let m1n1 = dir.path().join("m1n1");
        let root = dir.path().join("root");
        let out = dir.path().join("asahi.qcow2");
        std::fs::write(&kernel, b"KERN-cli").unwrap();
        std::fs::write(&m1n1, b"M1N1-cli").unwrap();
        std::fs::write(&root, [b"ROOT-cli".as_slice(), &[0u8; 32]].concat()).unwrap();

        let stage1 = dir.path().join("stage1.bin");
        let mut stage1_fixture = vec![0u8; 2048];
        stage1_fixture[..12].copy_from_slice(b"##m1n1_ver##");
        std::fs::write(&stage1, stage1_fixture).unwrap();
        let created = run(&[
            "create".into(),
            "--stage1".into(),
            stage1.display().to_string(),
            "--output".into(),
            out.display().to_string(),
            "--kernel".into(),
            kernel.display().to_string(),
            "--m1n1".into(),
            m1n1.display().to_string(),
            "--root".into(),
            root.display().to_string(),
            "--size".into(),
            "8M".into(),
        ])
        .expect("headless create");
        assert!(created.contains("created"));
        assert!(created.contains("qcow2=true"));
        assert!(created.contains("apfs=true"));
        assert!(crate::asahi_ops::qcow2_magic_is_present(&out));

        let report = run(&["validate".into(), out.display().to_string()]).expect("validate");
        assert!(report.contains("snapshots="));
        assert!(report.contains("chainload=true"));
        assert!(report.contains("efi=true"));
        assert!(report.contains("linux=true"));
    }

    #[test]
    fn flavors_lists_os_from_local_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let meta = dir.path().join("installer_data.json");
        std::fs::write(
            &meta,
            r#"{
                "os_list": [
                    {"name": "Fedora Asahi Remix 44 (KDE Plasma)", "package": "https://example.test/kde.zip", "partitions": []},
                    {"name": "Fedora Asahi Remix 44 Minimal", "package": "https://example.test/min.zip", "partitions": []},
                    {"name": "UEFI only", "expert": true, "package": "https://example.test/uefi.zip", "partitions": []}
                ]
            }"#,
        )
        .unwrap();
        let listed = run(&[
            "flavors".into(),
            "--metadata".into(),
            meta.display().to_string(),
        ])
        .expect("flavors");
        assert!(listed.contains("kde\t"));
        assert!(listed.contains("minimal\t"));
        assert!(!listed.contains("UEFI only"));
    }

    #[test]
    fn create_from_package_selects_flavour_and_streams_root() {
        let dir = tempfile::tempdir().unwrap();
        let meta = dir.path().join("installer_data.json");
        std::fs::write(
            &meta,
            r#"{
                "os_list": [
                    {
                        "name": "Fedora Asahi Remix 44 (KDE Plasma)",
                        "default_os_name": "Fedora KDE",
                        "boot_object": "m1n1.bin",
                        "next_object": "m1n1/boot.bin",
                        "package": "https://example.test/kde.zip",
                        "partitions": [
                            {"name": "Root", "image": "root.img"},
                            {"name": "Boot", "image": "boot.img"}
                        ]
                    },
                    {
                        "name": "Fedora Asahi Remix 44 Minimal",
                        "default_os_name": "Fedora Minimal",
                        "boot_object": "m1n1.bin",
                        "next_object": "m1n1/boot.bin",
                        "package": "https://example.test/min.zip",
                        "partitions": [
                            {"name": "Root", "image": "root.img"},
                            {"name": "Boot", "image": "boot.img"}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();
        let zip = dir.path().join("min.zip");
        std::fs::write(
            &zip,
            crate::asahi_ops::make_stored_zip(&[
                ("root.img", b"MIN-ROOT"),
                ("boot.img", b"MIN-BOOT"),
                ("esp/m1n1/boot.bin", b"MIN-M1N1"),
            ]),
        )
        .unwrap();
        let out = dir.path().join("asahi.qcow2");
        let stage1 = dir.path().join("stage1.bin");
        let mut stage1_fixture = vec![0u8; 2048];
        stage1_fixture[..12].copy_from_slice(b"##m1n1_ver##");
        std::fs::write(&stage1, stage1_fixture).unwrap();
        let created = run(&[
            "create".into(),
            "--stage1".into(),
            stage1.display().to_string(),
            "--output".into(),
            out.display().to_string(),
            "--package".into(),
            zip.display().to_string(),
            "--os".into(),
            "minimal".into(),
            "--metadata".into(),
            meta.display().to_string(),
            "--workdir".into(),
            dir.path().join("work").display().to_string(),
            "--size".into(),
            "8M".into(),
        ])
        .expect("create from package");
        assert!(created.contains("os=Fedora Minimal"), "{created}");
        assert!(created.contains("linux=true"));
        let info = crate::asahi_ops::inspect_created(&out).unwrap();
        assert!(info.linux_prefix.starts_with(b"MIN-ROOT"));
    }
}
