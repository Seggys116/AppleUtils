use std::process::Command;

#[test]
fn binary_creates_and_validates_a_qcow2_headlessly() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("kernel");
    let m1n1 = dir.path().join("m1n1");
    let root = dir.path().join("root");
    let stage1 = dir.path().join("stage1");
    let out = dir.path().join("asahi.qcow2");
    std::fs::write(&kernel, b"KERN-bin").unwrap();
    std::fs::write(&m1n1, b"M1N1-bin").unwrap();
    std::fs::write(&root, [b"ROOT-bin".as_slice(), &[0u8; 32]].concat()).unwrap();

    let mut stage1_bytes = vec![0u8; 2048];
    stage1_bytes[..12].copy_from_slice(b"##m1n1_ver##");
    std::fs::write(&stage1, stage1_bytes).unwrap();

    let bin = env!("CARGO_BIN_EXE_apple-utils");
    let create = Command::new(bin)
        .args([
            "asahi",
            "create",
            "--output",
            out.to_str().unwrap(),
            "--kernel",
            kernel.to_str().unwrap(),
            "--m1n1",
            m1n1.to_str().unwrap(),
            "--stage1",
            stage1.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--size",
            "8M",
        ])
        .output()
        .expect("run asahi create");
    assert!(
        create.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let stdout = String::from_utf8_lossy(&create.stdout);
    assert!(stdout.contains("qcow2=true"), "{stdout}");
    assert!(stdout.contains("apfs=true"), "{stdout}");
    assert!(out.exists());

    let validate = Command::new(bin)
        .args(["asahi", "validate", out.to_str().unwrap()])
        .output()
        .expect("run asahi validate");
    assert!(
        validate.status.success(),
        "validate failed: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let report = String::from_utf8_lossy(&validate.stdout);
    assert!(report.contains("chainload=true"), "{report}");
    assert!(report.contains("linux=true"), "{report}");
    assert!(report.contains("efi=true"), "{report}");
    assert!(report.contains("picker_visible=true"), "{report}");
    assert!(report.contains("custom_boot_object=true"), "{report}");
    let blessed = report
        .lines()
        .find(|line| line.starts_with("blessed_vgid="))
        .unwrap_or("");
    assert!(
        blessed.len() > "blessed_vgid=".len() + 8,
        "blessed_vgid must name the stub SYSTEM VGID, got {report}"
    );
}
