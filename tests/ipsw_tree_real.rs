//! Runs the IPSW tree against a real archive. Set `APPLE_UTILS_TEST_IPSW` to an IPSW, and
//! optionally `APPLE_UTILS_TEST_IPSW_EXTRACTED` to a folder it was already unpacked into, then:
//! `cargo test --test ipsw_tree_real -- --ignored`

use std::fs;
use std::path::PathBuf;

use apple_utils::ipsw_tree::IpswStage;

fn archive() -> Option<PathBuf> {
    std::env::var_os("APPLE_UTILS_TEST_IPSW").map(PathBuf::from)
}

#[test]
#[ignore = "needs APPLE_UTILS_TEST_IPSW"]
fn stages_real_entries_that_match_an_extracted_copy() {
    let Some(archive) = archive() else {
        panic!("APPLE_UTILS_TEST_IPSW is not set");
    };
    let stage = IpswStage::open(&archive).expect("open the IPSW");
    assert!(
        stage.tree().len() > 1000,
        "tree has {} entries",
        stage.tree().len()
    );
    assert!(stage.tree().is_directory("Firmware/Manifests"));
    assert!(stage.tree().is_directory("BootabilityBundle"));
    assert!(
        fs::read_dir(stage.root()).unwrap().next().is_none(),
        "opening must not unpack anything"
    );

    let manifest = stage.stage("BuildManifest.plist").unwrap();
    assert!(fs::metadata(&manifest).unwrap().len() > 1_000_000);
    assert_eq!(
        fs::read_dir(stage.root()).unwrap().count(),
        1,
        "only the requested entry is written"
    );

    let kernel = "kernelcache.release.mac14j";
    let staged_kernel = stage.stage(kernel).unwrap();
    if let Some(extracted) = std::env::var_os("APPLE_UTILS_TEST_IPSW_EXTRACTED") {
        let extracted = PathBuf::from(extracted);
        assert_eq!(
            fs::read(&staged_kernel).unwrap(),
            fs::read(extracted.join(kernel)).unwrap(),
            "staged kernelcache differs from the extracted one"
        );
        assert_eq!(
            fs::read(&manifest).unwrap(),
            fs::read(extracted.join("BuildManifest.plist")).unwrap()
        );
    }

    let staged = stage.stage_tree("BootabilityBundle").unwrap();
    assert!(staged >= 10, "staged {staged} bundle entries");
    let current = stage.staged_path(
        "BootabilityBundle/Restore/Bootability/BootabilityBrain.framework/Versions/Current",
    );
    assert!(
        fs::symlink_metadata(&current)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let root = stage.root().to_path_buf();
    drop(stage);
    assert!(!root.exists(), "the stage must clean up after itself");
}

#[test]
#[ignore = "needs APPLE_UTILS_TEST_IPSW and the ipsw command"]
fn decrypts_a_real_aea_image_in_temp() {
    let Some(archive) = archive() else {
        panic!("APPLE_UTILS_TEST_IPSW is not set");
    };
    let stage = IpswStage::open(&archive).expect("open the IPSW");
    assert!(stage.has_cli(), "the ipsw command is not installed");
    let plain = stage.decrypt("094-56699-098.dmg.aea").expect("decrypt");
    assert!(plain.ends_with("094-56699-098.dmg"));
    let head = fs::read(&plain).unwrap();
    assert!(head.len() > 100_000_000);
    assert!(!stage.staged_path("094-56699-098.dmg.aea").exists());
    let root = stage.root().to_path_buf();
    drop(stage);
    assert!(!root.exists());
}
