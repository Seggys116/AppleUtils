use apple_utils::ramrod::{FdrObjectError, FdrTrustMaterial};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

// Fixed public test seeds and explicit ordered authority profiles produce the
// frozen certificate and trust-object bytes in both libraries. These vectors
// exercise deterministic encoding and loading, not external trust acceptance.
const MX_VECTOR: &str = include_str!("fixtures/mx_fdr_material_interop.json");
const SDK_VECTOR: &str = include_str!("fixtures/sdk_fdr_material_interop.json");
const DESCRIPTOR: &str = "fdr-material.json";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MaterialVector {
    descriptor: Value,
    root_ca_seed_hex: String,
    root_ca_serial_hex: String,
    tls_root_seed_hex: String,
    tls_root_serial_hex: String,
    root_ca_public_key_hex: String,
    tls_root_public_key_hex: String,
    root_ca_certificate_hex: String,
    tls_root_certificate_hex: String,
    trust_object_hex: String,
    trust_object_sha256_hex: String,
}

fn vector(serialized: &str) -> MaterialVector {
    serde_json::from_str(serialized).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn populate(directory: &Path, fixture: &MaterialVector, omitted: Option<&str>) -> Vec<String> {
    let inputs = [
        (
            DESCRIPTOR,
            serde_json::to_vec_pretty(&fixture.descriptor).unwrap(),
        ),
        ("root-ca.seed", unhex(&fixture.root_ca_seed_hex)),
        ("root-ca.serial", unhex(&fixture.root_ca_serial_hex)),
        ("tls-root.seed", unhex(&fixture.tls_root_seed_hex)),
        ("tls-root.serial", unhex(&fixture.tls_root_serial_hex)),
    ];
    let mut names = Vec::new();
    for (name, bytes) in inputs {
        if omitted == Some(name) {
            continue;
        }
        fs::write(directory.join(name), bytes).unwrap();
        names.push(name.to_owned());
    }
    names
}

fn snapshot(directory: &Path, names: &[String]) -> Vec<(String, Vec<u8>)> {
    names
        .iter()
        .map(|name| (name.clone(), fs::read(directory.join(name)).unwrap()))
        .collect()
}

fn assert_outputs(material: &FdrTrustMaterial, fixture: &MaterialVector) {
    assert_eq!(
        material.root_ca_key().public_uncompressed().as_slice(),
        unhex(&fixture.root_ca_public_key_hex)
    );
    assert_eq!(
        material.tls_root_key().public_uncompressed().as_slice(),
        unhex(&fixture.tls_root_public_key_hex)
    );
    assert_eq!(
        material.root_ca_certificate(),
        unhex(&fixture.root_ca_certificate_hex)
    );
    assert_eq!(
        material.tls_root_certificate(),
        unhex(&fixture.tls_root_certificate_hex)
    );
    assert_eq!(material.trust_object(), unhex(&fixture.trust_object_hex));
    assert_eq!(
        material.digest().as_slice(),
        unhex(&fixture.trust_object_sha256_hex)
    );
    let subject = material.root_ca_subject().attributes();
    let expected = fixture.descriptor["rootCa"]["subject"].as_array().unwrap();
    assert_eq!(subject.len(), expected.len());
    for ((_, actual_value), expected_attribute) in subject.iter().zip(expected) {
        assert_eq!(actual_value, expected_attribute["value"].as_str().unwrap());
    }
}

fn assert_vector(fixture: &MaterialVector) {
    let directory = tempfile::tempdir().unwrap();
    let names = populate(directory.path(), fixture, None);
    assert_eq!(names.len(), 5);
    let before = snapshot(directory.path(), &names);
    let loaded = FdrTrustMaterial::load_from_directory(directory.path())
        .expect("populated golden vector must execute the real loader");
    assert_outputs(&loaded, fixture);
    assert_eq!(snapshot(directory.path(), &names), before);
    let reloaded = FdrTrustMaterial::load_from_directory(directory.path()).unwrap();
    assert_outputs(&reloaded, fixture);
    assert_eq!(snapshot(directory.path(), &names), before);
}

fn refusal(result: Result<FdrTrustMaterial, FdrObjectError>, expected: &str) -> String {
    let error = match result {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected named refusal {expected}"),
    };
    assert!(error.contains(expected), "expected {expected}, got {error}");
    error
}

#[test]
fn mx_profile_reloads_exact_authority_and_preserves_input_files() {
    assert_vector(&vector(MX_VECTOR));
}

#[test]
fn sdk_profile_reloads_exact_authority_and_preserves_input_files() {
    assert_vector(&vector(SDK_VECTOR));
}

#[test]
fn invalid_material_descriptor_records_named_refusals() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let original = vector(serialized);
        assert_vector(&original);
        for authority in ["rootCa", "tlsRoot"] {
            for fault in [
                "version",
                "empty-domain",
                "odd-domain",
                "nonhex-domain",
                "attribute",
                "window",
                "json",
            ] {
                let mut fixture = vector(serialized);
                let expected = match fault {
                    "version" => {
                        fixture.descriptor["formatVersion"] = json!(2);
                        "fdr-material-metadata-version:"
                    }
                    "empty-domain" | "odd-domain" | "nonhex-domain" => {
                        fixture.descriptor[authority]["keyDerivationDomainHex"] =
                            json!(match fault {
                                "empty-domain" => "",
                                "odd-domain" => "a",
                                _ => "gg",
                            });
                        "fdr-material-domain-invalid:"
                    }
                    "attribute" => {
                        fixture.descriptor[authority]["subject"][0]["attribute"] =
                            json!("unregisteredAttribute");
                        "fdr-material-metadata-invalid:"
                    }
                    "window" => {
                        fixture.descriptor[authority]["notAfter"] = json!(0);
                        "fdr-material-window-invalid:"
                    }
                    "json" => "fdr-material-metadata-invalid:",
                    _ => unreachable!(),
                };
                let directory = tempfile::tempdir().unwrap();
                let names = populate(directory.path(), &fixture, None);
                if fault == "json" {
                    fs::write(directory.path().join(DESCRIPTOR), b"{").unwrap();
                }
                let before = snapshot(directory.path(), &names);
                refusal(
                    FdrTrustMaterial::load_from_directory(directory.path()),
                    expected,
                );
                assert_eq!(snapshot(directory.path(), &names), before);
            }
        }
    }
}

#[test]
fn missing_material_descriptor_records_named_refusal() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_vector(&fixture);
        let directory = tempfile::tempdir().unwrap();
        let names = populate(directory.path(), &fixture, Some(DESCRIPTOR));
        let before = snapshot(directory.path(), &names);
        let error = refusal(
            FdrTrustMaterial::load_from_directory(directory.path()),
            "fdr-material-metadata-unreadable:",
        );
        assert!(error.contains(DESCRIPTOR), "{error}");
        assert_eq!(snapshot(directory.path(), &names), before);
    }
}

#[test]
fn missing_material_seed_or_serial_records_named_refusal() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_vector(&fixture);
        for (missing, category) in [
            ("root-ca.seed", "fdr-material-root-key-unreadable:"),
            ("tls-root.seed", "fdr-material-tls-key-unreadable:"),
            ("root-ca.serial", "fdr-material-serial-unreadable:"),
            ("tls-root.serial", "fdr-material-serial-unreadable:"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let names = populate(directory.path(), &fixture, Some(missing));
            let before = snapshot(directory.path(), &names);
            let error = refusal(
                FdrTrustMaterial::load_from_directory(directory.path()),
                category,
            );
            assert!(
                error.contains(missing),
                "refusal must name {missing}: {error}"
            );
            assert_eq!(snapshot(directory.path(), &names), before);
        }
    }
}

#[test]
fn portable_loader_records_named_refusal_for_contradictory_window() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_vector(&fixture);
        let directory = tempfile::tempdir().unwrap();
        let names = populate(directory.path(), &fixture, None);
        let before = snapshot(directory.path(), &names);
        refusal(
            FdrTrustMaterial::load_or_generate_portable(
                directory.path(),
                1_577_836_800,
                2_524_608_001,
            ),
            "fdr-material-window-mismatch:",
        );
        assert_eq!(snapshot(directory.path(), &names), before);
    }
}
