use apple_utils::ramrod::{FdrObjectError, FdrTrustMaterial};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const MX_VECTOR: &str = include_str!("fixtures/mx_fdr_material_interop.json");
const SDK_VECTOR: &str = include_str!("fixtures/sdk_fdr_material_interop.json");
const RECORD: &str = "fdr-material.creation.json";
const DESCRIPTOR: &str = "fdr-material.json";
const LEGACY_REFUSAL: &str = "fdr-material-unrecorded-existing:";
const COMMITTED_JSON_REFUSAL: &str = "fdr-material-metadata-invalid:";

type Input = (&'static str, Vec<u8>);

// Public fixed seeds and ordered profiles pin the exact authority across record
// replay. Expected certificates and digests come from the frozen golden vectors.
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

fn window(fixture: &MaterialVector) -> (i64, i64) {
    (
        fixture.descriptor["rootCa"]["notBefore"].as_i64().unwrap(),
        fixture.descriptor["rootCa"]["notAfter"].as_i64().unwrap(),
    )
}

fn descriptor_json(fixture: &MaterialVector) -> String {
    format!(
        " \n{}\n ",
        serde_json::to_string_pretty(&fixture.descriptor).unwrap()
    )
}

fn committed_inputs(fixture: &MaterialVector) -> Vec<Input> {
    vec![
        ("root-ca.seed", unhex(&fixture.root_ca_seed_hex)),
        ("tls-root.seed", unhex(&fixture.tls_root_seed_hex)),
        ("root-ca.serial", unhex(&fixture.root_ca_serial_hex)),
        ("tls-root.serial", unhex(&fixture.tls_root_serial_hex)),
        (DESCRIPTOR, descriptor_json(fixture).into_bytes()),
    ]
}

fn record_bytes(fixture: &MaterialVector) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "creationVersion": 1,
        "descriptorJson": descriptor_json(fixture),
        "rootCaSeedHex": fixture.root_ca_seed_hex,
        "tlsRootSeedHex": fixture.tls_root_seed_hex,
        "rootCaSerialHex": fixture.root_ca_serial_hex,
        "tlsRootSerialHex": fixture.tls_root_serial_hex,
    }))
    .unwrap()
}

fn write_inputs(directory: &Path, inputs: &[Input]) {
    for (name, bytes) in inputs {
        fs::write(directory.join(name), bytes).unwrap();
    }
}

fn snapshot(directory: &Path, inputs: &[Input]) -> Vec<Input> {
    inputs
        .iter()
        .map(|(name, _)| (*name, fs::read(directory.join(name)).unwrap()))
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
}

fn create(directory: &Path, fixture: &MaterialVector) -> Result<FdrTrustMaterial, FdrObjectError> {
    let (not_before, not_after) = window(fixture);
    FdrTrustMaterial::load_or_generate_portable(directory, not_before, not_after)
}

fn assert_committed_control(fixture: &MaterialVector) {
    let directory = tempfile::tempdir().unwrap();
    let inputs = committed_inputs(fixture);
    write_inputs(directory.path(), &inputs);
    assert_outputs(
        &FdrTrustMaterial::load_from_directory(directory.path()).unwrap(),
        fixture,
    );
    assert_outputs(&create(directory.path(), fixture).unwrap(), fixture);
    assert_eq!(snapshot(directory.path(), &inputs), inputs);
}

fn assert_replay_prefix(fixture: &MaterialVector, prefix: usize) {
    let directory = tempfile::tempdir().unwrap();
    let mut inputs = committed_inputs(fixture);
    let record = record_bytes(fixture);
    fs::write(directory.path().join(RECORD), &record).unwrap();
    write_inputs(directory.path(), &inputs[..prefix]);
    let material = create(directory.path(), fixture)
        .expect("an elected creation record must complete its exact authority");
    assert_outputs(&material, fixture);
    inputs.push((RECORD, record));
    assert_eq!(snapshot(directory.path(), &inputs), inputs);
    assert_outputs(
        &FdrTrustMaterial::load_from_directory(directory.path()).unwrap(),
        fixture,
    );
    assert_outputs(&create(directory.path(), fixture).unwrap(), fixture);
    assert_eq!(snapshot(directory.path(), &inputs), inputs);
}

fn assert_refusal(result: Result<FdrTrustMaterial, FdrObjectError>, category: &str) -> String {
    let error = match result {
        Err(error) => error.to_string(),
        Ok(_) => panic!("expected named refusal {category}"),
    };
    assert!(
        error.starts_with(category),
        "expected {category}, got {error}"
    );
    error
}

#[test]
fn mx_creation_record_replays_every_authority_file_prefix() {
    let fixture = vector(MX_VECTOR);
    assert_committed_control(&fixture);
    for prefix in 0..=4 {
        assert_replay_prefix(&fixture, prefix);
    }
}

#[test]
fn sdk_creation_record_replays_every_authority_file_prefix() {
    let fixture = vector(SDK_VECTOR);
    assert_committed_control(&fixture);
    for prefix in 0..=4 {
        assert_replay_prefix(&fixture, prefix);
    }
}

#[test]
fn malformed_creation_record_records_named_refusal_and_preserves_inputs() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_committed_control(&fixture);
        assert_replay_prefix(&fixture, 4);
        for fault in [
            "json",
            "version",
            "unknown-field",
            "descriptor",
            "descriptor-version",
            "missing-seed",
            "seed-hex",
            "seed-length",
            "serial",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut record: Value = serde_json::from_slice(&record_bytes(&fixture)).unwrap();
            match fault {
                "json" => {}
                "version" => record["creationVersion"] = json!(2),
                "unknown-field" => record["unregisteredField"] = json!(true),
                "descriptor" => record["descriptorJson"] = json!("{"),
                "descriptor-version" => {
                    let mut descriptor = fixture.descriptor.clone();
                    descriptor["formatVersion"] = json!(2);
                    record["descriptorJson"] = json!(serde_json::to_string(&descriptor).unwrap());
                }
                "missing-seed" => {
                    record.as_object_mut().unwrap().remove("rootCaSeedHex");
                }
                "seed-hex" => record["rootCaSeedHex"] = json!("gg"),
                "seed-length" => record["rootCaSeedHex"] = json!("13"),
                "serial" => record["rootCaSerialHex"] = json!(""),
                _ => unreachable!(),
            }
            let bytes = if fault == "json" {
                b"{".to_vec()
            } else {
                serde_json::to_vec_pretty(&record).unwrap()
            };
            let mut inputs = committed_inputs(&fixture);
            inputs.truncate(4);
            inputs.push((RECORD, bytes));
            write_inputs(directory.path(), &inputs);
            assert_refusal(
                create(directory.path(), &fixture),
                "fdr-material-creation-invalid:",
            );
            assert_eq!(snapshot(directory.path(), &inputs), inputs);
        }
    }
}

#[test]
fn unreadable_creation_record_records_named_refusal_and_preserves_inputs() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_committed_control(&fixture);
        assert_replay_prefix(&fixture, 4);
        let directory = tempfile::tempdir().unwrap();
        let inputs = committed_inputs(&fixture);
        write_inputs(directory.path(), &inputs[..4]);
        fs::create_dir(directory.path().join(RECORD)).unwrap();
        assert_refusal(
            create(directory.path(), &fixture),
            "fdr-material-creation-unreadable:",
        );
        assert_eq!(snapshot(directory.path(), &inputs[..4]), inputs[..4]);
        assert!(
            fs::metadata(directory.path().join(RECORD))
                .unwrap()
                .is_dir()
        );
    }
}

#[test]
fn conflicting_creation_members_record_named_refusal_and_preserve_bytes() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_committed_control(&fixture);
        assert_replay_prefix(&fixture, 4);
        for conflicting in 0..4 {
            let directory = tempfile::tempdir().unwrap();
            let mut inputs = committed_inputs(&fixture);
            inputs.truncate(4);
            inputs[conflicting].1[0] ^= 0x40;
            let member = inputs[conflicting].0;
            inputs.push((RECORD, record_bytes(&fixture)));
            write_inputs(directory.path(), &inputs);
            let error = assert_refusal(
                create(directory.path(), &fixture),
                "fdr-material-creation-conflict:",
            );
            assert!(
                error.contains(member),
                "refusal must name {member}: {error}"
            );
            assert_eq!(snapshot(directory.path(), &inputs), inputs);
        }
    }
}

#[test]
fn unrecorded_existing_members_record_legacy_refusal_and_preserve_bytes() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_committed_control(&fixture);
        assert_replay_prefix(&fixture, 4);
        let inputs = committed_inputs(&fixture);
        for member in &inputs[..4] {
            let directory = tempfile::tempdir().unwrap();
            let preserved = vec![member.clone()];
            write_inputs(directory.path(), &preserved);
            assert_refusal(create(directory.path(), &fixture), LEGACY_REFUSAL);
            assert_eq!(snapshot(directory.path(), &preserved), preserved);
        }
    }
}

#[test]
fn creation_record_window_contradiction_records_named_refusal_and_preserves_bytes() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_committed_control(&fixture);
        assert_replay_prefix(&fixture, 4);
        for prefix in 0..=4 {
            let directory = tempfile::tempdir().unwrap();
            let mut inputs = committed_inputs(&fixture);
            inputs.truncate(prefix);
            inputs.push((RECORD, record_bytes(&fixture)));
            write_inputs(directory.path(), &inputs);
            let (not_before, not_after) = window(&fixture);
            assert_refusal(
                FdrTrustMaterial::load_or_generate_portable(
                    directory.path(),
                    not_before,
                    not_after + 1,
                ),
                "fdr-material-window-mismatch:",
            );
            assert_eq!(snapshot(directory.path(), &inputs), inputs);
        }
    }
}

#[test]
fn committed_descriptor_precedes_foreign_creation_record_and_preserves_authority() {
    for (committed, foreign) in [(MX_VECTOR, SDK_VECTOR), (SDK_VECTOR, MX_VECTOR)] {
        let fixture = vector(committed);
        let foreign = vector(foreign);
        assert_committed_control(&fixture);
        assert_replay_prefix(&foreign, 4);
        let directory = tempfile::tempdir().unwrap();
        let mut inputs = committed_inputs(&fixture);
        inputs.push((RECORD, record_bytes(&foreign)));
        write_inputs(directory.path(), &inputs);
        assert_outputs(&create(directory.path(), &fixture).unwrap(), &fixture);
        assert_outputs(
            &FdrTrustMaterial::load_from_directory(directory.path()).unwrap(),
            &fixture,
        );
        assert_outputs(&create(directory.path(), &fixture).unwrap(), &fixture);
        assert_eq!(snapshot(directory.path(), &inputs), inputs);
    }
}

#[test]
fn damaged_committed_descriptor_records_refusal_and_preserves_creation_record() {
    for serialized in [MX_VECTOR, SDK_VECTOR] {
        let fixture = vector(serialized);
        assert_committed_control(&fixture);
        assert_replay_prefix(&fixture, 4);
        let directory = tempfile::tempdir().unwrap();
        let mut inputs = committed_inputs(&fixture);
        inputs[4].1 = b"{".to_vec();
        inputs.push((RECORD, record_bytes(&fixture)));
        write_inputs(directory.path(), &inputs);
        assert_refusal(create(directory.path(), &fixture), COMMITTED_JSON_REFUSAL);
        assert_eq!(snapshot(directory.path(), &inputs), inputs);
    }
}
