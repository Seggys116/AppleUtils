use std::path::PathBuf;

use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};

use crate::ramrod::{
    RestoreBehavior, load_build_manifest, raw_identity_for_variant, select_install_identity,
    select_recovery_identity,
};
use crate::restore::ap_ticket::request_ap_ticket_with_fdr_trust_digest;
use crate::restore::local_policy::{
    CurlSigningTransport, SIGNING_ENVELOPE_VERSION_INFO, SigningEnvelope,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrebootTicketRequest {
    kit_path: PathBuf,
    hardware_model: String,
    behavior: String,
    chip_id: u32,
    board_id: u32,
    security_domain: u32,
    ecid: u64,
    production_mode: bool,
    security_mode: bool,
    uid_mode: Option<bool>,
    sika_fuse: Option<u64>,
    ap_nonce_hex: String,
    sep_nonce_hex: String,
    fdr_trust_digest_hex: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrebootTicketResponse {
    os_ticket_hex: String,
    recovery_ticket_hex: String,
}

fn decode_hex<const N: usize>(text: &str, name: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!(
            "{name} must be {} hex characters, got {}",
            N * 2,
            text.len()
        ));
    }
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        let pair = text
            .as_bytes()
            .get(start..start + 2)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .filter(|pair| pair.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| format!("{name} has invalid hex at byte {index}"))?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("{name} has invalid hex at byte {index}"))?;
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn hardware_info(request: &PrebootTicketRequest) -> Dictionary {
    let mut hardware = Dictionary::new();
    for (key, value) in [
        ("ChipID", Value::Integer(u64::from(request.chip_id).into())),
        (
            "BoardID",
            Value::Integer(u64::from(request.board_id).into()),
        ),
        (
            "SecurityDomain",
            Value::Integer(u64::from(request.security_domain).into()),
        ),
        ("UniqueChipID", Value::Integer(request.ecid.into())),
        ("ProductionMode", Value::Boolean(request.production_mode)),
        ("SecurityMode", Value::Boolean(request.security_mode)),
        ("SupportsImage4", Value::Boolean(true)),
        (
            "EffectiveProductionMode",
            Value::Boolean(request.production_mode),
        ),
        (
            "EffectiveSecurityMode",
            Value::Boolean(request.security_mode),
        ),
    ] {
        hardware.insert(key.to_string(), value);
    }
    if let Some(mode) = request.uid_mode {
        hardware.insert("UID_MODE".to_string(), Value::Boolean(mode));
    }
    if let Some(fuse) = request.sika_fuse {
        hardware.insert("Ap,SikaFuse".to_string(), Value::Integer(fuse.into()));
    }
    hardware
}

pub fn sign_from_json(input: &str) -> Result<String, String> {
    let request: PrebootTicketRequest =
        serde_json::from_str(input).map_err(|error| format!("preboot ticket request: {error}"))?;
    let ap_nonce = decode_hex::<32>(&request.ap_nonce_hex, "ApNonce")?;
    let sep_nonce = decode_hex::<20>(&request.sep_nonce_hex, "SepNonce")?;
    let fdr_trust_digest = request
        .fdr_trust_digest_hex
        .as_deref()
        .map(|text| decode_hex::<32>(text, "fdrTrustDigestHex"))
        .transpose()?;
    let manifest = load_build_manifest(&request.kit_path.join("BuildManifest.plist"))
        .map_err(|error| format!("preboot BuildManifest: {error}"))?;
    let hardware = hardware_info(&request);
    let envelope = SigningEnvelope::for_this_host(SIGNING_ENVELOPE_VERSION_INFO, None)?;
    let transport = CurlSigningTransport::default();
    let behavior = RestoreBehavior::from_wire(&request.behavior).ok_or_else(|| {
        format!(
            "preboot restore behavior {:?} is not Erase or Update",
            request.behavior
        )
    })?;
    let install = select_install_identity(&manifest, &request.hardware_model, behavior)
        .map_err(|error| format!("OS identity for {}: {error}", request.hardware_model))?;
    let recovery_variant = install
        .info_string("RecoveryVariant")
        .ok_or_else(|| format!("OS identity {} has no RecoveryVariant", install.variant))?;
    let recovery = select_recovery_identity(&manifest, &request.hardware_model, recovery_variant)
        .map_err(|error| {
        format!(
            "recoveryOS identity for {}: {error}",
            request.hardware_model
        )
    })?;
    let sign = |role: &str, variant: &str, digest: Option<&[u8; 32]>| -> Result<Vec<u8>, String> {
        let identity = raw_identity_for_variant(&manifest, &request.hardware_model, variant)
            .ok_or_else(|| {
                format!(
                    "{role} identity {variant:?} for {} is unavailable",
                    request.hardware_model
                )
            })?;
        request_ap_ticket_with_fdr_trust_digest(
            &transport,
            &identity,
            &hardware,
            &ap_nonce,
            Some(&sep_nonce),
            &envelope,
            digest,
        )
        .map(|signed| signed.ticket)
        .map_err(|error| format!("{role} AP ticket: {error}"))
    };
    let os = sign("OS", &install.variant, fdr_trust_digest.as_ref())?;
    let recovery = sign("recoveryOS", &recovery.variant, None)?;
    serde_json::to_string(&PrebootTicketResponse {
        os_ticket_hex: encode_hex(&os),
        recovery_ticket_hex: encode_hex(&recovery),
    })
    .map_err(|error| format!("preboot ticket response encoding: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_fdr_digest_hex_preserves_all_32_bytes() {
        let digest = std::array::from_fn::<_, 32, _>(|index| (index * 7) as u8);
        assert_eq!(
            decode_hex::<32>(&encode_hex(&digest), "fdrTrustDigestHex").unwrap(),
            digest
        );
        let request = serde_json::json!({
            "kitPath": "configured-kit", "hardwareModel": "test-board", "behavior": "Erase",
            "chipId": 1, "boardId": 2, "securityDomain": 1, "ecid": 3,
            "productionMode": true, "securityMode": true,
            "apNonceHex": "00".repeat(32), "sepNonceHex": "00".repeat(20),
            "fdrTrustDigestHex": encode_hex(&digest),
        });
        let request: PrebootTicketRequest = serde_json::from_value(request).unwrap();
        assert_eq!(
            decode_hex::<32>(
                request.fdr_trust_digest_hex.as_deref().unwrap(),
                "fdrTrustDigestHex"
            )
            .unwrap(),
            digest
        );
    }

    #[test]
    fn malformed_fdr_digest_hex_returns_the_named_input_refusal() {
        for encoded in [
            "00".repeat(31),
            "00".repeat(33),
            format!("+f{}", "00".repeat(31)),
            "é".repeat(32),
        ] {
            let error = decode_hex::<32>(&encoded, "fdrTrustDigestHex").unwrap_err();
            assert!(error.contains("fdrTrustDigestHex"), "{error}");
        }
    }

    #[test]
    fn nonce_hex_round_trip_preserves_each_byte() {
        let nonce = std::array::from_fn::<_, 32, _>(|index| index as u8);
        let encoded = encode_hex(&nonce);
        assert_eq!(decode_hex::<32>(&encoded, "ApNonce").unwrap(), nonce);
    }
}
