use plist::{Dictionary, Value};

use super::local_policy::{
    HARDWARE_INFO_SUPPORTS_IMAGE4, KEY_AP_BOARD_ID, KEY_AP_CHIP_ID, KEY_AP_ECID,
    KEY_AP_IMG4_TICKET_REQUESTED, KEY_AP_PRODUCTION_MODE, KEY_AP_SECURITY_DOMAIN,
    KEY_AP_SECURITY_MODE, KEY_HOST_PLATFORM_INFO, KEY_RESPONSE_AP_IMG4_TICKET, KEY_UUID,
    KEY_VERSION_INFO, LocalPolicyIdentity, SIGNING_SERVER_CONTENT_TYPE,
    SIGNING_SERVER_DEFAULT_BASE_URL, SIGNING_SERVER_REQUEST_PATH, SigningEnvelope,
    SigningTransport, encode_signing_server_body, parse_signing_server_response,
};
use crate::ramrod::{PropertyValue, read_manifest};

#[derive(Clone, Debug, PartialEq)]
pub struct SignedApTicket {
    pub ticket: Vec<u8>,
    pub response: Dictionary,
}

fn refusal(name: &str, detail: impl std::fmt::Display) -> String {
    format!("ap-ticket-{name}: {detail}")
}

fn unsigned(value: &Value, key: &str) -> Result<u64, String> {
    let parsed = match value {
        Value::Integer(value) => value.as_unsigned(),
        Value::String(value) => {
            let text = value.trim();
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                text.parse().ok()
            }
        }
        _ => None,
    };
    parsed.ok_or_else(|| {
        refusal(
            "input-unreadable",
            format!("{key} must be an unsigned integer or numeric string"),
        )
    })
}

fn flag(value: &Value, key: &str) -> Result<bool, String> {
    match value {
        Value::Boolean(value) => Ok(*value),
        Value::Integer(value) => match value.as_unsigned() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(refusal(
                "input-unreadable",
                format!("{key} must be boolean or 0/1"),
            )),
        },
        _ => Err(refusal(
            "input-unreadable",
            format!("{key} must be boolean or 0/1"),
        )),
    }
}

fn required<'a>(dictionary: &'a Dictionary, key: &str) -> Result<&'a Value, String> {
    dictionary
        .get(key)
        .ok_or_else(|| refusal("input-missing", key))
}

fn rule_condition(key: &str, hardware: &Dictionary, part: LocalPolicyIdentity) -> Option<Value> {
    match key {
        "ApRawProductionMode" | "ApCurrentProductionMode" => {
            Some(Value::Boolean(part.production_mode))
        }
        "ApRawSecurityMode" => Some(Value::Boolean(part.security_mode)),
        "ApRequiresImage4" => Some(Value::Boolean(true)),
        "ApDemotionPolicyOverride" => hardware.get("DemotionPolicy").cloned(),
        "ApInRomDFU" => hardware
            .get("ApInRomDFU")
            .and_then(|value| flag(value, key).ok())
            .map(Value::Boolean),
        _ => None,
    }
}

fn apply_rules(
    entry: &mut Dictionary,
    rules: &Value,
    hardware: &Dictionary,
    part: LocalPolicyIdentity,
    component: &str,
) -> Result<(), String> {
    let rules = rules.as_array().ok_or_else(|| {
        refusal(
            "rules-unreadable",
            format!("{component}.Info.RestoreRequestRules must be an array"),
        )
    })?;
    for rule in rules {
        let rule = rule.as_dictionary().ok_or_else(|| {
            refusal(
                "rules-unreadable",
                format!("{component} rule must be a dictionary"),
            )
        })?;
        let conditions = rule
            .get("Conditions")
            .and_then(Value::as_dictionary)
            .ok_or_else(|| {
                refusal(
                    "rules-unreadable",
                    format!("{component} rule Conditions must be a dictionary"),
                )
            })?;
        let actions = rule
            .get("Actions")
            .and_then(Value::as_dictionary)
            .ok_or_else(|| {
                refusal(
                    "rules-unreadable",
                    format!("{component} rule Actions must be a dictionary"),
                )
            })?;
        if conditions.iter().all(|(key, expected)| {
            rule_condition(key, hardware, part).is_some_and(|actual| actual == *expected)
        }) {
            for (key, value) in actions {
                if let Value::Boolean(value) = value {
                    entry.insert(key.clone(), Value::Boolean(*value));
                }
            }
        }
    }
    Ok(())
}

pub fn build_ap_ticket_request(
    identity: &Dictionary,
    hardware: &Dictionary,
    ap_nonce: &[u8],
    sep_nonce: Option<&[u8]>,
    envelope: &SigningEnvelope,
) -> Result<Dictionary, String> {
    build_ap_ticket_request_with_fdr_trust_digest(
        identity, hardware, ap_nonce, sep_nonce, envelope, None,
    )
}

pub fn build_ap_ticket_request_with_fdr_trust_digest(
    identity: &Dictionary,
    hardware: &Dictionary,
    ap_nonce: &[u8],
    sep_nonce: Option<&[u8]>,
    envelope: &SigningEnvelope,
    fdr_trust_digest: Option<&[u8; 32]>,
) -> Result<Dictionary, String> {
    let part = LocalPolicyIdentity::from_hardware_info(hardware)
        .map_err(|error| refusal("hardware-identity", format!("{}: {error}", error.name())))?;
    if !flag(
        required(hardware, HARDWARE_INFO_SUPPORTS_IMAGE4)?,
        HARDWARE_INFO_SUPPORTS_IMAGE4,
    )? {
        return Err(refusal("image4-required", HARDWARE_INFO_SUPPORTS_IMAGE4));
    }
    if ap_nonce.is_empty() {
        return Err(refusal(
            "nonce-missing",
            "a live nonempty ApNonce is required",
        ));
    }
    for (key, actual) in [
        (KEY_AP_CHIP_ID, part.chip_id),
        (KEY_AP_BOARD_ID, part.board_id),
        (KEY_AP_SECURITY_DOMAIN, part.security_domain),
    ] {
        let selected = unsigned(required(identity, key)?, key)?;
        if selected != u64::from(actual) {
            return Err(refusal(
                "identity-mismatch",
                format!("{key}: selected=0x{selected:x} hardware=0x{actual:x}"),
            ));
        }
    }
    let build_id = required(identity, "UniqueBuildID")?
        .as_data()
        .filter(|data| !data.is_empty())
        .ok_or_else(|| refusal("input-unreadable", "UniqueBuildID must be nonempty data"))?;
    let manifest = required(identity, "Manifest")?
        .as_dictionary()
        .ok_or_else(|| refusal("input-unreadable", "Manifest must be a dictionary"))?;
    if let Some(digest) = fdr_trust_digest {
        for name in ["rfta", "ftap"] {
            let entry = manifest
                .get(name)
                .and_then(Value::as_dictionary)
                .ok_or_else(|| {
                    refusal(
                        "fdr-component-missing",
                        format!("Manifest.{name} must declare the FDR component"),
                    )
                })?;
            if entry
                .get("Trusted")
                .map(|value| flag(value, "Trusted"))
                .transpose()?
                != Some(true)
            {
                return Err(refusal(
                    "fdr-component-untrusted",
                    format!("Manifest.{name}.Trusted must be true"),
                ));
            }
            let info = entry
                .get("Info")
                .and_then(Value::as_dictionary)
                .ok_or_else(|| {
                    refusal(
                        "fdr-component-metadata",
                        format!("Manifest.{name}.Info must declare the hash method"),
                    )
                })?;
            if info.get("HashMethod").and_then(Value::as_string) != Some("sha2-256") {
                return Err(refusal(
                    "fdr-component-hash-method",
                    format!("Manifest.{name}.Info.HashMethod must be sha2-256"),
                ));
            }
            if let Some(value) = entry.get("Digest") {
                let declared = value.as_data().ok_or_else(|| {
                    refusal(
                        "fdr-component-digest-unreadable",
                        format!("Manifest.{name}.Digest must be data"),
                    )
                })?;
                if !declared.is_empty() && declared != digest.as_slice() {
                    return Err(refusal(
                        "fdr-component-digest-mismatch",
                        format!("Manifest.{name}.Digest differs from the configured trust digest"),
                    ));
                }
            }
        }
    }
    let mut request = Dictionary::new();
    for (key, value) in [
        (KEY_AP_ECID, part.ecid),
        (KEY_AP_CHIP_ID, u64::from(part.chip_id)),
        (KEY_AP_BOARD_ID, u64::from(part.board_id)),
        (KEY_AP_SECURITY_DOMAIN, u64::from(part.security_domain)),
    ] {
        request.insert(key.to_string(), Value::Integer(value.into()));
    }
    request.insert(
        KEY_AP_PRODUCTION_MODE.to_string(),
        Value::Boolean(part.production_mode),
    );
    request.insert(
        KEY_AP_SECURITY_MODE.to_string(),
        Value::Boolean(part.security_mode),
    );
    request.insert(
        KEY_AP_IMG4_TICKET_REQUESTED.to_string(),
        Value::Boolean(true),
    );
    request.insert("UniqueBuildID".to_string(), Value::Data(build_id.to_vec()));
    request.insert("ApNonce".to_string(), Value::Data(ap_nonce.to_vec()));
    request.insert(
        KEY_HOST_PLATFORM_INFO.to_string(),
        Value::String(envelope.host_platform_info.clone()),
    );
    request.insert(
        KEY_VERSION_INFO.to_string(),
        Value::String(envelope.version_info.clone()),
    );
    if let Some(uuid) = &envelope.uuid {
        request.insert(KEY_UUID.to_string(), Value::String(uuid.clone()));
    }
    for key in [
        "Ap,OSLongVersion",
        "Ap,OSReleaseType",
        "Ap,ProductMarketingVersion",
        "Ap,ProductType",
        "Ap,SDKPlatform",
        "Ap,Target",
        "Ap,TargetType",
        "Ap,Timestamp",
    ] {
        if let Some(value) = identity.get(key) {
            let text = value
                .as_string()
                .ok_or_else(|| refusal("input-unreadable", format!("{key} must be text")))?;
            request.insert(key.to_string(), Value::String(text.to_string()));
        }
    }
    if let Some(nonce) = sep_nonce {
        if nonce.is_empty() {
            return Err(refusal("nonce-missing", "the stated SepNonce is empty"));
        }
        request.insert("SepNonce".to_string(), Value::Data(nonce.to_vec()));
    }
    if let Some(epoch) = identity.get("NeRDEpoch") {
        request.insert(
            "NeRDEpoch".to_string(),
            Value::Integer(unsigned(epoch, "NeRDEpoch")?.into()),
        );
        request.insert("PermitNeRDPivot".to_string(), Value::Data(Vec::new()));
    }
    if let Some(value) = identity.get("PearlCertificationRootPub") {
        let data = value
            .as_data()
            .ok_or_else(|| refusal("input-unreadable", "PearlCertificationRootPub must be data"))?;
        request.insert(
            "PearlCertificationRootPub".to_string(),
            Value::Data(data.to_vec()),
        );
    }
    if let Some(value) = identity.get("AllowNeRDBoot") {
        request.insert(
            "AllowNeRDBoot".to_string(),
            Value::Boolean(flag(value, "AllowNeRDBoot")?),
        );
    }
    let requires_uid = identity
        .get("Info")
        .and_then(Value::as_dictionary)
        .and_then(|info| info.get("RequiresUIDMode"))
        .map(|value| flag(value, "RequiresUIDMode"))
        .transpose()?
        .unwrap_or(false);
    if let Some(value) = hardware.get("UID_MODE") {
        request.insert(
            "UID_MODE".to_string(),
            Value::Boolean(flag(value, "UID_MODE")?),
        );
    } else if requires_uid {
        return Err(refusal(
            "input-missing",
            "RequiresUIDMode requires the device to state UID_MODE",
        ));
    }
    if let Some(value) = hardware
        .get("Ap,SikaFuse")
        .or_else(|| hardware.get("ApSikaFuse"))
    {
        request.insert(
            "Ap,SikaFuse".to_string(),
            Value::Integer(unsigned(value, "Ap,SikaFuse")?.into()),
        );
    }
    for (name, value) in manifest {
        let entry = value.as_dictionary().ok_or_else(|| {
            refusal(
                "component-unreadable",
                format!("Manifest.{name} must be a dictionary"),
            )
        })?;
        if matches!(
            name.as_str(),
            "BasebandFirmware" | "SE,UpdatePayload" | "BaseSystem" | "Diags" | "Ap,ExclaveOS"
        ) {
            continue;
        }
        let Some(info_value) = entry.get("Info") else {
            continue;
        };
        let info = info_value.as_dictionary().ok_or_else(|| {
            refusal(
                "component-unreadable",
                format!("{name}.Info must be a dictionary"),
            )
        })?;
        let trusted = entry
            .get("Trusted")
            .map(|value| flag(value, "Trusted"))
            .transpose()?
            .unwrap_or(false);
        let rules = info.get("RestoreRequestRules");
        if rules.is_none() && !trusted {
            continue;
        }
        if info
            .get("IsFTAB")
            .map(|value| flag(value, "IsFTAB"))
            .transpose()?
            .unwrap_or(false)
        {
            continue;
        }
        if request.contains_key(name) {
            return Err(refusal("component-name-collision", name));
        }
        let mut component = entry.clone();
        component.remove("Info");
        if let Some(rules) = rules {
            apply_rules(&mut component, rules, hardware, part, name)?;
        } else {
            component.insert("EPRO".to_string(), Value::Boolean(part.production_mode));
            component.insert("ESEC".to_string(), Value::Boolean(part.security_mode));
        }
        if let Some(digest) = entry.get("Digest") {
            if digest.as_data().is_none() {
                return Err(refusal(
                    "component-unreadable",
                    format!("{name}.Digest must be data"),
                ));
            }
        } else if trusted {
            component.insert("Digest".to_string(), Value::Data(Vec::new()));
        }
        if !component.is_empty() {
            request.insert(name.clone(), Value::Dictionary(component));
        }
    }
    if let Some(digest) = fdr_trust_digest {
        for name in ["rfta", "ftap"] {
            let component = match request.get_mut(name) {
                Some(Value::Dictionary(component)) => component,
                _ => {
                    return Err(refusal(
                        "fdr-component-request-missing",
                        format!("{name} was not selected by its declared request metadata"),
                    ));
                }
            };
            if component
                .get("Trusted")
                .map(|value| flag(value, "Trusted"))
                .transpose()?
                != Some(true)
            {
                return Err(refusal(
                    "fdr-component-request-untrusted",
                    format!("{name} request rules must preserve Trusted=true"),
                ));
            }
            component.insert("Digest".to_string(), Value::Data(digest.to_vec()));
        }
    }
    Ok(request)
}

pub fn request_ap_ticket(
    transport: &dyn SigningTransport,
    identity: &Dictionary,
    hardware: &Dictionary,
    ap_nonce: &[u8],
    sep_nonce: Option<&[u8]>,
    envelope: &SigningEnvelope,
) -> Result<SignedApTicket, String> {
    request_ap_ticket_with_fdr_trust_digest(
        transport, identity, hardware, ap_nonce, sep_nonce, envelope, None,
    )
}

pub fn request_ap_ticket_with_fdr_trust_digest(
    transport: &dyn SigningTransport,
    identity: &Dictionary,
    hardware: &Dictionary,
    ap_nonce: &[u8],
    sep_nonce: Option<&[u8]>,
    envelope: &SigningEnvelope,
    fdr_trust_digest: Option<&[u8; 32]>,
) -> Result<SignedApTicket, String> {
    let request = build_ap_ticket_request_with_fdr_trust_digest(
        identity,
        hardware,
        ap_nonce,
        sep_nonce,
        envelope,
        fdr_trust_digest,
    )?;
    let encoded =
        encode_signing_server_body(&request).map_err(|error| refusal("request-encoding", error))?;
    let url = format!("{SIGNING_SERVER_DEFAULT_BASE_URL}{SIGNING_SERVER_REQUEST_PATH}");
    let answer = transport
        .post(&url, SIGNING_SERVER_CONTENT_TYPE, &encoded)
        .map_err(|error| refusal("transport", format!("{}: {error}", transport.name())))?;
    let response = parse_signing_server_response(&answer)
        .map_err(|error| refusal("response-status", error))?;
    let ticket = response
        .get(KEY_RESPONSE_AP_IMG4_TICKET)
        .and_then(Value::as_data)
        .filter(|ticket| !ticket.is_empty())
        .ok_or_else(|| {
            refusal(
                "response-ticket-missing",
                "ApImg4Ticket must be nonempty data",
            )
        })?;
    let manifest =
        read_manifest(ticket).map_err(|error| refusal("response-ticket-unreadable", error))?;
    let returned = LocalPolicyIdentity::from_manifest(&manifest)
        .map_err(|error| refusal("response-identity-unreadable", error))?;
    let expected = LocalPolicyIdentity::from_hardware_info(hardware)
        .map_err(|error| refusal("hardware-identity", error))?;
    if returned != expected {
        return Err(refusal(
            "response-identity-mismatch",
            format!(
                "returned={} expected={}",
                returned.trace_fields(),
                expected.trace_fields()
            ),
        ));
    }
    if let Some(property) = manifest.property("BNCH") {
        match &property.value {
            PropertyValue::Bytes(nonce) if nonce.as_slice() == ap_nonce => {}
            PropertyValue::Bytes(_) => {
                return Err(refusal(
                    "response-nonce-mismatch",
                    "BNCH does not match the supplied ApNonce",
                ));
            }
            _ => return Err(refusal("response-nonce-unreadable", "BNCH must be data")),
        }
    }
    if let Some(expected) = fdr_trust_digest {
        for name in ["rfta", "ftap"] {
            let mut objects = manifest.objects.iter().filter(|object| object.tag == name);
            let object = objects
                .next()
                .ok_or_else(|| refusal("response-fdr-object-missing", format!("MANB.{name}")))?;
            if objects.next().is_some() {
                return Err(refusal(
                    "response-fdr-object-ambiguous",
                    format!("MANB.{name} occurs more than once"),
                ));
            }
            let mut digests = object
                .properties
                .iter()
                .filter(|property| property.tag == "DGST");
            let property = digests.next().ok_or_else(|| {
                refusal("response-fdr-digest-missing", format!("MANB.{name}.DGST"))
            })?;
            if digests.next().is_some() {
                return Err(refusal(
                    "response-fdr-digest-ambiguous",
                    format!("MANB.{name}.DGST occurs more than once"),
                ));
            }
            match &property.value {
                PropertyValue::Bytes(digest) if digest.as_slice() == expected.as_slice() => {}
                PropertyValue::Bytes(_) => {
                    return Err(refusal(
                        "response-fdr-digest-mismatch",
                        format!("MANB.{name}.DGST differs from the configured trust digest"),
                    ));
                }
                _ => {
                    return Err(refusal(
                        "response-fdr-digest-unreadable",
                        format!("MANB.{name}.DGST must be data"),
                    ));
                }
            }
        }
    }
    Ok(SignedApTicket {
        ticket: ticket.to_vec(),
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn dictionary(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Dictionary {
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect()
    }

    fn hardware() -> Dictionary {
        dictionary([
            ("ChipID", Value::Integer(0x8103u64.into())),
            ("BoardID", Value::Integer(0x22u64.into())),
            ("UniqueChipID", Value::Integer(0x1234u64.into())),
            ("SecurityDomain", Value::Integer(1u64.into())),
            ("ProductionMode", Value::Boolean(true)),
            ("SecurityMode", Value::Boolean(true)),
            ("SupportsImage4", Value::Boolean(true)),
        ])
    }

    fn component(digest: Vec<u8>) -> Value {
        Value::Dictionary(dictionary([
            ("Trusted", Value::Boolean(true)),
            ("Digest", Value::Data(digest)),
            ("Info", Value::Dictionary(Dictionary::new())),
        ]))
    }

    fn identity(build_id: Vec<u8>, digest: Vec<u8>) -> Dictionary {
        dictionary([
            ("ApChipID", Value::String("0x8103".to_string())),
            ("ApBoardID", Value::String("0x22".to_string())),
            ("ApSecurityDomain", Value::String("0x1".to_string())),
            ("UniqueBuildID", Value::Data(build_id)),
            ("Ap,OSLongVersion", Value::String("18.0.1".to_string())),
            (
                "Manifest",
                Value::Dictionary(dictionary([("KernelCache", component(digest))])),
            ),
        ])
    }

    fn envelope() -> SigningEnvelope {
        SigningEnvelope {
            host_platform_info: "sender-platform".to_string(),
            version_info: "test-sender-version".to_string(),
            uuid: Some("sender-uuid".to_string()),
        }
    }

    fn rule(conditions: Dictionary, actions: Dictionary) -> Value {
        Value::Dictionary(dictionary([
            ("Conditions", Value::Dictionary(conditions)),
            ("Actions", Value::Dictionary(actions)),
        ]))
    }

    #[test]
    fn modern_request_uses_live_identity_nonce_metadata_and_component_digest() {
        let mut selected = identity(vec![1, 2, 3], vec![4, 5, 6]);
        selected.insert("NeRDEpoch".to_string(), Value::String("0x12".to_string()));
        selected.insert(
            "PearlCertificationRootPub".to_string(),
            Value::Data(vec![7, 8]),
        );
        selected.insert("AllowNeRDBoot".to_string(), Value::Boolean(true));
        selected.insert(
            "Info".to_string(),
            Value::Dictionary(dictionary([("RequiresUIDMode", Value::Boolean(true))])),
        );
        let mut hardware = hardware();
        hardware.insert("UID_MODE".to_string(), Value::Boolean(true));
        hardware.insert("ApSikaFuse".to_string(), Value::Integer(3u64.into()));
        let request =
            build_ap_ticket_request(&selected, &hardware, &[9, 10], Some(&[11, 12]), &envelope())
                .expect("live device terms build an Image4 request");
        assert_eq!(request["ApECID"].as_unsigned_integer(), Some(0x1234));
        assert_eq!(request["ApChipID"].as_unsigned_integer(), Some(0x8103));
        assert_eq!(request["ApBoardID"].as_unsigned_integer(), Some(0x22));
        assert_eq!(request["ApSecurityDomain"].as_unsigned_integer(), Some(1));
        assert_eq!(request["ApProductionMode"].as_boolean(), Some(true));
        assert_eq!(request["ApSecurityMode"].as_boolean(), Some(true));
        assert_eq!(request["@ApImg4Ticket"].as_boolean(), Some(true));
        assert_eq!(request["ApNonce"].as_data(), Some([9, 10].as_slice()));
        assert_eq!(request["SepNonce"].as_data(), Some([11, 12].as_slice()));
        assert_eq!(
            request["UniqueBuildID"].as_data(),
            Some([1, 2, 3].as_slice())
        );
        assert_eq!(request["Ap,OSLongVersion"].as_string(), Some("18.0.1"));
        assert_eq!(
            request["@HostPlatformInfo"].as_string(),
            Some("sender-platform")
        );
        assert_eq!(
            request["@VersionInfo"].as_string(),
            Some("test-sender-version")
        );
        assert_eq!(request["@UUID"].as_string(), Some("sender-uuid"));
        assert_eq!(request["UID_MODE"].as_boolean(), Some(true));
        assert_eq!(request["Ap,SikaFuse"].as_unsigned_integer(), Some(3));
        assert_eq!(request["NeRDEpoch"].as_unsigned_integer(), Some(0x12));
        assert_eq!(request["PermitNeRDPivot"].as_data(), Some([].as_slice()));
        assert_eq!(
            request["PearlCertificationRootPub"].as_data(),
            Some([7, 8].as_slice())
        );
        assert_eq!(request["AllowNeRDBoot"].as_boolean(), Some(true));
        let kernel = request["KernelCache"]
            .as_dictionary()
            .expect("the AP component is a dictionary");
        assert_eq!(kernel["Digest"].as_data(), Some([4, 5, 6].as_slice()));
        assert_eq!(kernel["EPRO"].as_boolean(), Some(true));
        assert_eq!(kernel["ESEC"].as_boolean(), Some(true));
        assert_eq!(
            kernel.len(),
            4,
            "the wire component has Trusted, Digest, EPRO and ESEC"
        );
    }

    #[test]
    fn request_and_component_modes_follow_the_device_stated_modes() {
        let mut hardware = hardware();
        hardware.insert("ProductionMode".to_string(), Value::Boolean(false));
        hardware.insert("SecurityMode".to_string(), Value::Integer(0u64.into()));
        let request = build_ap_ticket_request(
            &identity(vec![1], vec![2]),
            &hardware,
            &[3],
            None,
            &envelope(),
        )
        .unwrap();
        assert_eq!(request["ApProductionMode"].as_boolean(), Some(false));
        assert_eq!(request["ApSecurityMode"].as_boolean(), Some(false));
        let kernel = request["KernelCache"].as_dictionary().unwrap();
        assert_eq!(kernel["EPRO"].as_boolean(), Some(false));
        assert_eq!(kernel["ESEC"].as_boolean(), Some(false));
    }

    #[test]
    fn restore_rules_use_hardware_conditions_and_apply_actions_in_order() {
        let mut selected = identity(vec![1], vec![2]);
        let rules = vec![
            rule(
                dictionary([
                    ("ApRawProductionMode", Value::Boolean(true)),
                    ("ApCurrentProductionMode", Value::Boolean(true)),
                    ("ApRawSecurityMode", Value::Boolean(true)),
                    ("ApRequiresImage4", Value::Boolean(true)),
                ]),
                dictionary([
                    ("EPRO", Value::Boolean(true)),
                    ("ESEC", Value::Boolean(true)),
                ]),
            ),
            rule(
                dictionary([("ApDemotionPolicyOverride", Value::Boolean(true))]),
                dictionary([("EPRO", Value::Boolean(false))]),
            ),
            rule(
                dictionary([("ApInRomDFU", Value::Boolean(true))]),
                dictionary([("ESEC", Value::Boolean(false))]),
            ),
            rule(
                dictionary([("UnknownCondition", Value::Boolean(true))]),
                dictionary([("EPRO", Value::Boolean(true))]),
            ),
        ];
        selected
            .get_mut("Manifest")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .get_mut("KernelCache")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert(
                "Info".to_string(),
                Value::Dictionary(dictionary([("RestoreRequestRules", Value::Array(rules))])),
            );
        let mut hardware = hardware();
        hardware.insert("DemotionPolicy".to_string(), Value::Boolean(true));
        hardware.insert("ApInRomDFU".to_string(), Value::Integer(1u64.into()));
        let request =
            build_ap_ticket_request(&selected, &hardware, &[3], None, &envelope()).unwrap();
        let kernel = request["KernelCache"].as_dictionary().unwrap();
        assert_eq!(kernel["EPRO"].as_boolean(), Some(false));
        assert_eq!(kernel["ESEC"].as_boolean(), Some(false));
        assert_eq!(kernel["Digest"].as_data(), Some([2].as_slice()));
    }

    #[test]
    fn trusted_component_without_digest_uses_required_empty_data() {
        let mut selected = identity(vec![1], vec![2]);
        selected
            .get_mut("Manifest")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .get_mut("KernelCache")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .remove("Digest");
        let request =
            build_ap_ticket_request(&selected, &hardware(), &[3], None, &envelope()).unwrap();
        assert_eq!(
            request["KernelCache"].as_dictionary().unwrap()["Digest"].as_data(),
            Some([].as_slice())
        );
    }

    #[test]
    fn selected_identities_keep_their_own_build_id_and_component_digest() {
        for (build_id, digest) in [(vec![1, 2], vec![3, 4]), (vec![5, 6], vec![7, 8])] {
            let request = build_ap_ticket_request(
                &identity(build_id.clone(), digest.clone()),
                &hardware(),
                &[9],
                None,
                &envelope(),
            )
            .unwrap();
            assert_eq!(
                request["UniqueBuildID"].as_data(),
                Some(build_id.as_slice())
            );
            assert_eq!(
                request["KernelCache"].as_dictionary().unwrap()["Digest"].as_data(),
                Some(digest.as_slice())
            );
        }
    }

    #[test]
    fn missing_and_mismatching_inputs_have_named_refusals() {
        let selected = identity(vec![1], vec![2]);
        let mut missing = selected.clone();
        missing.remove("UniqueBuildID");
        let error =
            build_ap_ticket_request(&missing, &hardware(), &[3], None, &envelope()).unwrap_err();
        assert!(error.contains("ap-ticket-input-missing: UniqueBuildID"));
        let error =
            build_ap_ticket_request(&selected, &hardware(), &[], None, &envelope()).unwrap_err();
        assert!(error.contains("ap-ticket-nonce-missing"));
        for key in ["ApChipID", "ApBoardID", "ApSecurityDomain"] {
            let mut mismatch = selected.clone();
            mismatch.insert(key.to_string(), Value::String("0x99".to_string()));
            let error = build_ap_ticket_request(&mismatch, &hardware(), &[3], None, &envelope())
                .unwrap_err();
            assert!(error.contains("ap-ticket-identity-mismatch"));
            assert!(error.contains(key));
        }
        let mut requires_uid = selected.clone();
        requires_uid.insert(
            "Info".to_string(),
            Value::Dictionary(dictionary([("RequiresUIDMode", Value::Boolean(true))])),
        );
        let error = build_ap_ticket_request(&requires_uid, &hardware(), &[3], None, &envelope())
            .unwrap_err();
        assert!(error.contains("ap-ticket-input-missing"));
        assert!(error.contains("UID_MODE"));
        let mut unsupported_hardware = hardware();
        unsupported_hardware.insert("SupportsImage4".to_string(), Value::Boolean(false));
        let error =
            build_ap_ticket_request(&selected, &unsupported_hardware, &[3], None, &envelope())
                .unwrap_err();
        assert!(error.contains("ap-ticket-image4-required"));
        let mut hardware = hardware();
        hardware.remove("UniqueChipID");
        let error =
            build_ap_ticket_request(&selected, &hardware, &[3], None, &envelope()).unwrap_err();
        assert!(error.contains("ap-ticket-hardware-identity"));
        assert!(error.contains("UniqueChipID"));
    }

    fn der(tag: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = tag.to_vec();
        if body.len() < 0x80 {
            bytes.push(body.len() as u8);
        } else {
            let length = u16::try_from(body.len()).expect("fixture length fits two bytes");
            bytes.extend_from_slice(&[0x82, (length >> 8) as u8, length as u8]);
        }
        bytes.extend_from_slice(body);
        bytes
    }

    fn named(code: &str, body: &[u8]) -> Vec<u8> {
        let mut value = u32::from_be_bytes(code.as_bytes().try_into().unwrap());
        let mut groups = Vec::new();
        loop {
            groups.push((value & 0x7f) as u8);
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        groups.reverse();
        let last = groups.len() - 1;
        for group in &mut groups[..last] {
            *group |= 0x80;
        }
        let mut tag = vec![0xff];
        tag.extend_from_slice(&groups);
        let mut inner = der(&[0x16], code.as_bytes());
        inner.extend_from_slice(body);
        der(&tag, &der(&[0x30], &inner))
    }

    fn ticket(ecid: &[u8], nonce: &[u8]) -> Vec<u8> {
        ticket_with_objects(ecid, nonce, &[])
    }

    fn ticket_with_objects(ecid: &[u8], nonce: &[u8], objects: &[Vec<u8>]) -> Vec<u8> {
        let mut properties = Vec::new();
        for (tag, value) in [
            ("CHIP", &[0x00, 0x81, 0x03][..]),
            ("BORD", &[0x22][..]),
            ("SDOM", &[1][..]),
            ("ECID", ecid),
        ] {
            properties.extend_from_slice(&named(tag, &der(&[0x02], value)));
        }
        for tag in ["CPRO", "CSEC"] {
            properties.extend_from_slice(&named(tag, &der(&[0x01], &[0xff])));
        }
        properties.extend_from_slice(&named("BNCH", &der(&[0x04], nonce)));
        let mut entries = named("MANP", &der(&[0x31], &properties));
        for object in objects {
            entries.extend_from_slice(object);
        }
        let manb = named("MANB", &der(&[0x31], &entries));
        let mut body = der(&[0x16], b"IM4M");
        body.extend_from_slice(&der(&[0x02], &[0]));
        body.extend_from_slice(&der(&[0x31], &manb));
        body.extend_from_slice(&der(&[0x04], &[0x42; 8]));
        der(&[0x30], &body)
    }

    struct FixtureTransport {
        answer: Vec<u8>,
        submitted: Mutex<Option<(String, String, Vec<u8>)>>,
    }

    impl SigningTransport for FixtureTransport {
        fn name(&self) -> &'static str {
            "fixture"
        }

        fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, String> {
            *self.submitted.lock().unwrap() =
                Some((url.to_string(), content_type.to_string(), body.to_vec()));
            Ok(self.answer.clone())
        }
    }

    fn transport(ticket: Vec<u8>) -> FixtureTransport {
        let response = dictionary([
            ("ApImg4Ticket", Value::Data(ticket)),
            ("ServerMetadata", Value::String("preserved".to_string())),
        ]);
        let mut answer = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
        answer.extend_from_slice(&encode_signing_server_body(&response).unwrap());
        FixtureTransport {
            answer,
            submitted: Mutex::new(None),
        }
    }

    fn fdr_identity() -> Dictionary {
        let mut selected = identity(vec![1], vec![2]);
        let manifest = selected
            .get_mut("Manifest")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();
        for name in ["rfta", "ftap"] {
            manifest.insert(
                name.to_string(),
                Value::Dictionary(dictionary([
                    ("Trusted", Value::Boolean(true)),
                    (
                        "Info",
                        Value::Dictionary(dictionary([
                            ("HashMethod", Value::String("sha2-256".to_string())),
                            ("Personalize", Value::Boolean(false)),
                            ("IsFTAB", Value::Boolean(false)),
                            (
                                "RestoreRequestRules",
                                Value::Array(vec![
                                    rule(
                                        dictionary([("ApRawProductionMode", Value::Boolean(true))]),
                                        dictionary([("EPRO", Value::Boolean(true))]),
                                    ),
                                    rule(
                                        dictionary([("ApRawSecurityMode", Value::Boolean(true))]),
                                        dictionary([("ESEC", Value::Boolean(true))]),
                                    ),
                                ]),
                            ),
                        ])),
                    ),
                ])),
            );
        }
        selected
    }

    fn configured_trust_digest() -> [u8; 32] {
        let directory = tempfile::tempdir().unwrap();
        let material = crate::ramrod::FdrTrustMaterial::load_or_generate(
            directory.path(),
            crate::restore::plan::FDR_TRUST_NOT_BEFORE,
            crate::restore::plan::FDR_TRUST_NOT_AFTER,
        )
        .unwrap();
        material.digest()
    }

    fn fdr_object(name: &str, digest: &[u8]) -> Vec<u8> {
        named(name, &der(&[0x31], &named("DGST", &der(&[0x04], digest))))
    }

    #[test]
    fn configured_fdr_digest_uses_declared_trusted_sha256_components_and_request_rules() {
        let digest = configured_trust_digest();
        let selected = fdr_identity();
        let original = selected.clone();
        let request = build_ap_ticket_request_with_fdr_trust_digest(
            &selected,
            &hardware(),
            &[3],
            None,
            &envelope(),
            Some(&digest),
        )
        .unwrap();
        for name in ["rfta", "ftap"] {
            let component = request[name].as_dictionary().unwrap();
            assert_eq!(component["Digest"].as_data(), Some(digest.as_slice()));
            assert_eq!(component["Trusted"].as_boolean(), Some(true));
            assert_eq!(component["EPRO"].as_boolean(), Some(true));
            assert_eq!(component["ESEC"].as_boolean(), Some(true));
        }
        assert_eq!(selected, original);
    }

    #[test]
    fn configured_fdr_component_metadata_refusals_are_named() {
        let digest = configured_trust_digest();
        for (key, value, expected) in [
            (
                "Trusted",
                Value::Boolean(false),
                "ap-ticket-fdr-component-untrusted",
            ),
            (
                "Info",
                Value::Dictionary(dictionary([(
                    "HashMethod",
                    Value::String("sha2-384".to_string()),
                )])),
                "ap-ticket-fdr-component-hash-method",
            ),
            (
                "Digest",
                Value::Data(vec![0; 31]),
                "ap-ticket-fdr-component-digest-mismatch",
            ),
        ] {
            let mut selected = fdr_identity();
            selected
                .get_mut("Manifest")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .get_mut("rfta")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .insert(key.to_string(), value);
            let error = build_ap_ticket_request_with_fdr_trust_digest(
                &selected,
                &hardware(),
                &[3],
                None,
                &envelope(),
                Some(&digest),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
        let error = build_ap_ticket_request_with_fdr_trust_digest(
            &identity(vec![1], vec![2]),
            &hardware(),
            &[3],
            None,
            &envelope(),
            Some(&digest),
        )
        .unwrap_err();
        assert!(error.contains("ap-ticket-fdr-component-missing"), "{error}");
        assert!(error.contains("rfta"), "{error}");
    }

    #[test]
    fn returned_fdr_binding_preserves_the_native_response_bytes() {
        let digest = configured_trust_digest();
        let ticket = ticket_with_objects(
            &[0x12, 0x34],
            &[3],
            &[fdr_object("rfta", &digest), fdr_object("ftap", &digest)],
        );
        let transport = transport(ticket.clone());
        let signed = request_ap_ticket_with_fdr_trust_digest(
            &transport,
            &fdr_identity(),
            &hardware(),
            &[3],
            None,
            &envelope(),
            Some(&digest),
        )
        .unwrap();
        assert_eq!(signed.ticket, ticket);
        assert_eq!(
            signed.response["ApImg4Ticket"].as_data(),
            Some(ticket.as_slice())
        );
        let submitted = transport.submitted.lock().unwrap();
        let (_, _, body) = submitted.as_ref().unwrap();
        let request = Value::from_reader_xml(std::io::Cursor::new(body))
            .unwrap()
            .into_dictionary()
            .unwrap();
        for name in ["rfta", "ftap"] {
            assert_eq!(
                request[name].as_dictionary().unwrap()["Digest"].as_data(),
                Some(digest.as_slice())
            );
        }
    }

    #[test]
    fn returned_fdr_binding_refusals_name_the_exact_object_or_digest() {
        let digest = configured_trust_digest();
        let mut other = digest;
        other[0] ^= 1;
        for (objects, expected, name) in [
            (
                vec![fdr_object("rfta", &digest)],
                "ap-ticket-response-fdr-object-missing",
                "ftap",
            ),
            (
                vec![fdr_object("rfta", &other), fdr_object("ftap", &digest)],
                "ap-ticket-response-fdr-digest-mismatch",
                "rfta",
            ),
            (
                vec![fdr_object("rfta", &digest), fdr_object("ftap", &other)],
                "ap-ticket-response-fdr-digest-mismatch",
                "ftap",
            ),
            (
                vec![
                    fdr_object("rfta", &digest),
                    fdr_object("rfta", &digest),
                    fdr_object("ftap", &digest),
                ],
                "ap-ticket-response-fdr-object-ambiguous",
                "rfta",
            ),
        ] {
            let transport = transport(ticket_with_objects(&[0x12, 0x34], &[3], &objects));
            let error = request_ap_ticket_with_fdr_trust_digest(
                &transport,
                &fdr_identity(),
                &hardware(),
                &[3],
                None,
                &envelope(),
                Some(&digest),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert!(error.contains(name), "{error}");
        }
    }

    #[test]
    fn successful_status_preserves_ticket_and_response_and_posts_xml() {
        let ticket = ticket(&[0x12, 0x34], &[3, 4]);
        let transport = transport(ticket.clone());
        let signed = request_ap_ticket(
            &transport,
            &identity(vec![1], vec![2]),
            &hardware(),
            &[3, 4],
            None,
            &envelope(),
        )
        .expect("matching returned part and nonce are accepted");
        assert_eq!(signed.ticket, ticket);
        assert_eq!(
            signed.response["ApImg4Ticket"].as_data(),
            Some(ticket.as_slice())
        );
        assert_eq!(
            signed.response["ServerMetadata"].as_string(),
            Some("preserved")
        );
        let submitted = transport.submitted.lock().unwrap();
        let (url, content_type, body) = submitted
            .as_ref()
            .expect("the transport received one request");
        assert_eq!(url, "https://gs.apple.com:443/TSS/controller?action=2");
        assert_eq!(content_type, SIGNING_SERVER_CONTENT_TYPE);
        let request = Value::from_reader_xml(std::io::Cursor::new(body))
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(request["ApNonce"].as_data(), Some([3, 4].as_slice()));
        assert_eq!(request["@ApImg4Ticket"].as_boolean(), Some(true));
    }

    #[test]
    fn response_status_identity_and_nonce_refusals_are_named() {
        let selected = identity(vec![1], vec![2]);
        for (transport, expected) in [
            (
                FixtureTransport {
                    answer: b"STATUS=94&MESSAGE=not eligible".to_vec(),
                    submitted: Mutex::new(None),
                },
                "ap-ticket-response-status",
            ),
            (
                transport(ticket(&[0x12, 0x35], &[3])),
                "ap-ticket-response-identity-mismatch",
            ),
            (
                transport(ticket(&[0x12, 0x34], &[4])),
                "ap-ticket-response-nonce-mismatch",
            ),
        ] {
            let error =
                request_ap_ticket(&transport, &selected, &hardware(), &[3], None, &envelope())
                    .unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
    }
}
