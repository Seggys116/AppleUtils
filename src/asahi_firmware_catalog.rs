use crate::asahi_firmware::{
    CatalogProvenance, FirmwareCatalogEntry, Prerequisites, TargetConstraints,
};
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

const EXTRACT: &str = r#"
import ast,json,sys
module=ast.parse(sys.stdin.read())
names=('IPSW_VERSIONS','CHIP_MIN_VER','DEVICES')
found={}
for node in module.body:
    if isinstance(node,ast.Assign):
        for target in node.targets:
            if isinstance(target,ast.Name) and target.id in names:
                if target.id in found: raise ValueError('duplicate catalog '+target.id)
                found[target.id]=node.value
if set(found)!=set(names): raise ValueError('missing literal installer catalogs')
def literal(node):
    return ast.literal_eval(node)
def record(node,name,fields):
    if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Name) or node.func.id!=name:
        raise ValueError('unsupported catalog constructor')
    if node.keywords or len(node.args)!=len(fields): raise ValueError('unsupported constructor fields')
    return dict(zip(fields,map(literal,node.args)))
ipsws=found['IPSW_VERSIONS']
devices=found['DEVICES']
chips=literal(found['CHIP_MIN_VER'])
if not isinstance(ipsws,(ast.List,ast.Tuple)) or not isinstance(devices,ast.Dict) or not isinstance(chips,dict):
    raise ValueError('unsupported catalog shape')
out_devices={}
for k,v in zip(devices.keys,devices.values):
    key=literal(k)
    if key in out_devices: raise ValueError('duplicate device')
    out_devices[key]=record(v,'Device',('min_ver','expert_only'))
print(json.dumps({'ipsws':[record(v,'IPSW',('version','min_macos','min_iboot','min_sfr','expert_only','devices','url')) for v in ipsws.elts],
    'chips':{str(k):v for k,v in chips.items()},'devices':out_devices}))
"#;

pub struct InstallerFirmwarePolicy {
    pub catalog: Vec<FirmwareCatalogEntry>,
    pub target: TargetConstraints,
    pub provenance: CatalogProvenance,
}

fn string(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("invalid installer catalog field {field}"))
}

fn boolean(value: &Value, field: &str) -> Result<bool, String> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("invalid installer catalog field {field}"))
}

pub fn read_installer_firmware_policy(
    installer_main: &[u8],
    board: &str,
    chip_id: u32,
    expert: bool,
    provenance: CatalogProvenance,
) -> Result<InstallerFirmwarePolicy, String> {
    if installer_main.len() > 4 * 1024 * 1024 {
        return Err("installer policy source exceeds bounded parser input".into());
    }
    if provenance.source_uri.trim().is_empty() || provenance.revision.trim().is_empty() {
        return Err("installer policy requires verified archive provenance".into());
    }
    let mut child = Command::new("python3")
        .args(["-I", "-c", EXTRACT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start installer AST reader: {e}"))?;
    let write_result = child
        .stdin
        .take()
        .ok_or("installer AST reader has no input")?
        .write_all(installer_main);
    let output = child
        .wait_with_output()
        .map_err(|e| format!("installer AST reader failed: {e}"))?;
    write_result.map_err(|e| format!("cannot supply installer policy: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "unsupported installer policy: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid AST catalog output: {e}"))?;
    let device = value
        .get("devices")
        .and_then(|v| v.get(board))
        .ok_or("target board is absent from official device catalog")?;
    if boolean(device, "expert_only")? && !expert {
        return Err("official device catalog requires expert mode for this board".into());
    }
    let chip_min = value
        .get("chips")
        .and_then(|v| v.get(chip_id.to_string()))
        .and_then(Value::as_str)
        .ok_or("target chip is absent from official chip catalog")?;
    let mut catalog = Vec::new();
    for entry in value
        .get("ipsws")
        .and_then(Value::as_array)
        .ok_or("missing IPSW catalog")?
    {
        let devices = match entry.get("devices") {
            Some(Value::Null) => None,
            Some(Value::Array(values)) => Some(
                values
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| "invalid IPSW device allowlist".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => return Err("invalid IPSW devices field".into()),
        };
        catalog.push(FirmwareCatalogEntry {
            version: string(entry, "version")?,
            min_macos: string(entry, "min_macos")?,
            min_iboot: string(entry, "min_iboot")?,
            min_sfr: string(entry, "min_sfr")?,
            expert_only: boolean(entry, "expert_only")?,
            devices,
            restore_url: string(entry, "url")?,
        });
    }
    if catalog.is_empty() {
        return Err("empty official IPSW catalog".into());
    }
    Ok(InstallerFirmwarePolicy {
        catalog,
        target: TargetConstraints {
            board: board.into(),
            chip_id,
            chip_min_version: chip_min.into(),
            device_min_version: string(device, "min_ver")?,
            expert,
            prerequisites: Prerequisites::VirtualTarget,
        },
        provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &[u8] = br#"
raise RuntimeError('this must never execute')
CHIP_MIN_VER={91:'2.1'}
DEVICES={'fixture':Device('2.2',False)}
IPSW_VERSIONS=[IPSW('3.0','2','iBoot-7','8,0',False,None,'https://example.test/a'),
IPSW('2.5','2','iBoot-7','8,0',True,['fixture'],'https://example.test/b')]
"#;
    fn provenance() -> CatalogProvenance {
        CatalogProvenance {
            source_uri: "https://example.test/installer".into(),
            revision: "archive-digest".into(),
        }
    }
    #[test]
    fn parses_all_fields_without_executing_source() {
        let policy =
            read_installer_firmware_policy(SOURCE, "fixture", 91, false, provenance()).unwrap();
        assert_eq!(policy.catalog.len(), 2);
        assert_eq!(policy.catalog[1].version, "2.5");
        assert_eq!(policy.catalog[1].devices, Some(vec!["fixture".into()]));
        assert!(policy.catalog[1].expert_only);
        assert_eq!(policy.target.chip_min_version, "2.1");
        assert_eq!(policy.target.device_min_version, "2.2");
        assert_eq!(policy.target.prerequisites, Prerequisites::VirtualTarget);
    }
    #[test]
    fn rejects_unknown_targets_and_nonliteral_catalogs() {
        assert!(read_installer_firmware_policy(SOURCE, "other", 91, false, provenance()).is_err());
        assert!(
            read_installer_firmware_policy(SOURCE, "fixture", 92, false, provenance()).is_err()
        );
        let unsafe_source = String::from_utf8(SOURCE.to_vec())
            .unwrap()
            .replace("'2.1'", "str(2)");
        assert!(
            read_installer_firmware_policy(
                unsafe_source.as_bytes(),
                "fixture",
                91,
                false,
                provenance()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod real_catalog_tests {
    use super::*;
    #[test]
    #[ignore = "requires ASAHI_INSTALLER_MAIN pointing to official installer source"]
    fn reads_official_installer_catalog() {
        let bytes = std::fs::read(std::env::var("ASAHI_INSTALLER_MAIN").unwrap()).unwrap();
        let digest = crate::crypto::sha256(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let provenance = CatalogProvenance {
            source_uri: "https://github.com/AsahiLinux/asahi-installer".into(),
            revision: digest,
        };
        let policy =
            read_installer_firmware_policy(&bytes, "j274ap", 0x8103, false, provenance).unwrap();
        let supported = vec![
            "12.3".into(),
            "12.3.1".into(),
            "13.5".into(),
            "14.8.3".into(),
        ];
        let selected = crate::asahi_firmware::select_firmware(
            &policy.catalog,
            Some(&supported),
            &policy.target,
            &policy.provenance,
        )
        .unwrap();
        assert_eq!(selected.entry.version, "13.5");
    }
}
