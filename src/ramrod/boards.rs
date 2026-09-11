use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::OnceLock;

use plist::{Dictionary, Value};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardLabel {
    pub class: String,
    pub title: String,
    pub detail: String,
}

#[must_use]
pub fn describe_board(class: &str, platform: Option<&str>) -> BoardLabel {
    let key = class.trim().to_ascii_lowercase();
    let catalog = device_catalog();
    let record = catalog.boards.get(&key);
    let chip = record
        .and_then(|record| record.cpu.as_deref())
        .or_else(|| {
            platform
                .map(str::trim)
                .filter(|platform| !platform.is_empty())
                .and_then(|platform| catalog.platforms.get(&platform.to_ascii_lowercase()))
                .map(String::as_str)
        });
    let title = record
        .map(|record| format_board_title(&record.name, record.cpu.as_deref(), record.radio.as_deref()))
        .unwrap_or_else(|| class.to_string());
    let detail = match chip {
        Some(chip) => format!("{class}  ·  {chip}"),
        None => class.to_string(),
    };
    BoardLabel {
        class: class.to_string(),
        title,
        detail,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreCatalog {
    pub product_version: Option<String>,
    pub product_build: Option<String>,
    pub boards: Vec<String>,
    pub platforms: HashMap<String, String>,
}

#[must_use]
pub fn load_restore_catalog(extract_root: &Path) -> Option<RestoreCatalog> {
    let path = extract_root.join(super::RESTORE_PLIST_FILE_NAME);
    let file = File::open(path).ok()?;
    let Value::Dictionary(root) = Value::from_reader(file).ok()? else {
        return None;
    };
    Some(restore_catalog_from(&root))
}

#[must_use]
pub fn load_device_platforms(extract_root: &Path) -> HashMap<String, String> {
    load_restore_catalog(extract_root)
        .map(|catalog| catalog.platforms)
        .unwrap_or_default()
}

fn restore_catalog_from(root: &Dictionary) -> RestoreCatalog {
    let product_version = root
        .get("ProductVersion")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let product_build = root
        .get("ProductBuildVersion")
        .and_then(Value::as_string)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let mut boards = Vec::new();
    let mut platforms = HashMap::new();
    if let Some(entries) = root.get("DeviceMap").and_then(Value::as_array) {
        for entry in entries {
            let Some(body) = entry.as_dictionary() else {
                continue;
            };
            let Some(board) = body.get("BoardConfig").and_then(Value::as_string) else {
                continue;
            };
            if board.is_empty() {
                continue;
            }
            if !boards
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(board))
            {
                boards.push(board.to_string());
            }
            if let Some(platform) = body
                .get("Platform")
                .and_then(Value::as_string)
                .map(str::trim)
                .filter(|platform| !platform.is_empty())
            {
                platforms
                    .entry(board.to_ascii_lowercase())
                    .or_insert_with(|| platform.to_string());
            }
        }
    }
    RestoreCatalog {
        product_version,
        product_build,
        boards,
        platforms,
    }
}

#[cfg(test)]
fn device_platforms_from_restore(root: &Dictionary) -> HashMap<String, String> {
    restore_catalog_from(root).platforms
}

#[derive(Debug, Deserialize)]
struct DeviceCatalogFile {
    boards: HashMap<String, BoardRecord>,
    platforms: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct BoardRecord {
    name: String,
    #[serde(default)]
    cpu: Option<String>,
    #[serde(default)]
    radio: Option<String>,
}

fn format_board_title(name: &str, cpu: Option<&str>, radio: Option<&str>) -> String {
    let cpu = cpu.and_then(usable_chip_label);
    let mut extras = Vec::new();
    if let Some(cpu) = cpu.filter(|cpu| !name_already_has_chip(name, cpu)) {
        extras.push(cpu.to_string());
    }
    if let Some(radio) = radio.map(str::trim).filter(|radio| !radio.is_empty())
        && !name.to_ascii_lowercase().contains(&radio.to_ascii_lowercase())
    {
        extras.push(radio.to_string());
    }
    if extras.is_empty() {
        return name.to_string();
    }
    inject_title_extras(name, &extras)
}

fn usable_chip_label(cpu: &str) -> Option<&str> {
    let cpu = cpu.trim();
    if cpu.is_empty() || cpu.contains('/') || cpu.contains("Non-LTE") || cpu.len() > 20 {
        return None;
    }
    Some(cpu)
}

fn name_already_has_chip(name: &str, cpu: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let cpu = cpu.to_ascii_lowercase();
    name.contains(&cpu)
}

fn inject_title_extras(name: &str, extras: &[String]) -> String {
    let extra = extras.join(", ");
    match trailing_paren(name) {
        Some((prefix, inner))
            if inner.chars().all(|ch| ch.is_ascii_digit()) && inner.len() == 4 =>
        {
            format!("{prefix}({extra}, {inner})")
        }
        Some((prefix, inner)) => format!("{prefix}({inner}, {extra})"),
        None => format!("{name} ({extra})"),
    }
}

fn trailing_paren(name: &str) -> Option<(&str, &str)> {
    let body = name.trim_end();
    let start = body.rfind('(')?;
    let inner = body.strip_suffix(')')?.get(start + 1..)?;
    if inner.is_empty() {
        return None;
    }
    Some((&body[..start], inner))
}

fn device_catalog() -> &'static DeviceCatalogFile {
    static CATALOG: OnceLock<DeviceCatalogFile> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("data/apple_boards.json")).expect("apple_boards.json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::{Dictionary, Value};

    #[test]
    fn title_puts_chip_and_radio_where_they_help() {
        assert_eq!(
            format_board_title("Mac mini (2023)", Some("M2"), None),
            "Mac mini (M2, 2023)"
        );
        assert_eq!(
            format_board_title("Mac mini (M1, 2020)", Some("M1"), None),
            "Mac mini (M1, 2020)"
        );
        assert_eq!(
            format_board_title(
                "iPad Pro (11-inch) (4th generation)",
                Some("M2"),
                Some("Wi-Fi")
            ),
            "iPad Pro (11-inch) (4th generation, M2, Wi-Fi)"
        );
        assert_eq!(
            format_board_title("iPhone 15 Pro", Some("A17 Pro"), None),
            "iPhone 15 Pro (A17 Pro)"
        );
        assert_eq!(
            format_board_title("Apple Watch Ultra", Some("S6/S7/S8"), Some("GPS + Cellular")),
            "Apple Watch Ultra (GPS + Cellular)"
        );
    }

    #[test]
    fn known_boards_use_marketing_names() {
        let mini = describe_board("J274AP", Some("t8103"));
        assert_eq!(mini.class, "J274AP");
        assert_eq!(mini.title, "Mac mini (M1, 2020)");
        assert!(mini.detail.contains("J274AP"), "{}", mini.detail);
        assert!(mini.detail.contains("M1"), "{}", mini.detail);

        let air = describe_board("j313ap", None);
        assert_eq!(air.title, "MacBook Air (M1, 2020)");
        assert!(air.detail.contains("M1"), "{}", air.detail);

        let ipad = describe_board("J617AP", None);
        assert_eq!(
            ipad.title,
            "iPad Pro (11-inch) (4th generation, M2, Wi-Fi)"
        );
    }

    #[test]
    fn unknown_boards_keep_the_id_and_use_the_platform_chip() {
        let labeled = describe_board("j999ap", Some("t8103"));
        assert_eq!(labeled.title, "j999ap");
        assert!(labeled.detail.contains("j999ap"), "{}", labeled.detail);
        assert!(labeled.detail.contains("M1"), "{}", labeled.detail);

        let bare = describe_board("j999ap", None);
        assert_eq!(bare.title, "j999ap");
    }

    #[test]
    fn restore_device_map_feeds_platform_lookup() {
        let root = Dictionary::from_iter([(
            "DeviceMap".to_string(),
            Value::Array(vec![Value::Dictionary(Dictionary::from_iter([
                ("BoardConfig".to_string(), Value::String("j274ap".into())),
                ("Platform".to_string(), Value::String("t8103".into())),
            ]))]),
        )]);
        let map = device_platforms_from_restore(&root);
        assert_eq!(map.get("j274ap").map(String::as_str), Some("t8103"));
    }

    #[test]
    fn restore_catalog_reads_version_and_device_map() {
        let root = Dictionary::from_iter([
            ("ProductVersion".to_string(), Value::String("26.5.1".into())),
            (
                "ProductBuildVersion".to_string(),
                Value::String("25F80".into()),
            ),
            (
                "DeviceMap".to_string(),
                Value::Array(vec![Value::Dictionary(Dictionary::from_iter([
                    ("BoardConfig".to_string(), Value::String("j274ap".into())),
                    ("Platform".to_string(), Value::String("t8103".into())),
                ]))]),
            ),
        ]);
        let catalog = restore_catalog_from(&root);
        assert_eq!(catalog.product_version.as_deref(), Some("26.5.1"));
        assert_eq!(catalog.product_build.as_deref(), Some("25F80"));
        assert_eq!(catalog.boards, vec!["j274ap".to_string()]);
        assert_eq!(
            catalog.platforms.get("j274ap").map(String::as_str),
            Some("t8103")
        );
    }
}
