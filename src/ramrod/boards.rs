use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use plist::{Dictionary, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardLabel {
    pub class: String,
    pub title: String,
    pub detail: String,
}

#[must_use]
pub fn describe_board(class: &str, platform: Option<&str>) -> BoardLabel {
    let key = class.trim().to_ascii_lowercase();
    let chip = platform
        .map(str::trim)
        .filter(|platform| !platform.is_empty())
        .and_then(chip_name)
        .or_else(|| board_chip(&key));
    let title = board_name(&key)
        .map(str::to_string)
        .unwrap_or_else(|| match chip {
            Some(chip) => format!("{chip} Mac"),
            None => class.to_string(),
        });
    let detail = match chip {
        Some(chip) if board_name(&key).is_some() => format!("{class}  ·  {chip}"),
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

fn chip_name(platform: &str) -> Option<&'static str> {
    Some(match platform.trim().to_ascii_lowercase().as_str() {
        "t8103" => "M1",
        "t6000" => "M1 Pro",
        "t6001" => "M1 Max",
        "t6002" => "M1 Ultra",
        "t8112" => "M2",
        "t6020" => "M2 Pro",
        "t6021" => "M2 Max",
        "t6022" => "M2 Ultra",
        "t8122" => "M3",
        "t6030" => "M3 Pro",
        "t6031" => "M3 Max",
        "t6032" => "M3 Ultra",
        "t6034" => "M3 Max",
        "t8132" => "M4",
        "t6040" => "M4 Pro",
        "t6041" => "M4 Max",
        "t8140" => "M5",
        "t8142" => "M5",
        "t6050" => "M5 Pro",
        "vmapple2" => "Virtual Mac",
        _ => return None,
    })
}

fn board_chip(class: &str) -> Option<&'static str> {
    Some(match class {
        "j274ap" | "j293ap" | "j313ap" | "j456ap" | "j457ap" => "M1",
        "j314sap" | "j316sap" => "M1 Pro",
        "j314cap" | "j316cap" | "j375cap" => "M1 Max",
        "j375dap" => "M1 Ultra",
        "j413ap" | "j415ap" | "j473ap" | "j493ap" => "M2",
        "j414sap" | "j416sap" | "j474sap" => "M2 Pro",
        "j414cap" | "j416cap" | "j475cap" => "M2 Max",
        "j180dap" | "j475dap" => "M2 Ultra",
        "j433ap" | "j434ap" | "j504ap" | "j615ap" => "M3",
        "j514sap" | "j516sap" => "M3 Pro",
        "j514cap" | "j514map" | "j516cap" | "j516map" => "M3 Max",
        "j575dap" => "M3 Ultra",
        "j575cap" | "j604ap" | "j613ap" | "j623ap" | "j624ap" | "j713ap" | "j715ap" => "M4",
        "j614sap" | "j616sap" | "j773sap" => "M4 Pro",
        "j614cap" | "j616cap" | "j773gap" => "M4 Max",
        "j700ap" | "j704ap" | "j813ap" | "j815ap" => "M5",
        "j714cap" | "j714sap" | "j716cap" | "j716sap" => "M5 Pro",
        "vma2macosap" => "Virtual Mac",
        _ => return None,
    })
}

fn board_name(class: &str) -> Option<&'static str> {
    Some(match class {
        "j180dap" => "Mac Pro (M2 Ultra, 2023)",
        "j274ap" => "Mac mini (M1, 2020)",
        "j293ap" => "MacBook Pro 13-inch (M1, 2020)",
        "j313ap" => "MacBook Air (M1, 2020)",
        "j314cap" => "MacBook Pro 14-inch (M1 Max, 2021)",
        "j314sap" => "MacBook Pro 14-inch (M1 Pro, 2021)",
        "j316cap" => "MacBook Pro 16-inch (M1 Max, 2021)",
        "j316sap" => "MacBook Pro 16-inch (M1 Pro, 2021)",
        "j375cap" => "Mac Studio (M1 Max, 2022)",
        "j375dap" => "Mac Studio (M1 Ultra, 2022)",
        "j413ap" => "MacBook Air 13-inch (M2, 2022)",
        "j414cap" => "MacBook Pro 14-inch (M2 Max, 2023)",
        "j414sap" => "MacBook Pro 14-inch (M2 Pro, 2023)",
        "j415ap" => "MacBook Pro 13-inch (M2, 2022)",
        "j416cap" => "MacBook Pro 16-inch (M2 Max, 2023)",
        "j416sap" => "MacBook Pro 16-inch (M2 Pro, 2023)",
        "j433ap" => "iMac 24-inch (M3, 2023)",
        "j434ap" => "iMac 24-inch (M3, 2023)",
        "j456ap" => "iMac 24-inch (M1, 2021)",
        "j457ap" => "iMac 24-inch (M1, 2021)",
        "j473ap" => "Mac mini (M2, 2023)",
        "j474sap" => "Mac mini (M2 Pro, 2023)",
        "j475cap" => "Mac Studio (M2 Max, 2023)",
        "j475dap" => "Mac Studio (M2 Ultra, 2023)",
        "j493ap" => "MacBook Air 15-inch (M2, 2023)",
        "j504ap" => "MacBook Air 13-inch (M3, 2024)",
        "j514cap" | "j514map" => "MacBook Pro 14-inch (M3 Max, 2023)",
        "j514sap" => "MacBook Pro 14-inch (M3 Pro, 2023)",
        "j516cap" | "j516map" => "MacBook Pro 16-inch (M3 Max, 2023)",
        "j516sap" => "MacBook Pro 16-inch (M3 Pro, 2023)",
        "j575cap" => "Mac Studio (M4 Max, 2025)",
        "j575dap" => "Mac Studio (M3 Ultra, 2025)",
        "j604ap" => "MacBook Air 13-inch (M4, 2025)",
        "j613ap" => "Mac mini (M4, 2024)",
        "j614cap" => "MacBook Pro 14-inch (M4 Max, 2024)",
        "j614sap" => "MacBook Pro 14-inch (M4 Pro, 2024)",
        "j615ap" => "MacBook Air 15-inch (M3, 2024)",
        "j616cap" => "MacBook Pro 16-inch (M4 Max, 2024)",
        "j616sap" => "MacBook Pro 16-inch (M4 Pro, 2024)",
        "j623ap" | "j624ap" => "iMac 24-inch (M4, 2024)",
        "j700ap" => "MacBook Air (M5)",
        "j704ap" => "MacBook Air 13-inch (M5)",
        "j713ap" => "Mac mini (M4 Pro, 2024)",
        "j714cap" | "j714sap" => "MacBook Pro 14-inch (M5)",
        "j715ap" => "MacBook Air 15-inch (M4, 2025)",
        "j716cap" | "j716sap" => "MacBook Pro 16-inch (M5)",
        "j773gap" => "Mac Studio (M4 Max)",
        "j773sap" => "Mac Studio (M4 Pro)",
        "j813ap" | "j815ap" => "iMac 24-inch (M5)",
        "vma2macosap" => "Virtual Mac",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::{Dictionary, Value};

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
    }

    #[test]
    fn unknown_boards_keep_the_id_and_use_the_platform_chip() {
        let labeled = describe_board("j999ap", Some("t8103"));
        assert_eq!(labeled.title, "M1 Mac");
        assert!(labeled.detail.contains("j999ap"), "{}", labeled.detail);

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
