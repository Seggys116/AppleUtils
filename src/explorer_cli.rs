use std::path::Path;

use crate::explorer_image::{
    self, EntryKind, dump_image, export_entry, insert_host_path, load_view, preview_entry,
};

pub fn run(args: &[String]) -> Result<String, String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        return Ok(usage());
    }
    let mut list = None;
    let mut stat = None;
    let mut extract = None;
    let mut out = None;
    let mut insert = None;
    let mut at = "/".to_string();
    let mut volume = None;
    let mut image = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--list" => {
                list = Some(need(args, i + 1, "--list")?.to_string());
                i += 2;
            }
            "--stat" => {
                stat = Some(need(args, i + 1, "--stat")?.to_string());
                i += 2;
            }
            "--extract" => {
                extract = Some(need(args, i + 1, "--extract")?.to_string());
                i += 2;
            }
            "--out" => {
                out = Some(need(args, i + 1, "--out")?.to_string());
                i += 2;
            }
            "--insert" => {
                insert = Some(need(args, i + 1, "--insert")?.to_string());
                i += 2;
            }
            "--at" => {
                at = need(args, i + 1, "--at")?.to_string();
                i += 2;
            }
            "--volume" => {
                volume = Some(need(args, i + 1, "--volume")?.to_string());
                i += 2;
            }
            flag if flag.starts_with('-') => {
                return Err(format!("unknown explorer flag {flag}\n{}", usage()));
            }
            other => {
                if image.is_some() {
                    return Err(format!("unexpected argument {other}\n{}", usage()));
                }
                image = Some(other.to_string());
                i += 1;
            }
        }
    }
    let image = image.ok_or_else(|| format!("explorer requires an image path\n{}", usage()))?;
    let path = Path::new(&image);
    if list.is_none() && stat.is_none() && extract.is_none() && insert.is_none() {
        return dump_image(path).map_err(|e| e.to_string());
    }
    if let Some(dir) = list {
        let view = load_view(path, &dir, 0).map_err(|e| e.to_string())?;
        let mut out = format!(
            "backend={}\nvolume={}\ncwd={}\n",
            view.backend.as_str(),
            view.volume_name(),
            view.cwd
        );
        for entry in view.entries {
            match entry.kind {
                EntryKind::Symlink => {
                    out.push_str(&format!(
                        "{}  kind=symlink  target={}\n",
                        entry.name,
                        entry.symlink_target.unwrap_or_default()
                    ));
                }
                other => {
                    let size = entry
                        .size
                        .map(|s| format!("  size={s}"))
                        .unwrap_or_default();
                    out.push_str(&format!("{}  kind={}{size}\n", entry.name, other.as_str()));
                }
            }
        }
        return Ok(out);
    }
    if let Some(target) = stat {
        let parent = parent_of(&target);
        let name = name_of(&target);
        let view = load_view(path, parent, 0).map_err(|e| e.to_string())?;
        let entry = view
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| format!("{target} is not in {parent}"))?;
        let mut out = format!("path={target}\nkind={}\n", entry.kind.as_str());
        if let Some(size) = entry.size {
            out.push_str(&format!("size={size}\n"));
        }
        if let Some(link) = &entry.symlink_target {
            out.push_str(&format!("target={link}\n"));
        }
        return Ok(out);
    }
    if let Some(target) = extract {
        let vol = volume.unwrap_or_else(|| {
            load_view(path, "/", 0)
                .map(|v| v.volume_name().to_string())
                .unwrap_or_default()
        });
        if let Some(dest) = out {
            let written =
                export_entry(path, &vol, &target, Path::new(&dest)).map_err(|e| e.to_string())?;
            return Ok(format!("exported {target} -> {}\n", written.display()));
        }
        let parent = parent_of(&target);
        let name = name_of(&target);
        let view = load_view(path, parent, 0).map_err(|e| e.to_string())?;
        let entry = view
            .entries
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .ok_or_else(|| format!("{target} is not in {parent}"))?;
        let body =
            preview_entry(path, view.volume_name(), parent, &entry).map_err(|e| e.to_string())?;
        return Ok(format!(
            "path={target}\nkind={}\ncontents: {body}\n",
            entry.kind.as_str()
        ));
    }
    if let Some(host) = insert {
        let vol = volume.unwrap_or_else(|| {
            load_view(path, "/", 0)
                .map(|v| v.volume_name().to_string())
                .unwrap_or_default()
        });
        return insert_host_path(path, &vol, &at, Path::new(&host)).map_err(|e| e.to_string());
    }
    let _ = explorer_image::open_image(path);
    Ok(usage())
}

fn usage() -> String {
    "apple-utils explorer IMAGE\n\
     apple-utils explorer IMAGE --list PATH\n\
     apple-utils explorer IMAGE --stat PATH\n\
     apple-utils explorer IMAGE --extract PATH [--out DEST]\n\
     apple-utils explorer IMAGE --insert HOST [--at DIR] [--volume NAME]"
        .into()
}

fn need<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parent_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some(("/", _)) => "/",
        Some((parent, _)) => parent,
    }
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
