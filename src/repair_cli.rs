use std::io::{self, Write};
use std::path::Path;

use crate::repair_ops::{self, ApplyReport, SweepReport};

pub fn run(args: &[String]) -> Result<String, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help" | "help"))
    {
        return Ok(usage());
    }
    if args.is_empty() {
        return Err(usage());
    }

    let mut image = None;
    let mut apply_ids = Vec::new();
    let mut interactive = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dump" => {
                i += 1;
            }
            "--interactive" => {
                interactive = true;
                i += 1;
            }
            "--apply" => {
                apply_ids.push(need(args, i + 1, "--apply")?.to_string());
                i += 2;
            }
            flag if flag.starts_with('-') => {
                return Err(format!("unknown repair flag {flag}\n{}", usage()));
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
    let image = image.ok_or_else(|| format!("repair requires an image path\n{}", usage()))?;
    let path = Path::new(&image);

    if interactive && !apply_ids.is_empty() {
        return Err(format!(
            "cannot combine --apply and --interactive\n{}",
            usage()
        ));
    }
    if interactive {
        return run_interactive(path);
    }
    if !apply_ids.is_empty() {
        return apply_and_report(path, &apply_ids);
    }

    let report = repair_ops::sweep(path)?;
    Ok(repair_ops::format_dump(&report))
}

fn usage() -> String {
    "apple-utils repair IMAGE\n\
     apple-utils repair IMAGE --dump\n\
     apple-utils repair IMAGE --apply ID\n\
     apple-utils repair IMAGE --apply all\n\
     apple-utils repair IMAGE --interactive"
        .into()
}

fn need<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn run_interactive(path: &Path) -> Result<String, String> {
    let report = repair_ops::sweep(path)?;
    let dump = repair_ops::format_dump(&report);

    let mut stdout = io::stdout();
    write!(stdout, "{dump}").map_err(|e| e.to_string())?;
    if !dump.ends_with('\n') {
        writeln!(stdout).map_err(|e| e.to_string())?;
    }
    writeln!(
        stdout,
        "Enter repair ids (comma-separated), 'all', or blank to skip:"
    )
    .map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    match parse_pick_line(&line) {
        None => Ok(String::new()),
        Some(ids) => apply_resolved(path, &resolve_ids(&ids, &report)),
    }
}

fn apply_and_report(path: &Path, ids: &[String]) -> Result<String, String> {
    let resolved = if ids.iter().any(|id| id == "all") {
        let report = repair_ops::sweep(path)?;
        resolve_ids(ids, &report)
    } else {
        ids.to_vec()
    };
    apply_resolved(path, &resolved)
}

fn apply_resolved(path: &Path, ids: &[String]) -> Result<String, String> {
    let report = repair_ops::apply(path, ids)?;
    Ok(format_apply_report(&report))
}

fn format_apply_report(report: &ApplyReport) -> String {
    let mut out = String::new();
    for id in &report.applied {
        out.push_str(&format!("applied: {id}\n"));
    }
    for (id, err) in &report.failed {
        out.push_str(&format!("failed: {id}: {err}\n"));
    }
    out.push('\n');
    out.push_str(&repair_ops::format_dump(&report.after));
    out
}

fn resolve_ids(ids: &[String], report: &SweepReport) -> Vec<String> {
    if ids.iter().any(|id| id == "all") {
        repairable_failed_ids(report)
    } else {
        ids.to_vec()
    }
}

fn repairable_failed_ids(report: &SweepReport) -> Vec<String> {
    report
        .findings
        .iter()
        .filter(|finding| finding.failed() && finding.repairable)
        .map(|finding| finding.id.clone())
        .collect()
}

fn parse_pick_line(line: &str) -> Option<Vec<String>> {
    let tokens: Vec<String> = line
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_prints_usage() {
        for flag in ["-h", "--help", "help"] {
            let out = run(&[flag.into()]).expect("help");
            assert_eq!(out, usage());
            assert!(out.contains("apple-utils repair IMAGE"));
            assert!(out.contains("--dump"));
            assert!(out.contains("--apply ID"));
            assert!(out.contains("--apply all"));
            assert!(out.contains("--interactive"));
        }
    }

    #[test]
    fn missing_image_returns_usage_as_error() {
        let err = run(&[]).expect_err("no image");
        assert_eq!(err, usage());
    }

    #[test]
    fn flags_without_image_return_usage_as_error() {
        let err = run(&["--dump".into()]).expect_err("dump needs an image");
        assert!(err.contains("repair requires an image path"), "{err}");
        assert!(err.contains("apple-utils repair IMAGE"), "{err}");
    }

    #[test]
    fn unknown_flag_returns_usage_as_error() {
        let err = run(&["disk.img".into(), "--nope".into()]).expect_err("unknown flag");
        assert!(err.contains("unknown repair flag --nope"), "{err}");
        assert!(err.contains("apple-utils repair IMAGE"), "{err}");
    }

    #[test]
    fn parse_pick_line_blank_skips() {
        assert_eq!(parse_pick_line(""), None);
        assert_eq!(parse_pick_line("   "), None);
        assert_eq!(parse_pick_line("\n"), None);
        assert_eq!(parse_pick_line(" \t ,  \n"), None);
    }

    #[test]
    fn parse_pick_line_all() {
        assert_eq!(parse_pick_line("all"), Some(vec!["all".into()]));
        assert_eq!(parse_pick_line("  all  \n"), Some(vec!["all".into()]));
    }

    #[test]
    fn parse_pick_line_comma_and_whitespace_ids() {
        assert_eq!(
            parse_pick_line("checksum:0, volume-magic:21"),
            Some(vec!["checksum:0".into(), "volume-magic:21".into()])
        );
        assert_eq!(
            parse_pick_line("  checksum:0 ,  volume-magic:21  "),
            Some(vec!["checksum:0".into(), "volume-magic:21".into()])
        );
        assert_eq!(
            parse_pick_line("checksum:0   volume-magic:21"),
            Some(vec!["checksum:0".into(), "volume-magic:21".into()])
        );
    }

    #[test]
    fn dump_of_raw_gpt_fixture_is_stable_and_contains_findings() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        crate::apfs_fixture::write_fixture(&image, crate::apfs_fixture::ImageWrap::RawGpt)
            .expect("write gpt fixture");
        let path = image.display().to_string();
        let first = run(std::slice::from_ref(&path)).expect("repair dump");
        let second = run(std::slice::from_ref(&path)).expect("repair dump again");
        let dumped = run(&["--dump".into(), path]).expect("repair --dump");
        assert_eq!(first, second, "two identical invocations");
        assert_eq!(first, dumped, "default dump matches --dump");
        assert!(first.contains("findings:"), "{first}");
        assert!(first.contains("PASS"), "{first}");
    }
}
