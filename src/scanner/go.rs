use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct GoScanner;

impl Scanner for GoScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;

        let mut packages = Vec::new();
        let mut in_require_block = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if in_require_block {
                if trimmed == ")" {
                    in_require_block = false;
                    continue;
                }

                if let Some((name, version)) = parse_require_line(trimmed) {
                    packages.push(Package {
                        name,
                        version,
                        source: PackageSource::Go,
                        path: Some(path.into()),
                        purl: None,
                    });
                }

                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("require") {
                let require_line = rest.trim();

                if require_line == "(" {
                    in_require_block = true;
                    continue;
                }

                if let Some((name, version)) = parse_require_line(require_line) {
                    packages.push(Package {
                        name,
                        version,
                        source: PackageSource::Go,
                        path: Some(path.into()),
                        purl: None,
                    });
                }
            }
        }

        Ok(packages)
    }
}

fn parse_require_line(line: &str) -> Option<(String, String)> {
    let trimmed_line = if let Some(index) = line.find("//") {
        &line[..index]
    } else {
        line
    }
    .trim();

    let parts: Vec<&str> = trimmed_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0];
    let version = parts[1];

    match name {
        "module" | "go" | "replace" | "exclude" | "retract" | "tool" => return None,
        _ => {}
    }

    if version.starts_with('v') {
        Some((name.to_string(), version.to_string()))
    } else {
        None
    }
}