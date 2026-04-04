use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct GoScanner;

impl Scanner for GoScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| e.to_string())?;

        let mut packages = Vec::new();

        // Parse go.mod format
        // Format: require (
        //     package v1.2.3
        // )
        // Or single line: require package v1.2.3

        let in_require = content
            .lines()
            .any(|line| line.trim() == "require");

        if !in_require {
            // Try to find require blocks with parentheses
            let mut in_require_block = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed == "require" {
                    in_require_block = true;
                    continue;
                }
                if trimmed == "(" && in_require_block {
                    continue;
                }
                if trimmed == ")" {
                    in_require_block = false;
                    continue;
                }
                if in_require_block {
                    if let Some((name, version)) = parse_require_line(trimmed) {
                        packages.push(Package {
                            name,
                            version,
                            source: PackageSource::Go,
                            path: Some(path.into()),
                        });
                    }
                }
            }
        } else {
            // Parse multi-line require blocks
            let mut in_require_block = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed == "require" {
                    continue;
                }
                if trimmed == "(" {
                    in_require_block = true;
                    continue;
                }
                if trimmed == ")" {
                    in_require_block = false;
                    continue;
                }
                if in_require_block {
                    if let Some((name, version)) = parse_require_line(trimmed) {
                        packages.push(Package {
                            name,
                            version,
                            source: PackageSource::Go,
                            path: Some(path.into()),
                        });
                    }
                }
            }
        }

        Ok(packages)
    }
}

fn parse_require_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Expected format: package_name v1.2.3
    if parts.len() >= 2 && parts[0].starts_with('v') {
        // Version only, skip
        return None;
    }
    if parts.len() >= 2 && parts[0].starts_with("module") || parts[0].starts_with("go") {
        // Module declaration or go version, skip
        return None;
    }
    if parts.len() >= 2 {
        let name = parts[0].to_string();
        let version = parts[1].to_string();
        if version.starts_with('v') {
            Some((name, version))
        } else {
            None
        }
    } else {
        None
    }
}