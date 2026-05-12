use crate::core::traits::Matcher;
use crate::core::types::*;
use crate::core::log::{log_message, Level};
use semver::Version;
use regex::Regex;

pub struct EcosystemMatcher;

impl Matcher for EcosystemMatcher {
    fn match_packages(&self, packages: &[Package], vulns: &[Vulnerability]) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Regex to extract https://github.com/owner/repo from package name for GIT sources
        let re = Regex::new(r"https://github\.com/[^/\s]+/([^/\s]+)").unwrap();

        for pkg in packages {
            let cleaned_version = normalize_version(&pkg.version);
            log_message(Level::Debug, "ECOSYSTEM", &format!("Normalized version for package {} version {}: {}", &pkg.name, &pkg.version, &cleaned_version));

            let parsed_version = match Version::parse(&cleaned_version) {
                Ok(v) => v,
                Err(_) => continue,
            };
            log_message(Level::Debug, "ECOSYSTEM", &format!("Parsed version for package {}: {:?}", &pkg.name, &parsed_version));

            // Binary search to match pkg to vuln
            for vuln in vulns {
                if let Some(vuln_source) = &vuln.source {
                    if vuln_source != &pkg.source {
                        continue;
                    }
                }

                // Extract package name for GIT sources
                let pkg_name = if &pkg.source.as_str() == &"GIT" {
                    if let Some(caps) = re.captures(&pkg.name) {
                        caps.get(1).map_or(pkg.name.as_str(), |m| m.as_str())
                    } else {
                        pkg.name.as_str()
                    }
                } else {
                    pkg.name.as_str()
                };

                log_message(Level::Debug, "ECOSYSTEM", &format!("Trying to match package name {} to vuln package {}", pkg_name, &vuln.package));
                if pkg_name != vuln.package {
                    continue;
                }



                log_message(Level::Debug, "ECOSYSTEM", &format!("Matched vulnerability to package: {} == {}", &vuln.package, &pkg.name));

                for range in &vuln.version_ranges {
                    if version_in_range(&parsed_version, range) {
                        findings.push(Finding {
                            package: pkg.clone(),
                            vulnerability: vuln.clone(),
                        });
                        break;
                    }
                }
            }
        }
        findings
    }
}

fn normalize_version(v: &str) -> String {
    let mut version = v.trim();

    if version.starts_with('^') || version.starts_with('~') {
        version = &version[1..];
    }
    if version.starts_with('v') {
        version = &version[1..];
    }

    // Strip any non-digit prefix (e.g., "release-" in "release-78.3")
    if let Some(pos) = version.find(|c: char| c.is_ascii_digit()) {
        version = &version[pos..];
    }

    if let Some((actual_version, _max_version)) = version.split_once(",") {
        version = actual_version.split_terminator(&",").next().unwrap_or(version);
        log_message(Level::Debug, "ECOSYSTEM", &format!("Actual version after split: {}", &version));
    }

    let mut cleaned = version.trim().to_string();
    let dot_count = cleaned.matches('.').count();
    if dot_count == 0 {
        cleaned.push_str(".0.0");
    } else if dot_count == 1 {
        cleaned.push_str(".0");
    }

    cleaned
}

fn version_in_range(version: &Version, range: &str) -> bool {
    let constraints = range
        .split(',')
        .flat_map(|s| s.split_whitespace())
        .filter_map(|s| parse_constraint(s))
        .collect::<Vec<_>>();

    if constraints.is_empty() {
        return false;
    }

    constraints.into_iter().all(|(op, bound)| match op.as_str() {
        ">=" => version >= &bound,
        ">" => version > &bound,
        "<=" => version <= &bound,
        "<" => version < &bound,
        "=" => version == &bound,
        _ => false,
    })
}

fn parse_constraint(segment: &str) -> Option<(String, Version)> {
    let segment = segment.trim().trim_end_matches(',').trim();
    if segment.is_empty() {
        return None;
    }

    let ops = [">=", "<=", ">", "<", "==", "="];
    let mut op = "=";
    let mut version_part = segment;

    for candidate in ops {
        if segment.starts_with(candidate) {
            op = candidate;
            version_part = segment.strip_prefix(candidate)?.trim();
            break;
        }
    }

    let op = if op == "==" { "=".to_string() } else { op.to_string() };
    let parsed_version = Version::parse(&normalize_version(version_part)).ok()?;
    Some((op, parsed_version))
}

