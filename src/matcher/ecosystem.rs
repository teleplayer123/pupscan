use crate::core::traits::Matcher;
use crate::core::types::*;
use semver::Version;

pub struct EcosystemMatcher;

impl Matcher for EcosystemMatcher {
    fn match_packages(
        &self,
        packages: &[Package],
        vulns: &[Vulnerability],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pkg in packages {
            let cleaned_version = normalize_version(&pkg.version);

            let parsed_version = match Version::parse(&cleaned_version) {
                Ok(v) => v,
                Err(_) => continue,
            };

            for vuln in vulns {
                if pkg.name != vuln.package {
                    continue;
                }

                if let Some(vuln_source) = &vuln.source {
                    if vuln_source != &pkg.source {
                        continue;
                    }
                }

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

    let ops = [">=", "<=", ">", "<", "=", "=="];
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

