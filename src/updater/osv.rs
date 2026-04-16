use crate::core::types::*;
use crate::database::json_store::JsonStore;
use serde::Deserialize;
use serde_json::json;
use std::process::Command;

pub struct OsvFetcher;

impl OsvFetcher {
    pub fn fetch_data(pkg: &Package) -> Result<Vec<Vulnerability>, String> {
        let ecosystem = Self::map_ecosystem(&pkg.source);
        let url = "https://api.osv.dev/v1/query";
        
        let query = if !pkg.purl.is_none() {
            json!({
                "package": {
                    "purl": pkg.purl
                }
            })
        } else {
            json!({
                "package": {
                    "name": pkg.name,
                    "ecosystem": ecosystem
                },
                "version": pkg.version
            })
        };

        let response_body = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_string(&query.to_string())
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())?;

        let response: OsvQueryResponse = serde_json::from_str(&response_body)
            .map_err(|e| e.to_string())?;

        //println!("Response: {:?}", &response);

        let mut results = Vec::new();
        for vuln in response.vulns {
            results.extend(Self::parse_osv(vuln, pkg.source.clone(), pkg.purl.clone()));
        }

        Ok(results)
    }

    pub fn save_to_database(vulns: &[Vulnerability], db_path: &str) -> Result<(), String> {
        let store = JsonStore {
            path: db_path.to_string(),
        };

        // Serialize to JSON and write to file
        let json_data = serde_json::to_string_pretty(vulns)
            .map_err(|e| e.to_string())?;

        std::fs::write(&store.path, json_data)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn map_ecosystem(source: &PackageSource) -> &'static str {
        match source {
            PackageSource::CargoToml => "crates.io",
            PackageSource::PyPI => "PyPI",
            PackageSource::Npm => "npm",
            PackageSource::Go => "Go",
            PackageSource::GIT => "GIT",
            PackageSource::RubyGems => "RubyGems",
        }
    }

    fn parse_osv(vuln: OsvVuln, source: PackageSource, purl: Option<String>) -> Vec<Vulnerability> {
        let mut results = Vec::new();

        for affected in vuln.affected {
            let package = affected.package.name;
            let mut version_ranges = Vec::new();

            if let Some(ranges) = affected.ranges {
                for range in ranges {
                    match range.range_type.as_str() {
                        "SEMVER" | "ECOSYSTEM" => {
                            version_ranges.extend(Self::collect_version_ranges(&range.events, |_value| {
                                Some(_value.to_string())
                            }));
                        }
                        "GIT" => {
                            version_ranges.extend(Self::collect_version_ranges(&range.events, |value| {
                                // normalize function parameter to resolve git commits to tags when possible
                                if value.starts_with('v') || value.contains('.') {
                                    Some(value.to_string())
                                } else {
                                    Self::resolve_commit_to_tag(value, &purl)
                                }
                            }));
                        }
                        _ => {}
                    }
                }
            }

            if !version_ranges.is_empty() {
                results.push(Vulnerability {
                    id: vuln.id.clone(),
                    package,
                    version_ranges,
                    severity: Self::severity_from_osv(vuln.severity.as_ref()),
                    source: Some(source.clone()),
                });
            }
        }

        results
    }

    // normalize parameter takes a function that converts a version string to a normalized format
    fn collect_version_ranges<F>(events: &[OsvEvent], mut normalize: F) -> Vec<String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut version_ranges = Vec::new();
        let mut current_start: Option<String> = None;

        for event in events {
            if let Some(introduced) = &event.introduced {
                current_start = normalize(introduced);
            }

            if let Some(fixed) = &event.fixed {
                if let Some(start) = current_start.take() {
                    if let Some(fixed_version) = normalize(fixed) {
                        version_ranges.push(format!(">={}, <{}", start, fixed_version));
                    }
                }
            }
        }

        if let Some(start) = current_start {
            version_ranges.push(format!(">={}", start));
        }

        version_ranges
    }

    fn severity_from_osv(severity: Option<&OsvSeverityField>) -> Severity {
        match severity {
            Some(OsvSeverityField::List(entries)) => {
                entries
                    .iter()
                    .find_map(|entry| {
                        entry
                            .score
                            .as_ref()
                            .and_then(|score| {
                                if let Ok(num) = score.parse::<f32>() {
                                    Some(num)
                                } else if score.starts_with("CVSS:3") {
                                    Self::calculate_cvss3_base_score(score)
                                } else if score.starts_with("CVSS:4") {
                                    Some(7.0) // Approximate high severity for CVSS v4
                                } else {
                                    None
                                }
                            })
                            .map(|score| match score {
                                s if s >= 9.0 => Severity::Critical,
                                s if s >= 7.0 => Severity::High,
                                s if s >= 4.0 => Severity::Medium,
                                _ => Severity::Low,
                            })
                            .or_else(|| {
                                entry
                                    .severity_type
                                    .as_ref()
                                    .map(|typ| match typ.to_lowercase().as_str() {
                                        "critical" => Severity::Critical,
                                        "high" => Severity::High,
                                        "medium" | "moderate" => Severity::Medium,
                                        "low" => Severity::Low,
                                        _ => Severity::Medium,
                                    })
                            })
                    })
                    .unwrap_or(Severity::Medium)
            }
            Some(OsvSeverityField::String(value)) => match value.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" | "moderate" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Medium,
            },
            None => Severity::Medium,
        }
    }

    fn resolve_commit_to_tag(commit: &str, purl: &Option<String>) -> Option<String> {
        // Only attempt resolution when we have a pkg:git purl
        let purl = purl.as_ref()?;
        if !purl.starts_with("pkg:git/") {
            return None;
        }

        let repo_part = purl.trim_start_matches("pkg:git/").split('@').next()?;
        let repo_url = if repo_part.ends_with(".git") {
            format!("https://{}", repo_part)
        } else {
            format!("https://{}.git", repo_part)
        };

        let output = Command::new("git")
            .arg("ls-remote")
            .arg("--tags")
            .arg(&repo_url)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut tag_map = std::collections::HashMap::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let hash = parts[0];
            let refname = parts[1];

            if refname.ends_with("^{}") {
                let tag = refname.trim_start_matches("refs/tags/").trim_end_matches("^{}");
                tag_map.insert(tag.to_string(), hash.to_string());
            } else if refname.starts_with("refs/tags/") {
                let tag = refname.trim_start_matches("refs/tags/");
                tag_map.entry(tag.to_string()).or_insert_with(|| hash.to_string());
            }
        }

        // Try to match by prefix (OSV may shorten commits)
        for (tag, h) in tag_map {
            if h == commit || h.starts_with(commit) || commit.starts_with(&h) || h.starts_with(&commit[..std::cmp::min(commit.len(), 7)]) {
                return Some(tag);
            }
        }

        None
    }

    fn calculate_cvss3_base_score(vector: &str) -> Option<f32> {
        if !vector.starts_with("CVSS:3.") {
            return None;
        }
        let metrics: std::collections::HashMap<&str, &str> = vector
            .split('/')
            .skip(1) // skip CVSS:3.x
            .filter_map(|part| {
                let mut split = part.split(':');
                Some((split.next()?, split.next()?))
            })
            .collect();

        let av = match metrics.get("AV")? {
            &"N" => 0.85,
            &"A" => 0.62,
            &"L" => 0.55,
            &"P" => 0.2,
            _ => return None,
        };
        let ac = match metrics.get("AC")? {
            &"H" => 0.44,
            &"L" => 0.77,
            _ => return None,
        };
        let pr = match metrics.get("PR")? {
            &"N" => 0.85,
            &"L" => 0.62,
            &"H" => 0.27,
            _ => return None,
        };
        let ui = match metrics.get("UI")? {
            &"N" => 0.85,
            &"R" => 0.62,
            _ => return None,
        };
        let s = metrics.get("S")?;
        let c = match metrics.get("C")? {
            &"N" => 0.0,
            &"L" => 0.22,
            &"H" => 0.56,
            _ => return None,
        };
        let i = match metrics.get("I")? {
            &"N" => 0.0,
            &"L" => 0.22,
            &"H" => 0.56,
            _ => return None,
        };
        let a = match metrics.get("A")? {
            &"N" => 0.0,
            &"L" => 0.22,
            &"H" => 0.56,
            _ => return None,
        };

        let isc = 1.0f32 - (1.0f32 - c) * (1.0f32 - i) * (1.0f32 - a);
        let impact = if *s == "U" {
            6.42f32 * isc
        } else {
            7.52f32 * (isc - 0.029f32) - 3.25f32 * (isc - 0.02f32).powf(15.0f32)
        };
        let exploitability = 8.22f32 * av * ac * pr * ui;

        let base = if impact <= 0.0f32 {
            0.0f32
        } else if *s == "U" {
            (impact + exploitability).min(10.0f32)
        } else {
            (1.08f32 * (impact + exploitability)).min(10.0f32)
        };

        // Roundup to 1 decimal
        Some((base * 10.0f32).ceil() / 10.0f32)
    }
}


//
// Typed OSV structs
//

#[derive(Debug, Deserialize)]
pub struct OsvQueryResponse {
    #[serde(default)]
    pub vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub severity: Option<OsvSeverityField>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OsvSeverityField {
    List(Vec<OsvSeverity>),
    String(String),
}

#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: Option<String>,
    pub score: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: OsvPackage,
    pub ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvPackage {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}