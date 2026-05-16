use crate::core::types::*;
use crate::database::json_store::JsonStore;
use crate::core::log::{log_message, Level};
use serde::Deserialize;
use serde_json::json;

pub struct OsvFetcher;

impl OsvFetcher {
    // Retuns a list of Vulnerabilities or an error string
    pub fn fetch_data(pkg: &Package) -> Result<Vec<Vulnerability>, String> {
        let ecosystem = pkg.source.as_str();
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

        log_message(Level::Debug, &"OSV", &format!("{:?}", &query));

        let response_body = ureq::post(url)
            .set("Content-Type", "application/json")
            .send_string(&query.to_string())
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())?;

        // Uncomment for debugging
        //println!("Response Body: {:?}", &response_body);
        log_message(Level::Info, "OSV", &format!("Response Raw -> {:?}", &response_body));

        let response: OsvQueryResponse = serde_json::from_str(&response_body)
            .map_err(|e| e.to_string())?;

        // Uncomment for debugging
        //println!("Response: {:?}", &response);
        log_message(Level::Info, "OSV", &format!("Response -> {:?}", &response));

        let mut results = Vec::new();
        for vuln in response.vulns {
            results.extend(Self::parse_osv(vuln, pkg.source.clone()));
        }

        Ok(results)
    }

    pub fn get_vuln_by_id(id: &str) -> Result<VulnerabilityReport, String> {
        let url = format!("https://api.osv.dev/v1/vulns/{}", id);

        let response_body = ureq::get(&url)
            .call()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())?;

        let vuln: OsvVuln = serde_json::from_str(&response_body)
            .map_err(|e| e.to_string())?;
        
        let severity = Self::severity_from_osv(vuln.severity.as_ref()).as_str();
        let package = vuln.affected.clone().into_iter().next()
            .ok_or_else(|| format!("No affected packages found for CVE '{}'", id))?.package.name;
        let affected_versions = vuln.affected.clone().into_iter().flat_map(|a| a.versions).collect();
        let fix_versions = vuln.affected.clone().into_iter().flat_map(|a| a.ranges.unwrap_or_default()).flat_map(|r| r.events.into_iter().filter_map(|e| e.fixed)).collect();
        let source = vuln.affected.clone().into_iter().flat_map(|a| a.ranges.unwrap_or_default()).flat_map(|r| r.range_type.parse::<String>().ok()).next().unwrap_or_else(|| "Unknown".into());

        Ok(VulnerabilityReport {
            id: vuln.id.clone(),
            summary: vuln.summary.clone(),
            details: vuln.details.clone().unwrap_or_default(),
            package,
            affected_versions,
            fix_versions,
            severity: severity.to_string(),
            source,
        })
    }

    #[allow(dead_code)]
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

    fn parse_osv(vuln: OsvVuln, source: PackageSource) -> Vec<Vulnerability> {
        let mut results = Vec::new();

        for affected in vuln.affected {
            let package = affected.package.name;
            let mut version_ranges = Vec::new();

            if let Some(ranges) = affected.ranges {
                for range in ranges {
                    match range.range_type.as_str() {
                        "SEMVER" | "ECOSYSTEM" => {
                            version_ranges.extend(Self::collect_version_ranges(&range.events, |_value| {
                                // normalize function parameter is not needed for SEMVER/ECOSYSTEM as OSV should already provide normalized versions
                                Some(_value.to_string())
                            }));
                        }
                        // GIT range events contain commit hashes, not version strings.
                        // Affected versions for GIT ecosystem packages come from affected.versions below.
                        _ => {}
                    }
                }
            }

            // When GIT commit resolution yielded nothing, fall back to the explicit versions list
            if version_ranges.is_empty() && !affected.versions.is_empty() {
                for v in &affected.versions {
                    version_ranges.push(format!("={}", v));
                }
            }

            if !version_ranges.is_empty() {
                results.push(Vulnerability {
                    id: vuln.id.clone(),
                    summary: vuln.summary.clone(),
                    details: Some(vuln.details.clone()).unwrap_or_default(),
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
    #[serde(default)]
    pub summary: String,
    pub details: Option<String>,
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

#[derive(Debug, Deserialize, Clone)]
pub struct OsvAffected {
    pub package: OsvPackage,
    pub ranges: Option<Vec<OsvRange>>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsvPackage {
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsvEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}