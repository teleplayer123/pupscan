use crate::core::types::*;
use crate::database::json_store::JsonStore;
use serde::Deserialize;
use serde_json::json;

pub struct OsvFetcher;

impl OsvFetcher {
    pub fn fetch_data(pkg: &Package) -> Result<Vec<Vulnerability>, String> {
        let ecosystem = Self::map_ecosystem(&pkg.source);
        let url = "https://api.osv.dev/v1/query";

        let query = json!({
            "version": pkg.version,
            "package": {
                "name": pkg.name,
                "ecosystem": ecosystem
            }
        });

        let response: OsvVuln = ureq::post(url)
            .send_json(&query)
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;

        let vulns = Self::parse_osv(response);
        Ok(vulns)
    }

    pub fn fetch_all_ecosystems() -> Result<Vec<Vulnerability>, String> {
        let mut all_vulns = Vec::new();

        let ecosystems = [" crates", "npm", "pypi", "linux"];
        let mut page = 1;

        for ecosystem in ecosystems {
            let query = json!({
                "ecosystem": ecosystem
            });

            loop {
                let query_with_page = json!({
                    "ecosystem": ecosystem,
                    "page": page
                });

                let response: OsvVuln = match ureq::post("https://api.osv.dev/v1/query")
                    .send_json(&query_with_page)
                    .map_err(|e| e.to_string())?
                    .into_json()
                {
                    Ok(v) => v,
                    Err(_) => break,
                };

                let vulns = Self::parse_osv(response);
                if vulns.is_empty() {
                    break;
                }
                all_vulns.extend(vulns);
                page += 1;
            }
            page = 1;
        }

        Ok(all_vulns)
    }

    pub fn save_to_database(vulns: Vec<Vulnerability>, db_path: &str) -> Result<(), String> {
        let store = JsonStore {
            path: db_path.to_string(),
        };

        // Serialize to JSON and write to file
        let json_data = serde_json::to_string_pretty(&vulns)
            .map_err(|e| e.to_string())?;

        std::fs::write(&store.path, json_data)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn map_ecosystem(source: &PackageSource) -> &'static str {
        match source {
            PackageSource::CargoToml => "crates",
            PackageSource::PyPI => "pypi",
            PackageSource::Npm => "npm",
            PackageSource::System => "linux",
        }
    }

    fn parse_osv(vuln: OsvVuln) -> Vec<Vulnerability> {
        let mut results = Vec::new();

        for affected in vuln.affected {
            let package = affected.package.name;

            let mut version_ranges = Vec::new();

            if let Some(ranges) = affected.ranges {
                for range in ranges {
                    if range.range_type != "SEMVER" {
                        continue;
                    }

                    let mut current_start: Option<String> = None;

                    for event in range.events {
                        if let Some(introduced) = event.introduced {
                            current_start = Some(introduced);
                        }

                        if let Some(fixed) = event.fixed {
                            if let Some(start) = &current_start {
                                version_ranges.push(format!(">={}, <{}", start, fixed));
                            }
                            current_start = None;
                        }
                    }

                    // Still vulnerable (no fix yet)
                    if let Some(start) = current_start {
                        version_ranges.push(format!(">={}", start));
                    }
                }
            }

            if !version_ranges.is_empty() {
                results.push(Vulnerability {
                    id: vuln.id.clone(),
                    package,
                    version_ranges,
                    severity: Self::map_severity(&vuln.severity),
                });
            }
        }

        results
    }

    fn map_severity(osv_severity: &OsvSeverity) -> Severity {
        match osv_severity {
            OsvSeverity::Critical => Severity::Critical,
            OsvSeverity::High => Severity::High,
            OsvSeverity::Medium => Severity::Medium,
            OsvSeverity::Low => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

//
// Typed OSV structs
//

#[derive(Debug, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub severity: Vec<OsvSeverity>,
    pub affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsvSeverity {
    Low,
    Medium,
    High,
    Critical,
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