use crate::core::types::*;
use crate::database::json_store::JsonStore;
use serde::Deserialize;
use serde_json::json;

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
            results.extend(Self::parse_osv(vuln, pkg.source.clone()));
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

    fn parse_osv(vuln: OsvVuln, source: PackageSource) -> Vec<Vulnerability> {
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
                    severity: Severity::Medium,
                    source: Some(source.clone()),
                });
            }
        }

        results
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