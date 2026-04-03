use crate::core::types::*;
use serde::Deserialize;
use serde_json::json;
use std::io::Read;

pub struct OsvFetcher;

impl OsvFetcher {
    pub fn fetch_data(pkg: Package) -> Result<Vec<Vulnerability>, String> {

        let mut all = Vec::new();

        let url = "https://api.osv.dev/v1/query";

        // example query: { "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "3.1.4" }

        let query = json!({
                "version": pkg.version,
                "package": {
                    "name": pkg.name,
                    "ecosystem": pkg.source
                }
            });

        let response: serde_json::Value = ureq::post(url)
            .send_json(query)?
            .into_json()?;

        let mut reader = response.into_reader();
        let mut text = String::new();

        use std::io::Read;
        reader.read_to_string(&mut text)
            .map_err(|e| e.to_string())?;

        let parsed: OsvResponse =
            serde_json::from_str(&text).map_err(|e| e.to_string())?;

        let mut vulns = Self::parse_osv(parsed);
        all.append(&mut vulns);

        Ok(all)
    }

    fn parse_osv(parsed: OsvResponse) -> Vec<Vulnerability> {
        let mut results = Vec::new();

        for vuln in parsed {
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
                    });
                }
            }
        }

        results
    }
}

//
// Typed OSV structs
//

type OsvResponse = Vec<OsvVuln>;

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}