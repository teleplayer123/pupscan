use crate::core::types::*;
use std::io::Read;

pub struct OsvFetcher;

impl OsvFetcher {
    pub fn fetch_rust_vulns() -> Result<Vec<Vulnerability>, String> {
        let body = r#"{"ecosystem": "crates.io"}"#;

        let response = ureq::post("https://api.osv.dev/v1/query")
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| e.to_string())?;

        let mut reader = response.into_reader();
        let mut text = String::new();
        reader.read_to_string(&mut text)
            .map_err(|e| e.to_string())?;

        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| e.to_string())?;

        Self::parse_osv(json)
    }

    fn parse_osv(json: serde_json::Value) -> Result<Vec<Vulnerability>, String> {
        let mut results = Vec::new();

        let vulns = json["vulns"]
            .as_array()
            .ok_or("missing vulns field")?;

        for v in vulns {
            let id = v["id"].as_str().unwrap_or("").to_string();

            let affected = match v["affected"].as_array() {
                Some(a) => a,
                None => continue,
            };

            for a in affected {
                let package = a["package"]["name"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                if package.is_empty() {
                    continue;
                }

                let mut version_ranges = Vec::new();

                if let Some(ranges) = a["ranges"].as_array() {
                    for r in ranges {
                        if r["type"].as_str() != Some("SEMVER") {
                            continue;
                        }

                        if let Some(events) = r["events"].as_array() {
                            let mut current_introduced: Option<String> = None;

                            for event in events {
                                if let Some(intro) = event["introduced"].as_str() {
                                    current_introduced = Some(intro.to_string());
                                }

                                if let Some(fixed) = event["fixed"].as_str() {
                                    if let Some(start) = &current_introduced {
                                        let range = format!(">={}, <{}", start, fixed);
                                        version_ranges.push(range);
                                    }
                                    current_introduced = None;
                                }
                            }

                            // Handle "introduced with no fixed" (still vulnerable)
                            if let Some(start) = current_introduced {
                                let range = format!(">={}", start);
                                version_ranges.push(range);
                            }
                        }
                    }
                }

                if !version_ranges.is_empty() {
                    results.push(Vulnerability {
                        id: id.clone(),
                        package: package.clone(),
                        version_ranges,
                        severity: Severity::Medium, // can improve later
                    });
                }
            }
        }

        Ok(results)
    }
}