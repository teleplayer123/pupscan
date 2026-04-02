use crate::core::traits::VulnerabilityStore;
use crate::core::types::*;
use std::fs;

pub struct JsonStore {
    pub path: String,
}

impl VulnerabilityStore for JsonStore {
    fn load(&self) -> Result<Vec<Vulnerability>, String> {
        let data = fs::read_to_string(&self.path)
            .map_err(|e| e.to_string())?;

        let raw: Vec<serde_json::Value> =
            serde_json::from_str(&data).map_err(|e| e.to_string())?;

        let mut vulns = Vec::new();

        for v in raw {
            vulns.push(Vulnerability {
                id: v["id"].as_str().unwrap_or("").to_string(),
                package: v["package"].as_str().unwrap_or("").to_string(),
                affected_versions: v["affected_versions"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                severity: match v["severity"].as_str().unwrap_or("") {
                    "Critical" => Severity::Critical,
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    _ => Severity::Low,
                },
            });
        }

        Ok(vulns)
    }
}