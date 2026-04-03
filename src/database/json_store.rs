use crate::core::traits::VulnerabilityStore;
use crate::core::types::*;
use std::fs;
use std::collections::HashSet;

pub struct JsonStore {
    pub path: String,
}

impl JsonStore {
    /// Load vulnerabilities from the store
    pub fn load(&self) -> Result<Vec<Vulnerability>, String> {
        match fs::read_to_string(&self.path) {
            Ok(data) => {
                let vulns: Vec<Vulnerability> =
                    serde_json::from_str(&data).map_err(|e| e.to_string())?;
                Ok(vulns)
            }
            Err(_) => Ok(Vec::new()), // File doesn't exist yet
        }
    }

    /// Save vulnerabilities, merging with existing data if present
    pub fn save_merged(&self, vulns: &[Vulnerability]) -> Result<(), String> {
        // Load existing data
        let mut existing = self.load()?;

        // Create a set of existing vulnerability IDs for quick lookup
        let existing_ids: HashSet<String> = existing.iter().map(|v| v.id.clone()).collect();

        // Add new vulnerabilities that don't already exist
        for vuln in vulns {
            if !existing_ids.contains(&vuln.id) {
                existing.push(vuln.clone());
            }
        }

        // Write back to file
        let tmp_path = format!("{}.tmp", self.path);
        let json = serde_json::to_string_pretty(&existing)
            .map_err(|e| e.to_string())?;

        fs::write(&tmp_path, json).map_err(|e| e.to_string())?;
        fs::rename(tmp_path, &self.path).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Save vulnerabilities, completely replacing existing data
    pub fn save(&self, vulns: &[Vulnerability]) -> Result<(), String> {
        let tmp_path = format!("{}.tmp", self.path);
        let json = serde_json::to_string_pretty(vulns)
            .map_err(|e| e.to_string())?;

        fs::write(&tmp_path, json).map_err(|e| e.to_string())?;
        fs::rename(tmp_path, &self.path).map_err(|e| e.to_string())?;

        Ok(())
    }
}

impl VulnerabilityStore for JsonStore {
    fn load(&self) -> Result<Vec<Vulnerability>, String> {
        match fs::read_to_string(&self.path) {
            Ok(data) => {
                serde_json::from_str(&data)
                    .map_err(|e| e.to_string())
            }
            Err(_) => Ok(Vec::new()),
        }
    }
}