use crate::core::types::*;
use crate::database::json_store::JsonStore;
use std::fs;
use std::time::SystemTime;

pub struct CacheManager {
    pub path: String,
    pub max_age_secs: u64,
}

impl CacheManager {
    pub fn is_stale(&self) -> bool {
        if let Ok(metadata) = fs::metadata(&self.path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(age) = SystemTime::now().duration_since(modified) {
                    return age.as_secs() > self.max_age_secs;
                }
            }
        }
        true
    }

    /// Save vulnerabilities while preserving existing data (non-destructive)
    pub fn save(&self, vulns: &[Vulnerability]) -> Result<(), String> {
        let store = JsonStore {
            path: self.path.clone(),
        };
        store.save_merged(vulns)
    }

    /// Save vulnerabilities, completely replacing existing data (destructive)
    pub fn save_overwrite(&self, vulns: &[Vulnerability]) -> Result<(), String> {
        let store = JsonStore {
            path: self.path.clone(),
        };
        store.save(vulns)
    }

    /// Load all vulnerabilities from cache
    pub fn load(&self) -> Result<Vec<Vulnerability>, String> {
        let store = JsonStore {
            path: self.path.clone(),
        };
        store.load()
    }

    /// Check if we should fetch new data for a package based on cached vulnerabilities
    /// Returns true if we should fetch (no data or has unfixed vulnerabilities)
    pub fn should_fetch_for_package(&self, cache: &[Vulnerability], pkg: &Package) -> bool {
        let relevant_vulns: Vec<&Vulnerability> = cache
            .iter()
            .filter(|v| v.package == pkg.name && v.source == Some(pkg.source.clone()))
            .collect();

        if relevant_vulns.is_empty() {
            return true; // No cached data, fetch
        }

        // Check if any vulnerability has an open range (no upper bound)
        for vuln in relevant_vulns {
            for range in &vuln.version_ranges {
                if !has_upper_bound(range) {
                    return true; // Has unfixed vulnerability, fetch for updates
                }
            }
        }

        false // All vulnerabilities appear fixed, don't fetch
    }
}

fn has_upper_bound(range: &str) -> bool {
    range.contains('<')
}