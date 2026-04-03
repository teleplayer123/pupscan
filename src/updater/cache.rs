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
}