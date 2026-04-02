use crate::core::types::*;
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

    pub fn save(&self, vulns: &[Vulnerability]) -> Result<(), String> {
        let tmp_path = format!("{}.tmp", self.path);

        let json = serde_json::to_string_pretty(vulns)
            .map_err(|e| e.to_string())?;

        fs::write(&tmp_path, json).map_err(|e| e.to_string())?;
        fs::rename(tmp_path, &self.path).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn load(&self) -> Result<Vec<Vulnerability>, String> {
        let data = fs::read_to_string(&self.path)
            .map_err(|e| e.to_string())?;

        serde_json::from_str(&data)
            .map_err(|e| e.to_string())
    }
}