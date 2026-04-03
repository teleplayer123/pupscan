use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct NpmScanner;

impl Scanner for NpmScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| e.to_string())?;

        let json: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let mut packages = Vec::new();

        Self::extract_deps(&json, "dependencies", path, &mut packages);
        Self::extract_deps(&json, "devDependencies", path, &mut packages);

        Ok(packages)
    }
}

impl NpmScanner {
    fn extract_deps(
        json: &serde_json::Value,
        key: &str,
        path: &str,
        packages: &mut Vec<Package>,
    ) {
        if let Some(deps) = json.get(key).and_then(|v| v.as_object()) {
            for (name, version_val) in deps {
                let version = version_val
                    .as_str()
                    .unwrap_or("*")
                    .to_string();

                packages.push(Package {
                    name: name.to_string(),
                    version,
                    source: PackageSource::Npm,
                    path: Some(path.into()),
                });
            }
        }
    }
}