use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct CargoScanner;

impl Scanner for CargoScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| e.to_string())?;

        let parsed: toml::Value =
            toml::from_str(&content).map_err(|e| e.to_string())?;

        let mut packages = Vec::new();

        if let Some(deps) = parsed.get("dependencies") {
            if let Some(table) = deps.as_table() {
                for (name, value) in table {
                    let version = if value.is_str() {
                        value.as_str().unwrap().to_string()
                    } else if let Some(tbl) = value.as_table() {
                        tbl.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("*")
                            .to_string()
                    } else {
                        "*".to_string()
                    };

                    packages.push(Package {
                        name: name.to_string(),
                        version,
                        source: PackageSource::CargoToml,
                        path: Some(path.into()),
                    });
                }
            }
        }

        Ok(packages)
    }
}