use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct PythonScanner;

impl Scanner for PythonScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| e.to_string())?;

        let mut packages = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments / empty
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (name, version) = if let Some((n, v)) = line.split_once("==") {
                (n.trim(), v.trim())
            } else if let Some((n, v)) = line.split_once(">=") {
                (n.trim(), v.trim())
            } else {
                (line, "*")
            };

            packages.push(Package {
                name: name.to_string(),
                version: version.to_string(),
                source: PackageSource::System,
                path: Some(path.into()),
            });
        }

        Ok(packages)
    }
}