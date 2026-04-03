use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct PythonScanner;

impl Scanner for PythonScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| e.to_string())?;

        let mut packages = Vec::new();

        if path.ends_with("pyproject.toml") {
            let toml_value: toml::Value = toml::from_str(&content)
                .map_err(|e| e.to_string())?;

            // PEP 621 project.dependencies
            if let Some(deps) = toml_value.get("project").and_then(|p| p.get("dependencies")) {
                if let Some(array) = deps.as_array() {
                    for dep in array {
                        if let Some(dep_str) = dep.as_str() {
                            let (name, version) = parse_requirement(dep_str);
                            packages.push(Package {
                                name: name.to_string(),
                                version: version.to_string(),
                                source: PackageSource::PyPI,
                                path: Some(path.into()),
                            });
                        }
                    }
                }
            }

            // Poetry tool.poetry.dependencies
            if let Some(poetry) = toml_value.get("tool").and_then(|t| t.get("poetry")).and_then(|p| p.get("dependencies")) {
                if let Some(table) = poetry.as_table() {
                    for (name, value) in table {
                        if name == "python" {
                            continue;
                        }
                        let version = match value {
                            toml::Value::String(s) => s.as_str(),
                            toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).unwrap_or("*"),
                            _ => "*",
                        };

                        packages.push(Package {
                            name: name.to_string(),
                            version: version.to_string(),
                            source: PackageSource::PyPI,
                            path: Some(path.into()),
                        });
                    }
                }
            }

            // Poetry tool.poetry.dev-dependencies
            if let Some(dev_deps) = toml_value.get("tool").and_then(|t| t.get("poetry")).and_then(|p| p.get("dev-dependencies")) {
                if let Some(table) = dev_deps.as_table() {
                    for (name, value) in table {
                        let version = match value {
                            toml::Value::String(s) => s.as_str(),
                            toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).unwrap_or("*"),
                            _ => "*",
                        };

                        packages.push(Package {
                            name: name.to_string(),
                            version: version.to_string(),
                            source: PackageSource::PyPI,
                            path: Some(path.into()),
                        });
                    }
                }
            }

            if let Some(requires) = toml_value.get("build-system").and_then(|b| b.get("requires")) {
                if let Some(array) = requires.as_array() {
                    for dep in array {
                        if let Some(dep_str) = dep.as_str() {
                            let (name, version) = parse_requirement(dep_str);
                            packages.push(Package {
                                name: name.to_string(),
                                version: version.to_string(),
                                source: PackageSource::PyPI,
                                path: Some(path.into()),
                            });
                        }
                    }
                }
            }

            return Ok(packages);
        }

        if !path.ends_with("requirements.txt") {
            return Err("Unsupported file type. Only pyproject.toml and requirements.txt are supported.".to_string());
        }

        for line in content.lines() {
            let line = line.trim();

            // Skip comments / empty
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (name, version) = parse_requirement(line);

            packages.push(Package {
                name: name.to_string(),
                version: version.to_string(),
                source: PackageSource::PyPI,
                path: Some(path.into()),
            });
        }

        Ok(packages)
    }
}

fn parse_requirement(req: &str) -> (&str, &str) {
    // support exact (==), lower/upper bound, ~=, >=
    let operators = ["==", ">=", "<=", "~=", "<", ">"];

    for op in operators {
        if let Some((name, version)) = req.split_once(op) {
            return (name.trim(), version.trim());
        }
    }

    (req.trim(), "*")
}