use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum PackageSource {
    CargoToml,
    System,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub version_ranges: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct Finding {
    pub package: Package,
    pub vulnerability: Vulnerability,
}