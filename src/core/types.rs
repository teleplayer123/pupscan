use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
    pub path: Option<PathBuf>,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum PackageSource {
    CargoToml,
    PyPI,
    Npm,
    Go,
    GIT,
    RubyGems,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub version_ranges: Vec<String>,
    pub severity: Severity,
    pub source: Option<PackageSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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