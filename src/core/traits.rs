use crate::core::types::*;

pub trait Scanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String>;
}

pub trait Matcher {
    fn match_packages(
        &self,
        packages: &[Package],
        vulns: &[Vulnerability],
    ) -> Vec<Finding>;
}

pub trait VulnerabilityStore {
    fn load(&self) -> Result<Vec<Vulnerability>, String>;
}