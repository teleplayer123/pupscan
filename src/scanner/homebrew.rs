use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;
use regex::Regex;

pub struct HomebrewScanner;

impl Scanner for HomebrewScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        // Make sure path is a directory
        let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err(format!("Path {} is not a directory", path));
        }

        // Homebrew stores packages and versions in homebrew/Cellar/<package>/<version>
        let mut packages = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().is_dir() {
                let package_name = entry.file_name().into_string().unwrap_or_default();
                for version_entry in fs::read_dir(entry.path()).map_err(|e| e.to_string())? {
                    let version_entry = version_entry.map_err(|e| e.to_string())?;
                    if version_entry.path().is_dir() {
                        //println!("Found Homebrew package: {}", version_entry.path().display());
                        let sbom_path = version_entry.path().join("sbom.spdx.json");
                        let github_url = find_github_url(sbom_path.to_str().unwrap_or_default());
                        //println!("Found github url: {:?}", &github_url.as_ref().unwrap_or(&"None".to_string()));
                        let version = version_entry.file_name().into_string().unwrap_or_default();
                        let pkg = Package {
                            name: github_url.unwrap_or_else(|| package_name.clone()).to_string(),
                            version,
                            source: PackageSource::GIT,
                            path: Some(version_entry.path().to_str().unwrap_or_default().into()),
                            purl: None,
                        };
                        packages.push(pkg);
                    }
                }
            }
        }

        Ok(packages)
    }
}

fn find_github_url(sbom_path: &str) -> Option<String> {
    // Search for github url in the sbom file
    let sbom_content = fs::read_to_string(sbom_path).unwrap_or_default();
    // Look in packages -> downloadLocation for github url
    let sbom_json: serde_json::Value = serde_json::from_str(&sbom_content).unwrap_or_default();
    if let Some(packages) = sbom_json.get("packages").and_then(|p| p.as_array()) {
        for package in packages {
            if let Some(download_location) = package.get("downloadLocation").and_then(|d| d.as_str()) {
                if download_location.contains("github.com") {
                    // Regex to extract https://github.com/owner/repo from download location
                    let re = Regex::new(r"https://github\.com/[^/\s]+/[^/\s]+").unwrap();
                    if let Some(caps) = re.captures(download_location) {
                        // Add .git suffix to the end of the url
                        let github_url = format!("{}.git", caps.get(0).unwrap().as_str());
                        return Some(github_url);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_homebrew_scanner() {
        let dir = tempdir().unwrap();
        let homebrew_dir = dir.path().join("Cellar");
        fs::create_dir(&homebrew_dir).unwrap();
        let package_dir = homebrew_dir.join("test_package");
        fs::create_dir(&package_dir).unwrap();
        let version_dir = package_dir.join("1.0.0");
        fs::create_dir(&version_dir).unwrap();
        println!("Created test directory at {:?}", dir.path());
        // Walk through the directory structure to verify it was created correctly
        for entry in fs::read_dir(&homebrew_dir).unwrap() {
            let entry = entry.unwrap();
            println!("Found entry: {:?}", entry.path());
            assert!(entry.path().is_dir());
            let package_name = entry.file_name().into_string().unwrap_or_default();
            assert_eq!(package_name, "test_package");
            let version_entry = fs::read_dir(entry.path()).unwrap().next().unwrap().unwrap();
            println!("Found version entry: {:?}", version_entry.path());
            assert!(version_entry.path().is_dir());
            let version = version_entry.file_name().into_string().unwrap_or_default();
            assert_eq!(version, "1.0.0");
        }
        let scanner = HomebrewScanner;
        let packages = scanner.scan(homebrew_dir.to_str().unwrap()).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "test_package");
        assert_eq!(packages[0].version, "1.0.0");
        assert_eq!(packages[0].purl, Some("pkg:generic/homebrew/test_package@1.0.0".to_string()));
    }
}