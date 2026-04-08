use crate::core::traits::Scanner;
use crate::core::types::*;
use std::fs;

pub struct HomebrewScanner;

impl Scanner for HomebrewScanner {
    fn scan(&self, path: &str) -> Result<Vec<Package>, String> {
        // Make sure path is a directory
        let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err(format!("Path {} is not a directory", path));
        }

        // TODO: instead we should find the sbom file for each package under homebrew/Cellar/<package>/<version> and parse as json
        // Homebrew stores packages and versions in homebrew/Cellar/<package>/<version>
        let mut packages = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().is_dir() {
                let package_name = entry.file_name().into_string().unwrap_or_default();
                for version_entry in fs::read_dir(entry.path()).map_err(|e| e.to_string())? {
                    let version_entry = version_entry.map_err(|e| e.to_string())?;
                    if version_entry.path().is_dir() {
                        //println!("Found Homebrew package: {} version: {}", package_name, version_entry.path().display());
                        let version = version_entry.file_name().into_string().unwrap_or_default();
                        packages.push(Package {
                            name: package_name.clone(),
                            version,
                            source: PackageSource::GIT,
                            path: Some(version_entry.path().to_str().unwrap_or_default().into()),
                        });
                    }
                }
            }
        }

        Ok(packages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
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
    }
}