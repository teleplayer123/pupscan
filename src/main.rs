mod core;
mod scanner;
mod matcher;
mod database;
mod updater;

use core::traits::{Matcher, Scanner, VulnerabilityStore};

use scanner::{CargoScanner, NpmScanner, PythonScanner};
use matcher::SimpleMatcher;
use database::JsonStore;
use updater::{OsvFetcher, CacheManager};

fn main() {
    // -----------------------------
    // 1. Update / Load Vulnerabilities
    // -----------------------------
    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24, // 24 hours
    };

    let vulns = if cache.is_stale() {
        println!("Updating vulnerability database...");

        match OsvFetcher::fetch_rust_vulns() {
            Ok(v) => {
                if let Err(e) = cache.save(&v) {
                    eprintln!("Failed to save cache: {}", e);
                }
                v
            }
            Err(e) => {
                eprintln!("Fetch failed, using cached data: {}", e);
                cache.load().unwrap_or_default()
            }
        }
    } else {
        cache.load().unwrap_or_default()
    };

    println!("Loaded {} vulnerabilities", vulns.len());

    // -----------------------------
    // 2. Scan Project Files
    // -----------------------------
    let cargo = CargoScanner;
    let npm = NpmScanner;
    let python = PythonScanner;

    let mut packages = Vec::new();

    if let Ok(p) = cargo.scan("Cargo.toml") {
        packages.extend(p);
    }

    if let Ok(p) = npm.scan("package.json") {
        packages.extend(p);
    }

    if let Ok(p) = python.scan("requirements.txt") {
        packages.extend(p);
    }

    println!("Discovered {} packages", packages.len());

    // -----------------------------
    // 3. Match Vulnerabilities
    // -----------------------------
    let matcher = SimpleMatcher;

    let findings = matcher.match_packages(&packages, &vulns);

    // -----------------------------
    // 4. Report Results
    // -----------------------------
    if findings.is_empty() {
        println!("No known vulnerabilities found ✅");
    } else {
        println!("Found {} potential issues:\n", findings.len());

        for f in findings {
            println!(
                "[{:?}] {}@{} → {}",
                f.vulnerability.severity,
                f.package.name,
                f.package.version,
                f.vulnerability.id
            );

            if let Some(path) = &f.package.path {
                println!("  Path: {:?}", path);
            }
        }
    }
}