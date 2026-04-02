mod core;
mod scanner;
mod matcher;
mod database;
mod updater;

use core::traits::{Matcher, Scanner};

use scanner::{CargoScanner, NpmScanner, PythonScanner};
use matcher::SimpleMatcher;
use updater::{OsvFetcher, CacheManager};

fn main() {
    // -----------------------------
    // 1. Load / Update CVE Database
    // -----------------------------
    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24,
    };

    let vulns = if cache.is_stale() {
        println!("Updating vulnerability database...");

        match OsvFetcher::fetch_rust_vulns() {
            Ok(v) => {
                if let Err(e) = cache.save(&v) {
                    eprintln!("Cache save failed: {}", e);
                }
                v
            }
            Err(e) => {
                eprintln!("Fetch failed: {}, using cache", e);
                cache.load().unwrap_or_default()
            }
        }
    } else {
        cache.load().unwrap_or_default()
    };

    println!("Loaded {} vulnerabilities", vulns.len());

    // -----------------------------
    // 2. Scan Files
    // -----------------------------
    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(CargoScanner),
        Box::new(NpmScanner),
        Box::new(PythonScanner),
    ];

    let mut packages = Vec::new();

    for scanner in scanners {
        if let Ok(mut p) = scanner.scan(".") {
            packages.append(&mut p);
        }
    }

    println!("Discovered {} packages", packages.len());

    // -----------------------------
    // 3. Match
    // -----------------------------
    let matcher = SimpleMatcher;
    let findings = matcher.match_packages(&packages, &vulns);

    // -----------------------------
    // 4. Report
    // -----------------------------
    if findings.is_empty() {
        println!("No known vulnerabilities found ✅");
    } else {
        println!("Found {} issues:\n", findings.len());

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