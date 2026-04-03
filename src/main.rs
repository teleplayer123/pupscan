mod core;
mod scanner;
mod matcher;
mod database;
mod updater;

use core::traits::{Matcher, Scanner};
use std::env;
use std::path::Path;

use scanner::CargoScanner;
use matcher::SimpleMatcher;
use updater::{OsvFetcher, CacheManager};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: pupscan <path-to-Cargo.toml-or-directory>");
        std::process::exit(1);
    }

    let input_path = Path::new(&args[1]);
    let manifest_path = if input_path.is_dir() {
        input_path.join("Cargo.toml")
    } else {
        input_path.to_path_buf()
    };

    if !manifest_path.exists() {
        eprintln!("Could not find Cargo.toml at {}", manifest_path.display());
        std::process::exit(1);
    }

    let package_file_path = manifest_path
        .to_str()
        .expect("manifest path cannot be converted to string");

    println!("Parsing packages from {}", package_file_path);
    let packages = match CargoScanner.scan(package_file_path) {
        Ok(pkgs) => pkgs,
        Err(e) => {
            eprintln!("Failed to parse package file: {}", e);
            std::process::exit(1);
        }
    };

    println!("Found {} packages", packages.len());

    let mut all_vulns = Vec::new();
    for pkg in &packages {
        match OsvFetcher::fetch_data(pkg) {
            Ok(mut pkg_vulns) => {
                all_vulns.append(&mut pkg_vulns);
            }
            Err(err) => {
                eprintln!("Failed to fetch OSV data for {}: {}", pkg.name, err);
            }
        }
    }

    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24,
    };

    if let Err(err) = cache.save(&all_vulns) {
        eprintln!("Failed to save cache: {}", err);
    } else {
        println!("Saved {} vulnerabilities to cache", all_vulns.len());
    }

    let matcher = SimpleMatcher;
    let findings = matcher.match_packages(&packages, &all_vulns);

    if findings.is_empty() {
        println!("No known vulnerabilities found ✅");
        return;
    }

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
