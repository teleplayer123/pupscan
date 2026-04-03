mod core;
mod scanner;
mod matcher;
mod database;
mod updater;

use core::traits::{Matcher, Scanner};
use std::env;
use std::path::Path;

use scanner::{CargoScanner, NpmScanner, PythonScanner};
use matcher::SimpleMatcher;
use updater::{OsvFetcher, CacheManager};

fn scanner_for_path(path: &Path) -> Vec<Box<dyn Scanner>> {
    let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();

    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
        match file_name {
            "Cargo.toml" => scanners.push(Box::new(CargoScanner)),
            "package.json" => scanners.push(Box::new(NpmScanner)),
            "requirements.txt" => scanners.push(Box::new(PythonScanner)),
            "pyproject.toml" => scanners.push(Box::new(CargoScanner)),
            _ => {}
        }
    }

    scanners
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: pupscan <path-to-Cargo.toml-or-package.json-or-requirements.txt-or-directory>");
        std::process::exit(1);
    }

    let input_path = Path::new(&args[1]);
    if !input_path.exists() {
        eprintln!("Path does not exist: {}", input_path.display());
        std::process::exit(1);
    }

    let mut package_paths = Vec::new();

    if input_path.is_dir() {
        let candidates = ["Cargo.toml", "package.json", "requirements.txt", "pyproject.toml"];
        for cand in &candidates {
            let file = input_path.join(cand);
            if file.exists() {
                package_paths.push(file);
            }
        }

        if package_paths.is_empty() {
            eprintln!("No supported manifest files found in directory: {}", input_path.display());
            std::process::exit(1);
        }
    } else {
        package_paths.push(input_path.to_path_buf());
    }

    let mut packages = Vec::new();
    for path in &package_paths {
        let file_path = path.to_str().unwrap_or_else(|| {
            eprintln!("Invalid path: {}", path.display());
            std::process::exit(1);
        });

        println!("Scanning file {}", file_path);

        let scanners = scanner_for_path(path);
        if scanners.is_empty() {
            eprintln!("No scanner available for file: {}", file_path);
            continue;
        }

        for scanner in scanners {
            match scanner.scan(file_path) {
                Ok(mut found) => packages.append(&mut found),
                Err(err) => eprintln!("Scanner failed on {}: {}", file_path, err),
            }
        }
    }

    println!("Collected {} package entries", packages.len());
    if packages.is_empty() {
        println!("No packages to scan; exiting.");
        return;
    }

    let mut all_vulns = Vec::new();
    for pkg in &packages {
        match OsvFetcher::fetch_data(pkg) {
            Ok(mut pkg_vulns) => all_vulns.append(&mut pkg_vulns),
            Err(err) => eprintln!("OSV fetch failed for {}: {}", pkg.name, err),
        }
    }

    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24,
    };

    if let Err(err) = cache.save(&all_vulns) {
        eprintln!("Failed to save vuln cache: {}", err);
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
