mod core;
mod scanner;
mod matcher;
mod database;
mod updater;

use core::traits::{Matcher, Scanner};
use core::types::{Package, PackageSource};
use std::path::Path;
use clap::{Parser, Subcommand};

use scanner::{CargoScanner, NpmScanner, PythonScanner};
use matcher::SimpleMatcher;
use updater::{OsvFetcher, CacheManager};

#[derive(Parser)]
#[command(name = "pupscan")]
#[command(about = "A package vulnerability scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a package manifest file or directory for vulnerabilities
    Scan {
        /// Path to the package manifest file or directory containing one
        path: String,
        /// Fetch vulnerabilities for all versions of packages, not just the specified versions
        #[arg(long)]
        all_versions: bool,
    },
    /// Fetch OSV vulnerability data for a specific package and version
    Fetch {
        /// Package ecosystem (crates.io, PyPI, npm)
        ecosystem: String,
        /// Package name
        package: String,
        /// Package version
        #[arg(short, long, default_value = "*")]
        version: String,
    },
    /// View the local vulnerability cache
    Cache {
        /// Path to the local vulnerability cache file
        #[arg(short, long, default_value = "vulns.json")]
        cache_path: String,
    },
}

fn scanner_for_path(path: &Path) -> Vec<Box<dyn Scanner>> {
    let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();

    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
        match file_name {
            "Cargo.toml" => scanners.push(Box::new(CargoScanner)),
            "package.json" => scanners.push(Box::new(NpmScanner)),
            "requirements.txt" => scanners.push(Box::new(PythonScanner)),
            "pyproject.toml" => scanners.push(Box::new(PythonScanner)),
            _ => {}
        }
    }

    scanners
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, all_versions } => run_scan(&path, all_versions),
        Commands::Fetch { ecosystem, package, version } => run_fetch(&ecosystem, &package, &version),
        Commands::Cache { cache_path } => view_cache(&cache_path),
    }
}

fn view_cache(cache_path: &str) {
    let cache = CacheManager {
        path: cache_path.into(),
        max_age_secs: 60 * 60 * 24,
    };
    cache.load().map(|vulns| {
        println!("Cached vulnerabilities:");
        for vuln in vulns {
            println!("  {}: {}", vuln.id, vuln.version_ranges.join(", "));
        }
    }).unwrap_or_else(|err| eprintln!("Failed to load cache: {}", err));
}

fn run_scan(input_path_str: &str, all_versions: bool) {
    let input_path = Path::new(input_path_str);
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
    if all_versions {
        // Collect unique packages by name and source, with version "*" to fetch all vulnerabilities
        let mut unique_packages = std::collections::HashMap::new();
        for pkg in &packages {
            let key = (pkg.name.clone(), pkg.source.clone());
            unique_packages.entry(key).or_insert(pkg.clone());
        }
        let mut fetch_packages: Vec<Package> = unique_packages.into_values().collect();
        for pkg in &mut fetch_packages {
            pkg.version = "*".to_string();
        }
        for pkg in &fetch_packages {
            match OsvFetcher::fetch_data(pkg) {
                Ok(mut pkg_vulns) => all_vulns.append(&mut pkg_vulns),
                Err(err) => eprintln!("OSV fetch failed for {}: {}", pkg.name, err),
            }
        }
    } else {
        for pkg in &packages {
            match OsvFetcher::fetch_data(pkg) {
                Ok(mut pkg_vulns) => all_vulns.append(&mut pkg_vulns),
                Err(err) => eprintln!("OSV fetch failed for {}: {}", pkg.name, err),
            }
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

fn run_fetch(ecosystem_str: &str, package_name: &str, version: &str) {
    let source = match ecosystem_str {
        "crates.io" => PackageSource::CargoToml,
        "PyPI" => PackageSource::PyPI,
        "npm" => PackageSource::Npm,
        _ => {
            eprintln!("Unsupported ecosystem: {}. Supported: crates.io, PyPI, npm", ecosystem_str);
            std::process::exit(1);
        }
    };

    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24,
    };

    let package = Package {
        name: package_name.to_string(),
        version: version.to_string(),
        source,
        path: None,
    };

    println!("Fetching OSV data for {}@{} in {}", package.name, package.version, ecosystem_str);

    match OsvFetcher::fetch_data(&package) {
        Ok(vulns) => {
            if vulns.is_empty() {
                println!("No vulnerabilities found for this package/version ✅");
            } else {
                println!("Found {} vulnerabilities:", vulns.len());
                cache.save(&vulns).unwrap_or_else(|err| eprintln!("Failed to save cache: {}", err));
                for vuln in vulns {
                    println!("  {}: {}", vuln.id, vuln.version_ranges.join(", "));
                }
            }
        }
        Err(err) => {
            eprintln!("Failed to fetch OSV data: {}", err);
            std::process::exit(1);
        }
    }
}
