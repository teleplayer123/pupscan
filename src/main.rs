mod core;
mod scanner;
mod matcher;
mod database;
mod updater;

use core::traits::{Matcher, Scanner};
use core::types::{Package, PackageSource};
use core::log::{log_message, initialize_logger, Level};
use std::path::Path;
use clap::{Parser, Subcommand};

use scanner::{CargoScanner, NpmScanner, PythonScanner, GoScanner, HomebrewScanner};
use matcher::EcosystemMatcher;
use updater::{OsvFetcher, CacheManager, NvdFetcher};

#[derive(Parser)]
#[command(name = "pupscan")]
#[command(about = "A package vulnerability scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Scan a package manifest file or directory for vulnerabilities
    Scan {
        // Path to the package manifest file or directory containing one
        path: String,
        // Fetch vulnerabilities for all versions of packages, not just the specified versions
        #[arg(long)]
        all_versions: bool,
        // Also query NVD/CVE database (slower; set NVD_API_KEY env var for higher rate limits)
        #[arg(long)]
        nvd: bool,
    },
    // Fetch OSV vulnerability data by ID or package constraints
    #[command(subcommand)]
    Fetch(FetchCommand),
    // View the local vulnerability cache
    Check {
        // Path to scan for package manifests (file or directory)
        #[arg(short, long, default_value = ".")]
        scan_path: String,
        // Path to the local vulnerability cache file
        #[arg(short, long, default_value = "vulns.json")]
        cache_path: String,
    },
    // Update the vulnerability database if stale
    Update {
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum FetchCommand {
    // Fetch vulnerabilities by package name, ecosystem, and optionally version
    Package {
        ecosystem: String,
        package: String,
        #[arg(short, long, default_value = "*")]
        version: String,
    },
    // Fetch vulnerability details by OSV ID
    Id {
        id: String,
    },
}

fn scanner_for_path(path: &Path) -> Vec<Box<dyn Scanner>> {
    let mut scanners: Vec<Box<dyn Scanner>> = Vec::new();

    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
        match file_name {
            "Cargo.toml" => scanners.push(Box::new(CargoScanner)),
            // For testing or custom rust manifest use test.toml
            "test.toml" => scanners.push(Box::new(CargoScanner)),
            "package.json" => scanners.push(Box::new(NpmScanner)),
            "requirements.txt" => scanners.push(Box::new(PythonScanner)),
            "pyproject.toml" => scanners.push(Box::new(PythonScanner)),
            "go.mod" => scanners.push(Box::new(GoScanner)),
            "Cellar" => scanners.push(Box::new(HomebrewScanner)),
            _ => {}
        }
    }

    scanners
}

fn main() {
    let cli = Cli::parse();
    let _ = initialize_logger();
    log_message(Level::Info, &"MAIN".to_string(), &"Logger initialized!".to_string());

    match cli.command {
        Commands::Scan { path, all_versions, nvd } => run_scan(&path, all_versions, nvd),
        Commands::Fetch(fetch_command) => match fetch_command {
            FetchCommand::Package { ecosystem, package, version } => run_fetch(&ecosystem, &package, &version),
            FetchCommand::Id { id } => get_vuln_info(&id),
        },
        Commands::Check { scan_path, cache_path } => check_cache(&scan_path, &cache_path),
        Commands::Update { force } => run_update(force),
    }
}

fn get_vuln_info(id: &str) {
    if id.starts_with("CVE-") {
        match NvdFetcher::get_cve_by_id(id) {
            Ok(cve) => print_nvd_cve(&cve),
            Err(err) => {
                eprintln!("Failed to fetch CVE from NVD: {}", err);
                std::process::exit(1);
            }
        }
        return;
    }

    match OsvFetcher::get_vuln_by_id(id) {
        Ok(vuln) => {
            println!("ID: {}", &vuln.id);
            println!("Summary: {}", &vuln.summary);
            println!("Details: {}", &vuln.details);
            println!("Package: {}", &vuln.package);
            println!("Affected versions: {}", &vuln.affected_versions.join(", "));
            println!("Fixed versions: {}", &vuln.fix_versions.join(", "));
            println!("Severity: {}", &vuln.severity);
            println!("Source: {}", &vuln.source);
        }
        Err(err) => {
            eprintln!("Failed to fetch vulnerability info: {}", err);
            std::process::exit(1);
        }
    }
}

fn print_nvd_cve(cve: &updater::nvd::NvdCve) {
    println!("ID: {}", cve.id);
    if !cve.published.is_empty() {
        println!("Published: {}", cve.published);
    }
    if let Some(desc) = cve.descriptions.iter().find(|d| d.lang == "en") {
        println!("Description: {}", desc.value);
    }

    // CVSS scores — prefer v3.1 > v3.0 > v2
    let metric = cve.metrics.cvss_metric_v31.as_ref().and_then(|v| v.first())
        .or_else(|| cve.metrics.cvss_metric_v30.as_ref().and_then(|v| v.first()))
        .or_else(|| cve.metrics.cvss_metric_v2.as_ref().and_then(|v| v.first()));

    if let Some(m) = metric {
        println!("CVSS Score: {} ({})", m.cvss_data.base_score, m.cvss_data.base_severity);
        if !m.cvss_data.vector_string.is_empty() {
            println!("  Vector: {}", m.cvss_data.vector_string);
        }
    }

    // Affected configurations (CPE)
    let mut printed_cpe_header = false;
    for config in &cve.configurations {
        for node in &config.nodes {
            for m in &node.cpe_match {
                if !m.vulnerable { continue; }
                if !printed_cpe_header {
                    println!("Affected configurations:");
                    printed_cpe_header = true;
                }
                print!("  {}", m.criteria);
                if let Some(v) = &m.version_start_including { print!(" >= {}", v); }
                if let Some(v) = &m.version_start_excluding { print!(" > {}", v); }
                if let Some(v) = &m.version_end_including   { print!(" <= {}", v); }
                if let Some(v) = &m.version_end_excluding   { print!(" < {}", v); }
                println!();
            }
        }
    }

    // References (cap at 5 to keep output readable)
    if !cve.references.is_empty() {
        println!("References:");
        for r in cve.references.iter().take(5) {
            println!("  {}", r.url);
        }
        if cve.references.len() > 5 {
            println!("  ... and {} more", cve.references.len() - 5);
        }
    }
}

fn get_packages(input_path_str: &str) -> Vec<Package> {
    let input_path = Path::new(input_path_str);
    if !input_path.exists() {
        eprintln!("Path does not exist: {}", input_path.display());
        std::process::exit(1);
    }

    let mut package_paths = Vec::new();

    if input_path.is_dir() {
        let candidates = ["Cargo.toml", "package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cellar"];
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

    packages
}

fn check_cache(scan_path: &str, cache_path: &str) {
    let packages = get_packages(scan_path);

    println!("Collected {} package entries", packages.len());
    if packages.is_empty() {
        println!("No packages to scan; exiting.");
        return;
    }

    let cache = CacheManager {
        path: cache_path.into(),
        max_age_secs: 60 * 60 * 24,
    };
    let cached_vulns = match cache.load() {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Failed to load cache: {}", err);
            return;
        }
    };

    let matcher = EcosystemMatcher;
    let findings = matcher.match_packages(&packages, &cached_vulns);
    if findings.is_empty() {
        println!("No known vulnerabilities found in cache for packages at {} ✅", scan_path);
    } else {
        println!("Found {} cached vulnerabilities for packages at {}:", findings.len(), scan_path);
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

fn run_scan(input_path_str: &str, all_versions: bool, use_nvd: bool) {
    let packages = get_packages(input_path_str);

    println!("Collected {} package entries", packages.len());
    if packages.is_empty() {
        println!("No packages to scan; exiting.");
        return;
    }

    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24,
    };

    let mut all_vulns = match cache.load() {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };

    // Deduplicate packages by (name, source) for fetching
    let unique_packages: Vec<Package> = {
        let mut map = std::collections::HashMap::new();
        for pkg in &packages {
            let key = (pkg.name.clone(), pkg.source.clone());
            map.entry(key).or_insert_with(|| pkg.clone());
        }
        map.into_values().collect()
    };

    let mut fetched_vulns = Vec::new();

    // OSV fetch
    let mut osv_packages: Vec<Package> = unique_packages.iter()
        .filter(|pkg| cache.should_fetch_for_package(&all_vulns, pkg))
        .cloned()
        .collect();
    if all_versions {
        for pkg in &mut osv_packages {
            pkg.version = "*".to_string();
        }
    }
    for pkg in &osv_packages {
        match OsvFetcher::fetch_data(pkg) {
            Ok(mut pkg_vulns) => fetched_vulns.append(&mut pkg_vulns),
            Err(err) => eprintln!("OSV fetch failed for {}: {}", pkg.name, err),
        }
    }

    // NVD/CVE fetch (opt-in via --nvd)
    if use_nvd {
        let has_api_key = std::env::var("NVD_API_KEY").is_ok();
        // NVD rate limits: 5 req/30s unauthenticated, 50 req/30s with API key
        let delay_ms: u64 = if has_api_key { 600 } else { 6000 };
        if !has_api_key {
            println!("Note: Set NVD_API_KEY env var for higher NVD rate limits (currently 5 req/30s).");
        }
        println!("Fetching NVD/CVE data for {} packages...", unique_packages.len());
        for pkg in &unique_packages {
            match NvdFetcher::fetch_by_package(pkg) {
                Ok(mut nvd_vulns) => {
                    if !nvd_vulns.is_empty() {
                        println!("  NVD: {} CVEs matched for {}", nvd_vulns.len(), pkg.name);
                    }
                    fetched_vulns.append(&mut nvd_vulns);
                }
                Err(err) => eprintln!("NVD fetch failed for {}: {}", pkg.name, err),
            }
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }

    let new_vulns_count = fetched_vulns.len();
    all_vulns.extend(fetched_vulns);

    if let Err(err) = cache.save(&all_vulns) {
        eprintln!("Failed to save vuln cache: {}", err);
    } else {
        println!("Saved {} vulnerabilities to cache with a total of {} entries", new_vulns_count, all_vulns.len());
    }

    let matcher = EcosystemMatcher;
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

fn run_update(force: bool) {
    let cache = CacheManager {
        path: "vulns.json".into(),
        max_age_secs: 60 * 60 * 24,
    };

    if !cache.is_stale() {
        if !force {
            println!("Database is up to date (less than 24 hours old). No update needed.");
            return;
        }
    }

    println!("Database is stale. Updating...");

    let existing_vulns = match cache.load() {
        Ok(v) => v,
        Err(err) => {
            eprintln!("Failed to load existing cache: {}", err);
            return;
        }
    };

    // Collect unique packages from existing vulnerabilities
    let mut unique_packages = std::collections::HashMap::new();
    for vuln in &existing_vulns {
        if let Some(source) = &vuln.source {
            let key = (vuln.package.clone(), source.clone());
            unique_packages.entry(key).or_insert_with(|| Package {
                name: vuln.package.clone(),
                version: "*".to_string(),
                source: source.clone(),
                path: None,
                purl: None,
            });
        }
    }

    let fetch_packages: Vec<Package> = unique_packages.into_values().collect();

    if fetch_packages.is_empty() {
        println!("No packages found in cache to update.");
        return;
    }

    println!("Fetching updates for {} packages...", fetch_packages.len());

    let mut updated_vulns = Vec::new();
    for pkg in &fetch_packages {
        match OsvFetcher::fetch_data(pkg) {
            Ok(mut pkg_vulns) => updated_vulns.append(&mut pkg_vulns),
            Err(err) => eprintln!("OSV fetch failed for {}: {}", pkg.name, err),
        }
    }

    if let Err(err) = cache.save(&updated_vulns) {
        eprintln!("Failed to save updated cache: {}", err);
    } else {
        println!("Successfully updated database with {} vulnerabilities.", updated_vulns.len());
    }
}

fn run_fetch(ecosystem_str: &str, package_name: &str, version: &str) {
    let source = match ecosystem_str {
        "crates.io" => PackageSource::CargoToml,
        "PyPI" => PackageSource::PyPI,
        "npm" => PackageSource::Npm,
        "Go" => PackageSource::Go,
        "GIT" => PackageSource::GIT,
        _ => {
            eprintln!("Unsupported ecosystem: {}. Supported: crates.io, PyPI, npm, Go, GIT", ecosystem_str);
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
        purl: None,
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
