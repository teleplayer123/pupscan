use crate::core::types::*;
use crate::core::log::{log_message, Level};
use serde::Deserialize;

const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub struct NvdFetcher;

impl NvdFetcher {
    /// Fetch CVEs from NVD matching the given package via keyword search.
    /// Only returns entries where CPE version range data could be parsed.
    pub fn fetch_by_package(pkg: &Package) -> Result<Vec<Vulnerability>, String> {
        let encoded = url_encode(&pkg.name);
        let url = format!("{}?keywordSearch={}&resultsPerPage=50", NVD_BASE_URL, encoded);

        log_message(Level::Info, "NVD", &format!("Querying NVD for: {}", pkg.name));

        let body = nvd_get(&url)?;
        log_message(Level::Debug, "NVD", &body);

        let response: NvdResponse = serde_json::from_str(&body)
            .map_err(|e| format!("NVD parse error: {}", e))?;

        log_message(Level::Info, "NVD", &format!("{} CVEs found for {}", response.total_results, pkg.name));

        let results = response.vulnerabilities
            .into_iter()
            .filter_map(|w| parse_cve_to_vuln(w.cve, pkg))
            .collect();

        Ok(results)
    }

    /// Fetch a single CVE record by ID (e.g. "CVE-2021-44228").
    pub fn get_cve_by_id(cve_id: &str) -> Result<NvdCve, String> {
        let url = format!("{}?cveId={}", NVD_BASE_URL, cve_id);
        let body = nvd_get(&url)?;

        let response: NvdResponse = serde_json::from_str(&body)
            .map_err(|e| format!("NVD parse error: {}", e))?;

        response.vulnerabilities
            .into_iter()
            .next()
            .map(|w| w.cve)
            .ok_or_else(|| format!("CVE '{}' not found in NVD", cve_id))
    }
}

fn nvd_get(url: &str) -> Result<String, String> {
    let mut req = ureq::get(url);
    if let Ok(key) = std::env::var("NVD_API_KEY") {
        req = req.set("apiKey", &key);
    }
    req.call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            '/' => out.push_str("%2F"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            '&' => out.push_str("%26"),
            _   => out.push(c),
        }
    }
    out
}

fn parse_cve_to_vuln(cve: NvdCve, pkg: &Package) -> Option<Vulnerability> {
    let summary = cve.descriptions.iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let severity = severity_from_metrics(&cve.metrics);
    let version_ranges = extract_version_ranges(&cve.configurations, &pkg.name);

    // Skip if we couldn't pin down any version range — would match everything
    if version_ranges.is_empty() {
        log_message(Level::Debug, "NVD", &format!(
            "Skipping {} - no matching CPE version ranges for {}", cve.id, pkg.name
        ));
        return None;
    }

    Some(Vulnerability {
        id: cve.id,
        summary,
        package: pkg.name.clone(),
        version_ranges,
        severity,
        source: Some(pkg.source.clone()),
    })
}

/// Extract version ranges from NVD CPE configurations that match the package name.
fn extract_version_ranges(configurations: &[NvdConfiguration], package_name: &str) -> Vec<String> {
    let pkg_lower = package_name.to_lowercase();
    let mut ranges = Vec::new();

    for config in configurations {
        for node in &config.nodes {
            for m in &node.cpe_match {
                if !m.vulnerable {
                    continue;
                }

                // CPE 2.3 format: cpe:2.3:a:<vendor>:<product>:<version>:...
                let parts: Vec<&str> = m.criteria.split(':').collect();
                let vendor  = parts.get(3).copied().unwrap_or("").to_lowercase();
                let product = parts.get(4).copied().unwrap_or("").to_lowercase();

                let name_matches = product.contains(&pkg_lower)
                    || pkg_lower.contains(&product)
                    || vendor.contains(&pkg_lower)
                    || pkg_lower.contains(&vendor);

                if !name_matches {
                    continue;
                }

                if let Some(r) = cpe_match_to_range(m, &parts) {
                    ranges.push(r);
                }
            }
        }
    }

    ranges
}

fn cpe_match_to_range(m: &NvdCpeMatch, cpe_parts: &[&str]) -> Option<String> {
    let start = match (&m.version_start_including, &m.version_start_excluding) {
        (Some(v), _) => Some(format!(">={}", v)),
        (_, Some(v)) => Some(format!(">{}", v)),
        _            => None,
    };

    let end = match (&m.version_end_including, &m.version_end_excluding) {
        (Some(v), _) => Some(format!("<={}", v)),
        (_, Some(v)) => Some(format!("<{}", v)),
        _            => None,
    };

    if start.is_none() && end.is_none() {
        // Fall back to exact version embedded in the CPE criteria string
        let version = cpe_parts.get(5).copied().unwrap_or("*");
        if version != "*" && version != "-" && !version.is_empty() {
            return Some(format!("={}", version));
        }
        return None;
    }

    Some(match (start, end) {
        (Some(s), Some(e)) => format!("{}, {}", s, e),
        (Some(s), None)    => s,
        (None, Some(e))    => e,
        _                  => return None,
    })
}

fn severity_from_metrics(metrics: &NvdMetrics) -> Severity {
    // Prefer CVSS v3.1 > v3.0 > v2
    let score = metrics.cvss_metric_v31.as_ref()
        .and_then(|v| v.first())
        .or_else(|| metrics.cvss_metric_v30.as_ref().and_then(|v| v.first()))
        .or_else(|| metrics.cvss_metric_v2.as_ref().and_then(|v| v.first()))
        .map(|e| e.cvss_data.base_score);

    match score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(_)              => Severity::Low,
        None                 => Severity::Medium,
    }
}

// ── NVD API response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults", default)]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
pub struct NvdCve {
    pub id: String,
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub descriptions: Vec<NvdDescription>,
    #[serde(default)]
    pub metrics: NvdMetrics,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
    #[serde(default)]
    pub references: Vec<NvdReference>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    pub cvss_metric_v31: Option<Vec<NvdCvssEntry>>,
    #[serde(rename = "cvssMetricV30", default)]
    pub cvss_metric_v30: Option<Vec<NvdCvssEntry>>,
    #[serde(rename = "cvssMetricV2", default)]
    pub cvss_metric_v2: Option<Vec<NvdCvssEntry>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssEntry {
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
pub struct NvdCvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "vectorString", default)]
    pub vector_string: String,
    #[serde(rename = "baseSeverity", default)]
    pub base_severity: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdConfiguration {
    #[serde(default)]
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
pub struct NvdNode {
    #[serde(rename = "cpeMatch", default)]
    pub cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NvdReference {
    pub url: String,
}
